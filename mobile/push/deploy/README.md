# GChat push gateway deployment

This package deploys the unchanged gateway from GComs
`b864f9ba6660148589d1e67821f04e98064933ef`. It makes no deployment call itself.
`runtime-sources.json` binds the three server source files. The container build
refuses different bytes. `images.json` pins the official Python and nginx OCI
indexes; `requirements.lock` pins every Python dependency and accepted archive
hash. There is no mobile build or protocol change in this package.

One `Recreate` deployment/replica owns one 1 GiB ReadWriteOnce PVC in `ghost-com`.
The unchanged server listens only on `127.0.0.1:8791`; an unprivileged nginx
sidecar serves port 8080. An nginx Ingress terminates HTTPS for `push.gchat.boo`
with `letsencrypt-prod`. Only exact `/v1/register`, `/v1/unregister`, `/v1/events`
paths are exposed. Bodies are capped at 8 KiB, connections and request rates are
bounded, and request access logs are disabled at both proxies. The sidecar limit
is intentionally an aggregate bound per ingress source, without trusting an
arbitrary forwarded IP header. No public health or credential endpoint exists.

The policy permits ingress only from namespace `ingress-nginx`, DNS to
`kube-system`, and outbound TCP 443 for configured APNs/FCM/OAuth hosts. Confirm
those existing namespace labels, CNI enforcement and the default storage class
before applying; adjust the reviewed namespace selector if the installed ingress
controller lives elsewhere. External provider DNS addresses change, so the
network policy permits HTTPS egress rather than claiming a domain allowlist.
The application's provider URLs remain fixed in the frozen source.

## Private inputs

Root provisions a Secret named `gchat-push-private` with `config.json` and only
the configured providers' `apns.p8` / `fcm.json`. Never put them in this repository,
container, build context, command output or public receipt. Configuration is the
gateway schema in `../README.md`, with these exact deployment paths:

- `public_origin`: `https://push.gchat.boo`.
- App: `boo.gchat.app`; FCM project: `gchat-23115`.
- APNs `private_key_file`: `/private/current/apns.p8`; topic `boo.gchat.app`,
  `sandbox:false`. Include the real key ID and Apple team ID privately.
- FCM `service_account_file`: `/private/current/fcm.json`.
- Distinct nonzero 32-byte hex key for each relay ID, scoped to `boo.gchat.app`.
  Relay `--push-gateway-config` uses the matching byte array and
  `https://push.gchat.boo/v1/events`. No legacy registration key is needed.

A nonroot init container validates scope and copies the projected Secret into
0700/0600 files on a RAM volume. The proxy cannot mount that volume. The gateway
and init container run as UID/GID 10001, without Kubernetes API credentials,
Linux capabilities, privilege escalation or a writable root filesystem. SQLite
lives under private `/state/push`; its journal/WAL remains on the same PVC.
Secret rotation requires an explicit deployment restart because the private
copy is intentionally immutable for a pod. Retain old relay verification keys
until matching relay configuration updates are coordinated; IDs must stay unique.

## Build and activation commands (completion owner only)

Run these through the workstation's managed build reservation. Use a fresh
local output directory and retain command/image/manifest hashes. This package
has not contacted the cluster and contains no push credentials.

```sh
python3 -m unittest discover -s mobile/push/deploy -v
python3 mobile/push/deploy/build-context.py --output "$PUSH_CONTEXT"
docker build --pull -f "$PUSH_CONTEXT/mobile/push/deploy/Dockerfile" \
  -t "$PUSH_LOCAL_TAG" "$PUSH_CONTEXT"
docker image inspect "$PUSH_LOCAL_TAG" > "$PUSH_EVIDENCE/image.json"
```

The private registry is reachable through the existing `registry:5000` service.
In a separate terminal, bind its port-forward to loopback only; do not create
another registry or publish registry credentials:

```sh
kubectl -n ghost-com port-forward --address 127.0.0.1 service/registry 15000:5000
docker tag "$PUSH_LOCAL_TAG" 127.0.0.1:15000/ghost/gchat-push:"$PUSH_TAG"
docker push 127.0.0.1:15000/ghost/gchat-push:"$PUSH_TAG"
```

Record the push's `sha256:` manifest digest. Set `PUSH_IMAGE` to the existing
**node-reachable pull registry** plus `/ghost/gchat-push@sha256:...`, not the
workstation's loopback port-forward address. Use the cluster's existing pull
Secret if required (`render.py --pull-secret NAME`). Do not infer that kubelet
can resolve the short service name `registry` from inside a pod.

Create the private Secret using file paths, without printing a generated Secret
manifest; include only the enabled providers. The example includes both:

```sh
kubectl -n ghost-com create secret generic gchat-push-private \
  --from-file=config.json="$PUSH_PRIVATE/config.json" \
  --from-file=apns.p8="$PUSH_PRIVATE/apns.p8" \
  --from-file=fcm.json="$PUSH_PRIVATE/fcm.json"
python3 mobile/push/deploy/render.py --image "$PUSH_IMAGE" > "$PUSH_EVIDENCE/deployment.json"
kubectl apply --dry-run=server -f "$PUSH_EVIDENCE/deployment.json"
kubectl apply -f "$PUSH_EVIDENCE/deployment.json"
kubectl -n ghost-com rollout status deployment/gchat-push --timeout=120s
kubectl -n ghost-com exec deployment/gchat-push -c gateway -- python3 /app/health.py --ready
curl --fail-with-body --silent --show-error --max-time 15 \
  -H 'Content-Type: application/json' --data '{}' https://push.gchat.boo/v1/register
```

The final request **must return HTTP 400** with `{"error":"request rejected"}`;
`curl --fail-with-body` therefore exits 22. This proves TLS and rejection routing,
not successful registration or provider delivery. Do not change that rejection
into a passing registration. Before activation, also run `nginx -t` on the pinned
sidecar with this configuration; the native container build/proxy syntax and
server-side Kubernetes dry run remain operator activation checks.

After healthy HTTPS, perform the actual application's authenticated registration,
controlled relay enqueue and provider receipt checks using the bounded mobile
journey. Health checks never send a provider notification. No live delivery,
physical-device/battery or reliability qualification follows from this package.

## Shutdown, rollback and cleanup

SIGTERM is translated by `launcher.py` into the unchanged server's graceful
cleanup: close listener, stop/join provider worker, close SQLite. The pod allows
40 seconds, longer than its existing 15-second provider request timeout. An
already-submitted generic alert cannot be recalled. Liveness checks only the
local server's refusal path; readiness also verifies initialized SQLite tables.
Local tests exercise startup, real HTTP refusal, SIGTERM, port closure and reopen
of the retained database. Abrupt node loss still relies on SQLite recovery and
persistent-volume durability; no power-loss claim is made.

Rollback uses `kubectl rollout undo deployment/gchat-push`, then the same health
checks, only to a previously recorded compatible image/schema. For first-install
failure, scale to zero and investigate while retaining the PVC, Secret and
failed receipt. `kubectl -n ghost-com scale deployment/gchat-push --replicas=0`
should leave no matching running pods. Do not delete the PVC/Secret or relay
bindings as routine cleanup. Explicitly unregister test installations and
zero-bind their relay notifications after the controlled provider exercise;
retain only nonsecret evidence. Never print provider tokens or private keys.

Upstream references: [official Python image](https://hub.docker.com/_/python),
[official nginx image](https://hub.docker.com/_/nginx),
[ingress-nginx annotation reference](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/).
