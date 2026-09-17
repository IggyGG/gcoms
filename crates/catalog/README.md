# GComs catalog

`gcoms-catalog` provides signed public-channel discovery, an automatic-join
boundary, network defaults and invitation-scoped name registration. It is an
operator service; ordinary addons use `gcoms-rpc` or `gcoms-sdk`.

```sh
cargo run -p gcoms-catalog --bin gcoms-catalog -- /path/to/config.json
```

The JSON configuration is `gcoms_catalog::Config`. It requires a listen address
and public base URL. Normal operation requires persistent `state_dir`; the explicit
`ephemeral_test_mode` is for disposable fixtures. `channels` maps public or private
channel IDs to an owner control service. Each owner connection uses configured
TLS trust, a client certificate/key and a bearer-token file. Keep those credentials
in private operator storage, outside this repository. Never expose owner controls
as a public anonymous API.

`upstream_catalog_urls` enables bounded federation. `network` enables signed
defaults and scoped name registrations. `relay_bootstrap` is optional: it requests
client relay cards from configured owner controls; it does not implement Ghost
machine installation or enrollment. Disabled provisioning returns an unavailable
response. Readiness means the local service loaded, not that every upstream is live.

The router exposes `/healthz`, `/readyz`, `/v1/catalog`, `/v1/descriptors`,
`/v1/channels/{channel_id}/join`, `/v1/relay-provisions`, `/v1/network-defaults`
and `/v1/names`. Use an HTTPS ingress appropriate to the deployment; the public
listener itself is HTTP. Preserve signed-document checks and rate/capacity limits.

The retained `gc-network-operator` binary creates signing keys, signs defaults,
prepares key transitions, issues/revokes invitation grants and verifies documents.
Run it without arguments for its exact file-oriented syntax. Secret outputs must
be new files in private directories; they are never printed. Back up operator keys
and state and rehearse rotation/recovery before accepting external users.

See the root SPEC.md, TESTING.md and SECURITY.md. GC/1 identifiers and the existing
`GC_CATALOG_CONFIG` environment variable retain their compatibility names.
Licensed under MIT OR Apache-2.0; this is a developer preview.
