#!/usr/bin/env python3
"""Render reviewable Kubernetes JSON. Does not contact or mutate a cluster."""
import argparse
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
LABELS = {"app.kubernetes.io/name": "gchat-push"}


def render(image, pull_secret=None):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9./:_-]*/gchat-push@sha256:[0-9a-f]{64}", image):
        raise ValueError("an immutable registry/repository/gchat-push image digest is required")
    if pull_secret and not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", pull_secret):
        raise ValueError("invalid image pull secret name")
    def resource(kind, name, spec=None, **extra):
        value = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": "ghost-com", "labels": LABELS.copy()}}
        if spec is not None:
            value["spec"] = spec
        value.update(extra)
        return value
    def mount(name, path, readonly=False):
        return {"name": name, "mountPath": path, "readOnly": readonly}
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    probe = lambda args: {"exec": {"command": ["python3", "/app/health.py", *args]}, "timeoutSeconds": 5, "periodSeconds": 10, "failureThreshold": 3}
    gateway = {"name": "gateway", "image": image, "securityContext": security,
               "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"cpu": "1", "memory": "256Mi"}},
               "volumeMounts": [mount("private", "/private", True), mount("state", "/state"), mount("tmp", "/tmp")],
               "readinessProbe": probe(["--ready"]), "livenessProbe": probe([]),
               "startupProbe": {**probe(["--ready"]), "failureThreshold": 12, "periodSeconds": 5}}
    nginx = json.loads((HERE / "images.json").read_text())["nginx"]["image"]
    proxy = {"name": "proxy", "image": nginx, "command": ["nginx", "-c", "/config/nginx.conf", "-g", "daemon off;"],
             "securityContext": security, "ports": [{"name": "http", "containerPort": 8080}],
             "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "250m", "memory": "64Mi"}},
             "volumeMounts": [mount("proxy", "/config", True), mount("proxy-tmp", "/tmp")],
             "readinessProbe": {"httpGet": {"path": "/healthz", "port": "http"}, "timeoutSeconds": 2, "periodSeconds": 10}}
    spec = {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": LABELS},
            "template": {"metadata": {"labels": LABELS, "annotations": {"gchat.boo/runtime-source": "b864f9ba6660148589d1e67821f04e98064933ef"}},
                         "spec": {"automountServiceAccountToken": False, "terminationGracePeriodSeconds": 40,
                                  "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001, "fsGroupChangePolicy": "OnRootMismatch", "seccompProfile": {"type": "RuntimeDefault"}},
                                  "initContainers": [{"name": "private-config", "image": image, "command": ["python3", "/app/prepare.py"], "securityContext": security,
                                                      "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "250m", "memory": "64Mi"}},
                                                      "volumeMounts": [mount("credentials", "/input", True), mount("private", "/private")]}],
                                  "containers": [gateway, proxy],
                                  "volumes": [{"name": "credentials", "secret": {"secretName": "gchat-push-private", "defaultMode": 288}},
                                              {"name": "private", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
                                              {"name": "state", "persistentVolumeClaim": {"claimName": "gchat-push-state"}},
                                              {"name": "proxy", "configMap": {"name": "gchat-push-proxy"}},
                                              {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}},
                                              {"name": "proxy-tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}}]}}}
    if pull_secret:
        spec["template"]["spec"]["imagePullSecrets"] = [{"name": pull_secret}]
    deployment = resource("Deployment", "gchat-push", spec)
    deployment["apiVersion"] = "apps/v1"
    ingress = resource("Ingress", "gchat-push", {"ingressClassName": "nginx", "tls": [{"hosts": ["push.gchat.boo"], "secretName": "gchat-push-tls"}],
        "rules": [{"host": "push.gchat.boo", "http": {"paths": [{"path": "/v1/" + route, "pathType": "Exact", "backend": {"service": {"name": "gchat-push", "port": {"number": 80}}}} for route in ("register", "unregister", "events")]}}]})
    ingress["apiVersion"] = "networking.k8s.io/v1"
    ingress["metadata"]["annotations"] = {"cert-manager.io/cluster-issuer": "letsencrypt-prod", "nginx.ingress.kubernetes.io/ssl-redirect": "true", "nginx.ingress.kubernetes.io/enable-access-log": "false", "nginx.ingress.kubernetes.io/proxy-body-size": "8k", "nginx.ingress.kubernetes.io/proxy-connect-timeout": "2", "nginx.ingress.kubernetes.io/proxy-read-timeout": "15", "nginx.ingress.kubernetes.io/proxy-send-timeout": "10", "nginx.ingress.kubernetes.io/limit-rps": "20", "nginx.ingress.kubernetes.io/limit-connections": "24"}
    network = resource("NetworkPolicy", "gchat-push", {"podSelector": {"matchLabels": LABELS}, "policyTypes": ["Ingress", "Egress"],
        "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}}], "ports": [{"protocol": "TCP", "port": 8080}]}],
        "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]}, {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}, {"ipBlock": {"cidr": "::/0"}}], "ports": [{"protocol": "TCP", "port": 443}]}]})
    network["apiVersion"] = "networking.k8s.io/v1"
    return {"apiVersion": "v1", "kind": "List", "items": [resource("PersistentVolumeClaim", "gchat-push-state", {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}),
        resource("ConfigMap", "gchat-push-proxy", data={"nginx.conf": (HERE / "nginx.conf").read_text()}), deployment,
        resource("Service", "gchat-push", {"type": "ClusterIP", "selector": LABELS, "ports": [{"name": "http", "port": 80, "targetPort": "http"}]}), ingress, network]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", required=True)
    p.add_argument("--pull-secret")
    args = p.parse_args()
    print(json.dumps(render(args.image, args.pull_secret), indent=2))
