# Local Kubernetes + Istio Runbook

## Scope

Local-only execution baseline for Istio service mesh on Kubernetes (`kind`).
This runbook does not require GitLab.

## Prerequisites

- Docker
- kind
- kubectl
- istioctl

## Bootstrap

```bash
scripts/istio/local/bootstrap-local-istio.sh
```

This will:

1. Create (or reuse) a `kind` cluster (`fintechbankx-local`)
2. Install Istio (if not installed)
3. Apply strict mTLS policies and network policies
4. Deploy smoke workloads (`echo-server`, `sleep`)
5. Apply gateway + virtual service for local routing

## Verify

```bash
scripts/istio/local/verify-local-istio.sh
```

Verification checks include:

1. Istio control plane status
2. Banking namespace workloads
3. PeerAuthentication, DestinationRule, NetworkPolicy, Gateway/VirtualService resources
4. In-mesh call from `sleep` to `echo-server`

## Cleanup

```bash
scripts/istio/local/cleanup-local-istio.sh
```

## Local Manifests

- `k8s/istio/local/kind-config.yaml`
- `k8s/istio/local/namespaces.yaml`
- `k8s/istio/local/strict-mtls.yaml`
- `k8s/istio/local/network-policies.yaml`
- `k8s/istio/local/smoke-workload.yaml`
- `k8s/istio/local/gateway-and-routing.yaml`

