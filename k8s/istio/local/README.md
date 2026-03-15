# Local Istio + Kubernetes Baseline

This folder contains a reproducible local mesh baseline for `kind` clusters.

## Included manifests

- `kind-config.yaml`: local cluster topology and port mapping
- `namespaces.yaml`: local banking namespaces with sidecar injection labels
- `strict-mtls.yaml`: mesh and namespace strict mTLS + default destination rule
- `network-policies.yaml`: default deny + minimal allow-list policies
- `smoke-workload.yaml`: `echo-server` and `sleep` test workloads
- `gateway-and-routing.yaml`: local gateway and virtual service routing

## Apply order

1. `namespaces.yaml`
2. `strict-mtls.yaml`
3. `network-policies.yaml`
4. `smoke-workload.yaml`
5. `gateway-and-routing.yaml`

