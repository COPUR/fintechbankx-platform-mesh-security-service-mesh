#!/usr/bin/env bash
# Install Istio (Helm) and the mesh security policies (kustomize) for one
# environment. Default is a plan: commands are printed, nothing is changed.
#
#   scripts/istio/install-mesh.sh <dev|staging|prod>            # print plan
#   scripts/istio/install-mesh.sh <dev|staging|prod> --apply    # execute
#
# Order: CRDs -> istiod -> namespaces + policies -> gateway. Policies go in
# before workloads so no pod ever runs without default-deny. Service charts
# deploy afterwards from their own repositories.
set -euo pipefail

ENVIRONMENT="${1:?usage: install-mesh.sh <dev|staging|prod> [--apply]}"
MODE="${2:-plan}"
case "$ENVIRONMENT" in dev|staging|prod) ;; *) echo "unknown environment $ENVIRONMENT" >&2; exit 2;; esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
V="$ROOT/deploy/istio/helm"
ISTIO_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/istio/ISTIO_VERSION")"

run() {
  echo "+ $*"
  if [ "$MODE" = "--apply" ]; then "$@"; fi
}

run helm repo add istio https://istio-release.storage.googleapis.com/charts --force-update
run helm upgrade --install istio-base istio/base --version "$ISTIO_VERSION" \
  -n istio-system --create-namespace -f "$V/base.values.yaml" --wait
run helm upgrade --install istiod istio/istiod --version "$ISTIO_VERSION" \
  -n istio-system -f "$V/istiod.values.yaml" -f "$V/env/$ENVIRONMENT/istiod.values.yaml" --wait
# Namespaces, PeerAuthentication, AuthorizationPolicies, NetworkPolicies,
# ServiceEntries, Sidecars, Gateway/VirtualServices, ClusterSecretStore.
# Requires the External Secrets Operator CRDs to be installed already.
run kubectl apply --server-side -k "$ROOT/deploy/kustomize/overlays/$ENVIRONMENT"
run helm upgrade --install istio-ingressgateway istio/gateway --version "$ISTIO_VERSION" \
  -n istio-ingress -f "$V/gateway.values.yaml" -f "$V/env/$ENVIRONMENT/gateway.values.yaml" --wait

if [ "$MODE" != "--apply" ]; then
  echo "plan only; re-run with --apply against the intended cluster context"
fi
