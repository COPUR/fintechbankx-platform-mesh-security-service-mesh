#!/usr/bin/env bash
# Install the platform PKI (cert-manager, trust-manager, internal CA issuer,
# trust bundles), Istio (Helm) and the mesh security policies (kustomize) for
# one environment. Default is a plan: commands are printed, nothing is changed.
#
#   scripts/istio/install-mesh.sh <dev|staging|prod>            # print plan
#   scripts/istio/install-mesh.sh <dev|staging|prod> --apply    # execute
#
# Order, each step waited for before the next:
#   0. preflight: External Secrets Operator CRDs present (installed elsewhere);
#      both jetstack chart archives pulled and checked against their sha256 in
#      deploy/cert-manager/CHART_DIGESTS (sha256sum -c) before any install
#   1. cert-manager   (verified local archive, deploy/cert-manager/CERT_MANAGER_VERSION)
#   2. trust-manager  (verified local archive, deploy/cert-manager/TRUST_MANAGER_VERSION)
#   3. platform PKI   (deploy/kustomize/platform-pki/<env>: ClusterIssuer
#                      fintechbankx-internal-ca, Bundles rds-ca-bundle and
#                      fintechbankx-internal-ca, their sources and stores)
#   4. Istio CRDs -> istiod -> namespaces + policies -> gateway
#   5. rds-ca-bundle ConfigMap present in every FinTechBankX namespace
# --apply refuses to start while CHART_DIGESTS lacks a sha256 for either
# archive (PLACEHOLDER): it fails before it touches the cluster.
# Policies go in before workloads so no pod ever runs without default-deny.
# Service charts deploy afterwards from their own repositories and assume
# ConfigMap rds-ca-bundle and ClusterIssuer fintechbankx-internal-ca exist.
set -euo pipefail

ENVIRONMENT="${1:?usage: install-mesh.sh <dev|staging|prod> [--apply]}"
MODE="${2:-plan}"
case "$ENVIRONMENT" in dev|staging|prod) ;; *) echo "unknown environment $ENVIRONMENT" >&2; exit 2;; esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
V="$ROOT/deploy/istio/helm"
P="$ROOT/deploy/cert-manager/helm"
ISTIO_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/istio/ISTIO_VERSION")"
CERT_MANAGER_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/cert-manager/CERT_MANAGER_VERSION")"
TRUST_MANAGER_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/cert-manager/TRUST_MANAGER_VERSION")"
WAIT="${WAIT_TIMEOUT:-300s}"
DIGESTS="$ROOT/deploy/cert-manager/CHART_DIGESTS"
CM_CHART="cert-manager-$CERT_MANAGER_VERSION.tgz"
TM_CHART="trust-manager-$TRUST_MANAGER_VERSION.tgz"
# shellcheck source-path=SCRIPTDIR source=../lib/chart-digests.sh
. "$ROOT/scripts/lib/chart-digests.sh"

# Fail closed before anything else: both archives need a committed sha256.
if ! check_chart_digests_file "$DIGESTS" 0 "$CM_CHART" "$TM_CHART"; then
  if [ "$MODE" = "--apply" ]; then
    echo "refusing --apply: deploy/cert-manager/CHART_DIGESTS has no verified sha256 for $CM_CHART and $TM_CHART" >&2
    exit 1
  fi
  echo "WARNING: plan only; --apply refuses until deploy/cert-manager/CHART_DIGESTS holds both sha256 values" >&2
fi
# Archives are pulled into a fresh directory and installed from there only.
CHART_DIR="$(mktemp -d)"
trap 'rm -rf "$CHART_DIR"' EXIT

run() {
  echo "+ $*"
  if [ "$MODE" = "--apply" ]; then "$@"; fi
}

# trust-manager writes the target ConfigMap once a namespace carries the
# fintechbankx.io/namespace-kind label (set by the mesh overlay in step 4).
verify_rds_ca_bundle() {
  echo "+ verify ConfigMap rds-ca-bundle in every namespace labelled fintechbankx.io/namespace-kind in (service,platform)"
  if [ "$MODE" != "--apply" ]; then return 0; fi
  local attempt ns missing
  for attempt in $(seq 1 30); do
    missing=""
    for ns in $(kubectl get namespaces -l 'fintechbankx.io/namespace-kind in (service,platform)' \
        -o jsonpath='{.items[*].metadata.name}'); do
      kubectl -n "$ns" get configmap rds-ca-bundle >/dev/null 2>&1 || missing="$missing $ns"
    done
    [ -z "$missing" ] && return 0
    sleep 10
  done
  echo "ConfigMap rds-ca-bundle missing in:$missing (attempt $attempt)" >&2
  return 1
}

# 0. Preflight: the platform PKI and the mesh overlay contain ExternalSecrets
# and ClusterSecretStores.
run kubectl get crd externalsecrets.external-secrets.io clustersecretstores.external-secrets.io
# Both jetstack archives, pulled and checked (sha256sum -c) before either installs.
run helm repo add jetstack https://charts.jetstack.io --force-update
run helm pull jetstack/cert-manager --version "$CERT_MANAGER_VERSION" -d "$CHART_DIR"
run helm pull jetstack/trust-manager --version "$TRUST_MANAGER_VERSION" -d "$CHART_DIR"
run verify_chart_archive "$DIGESTS" "$CHART_DIR/$CM_CHART"
run verify_chart_archive "$DIGESTS" "$CHART_DIR/$TM_CHART"

# 1. cert-manager (CRDs in the release, kept on uninstall), from the verified archive.
run helm upgrade --install cert-manager "$CHART_DIR/$CM_CHART" \
  -n cert-manager --create-namespace -f "$P/cert-manager.values.yaml" --wait --timeout 10m
run kubectl wait --for=condition=Established --timeout="$WAIT" \
  crd/certificates.cert-manager.io crd/issuers.cert-manager.io crd/clusterissuers.cert-manager.io
run kubectl -n cert-manager wait --for=condition=Available --timeout="$WAIT" \
  deployment/cert-manager deployment/cert-manager-webhook deployment/cert-manager-cainjector

# 2. trust-manager (trust namespace cert-manager, ConfigMap targets only), from the verified archive.
run helm upgrade --install trust-manager "$CHART_DIR/$TM_CHART" \
  -n cert-manager -f "$P/trust-manager.values.yaml" --wait --timeout 10m
run kubectl wait --for=condition=Established --timeout="$WAIT" crd/bundles.trust.cert-manager.io
run kubectl -n cert-manager wait --for=condition=Available --timeout="$WAIT" deployment/trust-manager

# 3. Platform PKI: internal CA issuer and trust bundles, before any workload.
# The CA key pair comes from AWS Secrets Manager <env>/platform/internal-ca
# through ClusterSecretStore aws-secrets-manager-platform (IRSA).
run kubectl apply --server-side -k "$ROOT/deploy/kustomize/platform-pki/$ENVIRONMENT"
run kubectl wait --for=condition=Ready --timeout="$WAIT" clustersecretstore/aws-secrets-manager-platform
run kubectl -n cert-manager wait --for=condition=Ready --timeout="$WAIT" externalsecret/fintechbankx-internal-ca-keypair
run kubectl wait --for=condition=Ready --timeout="$WAIT" clusterissuer/fintechbankx-internal-ca
run kubectl wait --for=condition=Synced --timeout="$WAIT" bundle/rds-ca-bundle bundle/fintechbankx-internal-ca

# 4. Istio.
run helm repo add istio https://istio-release.storage.googleapis.com/charts --force-update
run helm upgrade --install istio-base istio/base --version "$ISTIO_VERSION" \
  -n istio-system --create-namespace -f "$V/base.values.yaml" --wait
run helm upgrade --install istiod istio/istiod --version "$ISTIO_VERSION" \
  -n istio-system -f "$V/istiod.values.yaml" -f "$V/env/$ENVIRONMENT/istiod.values.yaml" --wait
# Namespaces, PeerAuthentication, AuthorizationPolicies, NetworkPolicies,
# ServiceEntries, Sidecars, Gateway/VirtualServices, ClusterSecretStores and
# the platform PKI again (identical to step 3, so a no-op for it).
run kubectl apply --server-side -k "$ROOT/deploy/kustomize/overlays/$ENVIRONMENT"
run helm upgrade --install istio-ingressgateway istio/gateway --version "$ISTIO_VERSION" \
  -n istio-ingress -f "$V/gateway.values.yaml" -f "$V/env/$ENVIRONMENT/gateway.values.yaml" --wait

# 5. Service charts may now rely on ConfigMap rds-ca-bundle.
verify_rds_ca_bundle

if [ "$MODE" != "--apply" ]; then
  echo "plan only; re-run with --apply against the intended cluster context"
fi
