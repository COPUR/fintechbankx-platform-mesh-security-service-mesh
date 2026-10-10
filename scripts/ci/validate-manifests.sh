#!/usr/bin/env bash
# Render and validate every overlay, the pre-Istio platform PKI overlays, the
# Istio Helm install and the cert-manager / trust-manager Helm install,
# without a cluster.
#
#   scripts/ci/validate-manifests.sh
#
# Tools (override with env vars): kustomize 5.x, kubeconform, helm 3.x,
# istioctl matching deploy/istio/ISTIO_VERSION (optional: ISTIOCTL=skip).
# JETSTACK_CHARTS=skip skips the cert-manager / trust-manager charts (only
# where charts.jetstack.io is unreachable; CI never sets it).
# Never applies anything.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KUSTOMIZE="${KUSTOMIZE:-kustomize}"
KUBECONFORM="${KUBECONFORM:-kubeconform}"
HELM="${HELM:-helm}"
ISTIOCTL="${ISTIOCTL:-istioctl}"
K8S_VERSION="${K8S_VERSION:-1.30.0}"
ISTIO_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/istio/ISTIO_VERSION")"
CERT_MANAGER_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/cert-manager/CERT_MANAGER_VERSION")"
TRUST_MANAGER_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/cert-manager/TRUST_MANAGER_VERSION")"
JETSTACK_CHARTS="${JETSTACK_CHARTS:-validate}"
OUT="$ROOT/build/rendered"
CRD_SCHEMAS='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
mkdir -p "$OUT"

kubeconform_run() {
  "$KUBECONFORM" -strict -summary -kubernetes-version "$K8S_VERSION" \
    -schema-location default -schema-location "$CRD_SCHEMAS" "$@"
}

for env in dev staging prod; do
  echo "== overlay $env"
  "$KUSTOMIZE" build "$ROOT/deploy/kustomize/overlays/$env" > "$OUT/mesh-$env.yaml"
  if grep -nE 'IDENTITY_HOST|API_HOST|LEGACY_OPEN_FINANCE_HOST|AWS_REGION|ENVIRONMENT|PLATFORM_SECRETS_ROLE_ARN|192\.0\.2\.' "$OUT/mesh-$env.yaml"; then
    echo "unsubstituted placeholder in overlay $env" >&2
    exit 1
  fi
  # Mesh policies and ESO resources must all have schemas: no -ignore-missing-schemas.
  kubeconform_run "$OUT/mesh-$env.yaml"
  node "$ROOT/scripts/validation/validate-strict-mtls.mjs" --rendered "$OUT/mesh-$env.yaml"
  if [ "$ISTIOCTL" != "skip" ]; then
    "$ISTIOCTL" analyze --use-kube=false "$OUT/mesh-$env.yaml"
  fi

  echo "== platform-pki $env"
  "$KUSTOMIZE" build "$ROOT/deploy/kustomize/platform-pki/$env" > "$OUT/platform-pki-$env.yaml"
  if grep -nE 'AWS_REGION|ENVIRONMENT|PLATFORM_SECRETS_ROLE_ARN' "$OUT/platform-pki-$env.yaml"; then
    echo "unsubstituted placeholder in platform-pki $env" >&2
    exit 1
  fi
  kubeconform_run "$OUT/platform-pki-$env.yaml"
  node "$ROOT/scripts/validation/check-rendered-subset.mjs" "$OUT/platform-pki-$env.yaml" "$OUT/mesh-$env.yaml"
done

echo "== istio helm charts $ISTIO_VERSION"
CHARTS="$OUT/charts"
mkdir -p "$CHARTS"
if [ ! -f "$CHARTS/istiod-$ISTIO_VERSION.tgz" ]; then
  "$HELM" repo add istio https://istio-release.storage.googleapis.com/charts --force-update >/dev/null
  for c in base istiod gateway; do
    "$HELM" pull "istio/$c" --version "$ISTIO_VERSION" -d "$CHARTS"
  done
fi
V="$ROOT/deploy/istio/helm"
for env in dev staging prod; do
  "$HELM" template istio-base "$CHARTS/base-$ISTIO_VERSION.tgz" -n istio-system \
    -f "$V/base.values.yaml" > "$OUT/istio-base-$env.yaml"
  "$HELM" template istiod "$CHARTS/istiod-$ISTIO_VERSION.tgz" -n istio-system \
    -f "$V/istiod.values.yaml" -f "$V/env/$env/istiod.values.yaml" > "$OUT/istiod-$env.yaml"
  "$HELM" template istio-ingressgateway "$CHARTS/gateway-$ISTIO_VERSION.tgz" -n istio-ingress \
    -f "$V/gateway.values.yaml" -f "$V/env/$env/gateway.values.yaml" > "$OUT/istio-gateway-$env.yaml"
  grep -q 'mode: REGISTRY_ONLY' "$OUT/istiod-$env.yaml" || { echo "istiod $env: REGISTRY_ONLY missing" >&2; exit 1; }
  # Chart output includes CRDs and webhook kinds without published schemas.
  kubeconform_run -ignore-missing-schemas "$OUT/istio-base-$env.yaml" "$OUT/istiod-$env.yaml" "$OUT/istio-gateway-$env.yaml"
done
echo "== jetstack charts cert-manager $CERT_MANAGER_VERSION, trust-manager $TRUST_MANAGER_VERSION"
if [ "$JETSTACK_CHARTS" = "skip" ]; then
  echo "JETSTACK_CHARTS=skip: cert-manager and trust-manager charts NOT validated" >&2
else
  if [ ! -f "$CHARTS/cert-manager-$CERT_MANAGER_VERSION.tgz" ] || [ ! -f "$CHARTS/trust-manager-$TRUST_MANAGER_VERSION.tgz" ]; then
    "$HELM" repo add jetstack https://charts.jetstack.io --force-update >/dev/null
    "$HELM" pull jetstack/cert-manager --version "$CERT_MANAGER_VERSION" -d "$CHARTS"
    "$HELM" pull jetstack/trust-manager --version "$TRUST_MANAGER_VERSION" -d "$CHARTS"
  fi
  P="$ROOT/deploy/cert-manager/helm"
  # Chart values schemas reject unknown keys in the committed values files.
  "$HELM" template cert-manager "$CHARTS/cert-manager-$CERT_MANAGER_VERSION.tgz" -n cert-manager \
    --kube-version "$K8S_VERSION" -f "$P/cert-manager.values.yaml" > "$OUT/cert-manager.yaml"
  "$HELM" template trust-manager "$CHARTS/trust-manager-$TRUST_MANAGER_VERSION.tgz" -n cert-manager \
    --kube-version "$K8S_VERSION" -f "$P/trust-manager.values.yaml" > "$OUT/trust-manager.yaml"
  grep -q 'name: certificates.cert-manager.io' "$OUT/cert-manager.yaml" \
    || { echo "cert-manager: CRDs not rendered (crds.enabled)" >&2; exit 1; }
  grep -q 'bundles.trust.cert-manager.io' "$OUT/trust-manager.yaml" \
    || { echo "trust-manager: Bundle CRD not rendered (crds.enabled)" >&2; exit 1; }
  grep -q -- '--trust-namespace=cert-manager' "$OUT/trust-manager.yaml" \
    || { echo "trust-manager: trust namespace is not cert-manager" >&2; exit 1; }
  if grep -q -- '--secret-targets-enabled=true' "$OUT/trust-manager.yaml"; then
    echo "trust-manager: secret targets must stay disabled" >&2; exit 1
  fi
  # No published schema for CustomResourceDefinition; every other kind
  # (including trust-manager's cert-manager Certificate/Issuer) must validate.
  kubeconform_run -skip CustomResourceDefinition "$OUT/cert-manager.yaml" "$OUT/trust-manager.yaml"
fi
echo "all manifests rendered and validated"
