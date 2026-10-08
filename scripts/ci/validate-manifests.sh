#!/usr/bin/env bash
# Render and validate every overlay and the Istio Helm install, without a cluster.
#
#   scripts/ci/validate-manifests.sh
#
# Tools (override with env vars): kustomize 5.x, kubeconform, helm 3.x,
# istioctl matching deploy/istio/ISTIO_VERSION (optional: ISTIOCTL=skip).
# Never applies anything.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KUSTOMIZE="${KUSTOMIZE:-kustomize}"
KUBECONFORM="${KUBECONFORM:-kubeconform}"
HELM="${HELM:-helm}"
ISTIOCTL="${ISTIOCTL:-istioctl}"
K8S_VERSION="${K8S_VERSION:-1.30.0}"
ISTIO_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/istio/ISTIO_VERSION")"
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
  if grep -nE 'IDENTITY_HOST|API_HOST|AWS_REGION|ENVIRONMENT/|192\.0\.2\.' "$OUT/mesh-$env.yaml"; then
    echo "unsubstituted placeholder in overlay $env" >&2
    exit 1
  fi
  # Mesh policies and ESO resources must all have schemas: no -ignore-missing-schemas.
  kubeconform_run "$OUT/mesh-$env.yaml"
  node "$ROOT/scripts/validation/validate-strict-mtls.mjs" --rendered "$OUT/mesh-$env.yaml"
  if [ "$ISTIOCTL" != "skip" ]; then
    "$ISTIOCTL" analyze --use-kube=false "$OUT/mesh-$env.yaml"
  fi
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
echo "all manifests rendered and validated"
