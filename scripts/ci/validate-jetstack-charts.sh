#!/usr/bin/env bash
# Pull the pinned cert-manager and trust-manager charts, check each archive
# against its committed sha256 (deploy/cert-manager/CHART_DIGESTS), then render
# the verified archives with the committed values and kubeconform them.
# Run by scripts/ci/validate-manifests.sh; never applies anything.
#
# A committed sha256 that does not match fails the run. While a digest is still
# the PLACEHOLDER, the archive is pulled, rendered and validated anyway, its
# sha256 is printed as "CHART_DIGEST <archive> <sha256>" (the source for the
# operator who fills CHART_DIGESTS) and the run passes with a warning; only
# scripts/istio/install-mesh.sh --apply refuses a placeholder.
# JETSTACK_CHARTS=skip (only where charts.jetstack.io is unreachable; CI never
# sets it) checks the digest file's entries but pulls and validates nothing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HELM="${HELM:-helm}"
KUBECONFORM="${KUBECONFORM:-kubeconform}"
K8S_VERSION="${K8S_VERSION:-1.31.0}"
JETSTACK_CHARTS="${JETSTACK_CHARTS:-validate}"
OUT="${OUT:-$ROOT/build/rendered}"
CRD_SCHEMAS='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
CERT_MANAGER_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/cert-manager/CERT_MANAGER_VERSION")"
TRUST_MANAGER_VERSION="$(tr -d '[:space:]' < "$ROOT/deploy/cert-manager/TRUST_MANAGER_VERSION")"
DIGESTS="$ROOT/deploy/cert-manager/CHART_DIGESTS"
CM_CHART="cert-manager-$CERT_MANAGER_VERSION.tgz"
TM_CHART="trust-manager-$TRUST_MANAGER_VERSION.tgz"
# shellcheck source-path=SCRIPTDIR source=../lib/chart-digests.sh
. "$ROOT/scripts/lib/chart-digests.sh"

echo "== jetstack charts cert-manager $CERT_MANAGER_VERSION, trust-manager $TRUST_MANAGER_VERSION"
if [ "$JETSTACK_CHARTS" = "skip" ]; then
  check_chart_digests_file "$DIGESTS" 1 "$CM_CHART" "$TM_CHART"
  echo "JETSTACK_CHARTS=skip: cert-manager and trust-manager charts NOT pulled, verified or validated" >&2
  exit 0
fi
check_chart_digests_file "$DIGESTS" 1 "$CM_CHART" "$TM_CHART"

kubeconform_run() {
  "$KUBECONFORM" -strict -summary -kubernetes-version "$K8S_VERSION" \
    -schema-location default -schema-location "$CRD_SCHEMAS" "$@"
}

CHARTS="$OUT/charts"
mkdir -p "$CHARTS"
if [ ! -f "$CHARTS/$CM_CHART" ] || [ ! -f "$CHARTS/$TM_CHART" ]; then
  "$HELM" repo add jetstack https://charts.jetstack.io --force-update >/dev/null
  "$HELM" pull jetstack/cert-manager --version "$CERT_MANAGER_VERSION" -d "$CHARTS"
  "$HELM" pull jetstack/trust-manager --version "$TRUST_MANAGER_VERSION" -d "$CHARTS"
fi
# Cached or freshly pulled: nothing renders an archive that does not match its
# committed sha256; a PLACEHOLDER archive is rendered and its digest printed.
verify_or_report_chart_archive "$DIGESTS" "$CHARTS/$CM_CHART"
verify_or_report_chart_archive "$DIGESTS" "$CHARTS/$TM_CHART"

P="$ROOT/deploy/cert-manager/helm"
# Chart values schemas reject unknown keys in the committed values files.
"$HELM" template cert-manager "$CHARTS/$CM_CHART" -n cert-manager \
  --kube-version "$K8S_VERSION" -f "$P/cert-manager.values.yaml" > "$OUT/cert-manager.yaml"
"$HELM" template trust-manager "$CHARTS/$TM_CHART" -n cert-manager \
  --kube-version "$K8S_VERSION" -f "$P/trust-manager.values.yaml" > "$OUT/trust-manager.yaml"
grep -Eq 'name: "?certificates\.cert-manager\.io"?$' "$OUT/cert-manager.yaml" \
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
