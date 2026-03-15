#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-fintechbankx-local}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOCAL_DIR="${ROOT_DIR}/k8s/istio/local"

log() { echo "[verify-istio] $*"; }
warn() { echo "[verify-istio][warn] $*" >&2; }
err() { echo "[verify-istio][error] $*" >&2; }

if ! kubectl config current-context | grep -q "kind-${CLUSTER_NAME}"; then
  warn "Current context is not kind-${CLUSTER_NAME}; continuing with current context"
fi

log "Checking Istio control plane"
kubectl get pods -n istio-system

log "Checking banking namespace workloads"
kubectl get pods -n banking-services
kubectl get peerauthentication -A
kubectl get destinationrule -n banking-services
kubectl get networkpolicy -n banking-services
kubectl get gateway,virtualservice -n banking-services

log "Running in-mesh request test (sleep -> echo-server)"
kubectl exec deploy/sleep -n banking-services -c sleep -- \
  curl -fsS "http://echo-server.banking-services:8000/" >/tmp/fintechbankx-istio-echo.out

if grep -q "fintechbankx-istio-ok" /tmp/fintechbankx-istio-echo.out; then
  log "Smoke call succeeded"
else
  err "Smoke call did not return expected payload"
  exit 1
fi

log "Attempting mTLS policy inspection"
if istioctl authn tls-check -n banking-services deploy/sleep echo-server.banking-services.svc.cluster.local >/tmp/fintechbankx-istio-tls-check.out 2>/dev/null; then
  cat /tmp/fintechbankx-istio-tls-check.out
else
  warn "istioctl authn tls-check not available/supported in this version; using destination-rule linkage check"
  istioctl proxy-config clusters deploy/sleep.banking-services \
    --fqdn echo-server.banking-services.svc.cluster.local \
    | tee /tmp/fintechbankx-istio-clusters.out
fi

log "Running negative test (no-sidecar pod -> echo-server should fail under STRICT mTLS)"
kubectl delete pod plain-client -n banking-services --ignore-not-found >/dev/null 2>&1 || true
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: plain-client
  namespace: banking-services
  annotations:
    sidecar.istio.io/inject: "false"
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "3600"]
EOF
kubectl wait --for=condition=Ready pod/plain-client -n banking-services --timeout=120s

set +e
kubectl exec plain-client -n banking-services -- \
  curl -sS --max-time 5 "http://echo-server.banking-services:8000/" >/tmp/fintechbankx-istio-plain-client.out 2>&1
plain_status=$?
set -e

if [ "${plain_status}" -eq 0 ]; then
  err "Negative test failed: non-mesh client unexpectedly reached echo-server"
  kubectl delete pod plain-client -n banking-services --ignore-not-found >/dev/null 2>&1 || true
  exit 1
fi
log "Negative test passed: non-mesh client blocked as expected"
kubectl delete pod plain-client -n banking-services --ignore-not-found >/dev/null 2>&1 || true

log "Verification complete"
