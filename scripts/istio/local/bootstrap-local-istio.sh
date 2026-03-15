#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-fintechbankx-local}"
ISTIO_PROFILE="${ISTIO_PROFILE:-demo}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOCAL_DIR="${ROOT_DIR}/k8s/istio/local"

log() { echo "[local-istio] $*"; }
err() { echo "[local-istio][error] $*" >&2; }

require_cmd() {
  local c="$1"
  if ! command -v "${c}" >/dev/null 2>&1; then
    err "Missing required command: ${c}"
    exit 1
  fi
}

require_cmd docker
require_cmd kind
require_cmd kubectl
require_cmd istioctl

ensure_docker_daemon() {
  if docker info >/dev/null 2>&1; then
    return 0
  fi

  if command -v colima >/dev/null 2>&1; then
    log "Docker daemon unavailable; attempting to start colima"
    colima start
    sleep 5
  fi

  if ! docker info >/dev/null 2>&1; then
    err "Docker daemon is not reachable. Start Docker/Colima and re-run."
    exit 1
  fi
}

ensure_docker_daemon

if ! kind get clusters | grep -qx "${CLUSTER_NAME}"; then
  log "Creating kind cluster: ${CLUSTER_NAME}"
  kind create cluster --name "${CLUSTER_NAME}" --config "${LOCAL_DIR}/kind-config.yaml"
else
  log "kind cluster already exists: ${CLUSTER_NAME}"
fi

kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

if ! kubectl get namespace istio-system >/dev/null 2>&1; then
  log "Installing Istio profile=${ISTIO_PROFILE}"
  istioctl install -y --set profile="${ISTIO_PROFILE}"
else
  log "Istio namespace already exists; skipping installation"
fi

log "Applying local namespaces and mesh policies"
kubectl apply -f "${LOCAL_DIR}/namespaces.yaml"
kubectl apply -f "${LOCAL_DIR}/strict-mtls.yaml"
kubectl apply -f "${LOCAL_DIR}/network-policies.yaml"
kubectl apply -f "${LOCAL_DIR}/smoke-workload.yaml"
kubectl apply -f "${LOCAL_DIR}/gateway-and-routing.yaml"

log "Waiting for smoke workloads"
kubectl rollout status deployment/echo-server -n banking-services --timeout=240s
kubectl rollout status deployment/sleep -n banking-services --timeout=240s

log "Local Istio environment bootstrap complete"
log "Run verification: scripts/istio/local/verify-local-istio.sh"
