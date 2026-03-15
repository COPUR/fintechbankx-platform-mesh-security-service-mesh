# Migration Granularity Notes

- Repository: `fintechbankx-platform-service-mesh-security`
- Source monorepo: `enterprise-loan-management-system`
- Sync date: `2026-03-15`
- Sync branch: `chore/granular-source-sync-20260313`

## Applied Rules

- dir: `k8s/istio` -> `k8s/istio`
- dir: `scripts/istio` -> `scripts/istio`
- file: `security/network/network-policies.yaml` -> `security/network/network-policies.yaml`
- file: `security/service-architecture/service-mesh-config.yaml` -> `security/service-architecture/service-mesh-config.yaml`
- file: `docs/technical/LOCAL_K8S_ISTIO_RUNBOOK.md` -> `docs/LOCAL_K8S_ISTIO_RUNBOOK.md`
- file: `docs/technical/istio-service-mesh-guide.md` -> `docs/istio-service-mesh-guide.md`
- dir: `docs/puml/service-mesh` -> `docs/puml/service-mesh`

## Notes

- This is an extraction seed for bounded-context split migration.
- Follow-up refactoring may be needed to remove residual cross-context coupling.
- Build artifacts and local machine files are excluded by policy.

