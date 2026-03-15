# Platform Service Mesh Security

DDD/EDA platform capability (`svc-msh-security`) owner: Mesh Security Squad wave: 0

## Phase-2 Runtime Hardening Slice

This repository now enforces **STRICT mTLS** as a blocking quality gate.

- Runtime policy source: `k8s/istio/security/mtls-policies.yaml`
- Validator: `scripts/validation/validate-strict-mtls.mjs`
- CI gate: `.github/workflows/strict-mtls-enforcement.yml`

### Guardrails Enforced
- Every `PeerAuthentication` must use `spec.mtls.mode: STRICT`
- No `portLevelMtls` downgrade (`PERMISSIVE`, `DISABLE`, `SIMPLE`) for internal mesh traffic
- Internal (`*.svc.cluster.local`) `DestinationRule` must use `trafficPolicy.tls.mode: ISTIO_MUTUAL`
- Mesh baseline must exist: `PeerAuthentication` in `istio-system` with `STRICT`

### Local Validation
```bash
npm ci
npm test
npm run validate:strict-mtls
```
