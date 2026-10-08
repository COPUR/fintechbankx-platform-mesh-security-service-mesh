# Deployable mesh baseline (Proposed)

Status: **Proposed**. Nothing here has been applied to a cluster. The evidence
is local rendering and validation only (see "Validation" below).

## Sources

| Source | Used for |
|---|---|
| `contracts/mesh-contract.yaml` (this repo) | Single source of truth for namespaces, service accounts, call edges, exceptions and gaps |
| Platform contract (platform pillar, 2026-10-08, with addendum) | Namespaces, SA names, ports, issuer/audience rules, `aws-secrets-manager` store, injected namespaces |
| Service repos, branch `claude/project-thread-ty79y4` | Real call edges: `application.yml`, Helm `values.yaml`, HTTP adapters and controller prefixes |
| Monolith `security/service-architecture/dependency-resilience-policies.yaml` | Connection timeout and outlier-detection values |
| Monolith `security/service-architecture/cell-a-zero-trust-policy-pack.yaml` | Default-deny + principal allow-list + NetworkPolicy pattern |
| Existing `k8s/istio/security/*`, `k8s/istio/local/*` | Kept as legacy reference (single `banking` namespace); not part of the deployable set |

Not imported: the monolith `k8s/sidecar/*` (a custom sidecar-injection webhook
in the `banking` namespace, which would conflict with Istio's own injector).

## Call graph found in the services

| Caller | Callee | Evidence | Mesh policy |
|---|---|---|---|
| ingress gateway | 7 open-finance APIs (`/open-finance/v1/{consents,confirmation-of-payee,accounts,corporate,metadata,atms,products}`) | Controllers on branch `claude/project-thread-nfwa8t`; confirmed by service threads | ALLOW by gateway principal, path-scoped; tokens checked by the services (DPoP/FAPI) |
| ingress gateway | 5 service APIs (customer also serves the staff/customer UI) (`/api/v1/{loans,payments,customers,risk,compliance}`) | `@RequestMapping` in each controller | ALLOW by gateway principal, JWT required |
| `lending/loan-lifecycle-service` | `customer/customer-profile-kyc-service` | `CUSTOMER_SERVICE_BASE_URL`, `CustomerProfileHttpAdapter` (GET customer, POST credit reserve/release); client-credentials token since loan commit a33b418 | ALLOW by principal on 8080, method- and path-scoped |
| `payments/payment-initiation-settlement-service` | `risk/risk-decisioning-service`, `compliance/compliance-evidence-service` | Confirmed by the service threads (2026-10-08); no adapter on the payment branch yet | ALLOW by principal on 8080, port-only (paths unknown) |
| every service | `identity/keycloak` | `OIDC_JWK_SET_URI`; client-credentials per platform contract | ALLOW JWKS GET, discovery GET, token POST |
| every service | `observability/otel-collector` | platform contract (OTLP 4317/4318) | ALLOW ports 4317/4318 |
| `payments/payment-initiation-settlement-service` | `open-finance/consent-authorization-service`, `open-finance/payee-verification-service` | Confirmed by the service threads (2026-10-08); no adapter on the payment branch yet | ALLOW by principal on 8080, port-only |
| `observability/prometheus` | every service (including the 3 new payments and 7 open-finance workloads), port 8081 | pod annotations `prometheus.io/port: 8081` | ALLOW `/actuator/prometheus`, `/actuator/health*` |
| loan, payment initiation, customer, open-finance consent, payee verification and the 3 data services | Amazon MSK | `spring.kafka`; service threads | ServiceEntry + NetworkPolicy to `MSK_CIDR`, selected per workload |
| open-finance personal, business and banking-metadata data services | DocumentDB 27017, ElastiCache Redis 6379 | `OPENFINANCE_*_MONGODB_URI`, `OPENFINANCE_*_REDIS_URL` | ServiceEntries + NetworkPolicy to `DOCDB_CIDR` / `REDIS_CIDR`, selected per workload |
| lending, payment initiation, customer, risk, compliance, open-finance consent, payee verification, ATM, products, Keycloak | Aurora PostgreSQL | `DB_URL` | ServiceEntry + NetworkPolicy to `AURORA_CIDR` |

### Gaps (not allowed by any policy)

| Caller | Wants | Why it is a gap |
|---|---|---|
| `payments/payment-initiation-settlement-service` | core-banking accounts API (`GET /api/v1/accounts/{id}`) | `ACCOUNTS_SERVICE_BASE_URL` is empty in Helm values and defaults to `http://core-banking-accounts:8080`; no core-banking repo, namespace or SA exists. With `ACCOUNTS_ADAPTER=http` the service fails closed. |
| `payments` request-to-pay, recurring-mandates, bulk-orchestration | ingress routes, datastores, call edges | Only the SAs are confirmed; they get identity, telemetry and scraping edges. Their controllers also expose `/open-finance/v1/{accounts,consents,loans}`, which overlap open-finance routes. |
| `payments` | risk / compliance / consent / payee-verification paths | Edge confirmed but no adapter yet; the rule is port-only until methods and paths are known, then it should be narrowed like loan -> customer. |
| `risk`, `compliance` | Kafka | Neither service configures Kafka yet; no MSK egress is granted. |

Open-finance services validate their own DPoP/FAPI tokens (issuer is service
configuration, `Authorization: DPoP` or `Bearer`; ATM and products are public
open data), so `open-finance` has no Keycloak RequestAuthentication or
`require-jwt-for-api`; it relies on default-deny, per-principal ALLOW rules and
the services' own checks. Datastore egress (Aurora, MSK, DocumentDB, Redis) is
selected per workload, not per namespace.

## What is in `deploy/`

| Area | Files | Notes |
|---|---|---|
| Istio install | `deploy/istio/ISTIO_VERSION` (1.24.3), `deploy/istio/helm/*.values.yaml`, `env/<env>/` | istiod HPA 3..6, zone spread, PDB; gateway HPA 3..12, PDB minAvailable 2, zone spread, AWS NLB (IP targets, cross-zone, health on 15021); `outboundTrafficPolicy: REGISTRY_ONLY`; OTel tracing provider; locality LB |
| Namespaces | `generated/namespaces.yaml` | Labels `istio-injection`, `fintechbankx.io/context` |
| mTLS | `generated/peer-authentication.yaml` | Mesh-wide `default` STRICT in `istio-system` plus per-namespace STRICT |
| AuthN | `generated/request-authentication.yaml` | Gateway: issuer only. Each workload: issuer + `aud` = its service id |
| AuthZ | `generated/authorization-policies.yaml` | `default-deny` per injected namespace, ALLOW per caller principal per edge, `require-jwt-for-api` DENY, health on 8081 |
| Traffic | `generated/destination-rules.yaml`, `generated/service-entries.yaml`, `generated/sidecars.yaml`, `generated/ingress-routing.yaml` | See resilience mapping |
| NetworkPolicy | `generated/network-policies.yaml` | Default-deny, DNS, istiod 15012, node health 15020/15021, scraping, edge-derived ingress/egress, Aurora/MSK/VPC-endpoint CIDRs |
| Secrets | `k8s/platform/external-secrets/cluster-secret-store.yaml`, `deploy/kustomize/base/ingress-tls-externalsecret.yaml` | `aws-secrets-manager` via IRSA; gateway TLS from `<env>/platform/ingress-tls` |
| Params | `deploy/kustomize/overlays/<env>/params.env`, `components/mesh-params` | Identity/API host, region, VPC/Aurora/MSK/DocumentDB/Redis CIDRs, environment |

### Resilience mapping

Only values backed by the dependency-resilience policy pack are set:

- `DestinationRule` for each in-mesh callee: `connectTimeout: 1s` (pack; also
  matches the loan adapter's `connect-timeout: PT1S`), outlier detection
  3 gateway errors (or 5 x 5xx) in 5s, eject 30s, max 50% (pack), locality-aware
  `LEAST_REQUEST` so traffic stays in-zone and fails over across zones.
- `DestinationRule identity-external`: exactly `keycloak-egress-dr` from the pack.
- **No VirtualService timeouts/retries.** The pack's `keycloak-egress-resilience`
  VirtualService sets HTTP timeout/retries on a host declared with protocol
  `TLS`; Envoy cannot apply HTTP route settings to TLS passthrough, so that
  rule was a no-op in the monolith and is not carried over. Request timeouts
  stay in the services (loan -> customer: 1s connect, 2s read). Istio's default
  retry policy (2 attempts on connect-failure/refused-stream/503) is unchanged;
  the loan adapter sends the same `x-idempotency-key` on an Envoy retry.

### Probes and scraping under STRICT mTLS

- Kubelet probes: Istio rewrites HTTP probes to the sidecar agent (port 15020),
  which calls the app on localhost, so probes never cross the mTLS/AuthZ path.
  Charts must not set `traffic.sidecar.istio.io/excludeInboundPorts`.
- Scraping: `enablePrometheusMerge` serves app + Envoy metrics on 15020 (plain
  text, allowed by NetworkPolicy from `observability/prometheus`). A Prometheus
  with its own sidecar can also scrape 8081 over mTLS; the AuthZ rule allows it.

## Exceptions (enforced by the validator)

| Kind | Namespace | Reason |
|---|---|---|
| injection | istio-system | Control plane |
| injection | external-secrets | Platform contract addendum; ESO webhook is called by the kube-apiserver |
| requestAuthentication | open-finance | Own DPoP/FAPI tokens with a per-service issuer; open data is public |
| networkPolicyDefaultDeny | istio-system, external-secrets | Webhooks called from EKS control-plane ENIs; not yet drilled |

There is no PeerAuthentication exception: no PERMISSIVE or DISABLE anywhere.

## Validation

```bash
npm ci
npm test                               # 18 node:test cases (validator + contract)
npm run validate:strict-mtls           # R1..R8 on the repo sources
bash scripts/ci/validate-manifests.sh  # kustomize build x3, kubeconform (Istio/ESO CRD
                                       # schemas from datreeio CRDs-catalog), validator on
                                       # rendered output, istioctl analyze, helm template
```

`istioctl analyze --use-kube=false` checks the policies in isolation; it cannot
see the workloads, so it does not prove the selectors match running pods.

## Drift found and fixed

- `.github/workflows/strict-mtls-enforcement.yml` hard-required STRICT evidence
  only for the repo names `fintechbankx-platform-service-mesh-security` and
  `fintechbankx-platform-identity-keycloak-ldap`, which are not the real repo
  names, so the STRICT check never ran here. Both real names were added.
- No `validate:strict-mtls` script existed although the workflow calls it.
- `scripts/istio/install-istio.sh` and `deploy-security-policies.sh` reference
  monorepo-only files (`k8s/istio/istio-installation.yaml`, ...) and Istio
  1.20.3; marked deprecated. `curlimages/curl:latest` pinned.
- Legacy `k8s/istio/security/mtls-policies.yaml` has a PeerAuthentication with
  `mode: SIMPLE` under `portLevelMtls`, which is not a PeerAuthentication mode.
  Left untouched as legacy; it is not part of the deployable set.
