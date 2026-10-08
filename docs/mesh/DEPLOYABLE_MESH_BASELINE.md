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
| Secrets | `k8s/platform/external-secrets/`, `deploy/kustomize/base/ingress-tls-externalsecret.yaml`, `deploy/kustomize/base/generated/externalsecret-admission.yaml` | `aws-secrets-manager` (IRSA SA `external-secrets`; conditions: namespaces labelled `fintechbankx.io/namespace-kind=service` and `observability`); `aws-secrets-manager-platform` (IRSA SA `external-secrets-platform`; conditions: `cert-manager`, `istio-ingress`, `identity`) for the internal CA, ingress TLS (`<env>/platform/ingress-tls`), corporate directory CA and Keycloak material; ValidatingAdmissionPolicy `fintechbankx-externalsecret-scope` + Deny binding: outside the platform-store namespaces an ExternalSecret must use `aws-secrets-manager` and read only `<env>/<slug>/` keys, where in a service namespace `<slug>` is its `app.kubernetes.io/name` label and one of that namespace's service accounts (payments holds four). Validator rule R10 checks the structure; the CEL runs only in a kube-apiserver |
| Internal TLS | `k8s/platform/cert-manager/` | ClusterIssuer `fintechbankx-internal-ca` (CA issuer; key pair synced by ExternalSecret from `<env>/platform/internal-ca` into ns `cert-manager`, no material in git); trust-manager Bundle `fintechbankx-internal-ca` -> ConfigMap `fintechbankx-internal-ca` (key `ca.crt`) in every namespace labelled `fintechbankx.io/namespace-kind` |
| Corporate directory (prod only) | `deploy/kustomize/components/corporate-directory/` | Bundle `corporate-directory-ca` -> ConfigMap in `identity` (source: ExternalSecret from `<env>/platform/corporate-directory-ca`); ServiceEntry + NetworkPolicy for Keycloak -> `DIRECTORY_HOST:636` (LDAPS) |
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

## Identity namespace

| Caller | Callee | Port | Notes |
|---|---|---|---|
| every service workload, ingress gateway (realm paths), Grafana (token, userinfo, certs) | keycloak | 8080 | path-scoped ALLOW |
| keycloak-realm-import (Job, native sidecar) | keycloak | 8080 | `/`, `/admin/*`, `/realms/*` (keycloak-config-cli) |
| keycloak | openldap | 389 | StartTLS; 636 not exposed (dev/staging) |
| keycloak | keycloak | 7800, 57800 | JGroups TCP and FD_SOCK2 failure detection |
| observability/prometheus | keycloak | 9000 | `/metrics`, `/health*` (Keycloak management port; exception to 8081) |
| keycloak (prod) | corporate directory | 636 | ServiceEntry `corporate-directory`, NetworkPolicy to `DIRECTORY_CIDR` |

**JGroups under STRICT mTLS (analysis, not drilled).** Keycloak 26 discovers
peers with JDBC_PING and connects to pod IPs on 7800 (and 57800 for FD_SOCK2).
No port exclusion is needed for mTLS: Istio 1.10+ forwards inbound traffic to
the pod IP, the payload is opaque TCP inside the sidecar mTLS, and Keycloak's
own JGroups TLS runs inside it. The constraint is `REGISTRY_ONLY`: an outbound
connection to `podIP:port` is only routed (with mTLS) if a Service lists that
pod and port; otherwise it is blackholed. The Keycloak Operator's headless
discovery Service is expected to declare 7800, but 57800 is not known to be
declared, so the identity repo should add a headless Service selecting the
Keycloak pods with `tcp-jgroups` 7800 and `tcp-jgroups-fd` 57800. If a drill
still shows split clusters, the fallback is
`traffic.sidecar.istio.io/excludeOutboundPorts` and `excludeInboundPorts`
"7800,57800" on the Keycloak pods. That would take JGroups out of the mesh,
needs a documented exception, and conflicts with the addendum's "no
excludeInboundPorts" rule. Drill evidence: `kubectl exec` into a Keycloak pod,
check the cluster view in the logs (`ISPN000094` with 3 members), and check
for `BlackHoleCluster` hits in `istio-proxy` stats.

## Observability namespace

Selectors come from `helm template` of the pinned observability charts with
the observability repo's values. Both OTel collectors carry
`app.kubernetes.io/name=opentelemetry-collector` and differ by
`app.kubernetes.io/instance`. Before this change the mesh selected
`app.kubernetes.io/name=otel-collector`, which matches no pod.

| Caller (SA) | Callee | Port |
|---|---|---|
| every meshed workload + ingress gateway | otel-collector (agent) | 4317, 4318 (app OTLP and Envoy tracing) |
| otel-collector | otel-gateway | 4317 |
| otel-gateway | tempo-distributor 4317; loki-gateway 8080 (`POST /otlp/*`); prometheus 9090 (`POST /api/v1/write`) | |
| tempo (metrics-generator; shared SA `tempo`) | prometheus | 9090 `POST /api/v1/write` |
| grafana | prometheus 9090, loki-gateway 8080, tempo-query-frontend 3100, alertmanager 9093, identity/keycloak 8080 | |
| ingress gateway | grafana | 3000 (no route yet: needs a Grafana host) |
| prometheus | otel-collector/gateway 8888, tempo 3100, loki 3100/8080/9150, grafana 3000, alertmanager 9093, prometheus 9090, yace 5000, kube-state-metrics 8080, keycloak 9000; service pods 8081/15020/15090; istiod 15014; CoreDNS 9153; nodes 9100/10250 | |
| tempo -> tempo, loki -> loki, alertmanager -> alertmanager | 3100/4317/4318/7946/9095/11211; 3100/7946/9095/11211; 9094 | |

Prometheus bypasses its own sidecar outbound and presents its Istio
certificate itself (observability repo), so the server-side sidecars still see
the `prometheus` principal. It is also not subject to `REGISTRY_ONLY`.
Memberlist and Alertmanager gossip also use UDP, which Istio does not
intercept. Only `allow-same-namespace` NetworkPolicy covers it, in plain text.
Egress: Tempo and Loki to S3 (ServiceEntry `aws-s3`; NetworkPolicy
`0.0.0.0/0:443` because the S3 gateway endpoint uses public prefixes),
Alertmanager to `hooks.slack.com` and `events.pagerduty.com`, AMP, CloudWatch
and tagging through VPC endpoints (`aws-observability-apis`), and Grafana to
Aurora. Observability backends get no DestinationRule (Istio defaults).
`meshConfig.defaultConfig.proxyStatsMatcher` includes the Envoy `ssl.*`
handshake and failure counters for `MeshMtlsHandshakeFailures`.

## Exceptions (enforced by the validator)

| Kind | Namespace | Reason |
|---|---|---|
| injection | istio-system | Control plane |
| injection | external-secrets | Platform contract addendum; ESO webhook is called by the kube-apiserver |
| injection | cert-manager | cert-manager / trust-manager webhooks are called by the kube-apiserver; holds the internal CA key pair |
| workloadInjection (R9) | observability/prometheus-operator, kube-state-metrics, node-exporter | API-server webhook and Jobs; scrape-only; hostNetwork. NetworkPolicy only, never a principal |
| requestAuthentication | open-finance | Own DPoP/FAPI tokens with a per-service issuer; open data is public |
| networkPolicyDefaultDeny | istio-system, external-secrets, cert-manager | Webhooks called from EKS control-plane ENIs; not yet drilled |

There is no PeerAuthentication exception: no PERMISSIVE or DISABLE anywhere.

## Validation

```bash
npm ci
npm test                               # 21 node:test cases (validator + contract)
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

## Edge rate limit and database CA (2026-10-08)

- Anonymous open-data routes (`svc-of-open-products-catalog`, `svc-of-atm-directory`, `svc-of-banking-metadata`) get an
  Envoy local rate limit on the ingress gateway (EnvoyFilter `anonymous-open-data-rate-limit`, generated from
  `gateway.anonymousRateLimit` in the contract): 100-token bucket refilled with 50 per second, per route and per gateway
  pod; an empty bucket returns 429 with `x-fbx-rate-limited: true`. Proposed values; tune from traffic.
- Amazon RDS / DocumentDB CA: trust-manager Bundle `rds-ca-bundle` publishes ConfigMap `rds-ca-bundle`, key
  `global-bundle.pem`, into every `service` and `platform` namespace. Its source is
  `k8s/platform/cert-manager/amazon-rds-global-bundle.pem`, a copy of
  `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`; refresh it when AWS announces a CA rotation.
