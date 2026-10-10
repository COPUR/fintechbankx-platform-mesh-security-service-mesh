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
| AuthN | `generated/request-authentication.yaml` | Gateway: issuer only. Each workload: issuer + `aud` = its service id. All read tokens from `Authorization` (`Bearer `, `DPoP `) only, never a query parameter |
| AuthZ | `generated/authorization-policies.yaml` | `default-deny` per injected namespace, ALLOW per caller principal per edge, `require-jwt-for-api` DENY, health on 8081 |
| Traffic | `generated/destination-rules.yaml`, `generated/service-entries.yaml`, `generated/sidecars.yaml`, `generated/ingress-routing.yaml` | See resilience mapping |
| NetworkPolicy | `generated/network-policies.yaml` | Default-deny, DNS, istiod 15012, node health 15020/15021, scraping, edge-derived ingress/egress, Aurora/MSK/VPC-endpoint CIDRs; Aurora egress keys on `app.kubernetes.io/name`, MSK egress on the name plus `app.kubernetes.io/component=service` (see "Database migration Jobs") |
| Secrets | `k8s/platform/external-secrets/`, `deploy/kustomize/base/ingress-tls-externalsecret.yaml`, `deploy/kustomize/base/generated/externalsecret-admission.yaml` | `aws-secrets-manager` (IRSA SA `external-secrets`; conditions: namespaces labelled `fintechbankx.io/namespace-kind=service` and `observability`); `aws-secrets-manager-platform` (IRSA SA `external-secrets-platform`; conditions: `cert-manager`, `istio-ingress`, `identity`) for the internal CA, ingress TLS (`<env>/platform/ingress-tls`), corporate directory CA and Keycloak material; ValidatingAdmissionPolicy `fintechbankx-externalsecret-scope` + Deny binding: outside the platform-store namespaces an ExternalSecret must use `aws-secrets-manager` and read only `<env>/<slug>/` keys, where in a service namespace `<slug>` is its `app.kubernetes.io/name` label and one of that namespace's service accounts (payments holds four), and no remote key may end in `/db-import` (the operator import credential of terraform-modules `operator-db-access` is never synced into a cluster). Validator rule R10 checks the structure; the CEL runs only in a kube-apiserver |
| PKI install | `deploy/cert-manager/` (versions, Helm values), `deploy/kustomize/platform-pki/<env>/`, `components/platform-params` | cert-manager and trust-manager installed by this repo before Istio; see "Platform PKI install" |
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

### Database migration Jobs (Proposed)

Each service runs Flyway in a Helm `pre-install,pre-upgrade` hook Job, never in
the API pods (cicd-templates 335a345). The Job pods carry the service's
`app.kubernetes.io/name` and `app.kubernetes.io/component=db-migration`; the API
pods carry `component=service`.

- `allow-egress-aurora` (and DocumentDB, Redis) select on the name only, so the
  Job reaches its service's database.
- `allow-egress-msk` selects the name **and** `component=service`: a migration
  pod, or any pod without the component label, never reaches the brokers.
  Every service chart must label its API pods `app.kubernetes.io/component:
  service`; a chart without it loses MSK egress (fail closed).
- Customer, risk and compliance run their Jobs **without** a sidecar (CRC
  branch `claude/customer-risk-compliance-deployable-ygi0zo`, each chart's
  `templates/migration-job.yaml:39-49`: `sidecar.istio.io/inject: "false"`
  written after `podLabels`), each as its own ServiceAccount
  `<service>-db-migration` with no token and no IAM role. The contract lists
  them as `role: db-migration` workloads
  (`customer/customer-profile-kyc-service-db-migration`,
  `risk/risk-decisioning-service-db-migration`,
  `compliance/compliance-evidence-service-db-migration`; `migrates: <service>`,
  selector name + component, `sidecar: false`, Aurora only), each with an
  `exceptions.workloadInjection` entry (validator R9). The services'
  Deployments keep their sidecars. This mesh does not need the opt-out
  (native sidecars let a Job complete); it is the owner's choice.
- A sidecar-less Job pod gets `allow-egress-dns` and its service's name-keyed
  `allow-egress-aurora` (5432 to `AURORA_CIDR`, the policy its API pods use)
  and nothing else. Every other NetworkPolicy of its namespace that could
  select it excludes `component=db-migration` (`NotIn`): `allow-egress-istiod`,
  `allow-egress-vpc-https`, `allow-ingress-node-health`,
  `allow-ingress-observability-scrape`, `allow-ingress-from-<namespace>` and
  the service's edge egress to identity and observability. So: no istiod, no
  VPC endpoints, no MSK, no east-west, no ingress. The rule is the same one
  the products history-guard check pods use (below); it applies to any
  `role: db-migration` or `role: history-guard-check` workload with
  `sidecar: false`, and a store policy excludes only the Jobs that do not
  declare that store. No pod without that component label, and nothing
  outside these namespaces, changes.
- The selector is name + component: the only other chart label,
  `app.kubernetes.io/instance`, is the Helm release name, chosen per install.
  The charts must keep both labels on the Job pods. Without
  `component=db-migration` a Job pod falls back to everything its API pods get
  at L3/L4 except MSK (MSK requires `component=service`); without the name
  label it loses Aurora (fail closed).
- No RequestAuthentication, AuthorizationPolicy, call or telemetry edge or
  secret slug names the Jobs (each ExternalSecret carries the service's name
  and reads `<env>/<service>/db-migration`). The renderer refuses a migration
  workload with MSK, a looser selector, an `apiPrefix`/`serviceId`, a
  DestinationRule, `sidecar: true` or an edge; a migration workload without
  `sidecar` (native sidecar) still renders with istiod egress and never MSK
  (`tests/migration-job-egress.test.mjs`,
  `tests/sidecarless-migration-job-egress.test.mjs`).
- The other services' Jobs (loan-lifecycle, payment initiation/settlement,
  request-to-pay, recurring mandates, bulk orchestration, consent
  authorization) run as the namespace `default` ServiceAccount with no token
  and have no contract entry; Aurora egress reaches them by the name label,
  and so do the namespace-wide policies. Several of them also run without a
  sidecar (open ask: model them the same way).

**Drill checklist for the first dev-cluster install** (not run yet; record the
evidence with the install log). Use `helm upgrade --install ... --timeout 15m`
(the Job's `activeDeadlineSeconds` is 600 s; Helm's 5 min default is shorter).

- [ ] The hook Job completes: `kubectl -n compliance get job
  compliance-evidence-service-db-migration` shows `COMPLETIONS 1/1` and the
  Helm release reaches `deployed`; the Job log shows Flyway's applied version.
  A failed or timed-out Job must fail the install and leave the Deployment
  untouched.
- [ ] ESO syncs the migration secret within 600 s: the ExternalSecret
  `compliance-evidence-service-db-migration` reaches `Ready=True`
  (`SecretSynced`) and the pod leaves `CreateContainerConfigError` well inside
  the Job's 600 s `activeDeadlineSeconds` (the deadline counts from Job start,
  so a slow sync eats migration time). Record the sync time from the
  ExternalSecret status.
- [ ] No sidecar: the Job pod spec has no `istio-proxy` container or init
  container, and the pod phase is `Succeeded` after the `db-migration`
  container exits 0.
- [ ] Network path: Flyway reaches Aurora 5432 (`AURORA_CIDR`) with DNS only;
  from a debug pod carrying the Job's labels in the same namespace, istiod
  15012, a VPC endpoint 443, MSK 9098/9094 and Keycloak 8080 time out.
- [ ] Hook resources are deleted per `helm.sh/hook-delete-policy`: after
  success the ServiceAccount and the db-migration ExternalSecret
  (`before-hook-creation,hook-succeeded`) are gone, and with them the synced
  Secret (`creationPolicy: Owner`); the Job (`before-hook-creation`) stays for
  its logs until `ttlSecondsAfterFinished` (86400 s) or the next install or
  upgrade replaces it. `kubectl -n compliance get secret
  compliance-evidence-service-db-migration` must return NotFound.

### Products history-guard check pods (Proposed)

open-products-catalog-service (products PR #14) runs `fbx_history_guard.verify()`
from two Jobs: the 15-minute verify CronJob
`open-products-catalog-service-history-guard-check` and the `pre-upgrade` gate
Job `open-products-catalog-service-history-guard-gate`. Their pods run as the
Deployment's ServiceAccount **without** a sidecar, because the products chart
sets `sidecar.istio.io/inject: "false"` on them, and carry
`app.kubernetes.io/name=open-products-catalog-service` and
`app.kubernetes.io/component=history-guard-check`. This mesh does not need
that opt-out: istiod injects native sidecars (`ENABLE_NATIVE_SIDECARS`), so a
Job completes with a sidecar, as the `keycloak-realm-import` Job does. The
exception records the owner's choice, not a mesh constraint.

- Contract: the `role: history-guard-check` workload
  `open-finance/open-products-catalog-service-history-guard-check`
  (`checks: open-products-catalog-service`, selector name + component,
  `sidecar: false`, Aurora only) and its `exceptions.workloadInjection` entry
  (validator R9). The products Deployment keeps its sidecar.
- Egress: `allow-egress-dns` and the name-keyed `allow-egress-aurora`
  (5432 to `AURORA_CIDR`, the policy the products API pods use) only.
- Every other open-finance NetworkPolicy that could select them excludes
  `component=history-guard-check` (`NotIn`): `allow-egress-istiod`,
  `allow-egress-vpc-https`, `allow-ingress-node-health`,
  `allow-ingress-observability-scrape`, `allow-ingress-from-<namespace>` and
  products' edge egress to identity and observability. So: no istiod, no VPC
  endpoints, no MSK (that policy already requires `component=service`), no
  east-west, no ingress. No pod without that component label is affected.
- No AuthorizationPolicy, RequestAuthentication, call or telemetry edge or
  secret slug names the check pods; the renderer refuses an edge, a sidecar,
  a looser selector, MSK or an `apiPrefix` for the workload
  (`tests/history-guard-check-egress.test.mjs`).
- The chart must keep both labels on the check pods. Without
  `component=history-guard-check` the pods would fall back to everything the
  products API pods get at L3/L4 (fail open to the products baseline, not
  beyond it); without the name label they lose Aurora (fail closed).

Open asks for the open-finance/products thread (not mesh defects):

- Sidecar opt-out. Products may drop `sidecar.istio.io/inject: "false"` and
  run the check pods meshed with no ALLOW naming them, as
  `keycloak-realm-import` does; the `exceptions.workloadInjection` entry and
  the renderer's sidecar-less rule for `role: history-guard-check` would then
  be revisited. The
  NetworkPolicy scoping above holds either way.
- Tracing. The check pods `envFrom` the products ConfigMap, which sets
  `TRACING_ENABLED="true"` and the collector OTLP endpoint (4318); their
  egress to the collector is blocked by design. Products may set
  `TRACING_ENABLED=false` in the check pod env to avoid export errors or an
  exporter timeout at shutdown (runtime effect not reproduced).

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
| workloadInjection (R9) | observability/prometheus-operator, kube-state-metrics, node-exporter | API-server webhook; scrape-only; hostNetwork. NetworkPolicy only, never a principal |
| workloadInjection (R9) | open-finance/open-products-catalog-service-history-guard-check | Products chart opts its check pods out (not a mesh constraint; open ask). DNS and products Aurora only, never a principal |
| workloadInjection (R9) | customer/customer-profile-kyc-service-db-migration, risk/risk-decisioning-service-db-migration, compliance/compliance-evidence-service-db-migration | CRC charts opt their Flyway Jobs out (not a mesh constraint). DNS and the service's Aurora only, never a principal |
| requestAuthentication | open-finance | Own DPoP/FAPI tokens with a per-service issuer; open data is public |
| networkPolicyDefaultDeny | istio-system, external-secrets, cert-manager | Webhooks called from EKS control-plane ENIs; not yet drilled |

There is no PeerAuthentication exception: no PERMISSIVE or DISABLE anywhere.

## Platform PKI install (Proposed)

The platform mesh repository installs cert-manager and trust-manager; service
charts assume ConfigMap `rds-ca-bundle` and ClusterIssuer
`fintechbankx-internal-ca` already exist and never install either component.
`scripts/istio/install-mesh.sh <env> [--apply]` runs, waiting after each step:

| Step | What | Readiness wait |
|---|---|---|
| 0 | Preflight: External Secrets Operator CRDs present (ESO is installed outside this repo); both jetstack archives pulled into a fresh directory and checked against `deploy/cert-manager/CHART_DIGESTS` (`sha256sum -c`) | `kubectl get crd`; a mismatch stops the run before any install |
| 1 | `cert-manager-v1.19.6.tgz` (verified archive), ns `cert-manager`, values `deploy/cert-manager/helm/cert-manager.values.yaml` | `helm --wait` (incl. startupapicheck), CRDs Established, three Deployments Available |
| 2 | `trust-manager-v0.20.3.tgz` (verified archive), ns `cert-manager`, values `deploy/cert-manager/helm/trust-manager.values.yaml` | `helm --wait`, CRD `bundles.trust.cert-manager.io` Established, Deployment Available |
| 3 | `kubectl apply --server-side -k deploy/kustomize/platform-pki/<env>` | ClusterSecretStore and ExternalSecret Ready, ClusterIssuer Ready, both Bundles Synced |
| 4 | Istio base, istiod, mesh overlay, ingress gateway | `helm --wait` |
| 5 | ConfigMap `rds-ca-bundle` present in every namespace labelled `fintechbankx.io/namespace-kind` `service` or `platform` | polls up to 5 minutes |

Values (both charts): CRDs in the release with `crds.keep: true`. cert-manager:
2 replicas and a PDB for controller, webhook and cainjector, leader-election
lease in `cert-manager`, ServiceMonitor off (owned by the observability repo).
trust-manager: trust namespace `cert-manager` (where `amazon-rds-ca-source`,
`fintechbankx-internal-ca-keypair` and `corporate-directory-ca-source` live),
`secretTargets.enabled: false` (every Bundle targets ConfigMaps),
`defaultPackage.enabled: false` (no Bundle uses `useDefaultCAs`), 2 replicas
and a PDB.

Why these versions: the target is EKS 1.31 (terraform-modules
`modules/eks-cluster` default; validation `K8S_VERSION` is 1.31.0).
cert-manager 1.19.6 is the newest 1.19 patch; its e2e matrix covers
Kubernetes 1.31 to 1.34 (1.20 starts at 1.32). trust-manager v0.20.3 is the
newest v0.20 patch; its kind matrix starts at 1.31. Both serve the APIs used
here (`cert-manager.io/v1` ClusterIssuer, `trust.cert-manager.io/v1alpha1`
Bundle) and accept the committed values files unchanged. Move both to the
next lines when the clusters leave Kubernetes 1.31.

The platform PKI resources render twice: in `platform-pki/<env>` (step 3) and
in the mesh overlay (step 4). `components/platform-params` substitutes them in
both, `platform-pki/<env>/params.env` repeats three keys of the overlay
`params.env` (checked by `tests/platform-pki-install.test.mjs`), and
`scripts/ci/validate-manifests.sh` checks that every PKI document is identical
in the mesh render, so the second server-side apply changes nothing.

The legacy `scripts/istio/deploy-security-policies.sh` no longer applies
cert-manager from a remote release URL; it points to `install-mesh.sh`.

**Chart archives pinned by content.** `deploy/cert-manager/CHART_DIGESTS`
holds the expected sha256 of `cert-manager-<version>.tgz` and
`trust-manager-<version>.tgz` in `sha256sum -c` format
(`scripts/lib/chart-digests.sh`). `install-mesh.sh` checks the file first
(`--apply` refuses to start without both digests), pulls both archives into a
fresh temporary directory, verifies them, and installs from the verified local
files, never from a repository reference. `scripts/ci/validate-jetstack-charts.sh`
(called by `validate-manifests.sh`) verifies the archives the same way before
`helm template`, and a committed digest that does not match fails CI;
`JETSTACK_CHARTS=skip` checks only that the file names both archives.

**Where the digests come from.** The committed values are the
`CHART_DIGEST <archive> <sha256>` lines that `validate-jetstack-charts.sh`
printed while the file still held a placeholder, from two CI pulls of the
published archives on `charts.jetstack.io`: workflow "Mesh Manifests" run
38049446800 on commit 07af60a, attempt 1 (job 114205447335, 2026-10-10 11:44Z)
and attempt 2 (job 114240325299, 2026-10-10 14:54Z), on different GitHub-hosted
runners. Both attempts printed the same sha256 for both archives:

| Archive | sha256 |
|---|---|
| `cert-manager-v1.19.6.tgz` | `da30bd46705092fdc086571f1dfa18bd626872966eb70cd99fc7bf8f1165a850` |
| `trust-manager-v0.20.3.tgz` | `8b238bdeaa70d4f5d7379256335522bb7c4e84867764e4fbb95896e1bce1aa84` |

`install-mesh.sh --apply` now passes its digest preflight and installs only
archives that match; CI verifies every pull against them (a mismatch fails
before `helm template`). The placeholder path in `scripts/lib/chart-digests.sh`
stays for a version bump, but `tests/platform-pki-install.test.mjs` refuses a
committed placeholder, so a bump needs both pulls before it is committed (steps
in the file). Both pulls ran on GitHub-hosted runners; no pull from a network
outside GitHub has been compared yet.

Not verified: no cluster install has been run.

## Validation

```bash
npm ci
npm test                               # 21 node:test cases (validator + contract)
npm run validate:strict-mtls           # R1..R8 on the repo sources
bash scripts/ci/validate-manifests.sh  # kustomize build x3 (+ platform-pki x3), kubeconform
                                       # (Istio/ESO/cert-manager CRD schemas from datreeio
                                       # CRDs-catalog), validator on rendered output,
                                       # istioctl analyze, helm template of the Istio,
                                       # cert-manager and trust-manager charts (the
                                       # jetstack archives only after sha256sum -c
                                       # against deploy/cert-manager/CHART_DIGESTS)
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

## Request-to-pay cut-over at the gateway (Proposed, request-to-pay PR #14 d6049d7)

Contract `gateway.cutovers` entry `rtp-cutover` renders the runbook's rules (RUNBOOK-EXTRACT-pay-request-to-pay
section 3) as the first routes of VirtualService `fintechbankx-api`, in this order, with forwarded headers overwritten
like every public route:

| Route | Match (method, RE2 full match on the path without query) | Destination |
|---|---|---|
| `rtp-cutover-r1` | `GET ^/open-finance/v1/payment-consents/CONS-RTP2-[0-9a-f-]{36}$`, `POST .../CONS-RTP2-[0-9a-f-]{36}/(accept\|reject)$` | `payment-request-to-pay-service.payments:8080` |
| `rtp-cutover-r2` | the same operations with any other id segment | monolith (`legacy-open-finance`) |
| `rtp-cutover-r3` | `POST ^/open-finance/v1/par$` and `@request.auth.claims.azp` exactly one of `rtp-cutover-cohort` | `payment-request-to-pay-service.payments:8080` |
| `rtp-cutover-r4` | `POST ^/open-finance/v1/par$` | monolith |

- No prefix route reaches request to pay; every other method or sub-path on these paths gets no route (404).
- The cohort is `gateway.cutovers[rtp-cutover].cohort.clients`: literal TPP client ids only (the renderer rejects
  wildcards, regexes, `svc-*` and `fintechbankx-*` clients). It is empty (runbook step 2), and an empty cohort renders
  **no** R3 route, because an Istio route without match entries matches every request. Moving a TPP = adding its
  client id and re-rendering.
- R3 reads `azp` from the token the gateway validated. TPP tokens use `Authorization: DPoP`, so the gateway
  RequestAuthentication extracts `Bearer ` and `DPoP ` from `Authorization` only. The `access_token` query parameter
  (an Istio default location) is not read: a token in the URL must never select the cohort. Every workload
  RequestAuthentication uses the same header-only list, and the renderer refuses any `gateway.tokenLocations` with
  `fromParams`, `fromCookies` or no explicit header (Istio would fall back to its defaults). The gateway still checks the issuer only. JWT claim routing is supported on gateways
  only (Istio 1.24). Not verified on a cluster: how the gateway treats a DPoP token from another issuer (Envoy
  `allow_missing` is expected to treat an unknown issuer like a missing token, as it already does for Bearer); drill
  before step 3.
- AuthorizationPolicy cannot express the id split: Istio 1.24 paths support exact, prefix/suffix `*` and whole-segment
  templates (`{*}`, `{**}`), no regex. The nearest safe form is used: gateway -> request to pay is allowed per
  (method, path) for `POST /open-finance/v1/par`, `GET /open-finance/v1/payment-consents/{*}` and
  `POST /open-finance/v1/payment-consents/{*}/accept|reject` on 8080 only; the `CONS-RTP2-` split is enforced by
  the routes, and the service checks that the calling TPP owns the request. The gateway is the only principal allowed
  on 8080 (the DPoP `htu` is built from headers only the gateway sets); 8081 is never reachable from it.
- The monolith is `gateway.legacyBackends.legacy-open-finance`: one host per environment (`LEGACY_OPEN_FINANCE_HOST`
  in the overlay params, placeholder until its deployment target is decided), ServiceEntry and DestinationRule in
  `istio-ingress` exported to that namespace only, HTTPS originated by the gateway with SNI and SAN = the host. It must
  be reachable on 443 inside `VPC_CIDR` (the gateway's existing egress rule); anything else needs a contract change.
