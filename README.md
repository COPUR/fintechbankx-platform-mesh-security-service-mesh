# fintechbankx-platform-mesh-security-service-mesh

Bu repository, FinTechBankX DDD/EDA dönüşümünde **svc-msh-security** servis yetkinliğinin kaynak kodunu, kontratlarını ve operasyonel guardrail'lerini içerir.

## Sorumluluk ve Sahiplik
| Alan | Değer |
|---|---|
| Organizasyon Modeli | Spotify Model (Tribe/Squad) |
| Tribe | Platform & Enablement Tribe |
| Squad | Mesh Security Squad |
| Repo Kümesi (Capability) | platform |
| Service ID | svc-msh-security |
| Bounded Context | service_mesh_security |
| Wave | 0 |
| Mimari Yaklaşım | DDD + Hexagonal + Event-Driven |

## Sorumluluk Sınırları
- Bu repo kendi bounded context domain modelinin tek yetkili sahibidir.
- Domain kuralları altyapıdan bağımsız tutulur; entegrasyonlar port/adapter katmanında yönetilir.
- API/Event kontratları geriye dönük uyumluluk kontrolleri ile korunur.
- Güvenlik guardrail'leri (mTLS, token doğrulama, idempotency, log hijyeni) CI/CD ile zorlanır.

## Kapsam
### In Scope
- service_mesh_security bağlamına ait uygulama kodu, testler ve otomasyon.
- Bu servise ait OpenAPI/AsyncAPI veya şema artefaktları.
- Bu servisin çalışma zamanı operasyonları (gözlemlenebilirlik, release, rollback).

### Out of Scope
- Diğer bounded context'lerin iş kuralları ve veri sahipliği.
- Paylaşımlı DB anti-pattern'i; cross-context doğrudan tablo erişimi.
- Platform dışı gizli bilgi/anahtar yönetimi (merkezi policy dışında local hardcode).

## Mühendislik Standartları
- **TDD öncelikli** geliştirme, birim test + entegrasyon testi.
- **Clean Architecture**: Domain katmanı framework bağımsız.
- **12-Factor** ve environment-driven configuration.
- **FAPI odaklı güvenlik** (OIDC/OAuth2, mTLS, DPoP gereksinimleri ilgili servislerde).
- **PII güvenliği**: loglarda maskeleme, secret'ların source/env içine yazılmaması.

## Branching ve Release Akışı
- Uzun ömürlü branch'ler: `main`, `dev`, `staging`, `local`.
- Feature branch kuralı: `codex/<kisa-aciklama>`.
- Release yaklaşımı: PR + required status checks + tag tabanlı sürümleme.

## Dokümantasyon ve Referanslar
- [Enterprise Architecture Hub](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture)
- [Secure Microservices Architecture](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/architecture/overview/SECURE_MICROSERVICES_ARCHITECTURE.md)
- [Service Data Ownership Matrix](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/SERVICE_DATA_OWNERSHIP_MATRIX.md)
- [Service API Contracts Index](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/SERVICE_API_CONTRACTS_INDEX.md)
- [Transformation Plan](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/MICROSERVICES_TRANSFORMATION_PLAN.md)
- [Capability Map (PUML)](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/puml/service-mesh/enterprise-capability-map.puml)
- [Bu Repo Dokümantasyonu](./docs)

## Deployable mesh baseline (Proposed)

This repository provides the Istio service mesh and zero-trust network layer
for every FinTechBankX bounded context. It contains platform infrastructure
only, no domain logic. Status: **Proposed**; validated locally (render,
schema, policy checks), never applied to a cluster.

| Path | What it is |
|---|---|
| [contracts/mesh-contract.yaml](contracts/mesh-contract.yaml) | Source of truth: namespaces, service accounts, call edges, exceptions, gaps |
| [deploy/istio](deploy/istio) | Istio 1.24.3 Helm values (base, istiod HA, ingress gateway behind AWS NLB), per-env overrides |
| [deploy/kustomize](deploy/kustomize) | Base (generated policies) + overlays `dev`, `staging`, `prod` with `params.env` |
| [k8s/platform/external-secrets](k8s/platform/external-secrets) | ClusterSecretStore `aws-secrets-manager` (IRSA, SA `external-secrets`) |
| [scripts/generate](scripts/generate) | Renders `deploy/kustomize/base/generated/*.yaml` from the contract |
| [scripts/validation](scripts/validation) | `npm run validate:strict-mtls` (rules R1-R8) |
| [scripts/ci/validate-manifests.sh](scripts/ci/validate-manifests.sh) | kustomize build, kubeconform with Istio/ESO CRD schemas, istioctl analyze, helm template |
| [scripts/istio/install-mesh.sh](scripts/istio/install-mesh.sh) | Install order (prints a plan unless `--apply`) |
| [docs/mesh/DEPLOYABLE_MESH_BASELINE.md](docs/mesh/DEPLOYABLE_MESH_BASELINE.md) | Call graph, gaps, resilience mapping, exceptions, drift fixed |

What it enforces: mesh-wide STRICT mTLS (`PeerAuthentication default` in
`istio-system`, no PERMISSIVE/DISABLE anywhere), `default-deny`
AuthorizationPolicy and NetworkPolicy per namespace, ALLOW rules per caller
SPIFFE principal `cluster.local/ns/<ns>/sa/<sa>` for each real call edge,
Keycloak JWT validation (issuer at the gateway; issuer + `aud` = service id per
workload), a JWT required on `/api/**`, `outboundTrafficPolicy: REGISTRY_ONLY`
with ServiceEntries for Aurora, MSK, AWS APIs and the identity host,
DestinationRules with connection pools, outlier detection and locality-aware
load balancing.

### How a service consumes the mesh

A service chart must (platform contract addendum, 2026-10-08):

- install into its context namespace (`lending`, `payments`, `customer`,
  `risk`, `compliance`, `open-finance`); these and `identity`,
  `observability` are injected. `istio-system`, `kube-system`,
  `external-secrets` and `kafka` are not;
- use the service account named in the contract (= chart name), with pod labels
  `app.kubernetes.io/name=<sa>`, `app=<sa>`, `version=<semver or sha>`,
  `fintechbankx.io/service-id=<service id>`, `sidecar.istio.io/inject: "true"`;
- name Service ports `http` (8080) and `http-management` (8081) so Istio
  detects the protocol; serve `/actuator/health/{liveness,readiness}` and
  `/actuator/prometheus` on 8081;
- not set `traffic.sidecar.istio.io/excludeInboundPorts` (probes use Istio's
  probe rewrite) and not ship a PeerAuthentication or DestinationRule that
  weakens mTLS;
- reference secrets through ClusterSecretStore `aws-secrets-manager`
  (`platform-secrets` is not valid);
- validate JWT issuer `https://<identity-host>/realms/fintechbankx` and an
  `aud` containing its own service id.

A new call edge is added to `contracts/mesh-contract.yaml` (with evidence),
then `npm run generate`; the validator rejects principals that are not in the
contract.

### Validate locally

```bash
npm ci && npm test && npm run validate:strict-mtls
bash scripts/ci/validate-manifests.sh   # needs kustomize, kubeconform, helm, istioctl
```

Legacy material from the monolith extraction (`k8s/istio/security`,
`k8s/istio/local`, `security/`, `scripts/istio/install-istio.sh`) uses a
single `banking` namespace and is kept for reference; it is not part of the
deployable set. `k8s/istio/local` remains the kind-based local sandbox.

## Güvenlik ve Uyumluluk Notları
- Gerçek secret değerleri repo veya `.env` içinde tutulmaz.
- Secret üretim/rotasyon olayları merkezi log/SIEM'e taşınır.
- CI pipeline, anonimlik ve local-path sızıntısı kontrollerini bloklayıcı olarak çalıştırır.

## Katkı
- Katkı süreci için `CONTRIBUTING.md` ve squad runbook'ları izlenmelidir.
- PR'larda mimari kararlar ADR veya backlog referansı ile ilişkilendirilmelidir.

<!-- cell-architecture-start -->
## Cell-Based Architecture

This repository participates in the FinTechBankX cell-based resilience program.

- Plan: docs/architecture/CELL_BASED_ARCHITECTURE_IMPLEMENTATION_PLAN.md
- Backlog: docs/project-management/CELL_ARCHITECTURE_BACKLOG_BOARD.md
<!-- cell-architecture-end -->
