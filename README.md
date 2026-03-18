# fintechbankx-platform-mesh-security-service-mesh

Bu repo, FinTechBankX mikroservis dönüşümünde Spotify modeline göre tanımlanmış resmi servis alanıdır.

## Sorumluluk ve Sahiplik

- **Tribe:** Platform & Security Tribe
- **Squad:** Mesh Security Squad
- **Repo Kümesi:** `platform-security`
- **Bounded Context:** `security`
- **Ana Capability:** Istio/service-mesh security and mTLS policies
- **Dönüşüm Wave:** 0

Bu repo aşağıdaki yaklaşımı zorunlu olarak uygular:

1. DDD bounded context sınırlarına bağlı geliştirme.
2. Hexagonal (Ports & Adapters) mimari.
3. Event-driven ve sözleşme-öncelikli entegrasyon.
4. Güvenlik guardrail'leri (FAPI, mTLS, DPoP kapsamına göre).
5. PR-only governance, zorunlu CI quality gate ve izlenebilirlik.

## Kapsam

### In Scope

- `Istio/service-mesh security and mTLS policies` kapsamında kod, sözleşme, test, runbook ve release artefaktları.
- Bu bounded context'e ait servis içi iş kuralları.
- Sadece API/event sözleşmeleri üzerinden diğer context'lerle entegrasyon.

### Out of Scope

- Başka bounded context veritabanına doğrudan erişim.
- Ortak “shared database” yaklaşımı.
- Guardrail bypass eden manuel release adımları.

## Mühendislik Standartları

- Java 23 / Gradle (repo tipine göre)
- TDD öncelikli geliştirme
- Minimum test coverage hedefi: **%85+**
- OpenAPI/AsyncAPI sözleşme doğrulama
- Structured logging, trace-id propagation, metrics baseline

## Branching, Release ve Guardrail

- Korumalı branch seti: `main`, `dev`, `staging`
- Zorunlu kontroller:
  - `ci/build`
  - `ci/test`
  - `ci/security`
  - `local-path-leak-check`
  - `secret-pattern-scan`
  - `readme-doc-link-check`
- Wave 0 platform repolarında ek zorunlu kontrol: `strict-mtls`

## Dokümantasyon ve Referanslar

- **Enterprise Architecture Repo:** https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture
- **Spotify Tribe/Squad Repo Stratejisi:** https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/transformation/SPOTIFY_TRIBE_SQUAD_REPOSITORY_STRATEGY.md
- **Konsolide Backlog Board:** https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/transformation/outputs/backlog-normalization-board-2026-03-17.md
- **Cutover Closure Raporu:** https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/transformation/outputs/phase-c-cutover-closure-report-2026-03-17.md
- **Guardrail Hardening Raporu:** https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/transformation/outputs/phase-b-context-hardening-pass-2026-03-17.md

## Katkı Modeli

1. Doğrudan `main` yazımı yok, yalnızca PR ile değişiklik.
2. Mimari kararlarda ADR güncellemesi zorunlu.
3. Sözleşme değişikliği varsa OpenAPI/AsyncAPI ve testler birlikte güncellenir.
4. Güvenlik ve anonimlik kuralları ihlal eden içerik merge edilmez.
