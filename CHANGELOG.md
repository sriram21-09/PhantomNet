# Changelog

All notable changes to the PhantomNet project are documented in this file.

The format follows standard release logging conventions:
- 🚀 Features
- 🧠 Machine Learning & LLM
- 🛡️ Security & TAXII
- 📄 Export & Reporting
- 🎨 Dashboard & UI
- 🧪 Tests & Quality
- 🔄 CI/CD & Infrastructure
- 📚 Documentation

---

## [v3.0.0-rc1] - 2026-08-29

### 🚀 Features & Advanced Sentinel Capabilities (Week 21-22)
- **Playbook Diff & Comparison**: Side-by-side comparison endpoint (`GET /api/v1/sentinel/playbooks/compare`) with automated field-level diff metrics and frontend modal highlights.
- **Dynamic Quality Scoring**: Automated quality evaluation engine (`quality_scorer.py`) calculating quality badges and scores across all generated playbooks.
- **CVE Intelligence Enrichment**: Integrated CVE lookup and vulnerability correlation engine (`cve_mapper.py`) enriching playbooks and STIX bundles.
- **Campaign Timeline & Audit History**: Time-series campaign event aggregator and full compliance audit logging system (`SentinelAuditLog`, `/api/v1/sentinel/audit-logs`, `/export-history`).
- **Comprehensive Rules Packaging**: Bundled Snort and Sigma rule export engine streaming ZIP archives (`GET /api/v1/sentinel/rules/export-all`).
- **Webhook Alerts**: Asynchronous webhook dispatch engine (`webhook_notifier.py`) delivering real-time JSON payloads for critical incidents.

### 🛡️ Security Hardening & P0/P1 Remediations (Week 22)
- **API Security Hardening**: Timing attack prevention via `hmac.compare_digest()`, canonical path traversal defenses on PCAP downloads, input boundary validation, and global sanitized 500 exception handlers.
- **Cross-Platform Active Defense (BUG-P0-01)**: Multi-platform firewall blocking/unblocking with strict IP network parsing across Linux iptables/nftables and Windows netsh.
- **Corrupted Policy Resilience (BUG-P0-02)**: Graceful schema fallback preventing unhandled deserialization crashes.
- **High-Performance Socket Probing (BUG-P1-01)**: Reduced socket polling latency from 8s to <180ms across all honeypot monitors.
- **Thread Safety (BUG-P1-02)**: Reentrant mutex locks safeguarding concurrent threat response mutations.

### 🧪 Quality Assurance & E2E Validation
- **100% Automated Test Suite Pass Rate**: 4,181 / 4,181 automated tests passing with 0 failures across unit, integration, ML, and API test suites.
- **Cypress E2E Playbook Specs**: 6/6 specs passing covering individual reviews, batch approvals, PDF/STIX downloads, compare modal, and timeline navigation.
- **Stress & Load Testing**: 100 concurrent playbooks generated in 1.18s, 500+ object TAXII 2.1 feed paginated in 0.42s.

### 🏁 Sign-Off & Release Candidate Tag
- Formally signed off by Security Lead (`docs/rc1_security_signoff_week22_day5.md`), Frontend Lead (`docs/frontend_rc1_signoff.md`), and Team Lead (`docs/release_candidate_readiness_report_week22_day5.md`).
- Repository tagged: `v3.0.0-rc1`.

---

## [v3.0.0-beta] - 2026-08-07

### 🚀 Features
- **Sentinel V3 Layer**: Fully automated threat response pipeline integrating honeypot event telemetry with MITRE ATT&CK mapping, Snort/Sigma detection rules, and incident response playbooks.
- **TAXII 2.1 Server**: Built full STIX 2.1 intelligence sharing layer (`/taxii2/`) supporting Discovery, API Root, Collections, Objects, and Manifest endpoints for SIEM/MISP interoperation.
- **PDF Export Engine**: Implemented ReportLab-based PDF export (`pdf_exporter.py`) with executive summaries, network payload tables, detection rules, and MITRE mappings.
- **Batch Playbook Operations**: Added multi-select batch approval/rejection API (`POST /api/v1/sentinel/playbooks/batch-status`) and full revision history tracking (`version`, `parent_id`, `is_latest`, `regeneration_reason`).
- **MITRE ATT&CK v14 Upgrade**: Updated attack technique mappings to MITRE ATT&CK v14 (`mitre_attack_v14_mappings.json`) across all 12 supported threat scenarios.

### 🧠 Machine Learning & LLM
- **Local LLM Narrative Generation**: Integrated containerized Ollama with Mistral 7B (`backend/sentinel/llm_service.py`) for automated Jinja2 playbook summaries.
- **Resilience & Caching**: Built Redis prompt caching and background request queuing to handle concurrent generation without resource saturation.
- **Graceful Fallback**: Implemented automatic fallback to standard templated narratives during LLM service offline states or request timeouts.
- **Dynamic Feature Toggle**: Added `sentinel_llm_enabled` runtime configuration switch in `system_config` table and REST API.

### 🛡️ Security & TAXII
- **Authentication & BOLA Audit**: Hardened TAXII 2.1 endpoints with Basic and JWT authentication options and validated object-level authorization across playbook routes.
- **XSS & Path Traversal Safeguards**: Sanitized playbook payload metadata prior to PDF compilation and HTML rendering.
- **Deception Layer Pen-Test**: Verified honeypot resilience against Nmap, Nikto, and Hydra attacks (`pentest_day4_results.json`).

### 📄 Export & Reporting
- Downloadable PDF reports (`GET /api/v1/sentinel/playbooks/{id}/pdf`) with corporate branding and clean typography.
- Standardized cross-browser Blob handling for Firefox, Safari, and Chrome.

### 🎨 Dashboard & UI
- **Sentinel Analytics Panel**: Added `SentinelStatsPanel` and `PlaybookViewer` components with real-time counters and filter controls.
- **MITRE Visualization**: Interactive attack matrix layout showing mapped techniques, severity tiers, and confidence scores.
- **Accessibility & Polish**: Achieved 100% Lighthouse accessibility score with ARIA labels, contrast adjustments, and zero-data state chart safety.

### 🧪 Tests & Quality
- Added unit and integration tests for TAXII endpoints (`backend/tests/test_taxii.py`, `test_taxii_client.py`).
- Added Playwright end-to-end testing suite (`frontend-dev/tests/e2e/playbook.spec.ts`).
- Added load and stress testing scripts for STIX feeds and LLM generation.

### 🔄 CI/CD & Infrastructure
- Updated GitHub Actions workflow (`.github/workflows/python-app.yml`) with automated TAXII, LLM mock, and PDF generation test steps.
- Exported updated OpenAPI 3.0 schema and static HTML API reference (`docs/api_docs.html`, `docs/openapi.json`).

### 📚 Documentation
- Added Month 5 Retrospective & Release Planning (`docs/retrospective/month5_retrospective.md`).
- Added V3.0 Release Notes (`docs/release_notes/v3.0.0-rc1.md`).
- Added Database Migration Guide (`docs/migrations/v2_to_v3_migration_guide.md`).

---

## [v0.3-week7-ai-engine] - 2026-02-05

### 🚀 Features
- Implemented full ML model lifecycle using MLflow
  - Model training, evaluation, and logging
  - Model registry integration
  - Versioning with staging lifecycle
- Added secure model deployment pipeline using MLflow Registry
- Built threat intelligence correlation engine
  - External feed ingestion (mock + extensible design)
  - IOC and ML prediction correlation
  - Correlation scoring logic
  - CLI-based correlation API

### 🧠 Machine Learning
- Binary attack detection model
- Accuracy consistently ≥ 85%
- Inference latency consistently < 100ms
- MLflow experiment tracking enabled
- Model lineage, metadata, and tags tracked

### 🔗 Integrations
- Integrated ML pipeline with PhantomNet backend
- Integrated threat intelligence pipeline with ML predictions
- Unified execution paths for standalone and integrated runs

### 🧪 Tests & Quality
- Added unit tests for:
  - Model training
  - Model registry validation
  - Deployment and inference
- Added integration tests for:
  - End-to-end ML pipeline
  - Latency and accuracy validation
- All tests passing (warnings only, no failures)

### 🔄 CI/CD
- Added GitHub Actions workflow for ML pipeline
- Automated checks:
  - Dependency install
  - Test execution
  - Pipeline validation

### 📚 Documentation
- Added Week 7 Day 3 documentation for model lifecycle
- Added Week 7 Day 4 documentation for threat correlation pipeline
- Updated project changelog with release details

### 🏷 Release
- Created release tag: `v0.3-week7-ai-engine`
- Ready for next phase integration

---

## [v0.2-week6-ml-core]

- Initial ML pipeline
- Dataset preprocessing
- Baseline model training and evaluation

---

## [v0.1-initial]

- Project structure initialized
- Backend scaffolding created

