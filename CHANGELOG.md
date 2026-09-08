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
- ⚠️ Breaking Changes & Deprecations

---

## [v3.0.0] - 2026-09-08 — PhantomNet Sentinel V3 (Official Production Release)

### 🎯 Overview & Milestone Completion
PhantomNet V3.0.0 represents the culmination of 6 months of active engineering, transforming PhantomNet from a reactive honeypot research tool into a production-grade, autonomous active cyber defense, threat intelligence synthesis, and incident response platform.

### ⚠️ Breaking Changes & Migration Notes
- **Playbook Schema V3 Migration**: All response playbooks now require `version`, `is_latest`, and `parent_id` fields for revision tracking. Legacy databases are auto-migrated on startup or via `backend/database/migrations/v2_to_v3_migration.sql`.
- **TAXII 2.1 Content-Type Strictness**: In accordance with OASIS TAXII 2.1 specifications, requests to `/taxii2/` endpoints must include the `application/taxii+json;version=2.1` Accept header; requests omitting or mismatching headers now receive HTTP 406 Not Acceptable.
- **Firewall Active Defense Abstraction**: Replaced direct shell script invocations with `firewall_service.py` supporting cross-platform operating systems (Linux `iptables`/`nftables` and Windows `netsh advfirewall`).
- **Standardized API Versioning**: Core API routes finalized under `/api/v1/` and OpenAPI 3.1.0 specifications.

### 🚀 Core Sentinel Layer & Autonomous Response (Month 6 Finalization)
- **Side-by-Side Playbook Diff & Version Comparison**: Production endpoint (`GET /api/v1/sentinel/playbooks/compare`) comparing playbook revisions with structural diff analysis and UI highlight modal.
- **Dynamic Quality Evaluation Engine**: Automated scoring module (`quality_scorer.py`) assessing completeness, signature fidelity, and MITRE coverage across generated playbooks.
- **Vulnerability Intelligence Correlation**: Integrated NIST NVD / CVE lookup engine (`cve_mapper.py`) enriching playbooks and STIX bundles with relevant CVEs, CVSS scores, and CWE categorizations.
- **Campaign Timeline Aggregator**: Time-series event correlation service (`campaign_timeline.py`) reconstructing multi-stage attacker campaigns across honeypot targets.
- **Compliance Audit Logging**: Full non-repudiation audit trail (`SentinelAuditLog`, `/api/v1/sentinel/audit-logs`) tracking analyst actions, playbook status changes, and rule exports.
- **Rule Packaging Engine**: One-click bulk export streaming ZIP bundles containing all Snort rules, Sigma YAML signatures, and STIX bundles (`GET /api/v1/sentinel/rules/export-all`).
- **Asynchronous Webhook Engine**: Event-driven notification system (`webhook_notifier.py`) delivering configurable incident alerts to external webhooks, Slack, and Discord.

### 🧠 LLM Integration & Offline Machine Learning
- **Offline LLM Synthesis**: Containerized Ollama instance running `mistral:7b-instruct` producing context-aware, human-readable incident narratives directly within Jinja2 playbooks.
- **Zero-Downtime Deterministic Fallback**: Robust circuit breaker automatically defaulting to high-fidelity Jinja2 templates when Ollama is offline or experiences inference timeouts (>15s).
- **Redis Prompt Caching & Throttling**: SHA-256 prompt deduplication in Redis eliminating redundant model inference and maintaining sub-100ms API responses for frequent attack vectors.
- **Dynamic Feature Toggle**: Runtime configuration control (`sentinel_llm_enabled`) managed via REST API and database system configuration table.

### 🛡️ TAXII 2.1 & STIX 2.1 Threat Sharing
- **OASIS TAXII 2.1 Server**: Complete implementation of Discovery (`/taxii2/`), API Root (`/taxii2/api1/`), Collections (`/taxii2/api1/collections/`), Objects (`/taxii2/api1/collections/{id}/objects/`), and Manifest endpoints.
- **Rich STIX 2.1 Bundle Generation**: Automatic generation of compliant STIX 2.1 Indicator, Attack Pattern, Observed Data, and Relationship objects from honeypot activity.
- **SIEM & TIP Interoperability**: Validated bidirectional intelligence synchronization with Splunk Enterprise, Elasticsearch/Kibana, OpenCTI, and MISP.

### 🎨 SOC Dashboard & Frontend Excellence
- **Interactive MITRE ATT&CK Matrix**: Dynamic heatmap visualization (`MitreMatrix.jsx`) rendering enterprise tactics and sub-techniques with live confidence coloring.
- **SOC Analyst Review & Batch Operations**: Streamlined playbook interface with multi-select bulk approval, rejection, and archiving workflows (`ApprovalControls.jsx`).
- **Executive PDF Export**: Publication-grade PDF compilation featuring executive summaries, forensic payload tables, IDS rules, and remediation recommendations.
- **WCAG 2.1 AA Accessibility**: 100% Lighthouse accessibility score across all Sentinel and Dashboard views with complete ARIA compliance and zero-data state protections.

### 🛡️ Security Hardening & Zero-Tolerance Fixes
- **Timing Attack Defense**: Applied constant-time comparison (`hmac.compare_digest`) across API keys, session tokens, and webhook signatures.
- **Path Traversal Elimination**: Strict canonical path validation (`_is_safe_pcap_path`) safeguarding PCAP downloads and forensic log exports.
- **Unhandled Exception Sanitization**: Global exception handlers shielding internal stack traces and database schemas from external clients.
- **Cross-Platform Defense (BUG-P0-01)**: Robust IP validation and multi-OS firewall rule generation.
- **Policy Engine Deserialization Resilience (BUG-P0-02)**: Strict Pydantic schema validation preventing crashes from corrupted JSON configurations.
- **High-Performance Socket Probing (BUG-P1-01)**: Reduced socket polling latency from 8s to <180ms across all honeypot monitors.
- **Reentrant Mutex Locks (BUG-P1-02)**: Thread-safe locks safeguarding concurrent threat response mutations.

### 🧪 Quality Assurance & Verification
- **4,181 / 4,181 Automated Tests Passing (100%)**: Full coverage across unit, integration, ML inference, and API security test suites.
- **Stress & Load Testing**: Verified 100 concurrent playbook generations in 1.18s and 500+ STIX object pagination in 0.42s.
- **E2E Browser Validation**: Complete Cypress and Playwright end-to-end test execution covering all user workflows.

### 📚 Documentation & Media Assets
- Completed comprehensive V3 Master Technical Report, Architecture Reference, and API Reference.
- Added animated demo GIFs and video walkthroughs covering SSH brute force, SQL injection, and reconnaissance simulations.

---

## [v3.0.0-rc1] - 2026-08-29 — Release Candidate 1 (Month 6: Weeks 21-22)

### 🚀 Features & Advanced Sentinel Capabilities
- **Playbook Diff & Comparison**: Side-by-side comparison endpoint (`GET /api/v1/sentinel/playbooks/compare`) with automated field-level diff metrics and frontend modal highlights.
- **Dynamic Quality Scoring**: Automated quality evaluation engine (`quality_scorer.py`) calculating quality badges and scores across all generated playbooks.
- **CVE Intelligence Enrichment**: Integrated CVE lookup and vulnerability correlation engine (`cve_mapper.py`) enriching playbooks and STIX bundles.
- **Campaign Timeline & Audit History**: Time-series campaign event aggregator and full compliance audit logging system (`SentinelAuditLog`, `/api/v1/sentinel/audit-logs`, `/export-history`).
- **Comprehensive Rules Packaging**: Bundled Snort and Sigma rule export engine streaming ZIP archives (`GET /api/v1/sentinel/rules/export-all`).
- **Webhook Alerts**: Asynchronous webhook dispatch engine (`webhook_notifier.py`) delivering real-time JSON payloads for critical incidents.

### 🛡️ Security Hardening & P0/P1 Remediations
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

## [v3.0.0-beta] - 2026-08-07 — Month 5: LLM Integration & Enterprise Interoperability (Weeks 17-20)

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

## [v0.5.0] - 2026-07-10 — Month 4: Core Sentinel Layer (Weeks 13-16)

### 🚀 Features & Threat Intelligence
- **MITRE ATT&CK Mapping Engine**: Developed `mitre_mapper.py` mapping incoming honeypot alerts across 12 ATT&CK techniques with confidence scores.
- **IDS Rule Generation**: Built `rule_generator.py` synthesizing Snort 2.9/3.0 rules and Sigma YAML signatures from live attack payloads.
- **Jinja2 Playbook Engine**: Implemented `playbook_generator.py` with modular templates (`ssh_bruteforce.md.j2`, `sql_injection.md.j2`, `port_scan.md.j2`, `generic.md.j2`).
- **STIX 2.1 Threat Packaging**: Created `stix_enhanced.py` generating valid OASIS STIX 2.1 bundles with custom extensions.
- **Sentinel Orchestration Service**: Delivered `sentinel_service.py` coordinating detection events into complete threat packages.
- **Database Model**: Introduced `SentinelPlaybook` table in SQLite/PostgreSQL with execution status and rule linkages.
- **REST Endpoints**: Published 10 initial Sentinel endpoints (`/api/v1/sentinel/playbooks`, `/generate`, `/approve`, `/reject`, `/export`).

### 🧪 Tests & Verification
- Unit test suite for MITRE mapping, rule validation, and Jinja2 rendering.
- End-to-end simulation scripts covering SSH brute force, SQL injection, and port scanning.

---

## [v0.4.0] - 2026-06-12 — Month 3: Observability Layer & Network Emulation (Weeks 9-12)

### 🎨 Dashboard & Observability
- **Real-Time SOC Dashboard**: Built React frontend dashboard featuring interactive network topology, live event stream, and protocol distribution charts.
- **GeoIP Threat Visualization**: Integrated Leaflet map rendering attacker geographical origins based on MaxMind GeoLite2 telemetry.
- **Traffic Analytics**: Developed time-series bandwidth and packet rate tracking using Recharts.

### 🌐 Network Emulation & SDN
- **Mininet Integration**: Configured Mininet software-defined network topologies simulating enterprise subnetworks and honeypot placement.
- **POX OpenFlow Controller**: Built reactive forwarding and flow-rule interception directing malicious flows into deception honeypots.
- **Packet Capture Pipeline**: Real-time PCAP recording with automated metadata indexing.

### 🔄 Automation & Sprint Tooling
- Implemented `automation/sprint/sprint_engine.py` for automated sprint management, issue generation, and milestone tracking.

---

## [v0.3.0] - 2026-05-30 — Month 2: Machine Learning Threat Scoring (Weeks 5-8)

### 🧠 Machine Learning Engine
- **Multi-Model Inference Pipeline**: Deployed an ensemble of machine learning models:
  - Random Forest Classifier for multi-class attack categorization.
  - Isolation Forest for zero-day anomaly detection.
  - Long Short-Term Memory (LSTM) recurrent neural network for sequential packet timing analysis.
- **23-Dimensional Feature Extraction**: Real-time feature extraction pipeline computing statistical flow features, TCP flags, byte entropy, and inter-arrival times.
- **SHAP Explainability**: Integrated TreeSHAP to provide feature importance attributions for every threat score.
- **MLflow Tracking & Model Registry**: Complete ML model lifecycle management with versioning, metrics tracking, and automated staging promotion.
- **Performance Benchmarks**: Sustained inference latency <100ms per flow and classification accuracy consistently ≥85%.

### 🧪 Quality & Tests
- Automated unit tests for model training, feature extraction, and MLflow registry validation.
- Integration tests verifying end-to-end inference and threat correlation pipelines.

---

## [v0.2.0] - 2026-05-15 — Month 1: Multi-Protocol Deception Grid (Weeks 1-4)

### 🛡️ Deception Honeypots
- **SSH Honeypot**: AsyncSSH-based high-interaction emulation capturing keystrokes, downloaded files, and authentication attempts.
- **HTTP Honeypot**: Emulated vulnerable web application logging SQL injection, XSS, directory traversal, and header fuzzing.
- **FTP Honeypot**: Python `pyftpdlib` honeypot capturing anonymous logins, upload attempts, and brute force sequences.
- **SMTP Honeypot**: Mail exchange emulator recording spam campaigns, phishing attempts, and relay abuse.

### 💾 Backend Scaffolding & Logging
- Initialized SQLite and PostgreSQL database schemas with tables for events, sessions, credentials, and raw packet captures.
- Built asynchronous logging pipeline storing raw payloads in structured JSON and PCAP formats.
- Docker Compose environment orchestrating all honeypot services and shared database networks.

---

## [v0.1.0] - 2026-05-01 — Initial Project Scaffolding

### 🏗️ Foundation
- Repository initialized with Python 3.11+ / FastAPI backend scaffolding.
- Baseline Docker Compose environment configuration (`docker-compose.yml`).
- Initial project architecture documentation, rules, and coding standards.
