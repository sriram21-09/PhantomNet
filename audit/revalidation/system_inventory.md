# PhantomNet V3 — System Architecture & Component Inventory
**Generated**: September 19, 2026  
**Auditor**: Independent Senior Production Readiness & Security Audit Group  
**Target Git SHA**: `8c199f2877901773b1beb04f80e244f98d0f7e3f`

---

## 1. Route & API Inventory Summary

- **Total Registered Routes**: 134
  - **HTTP Endpoints**: 132
  - **WebSocket Endpoints**: 2
- **Public by Design**: 3 (`/health/*`, `/api/v1/auth/login`, `/api/v1/auth/refresh`, OpenAPI docs)
- **Authenticated Endpoints**: 52
- **Unprotected Non-Public Endpoints (POTENTIAL SEC-01 BREACHES)**: 79

### Unprotected Non-Public Endpoints List:
| Method | Path | Endpoint Function |
| :--- | :--- | :--- |
| GET | `/api/v1/model/metrics` | `api.model_metrics.get_model_metrics` |
| GET | `/api/v1/model/config` | `api.model_metrics.get_training_config` |
| GET | `/api/v1/model/stats` | `api.model_metrics.get_stats` |
| GET | `/api/v1/model/feature-importance` | `api.model_metrics.get_feature_importance` |
| GET | `/api/v1/model/predictions/recent` | `api.model_metrics.get_recent_predictions` |
| GET | `/api/v1/model/confidence-histogram` | `api.model_metrics.get_confidence_histogram` |
| GET | `/api/v1/enrich/ip/{ip}` | `api.threat_intel.enrich_ip_endpoint` |
| GET | `/api/v1/events/{event_id}/pcap` | `api.pcap.download_pcap` |
| GET | `/api/v1/pcap/analysis/{event_id}` | `api.pcap.get_pcap_analysis` |
| GET | `/api/v1/pcap/stats` | `api.pcap.pcap_stats` |
| POST | `/api/v1/pcap/capture/{event_id}` | `api.pcap.trigger_capture` |
| GET | `/api/v1/pcap/capture/{event_id}/status` | `api.pcap.capture_status` |
| POST | `/api/v1/pcap/cleanup` | `api.pcap.run_cleanup` |
| POST | `/api/v1/admin/login` | `api.admin.admin_login` |
| POST | `/api/v1/admin/refresh` | `api.admin.refresh_token_endpoint` |
| POST | `/api/v1/admin/logout` | `api.admin.logout_endpoint` |
| GET | `/api/v1/admin/users` | `api.admin.list_users` |
| POST | `/api/v1/admin/users` | `api.admin.create_user` |
| PUT | `/api/v1/admin/users/{user_id}` | `api.admin.update_user` |
| DELETE | `/api/v1/admin/users/{user_id}` | `api.admin.delete_user` |
| GET | `/api/v1/admin/config` | `api.admin.get_config` |
| PUT | `/api/v1/admin/config` | `api.admin.update_config` |
| GET | `/api/v1/admin/system-overview` | `api.admin.system_overview` |
| POST | `/api/v1/admin/backup` | `api.admin.create_backup` |
| GET | `/api/v1/admin/backups` | `api.admin.list_backups` |
| POST | `/api/v1/admin/vacuum` | `api.admin.vacuum_db` |
| DELETE | `/api/v1/admin/events/old` | `api.admin.delete_old_events` |
| POST | `/api/v1/admin/taxii/clients` | `api.taxii_admin.create_taxii_client` |
| GET | `/api/v1/admin/taxii/clients` | `api.taxii_admin.list_taxii_clients` |
| DELETE | `/api/v1/admin/taxii/clients/{key_id}` | `api.taxii_admin.revoke_taxii_client` |
| POST | `/api/v1/analyze/threat-score` | `api.threat_scoring.analyze_threat` |
| GET | `/api/v1/patterns/advanced` | `api.pattern_analytics.get_advanced_patterns` |
| POST | `/api/v1/reports/schedule` | `api.reports.schedule_report` |
| DELETE | `/api/v1/reports/schedule/{report_id}` | `api.reports.delete_schedule` |
| PUT | `/api/v1/reports/schedule/{report_id}` | `api.reports.update_schedule` |
| POST | `/api/v1/hunting/search` | `api.hunting.search_events` |
| POST | `/api/v1/hunting/extract-iocs` | `api.hunting.extract_iocs` |
| GET | `/api/v1/hunting/related-events` | `api.hunting.get_related_events` |
| GET | `/api/v1/hunting/history` | `api.hunting.get_search_history` |
| POST | `/api/v1/hunting/analyze-patterns` | `api.hunting.analyze_patterns` |
| GET | `/api/v1/hunting/templates` | `api.hunting.get_query_templates` |
| POST | `/api/v1/cases/` | `api.cases.create_case` |
| PUT | `/api/v1/cases/{case_id}` | `api.cases.update_case` |
| POST | `/api/v1/cases/{case_id}/evidence` | `api.cases.add_evidence` |
| PATCH | `/api/v1/alerts/{alert_id}/resolve` | `api.alerts.resolve_alert` |
| GET | `/api/sentinel/playbooks` | `api.sentinel.list_playbooks` |
| GET | `/api/sentinel/playbooks/{playbook_id}` | `api.sentinel.get_playbook` |
| GET | `/api/sentinel/stats` | `api.sentinel.get_sentinel_stats` |
| GET | `/api/sentinel/mitre/mapping` | `api.sentinel.get_mitre_mappings` |
| POST | `/api/sentinel/generate` | `api.sentinel.generate_playbook` |
| PATCH | `/api/sentinel/playbooks/{playbook_id}/approve` | `api.sentinel.approve_playbook` |
| PATCH | `/api/sentinel/playbooks/{playbook_id}/reject` | `api.sentinel.reject_playbook` |
| GET | `/api/sentinel/rules/snort` | `api.sentinel.list_snort_rules` |
| GET | `/api/sentinel/rules/sigma` | `api.sentinel.list_sigma_rules` |
| GET | `/api/sentinel/llm/status` | `api.sentinel.get_llm_status` |
| POST | `/api/sentinel/playbooks/{playbook_id}/regenerate-llm` | `api.sentinel.regenerate_playbook_llm` |
| GET | `/api/sentinel/mitre/matrix` | `api.sentinel.get_mitre_matrix` |
| POST | `/api/sentinel/playbooks/batch/approve` | `api.sentinel.batch_approve_playbooks` |
| POST | `/api/sentinel/playbooks/batch/reject` | `api.sentinel.batch_reject_playbooks` |
| POST | `/api/sentinel/playbooks/{playbook_id}/regenerate` | `api.sentinel.regenerate_playbook` |
| GET | `/api/sentinel/playbooks/{playbook_id}/versions` | `api.sentinel.get_playbook_versions` |
| GET | `/api/sentinel/rules/export-all` | `api.sentinel.export_all_rules` |
| GET | `/api/sentinel/campaigns/{campaign_id}/timeline` | `api.sentinel.get_campaign_timeline` |
| GET | `/api/sentinel/playbooks/{playbook_id}/export-history` | `api.sentinel.get_playbook_export_history` |
| GET | `/api/v1/sentinel/templates` | `api.sentinel.list_sentinel_templates` |
| POST | `/api/v1/sentinel/templates/preview` | `api.sentinel.preview_sentinel_template` |
| POST | `/api/v1/ingest/event` | `api.ingest.ingest_event` |
| POST | `/api/v1/ingest/batch` | `api.ingest.ingest_batch` |
| GET | `/api/v1/ingest/health` | `api.ingest.ingest_health` |
| GET | `/api/v1/governance/retention/policies` | `api.governance.get_retention_policies` |
| POST | `/api/v1/governance/retention/run` | `api.governance.run_retention_cycle_endpoint` |
| GET | `/metrics` | `api.health.prometheus_metrics` |
| GET | `/api/health` | `backend.main.health_check` |
| GET | `/analyze-traffic` | `backend.main.get_real_traffic` |
| GET | `/api/stats` | `backend.main.get_api_stats` |
| GET | `/metrics` | `backend.main.prometheus_metrics` |
| POST | `/active-defense/block/{ip}` | `backend.main.block_ip_address` |
| POST | `/api/response/unblock/{ip}` | `backend.main.unblock_ip` |
| PUT | `/api/response/policy` | `backend.main.update_response_policy` |

---

## 2. Background Workers & Scheduled Tasks
1. `RealTimeSniffer`: Background network traffic capture thread.
2. `delayed_analyzer_start`: Threat analyzer background task (2s delay).
3. `scheduler_service`: APScheduler loading scheduled reports, sentinel auto-gen, and retention cleanup.
4. `broadcast_live_metrics`: WebSocket real-time metrics broadcaster (every 2s).
5. `_pcap_cleanup_scheduler`: Daily PCAP retention pruning.
6. `broadcast_event_stream`: WebSocket live event stream broadcaster.
7. `sentinel_generation_loop`: Background DBSCAN campaign clustering & playbook auto-generation (every 5m).

---

## 3. Data & Storage Pipeline
- **Database**: PostgreSQL 15 (`phantomnet`), managed via SQLAlchemy with `QueuePool` (pool_size=20, max_overflow=10, pool_pre_ping=True).
- **Migrations**: Alembic migrations under `alembic/versions/`.
- **Cache & Message Broker**: Redis 7 Alpine with Append-Only File (`appendonly yes`, `appendfsync everysec`, `maxmemory 512mb`, `noeviction`).
- **Streams & Queues**: `events:stream` with consumer groups and `DeadLetterEvent` table fallback.

---

## 4. Docker Architecture & Hardening
- **Services (8)**:
  - `phantomnet_postgres`: PostgreSQL 15 Alpine (5432)
  - `phantomnet_redis`: Redis 7 Alpine (6379)
  - `phantomnet_api`: FastAPI backend on Uvicorn (8000), configured with `read_only: true`, `cap_drop: [ALL]`, `user: 10001:10001`.
  - `phantomnet_ollama`: Ollama LLM (11434)
  - `phantomnet_frontend`: Nginx serving React build (3000 -> 8080).
  - `phantomnet_ssh`: SSH honeypot (2722 -> 2222).
  - `phantomnet_http`: HTTP honeypot (8080 -> 8080).
  - `phantomnet_ftp`: FTP honeypot (2121 -> 2121).
  - `phantomnet_smtp`: SMTP honeypot (2725 -> 2525).
- **Networks**:
  - `app_net`: General service bridge network.
  - `honeypot_net`: `internal: true` network for honeypot-to-api communication.
  - `internal_broker_net`: `internal: true` network for broker isolation.

---

## 5. Machine Learning Pipeline
- **Production Artifact**: `ml_models/registry/anomaly_detector.pkl` (Random Forest Classifier).
- **Metadata**: `ml_models/registry/anomaly_detector.json` with hyperparameters and SHA-256 checksum.
- **Inference Service**: `backend/services/threat_scoring_service.py` with fail-closed architecture.
