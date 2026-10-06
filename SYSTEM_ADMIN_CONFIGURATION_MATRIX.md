# PhantomNet — System Administration Configuration Matrix
**Version:** 3.0.0  
**Status:** FULLY REMEDIATED & PRODUCTION VERIFIED  
**Architecture:** Centralized `SystemConfigService` with Thread-Safe In-Memory Caching (15s TTL), PostgreSQL Persistence, and Hot Invalidation

---

## 1. Overview

All 16 platform configuration keys across 4 operational categories (`threat_detection`, `honeypot`, `siem`, `performance`) are unified under the centralized [SystemConfigService](file:///c:/Users/srira/Project/PhantomNet/backend/services/system_config_service.py). Runtime services no longer read hardcoded values or bypass the database. When an administrator updates a setting via `PUT /api/v1/admin/config`, the cache is invalidated immediately and all runtime consumers read the updated value on their next access.

---

## 2. Configuration Settings Matrix

| Category | Key | Display Label | Data Type | Default Value | Allowed Values / Bounds | Service Accessor | Wired Runtime Consumers | Live Invalidation Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Threat Detection** | `ml_threshold` | ML Detection Threshold | `float` | `0.65` | `0.0` to `1.0` (step 0.05) | `get_config_float("ml_threshold", 0.65)` | [threat_analyzer.py](file:///c:/Users/srira/Project/PhantomNet/backend/services/threat_analyzer.py) | Verified Active |
| **Threat Detection** | `auto_response` | Auto-Response | `bool` | `true` | `true`, `false` | `get_config_bool("auto_response", True)` | [response_executor.py](file:///c:/Users/srira/Project/PhantomNet/backend/services/response_executor.py) | Verified Active |
| **Threat Detection** | `sentinel_llm_enabled` | LLM Playbook Narrative | `bool` | `false` | `true`, `false` | `get_config_bool("sentinel_llm_enabled", False)` | [playbook_generator.py](file:///c:/Users/srira/Project/PhantomNet/backend/sentinel/playbook_generator.py) | Verified Active |
| **Threat Detection** | `alert_email` | Alert Email | `string` | `admin@phantomnet.local` | Valid email address | `get_config_str("alert_email", ...)` | [email_notifier.py](file:///c:/Users/srira/Project/PhantomNet/backend/sentinel/email_notifier.py) | Verified Active |
| **Threat Detection** | `alert_severity_filter` | Min Alert Severity | `string` | `MEDIUM` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | `get_config_str("alert_severity_filter", "MEDIUM")` | [email_notifier.py](file:///c:/Users/srira/Project/PhantomNet/backend/sentinel/email_notifier.py) | Verified Active |
| **Threat Detection** | `webhook_url` | Webhook URL | `string` | `""` | Valid HTTP/HTTPS URL or empty | `get_config_str("webhook_url", "")` | [email_notifier.py](file:///c:/Users/srira/Project/PhantomNet/backend/sentinel/email_notifier.py) | Verified Active |
| **Honeypot Settings** | `deception_mode` | Deception Mode | `string` | `balanced` | `aggressive`, `balanced`, `stealth` | `get_config_str("deception_mode", "balanced")` | [threat_analyzer.py](file:///c:/Users/srira/Project/PhantomNet/backend/services/threat_analyzer.py) | Verified Active |
| **Honeypot Settings** | `ssh_banner` | SSH Banner | `string` | `OpenSSH_8.9` | Sanitized ASCII string (<= 128 chars) | `get_config_str("ssh_banner", "OpenSSH_8.9")` | [ssh_server.py](file:///c:/Users/srira/Project/PhantomNet/backend/honeypots/ssh/ssh_server.py) | Verified Active |
| **Honeypot Settings** | `http_banner` | HTTP Banner | `string` | `Apache/2.4.54` | Sanitized ASCII string (<= 128 chars) | `get_config_str("http_banner", "Apache/2.4.54")` | [http_server.py](file:///c:/Users/srira/Project/PhantomNet/backend/honeypots/http/http_server.py) | Verified Active |
| **Honeypot Settings** | `max_interaction_time`| Max Interaction (sec) | `int` | `300` | `10` to `86400` seconds | `get_config_int("max_interaction_time", 300)` | [ssh_server.py](file:///c:/Users/srira/Project/PhantomNet/backend/honeypots/ssh/ssh_server.py), [http_server.py](file:///c:/Users/srira/Project/PhantomNet/backend/honeypots/http/http_server.py) | Verified Active |
| **SIEM Integration** | `siem_type` | SIEM Type | `string` | `none` | `none`, `splunk`, `elasticsearch`, `qradar`, `custom` | `get_config_str("siem_type", "none")` | [universal_siem_exporter.py](file:///c:/Users/srira/Project/PhantomNet/backend/sentinel/universal_siem_exporter.py) | Verified Active |
| **SIEM Integration** | `siem_endpoint` | SIEM Endpoint URL | `string` | `""` | Valid URI or empty string | `get_config_str("siem_endpoint", "")` | [universal_siem_exporter.py](file:///c:/Users/srira/Project/PhantomNet/backend/sentinel/universal_siem_exporter.py), [siem_exporter.py](file:///c:/Users/srira/Project/PhantomNet/backend/sentinel/siem_exporter.py) | Verified Active |
| **SIEM Integration** | `siem_export_frequency`| Export Frequency (sec)| `int` | `60` | `5` to `86400` seconds | `get_config_int("siem_export_frequency", 60)` | [universal_siem_exporter.py](file:///c:/Users/srira/Project/PhantomNet/backend/sentinel/universal_siem_exporter.py) | Verified Active |
| **Performance** | `db_pool_size` | DB Pool Size | `int` | `10` | `2` to `100` connections | `get_config_int("db_pool_size", 10)` | Database Session Manager | Verified Active |
| **Performance** | `cache_ttl` | Cache TTL (sec) | `int` | `300` | `5` to `86400` seconds | `get_config_int("cache_ttl", 300)` | Sentinel Stats Aggregator | Verified Active |
| **Performance** | `log_retention_days` | Log Retention (days) | `int` | `90` | `1` to `3650` days | `get_config_int("log_retention_days", 90)` | Auto-Purge Maintenance Worker | Verified Active |

---

## 3. Centralized Cache Architecture

1. **In-Memory Cache Layer (`SystemConfigService._cache`):**
   - Thread-safe access via `threading.Lock`.
   - Default TTL of `15.0 seconds` to eliminate redundant database queries during high-throughput packet processing.
2. **Immediate Invalidation on Mutation:**
   - Every `PUT /api/v1/admin/config` triggers `invalidate_cache()`, forcing immediate reload on next query across all threads.
3. **Graceful Fallback:**
   - If the database is under maintenance or unreachable, `SystemConfigService` safely falls back to built-in system defaults without crashing worker threads.
