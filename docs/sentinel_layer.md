# PhantomNet Sentinel Layer — Technical Documentation

> **Version:** 3.0.0-sentinel  
> **Last Updated:** 2026-09-01  
> **Module Path:** `backend/sentinel/`  
> **API Prefix:** `/api/sentinel`  
> **Sprint Reference:** Phase 5 → Week 23  

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
   - 2.1 [Module Map](#21-module-map)
   - 2.2 [Data Flow Diagram](#22-data-flow-diagram)
   - 2.3 [Component Responsibilities](#23-component-responsibilities)
3. [Database Models](#3-database-models)
   - 3.1 [SentinelPlaybook](#31-sentinelplaybook)
   - 3.2 [SentinelAuditLog](#32-sentinelauditlog)
   - 3.3 [Entity-Relationship Diagram](#33-entity-relationship-diagram)
4. [Signature Extraction from Honeypot Payloads](#4-signature-extraction-from-honeypot-payloads)
   - 4.1 [Port-to-Service Inference](#41-port-to-service-inference)
   - 4.2 [SignatureEngine Analysis](#42-signatureengine-analysis)
   - 4.3 [Default Fallback Signatures](#43-default-fallback-signatures)
5. [MITRE ATT&CK Technique Mapping](#5-mitre-attck-technique-mapping)
   - 5.1 [Mapping Table (12 Signatures)](#51-mapping-table-12-signatures)
   - 5.2 [Mapping Rules & Resolution Logic](#52-mapping-rules--resolution-logic)
   - 5.3 [Technique Object Schema](#53-technique-object-schema)
6. [Playbook Generation Pipeline](#6-playbook-generation-pipeline)
   - 6.1 [9-Step Orchestration Flow](#61-9-step-orchestration-flow)
   - 6.2 [Confidence Scoring Engine](#62-confidence-scoring-engine)
   - 6.3 [Quality Scoring Engine](#63-quality-scoring-engine)
   - 6.4 [Jinja2 Template Selection](#64-jinja2-template-selection)
   - 6.5 [Detection Rule Generation (Snort & Sigma)](#65-detection-rule-generation-snort--sigma)
   - 6.6 [STIX 2.1 Bundle Generation](#66-stix-21-bundle-generation)
   - 6.7 [CVE Mapping & Enrichment](#67-cve-mapping--enrichment)
   - 6.8 [LLM Narrative Generation](#68-llm-narrative-generation)
7. [Playbook Lifecycle & Workflows](#7-playbook-lifecycle--workflows)
   - 7.1 [Status State Machine](#71-status-state-machine)
   - 7.2 [Approval & Rejection](#72-approval--rejection)
   - 7.3 [Batch Operations](#73-batch-operations)
   - 7.4 [Playbook Regeneration & Version Tracking](#74-playbook-regeneration--version-tracking)
   - 7.5 [Rule Export](#75-rule-export)
   - 7.6 [Retention Policies](#76-retention-policies)
8. [REST API Reference](#8-rest-api-reference)
9. [Notification System](#9-notification-system)
   - 9.1 [Email Alerts](#91-email-alerts)
   - 9.2 [Webhook Alerts](#92-webhook-alerts)
10. [Observability & Metrics](#10-observability--metrics)
11. [Configuration Reference](#11-configuration-reference)
12. [Appendices](#12-appendices)

---

## 1. Overview

The **Sentinel Layer** is PhantomNet's automated threat intelligence and incident-response pipeline. It transforms raw honeypot event data into actionable security artefacts:

- **Playbooks** — Structured incident-response guides rendered from Jinja2 templates
- **Detection Rules** — Snort IDS and Sigma rules ready for SOC deployment
- **STIX 2.1 Bundles** — Standards-compliant threat intelligence packages for TAXII sharing
- **MITRE ATT&CK Mappings** — Every detected threat mapped to the ATT&CK v14 Enterprise matrix
- **CVE References** — Enrichment with known vulnerability identifiers
- **AI Narratives** — LLM-generated executive summaries via Ollama integration

The layer operates as an event-driven pipeline: when campaign clustering detects a coordinated attack, the `SentinelService` orchestrator runs a 9-step process that infers service types, extracts signatures, maps techniques, generates rules, builds STIX bundles, renders playbooks, and persists everything into the `sentinel_playbooks` table.

SOC analysts interact with Sentinel through the **Sentinel Dashboard** (React frontend) backed by 16+ REST API endpoints for listing, filtering, approving, rejecting, batch-processing, comparing, exporting, and regenerating playbooks.

---

## 2. Architecture

### 2.1 Module Map

```
backend/sentinel/
├── __init__.py                # Package root (v3.0.0-sentinel)
├── sentinel_service.py        # Orchestration service (9-step pipeline)
├── models.py                  # ORM models: SentinelPlaybook, SentinelAuditLog
├── mitre_mapper.py            # Signature → ATT&CK technique mapping (12 rules)
├── rule_generator.py          # Snort & Sigma rule generator
├── playbook_generator.py      # Jinja2 playbook renderer
├── stix_enhanced.py           # STIX 2.1 bundle builder
├── cve_mapper.py              # CVE enrichment mapper
├── confidence_scoring.py      # Composite confidence scoring engine
├── quality_scorer.py          # Playbook quality scoring engine
├── llm_service.py             # Ollama LLM narrative generator
├── prompt_templates.py        # Structured prompt templates for LLM
├── audit_logger.py            # Audit trail logger
├── retention_service.py       # Retention policy & auto-purge
├── email_notifier.py          # Email alert dispatcher
├── webhook_notifier.py        # Webhook alert dispatcher
├── pdf_exporter.py            # PDF export renderer
├── metrics.py                 # Prometheus-compatible metrics collector
├── mitre_matrix.py            # ATT&CK matrix aggregation
└── templates/                 # Jinja2 playbook templates
    ├── base_playbook.md.j2
    ├── brute_force.md.j2
    ├── sqli_attempt.md.j2
    ├── port_scan.md.j2
    ├── data_exfiltration.md.j2
    ├── brute_force_response.yaml.j2
    ├── port_scan_response.yaml.j2
    ├── credential_reuse_response.yaml.j2
    ├── distributed_attack_response.yaml.j2
    └── narrative_prompt.md.j2
```

### 2.2 Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                     HONEYPOT EVENT INGESTION                        │
│   SSH (2222) │ HTTP (8080) │ FTP (2121) │ SMTP (2525)               │
└───────┬────────────┬──────────────┬──────────────┬──────────────────┘
        │            │              │              │
        ▼            ▼              ▼              ▼
  ┌──────────────────────────────────────────────────────┐
  │                 PacketLog + Events Tables             │
  │         (raw payloads, source IPs, timestamps)       │
  └────────────────────────┬─────────────────────────────┘
                           │
                           ▼
  ┌────────────────────────────────────────────────────────────────┐
  │              Campaign Clustering (ThreatAnalyzer)              │
  │    Groups events by source_ips, target_ports, time_window     │
  │    Output: {source_ips, target_ports, protocols, event_count} │
  └────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
  ┌────────────────────────────────────────────────────────────────┐
  │            SentinelService.generate_playbook()                 │
  │                    (9-Step Pipeline)                            │
  │                                                                │
  │  Step 1: Port → Service inference (_infer_service)             │
  │  Step 2: Query PacketLog for matching IPs + timestamps         │
  │  Step 2b: Query IOC table for threat intel enrichment          │
  │  Step 2c: Calculate composite confidence score                 │
  │  Step 2d: Calculate quality score                              │
  │  Step 3: Run SignatureEngine on raw event payloads             │
  │  Step 4: Map signatures → MITRE ATT&CK techniques             │
  │  Step 5: Generate Snort + Sigma detection rules                │
  │  Step 5b: CVE mapping enrichment                               │
  │  Step 6: Build enriched STIX 2.1 bundle                        │
  │  Step 7: Render Jinja2 playbook                                │
  │  Step 8: Persist SentinelPlaybook record                       │
  │  Step 8b: Trigger background LLM narrative                     │
  │  Step 8c: Trigger email alert (CRITICAL/HIGH)                  │
  │  Step 8d: Trigger webhook alert (CRITICAL)                     │
  │  Step 9: Store detected_signatures in PacketLog rows           │
  └────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
  ┌────────────────────────────────────────────────────────────────┐
  │                sentinel_playbooks Table                        │
  │    (27+ columns: identity, version, threat, MITRE, rules,     │
  │     content, lifecycle)                                        │
  └────────────────────────┬──────────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
     ┌──────────────┐ ┌─────────┐ ┌──────────────┐
     │  Sentinel    │ │  REST   │ │   Export     │
     │  Dashboard   │ │  API    │ │  (MD/JSON/   │
     │  (React)     │ │  (16+)  │ │  STIX/PDF)   │
     └──────────────┘ └─────────┘ └──────────────┘
```

### 2.3 Component Responsibilities

| Component | File | Responsibility |
|---|---|---|
| **Orchestrator** | `sentinel_service.py` | Wires all sub-modules into the 9-step pipeline; manages session lifecycle, deduplication, and campaign tracking |
| **Models** | `models.py` | Defines `SentinelPlaybook` and `SentinelAuditLog` ORM models with version-chain navigation |
| **MITRE Mapper** | `mitre_mapper.py` | Translates ML signature names to MITRE ATT&CK v14 technique objects (12 mappings) |
| **Rule Generator** | `rule_generator.py` | Produces Snort IDS rules and Sigma YAML rules with persistent SID tracking |
| **Playbook Generator** | `playbook_generator.py` | Renders Markdown and YAML playbooks from Jinja2 templates based on attack pattern |
| **STIX Builder** | `stix_enhanced.py` | Builds STIX 2.1 bundles with ATT&CK + CVE ExternalReferences, indicators, and TLP markings |
| **CVE Mapper** | `cve_mapper.py` | Maps attack types and technique IDs to known CVE references |
| **Confidence Scorer** | `confidence_scoring.py` | Calculates composite confidence (0.0–1.0) from 4 weighted signals |
| **Quality Scorer** | `quality_scorer.py` | Computes playbook quality (0–100) from IOC count, cluster volume, model confidence |
| **LLM Service** | `llm_service.py` | Generates AI narratives via Ollama (Mistral model) with caching and prompt templates |
| **Audit Logger** | `audit_logger.py` | Records analyst and system actions to `sentinel_audit_logs` table |
| **Retention Service** | `retention_service.py` | Auto-purges rejected and superseded playbooks based on configurable retention windows |
| **Email Notifier** | `email_notifier.py` | Dispatches HTML email alerts for CRITICAL/HIGH playbooks via SMTP |
| **Webhook Notifier** | `webhook_notifier.py` | Sends HTTP POST webhook alerts for CRITICAL playbooks with exponential backoff |
| **PDF Exporter** | `pdf_exporter.py` | Renders playbooks as downloadable PDF documents |
| **Metrics** | `metrics.py` | Prometheus-compatible counters and histograms for pipeline observability |

---

## 3. Database Models

### 3.1 SentinelPlaybook

**Table:** `sentinel_playbooks`  
**ORM Class:** `sentinel.models.SentinelPlaybook`  
**Extends:** `database.models.Base` (shared SQLAlchemy declarative base)

The `SentinelPlaybook` model stores one record per detected threat event that passes through the Sentinel pipeline. Each row represents a complete playbook with its associated threat context, detection rules, MITRE mapping, and lifecycle state.

#### Column Groups (27+ Columns)

**1. Core Identity (4 columns)**

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `Integer` | PK, auto-increment, indexed | Auto-increment primary key |
| `playbook_id` | `String(64)` | UNIQUE, NOT NULL, indexed | Human-readable ID, e.g. `PB-20260617-143022-A1B2C3` |
| `created_at` | `DateTime` | NOT NULL, indexed, default=`utcnow()` | UTC row creation timestamp |
| `updated_at` | `DateTime` | NOT NULL, default=`utcnow()`, onupdate=`utcnow()` | Last modification timestamp |

**2. Version Tracking (4 columns)**

| Column | Type | Constraints | Description |
|---|---|---|---|
| `version` | `Integer` | NOT NULL, default=1 | Monotonic revision number (1 = original, 2+ = regenerated) |
| `parent_id` | `Integer` | FK → `sentinel_playbooks.id`, nullable, ON DELETE SET NULL | FK to previous version's row (NULL for v1) |
| `is_latest` | `Boolean` | NOT NULL, default=True, indexed | True only for the most current revision in a lineage |
| `regeneration_reason` | `String(512)` | nullable | Human-readable reason for regeneration |

> **Version Chain Navigation:** The `parent` relationship (self-referential) enables walking the version chain. The `child_versions` backref provides forward traversal. Dashboard queries filter on `is_latest=True` to avoid showing superseded versions.

**3. Threat Context (7 columns)**

| Column | Type | Constraints | Description |
|---|---|---|---|
| `src_ip` | `String(45)` | nullable, indexed | Attacker source IP (IPv4 or IPv6) |
| `dst_port` | `Integer` | nullable, indexed | Destination port used to infer honeypot service type |
| `protocol` | `String(16)` | nullable | Network protocol: `TCP` \| `UDP` \| `ICMP` \| `IP` |
| `attack_type` | `String(128)` | nullable, indexed | ML classification label, e.g. `SSH_AUTH_FAILURE` |
| `threat_score` | `Float` | nullable, default=0.0 | ML threat confidence score in range 0.0–100.0 |
| `confidence_score` | `Float` | nullable | Composite playbook confidence score (0.0–1.0) |
| `severity` | `String(16)` | nullable, indexed | Severity tier: `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` |

> **`quality_score`** (`Float`, nullable): Dynamic quality score (0–100) based on IOC count, cluster volume, model confidence, and multi-source verification. Also duplicated as an `Integer` column with index for badge queries.

**4. MITRE ATT&CK Mapping (4 columns)**

| Column | Type | Constraints | Description |
|---|---|---|---|
| `technique_id` | `String(32)` | nullable, indexed | MITRE technique ID, e.g. `T1110.001` |
| `technique_name` | `String(256)` | nullable | Technique name, e.g. `Brute Force: Password Guessing` |
| `tactic` | `String(128)` | nullable | Tactic name, e.g. `Credential Access` |
| `mitre_url` | `String(512)` | nullable | Official ATT&CK reference URL |

**5. Detection Rules (2 columns)**

| Column | Type | Description |
|---|---|---|
| `snort_rule` | `Text` | Generated Snort IDS rule string (may be multi-line) |
| `sigma_rule` | `Text` | Generated Sigma detection rule in YAML format |

**6. Playbook Content (4 columns)**

| Column | Type | Description |
|---|---|---|
| `playbook_name` | `String(256)` | Short descriptive title, e.g. `SSH Brute Force: Password Guessing Playbook` |
| `playbook_content` | `Text` | Full rendered Jinja2 playbook body (Markdown format) |
| `template_name` | `String(128)` | Jinja2 template filename used, e.g. `brute_force.md.j2` |
| `llm_narrative` | `Text` | AI-generated playbook narrative summary (Markdown format) |

**7. Lifecycle / Workflow (3 columns)**

| Column | Type | Constraints | Description |
|---|---|---|---|
| `status` | `String(32)` | NOT NULL, default=`"pending"`, indexed | Workflow status: `pending` \| `approved` \| `rejected` \| `exported` |
| `reviewed_by` | `String(128)` | nullable | Username of the analyst who reviewed |
| `reviewed_at` | `DateTime` | nullable | UTC timestamp of the review action |

#### Key Methods

| Method | Returns | Description |
|---|---|---|
| `to_dict()` | `Dict[str, Any]` | Serialize all columns to plain dict with ISO-8601 timestamps |
| `get_version_history(db, playbook_id?, parent_chain_id?)` | `List[SentinelPlaybook]` | Walk the parent chain to collect all versions (newest first) |
| `get_latest_version(db, parent_chain_id)` | `SentinelPlaybook \| None` | Find the `is_latest=True` row in a version chain |

---

### 3.2 SentinelAuditLog

**Table:** `sentinel_audit_logs`  
**ORM Class:** `sentinel.models.SentinelAuditLog`

Records analyst and system audit events for compliance tracking and operational forensics.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `Integer` | PK, auto-increment, indexed | Auto-increment primary key |
| `playbook_id` | `String(64)` | nullable, indexed | Associated playbook ID or NULL for system actions |
| `action` | `String(64)` | NOT NULL, indexed | Audit action label (see table below) |
| `user` | `String(128)` | NOT NULL, default=`"system"` | Username or service performing the action |
| `details` | `Text` | nullable | JSON string or free text with action metadata |
| `timestamp` | `DateTime` | NOT NULL, indexed, default=`utcnow()` | UTC timestamp of the audit event |

#### Tracked Actions

| Action Label | Trigger | Description |
|---|---|---|
| `approve` | Analyst action | Single playbook approval |
| `reject` | Analyst action | Single playbook rejection |
| `batch_approve` | Analyst action | Batch approval of multiple playbooks |
| `batch_reject` | Analyst action | Batch rejection of multiple playbooks |
| `export` | Analyst action | Playbook exported (MD, JSON, STIX, PDF) |
| `regenerate` | Analyst action | Playbook regeneration requested |
| `generate` | System | New playbook generated by pipeline |
| `retention_purge` | System | Playbook purged by retention service |
| `archive` | System | Playbook archived |

#### Convenience Method

```python
SentinelAuditLog.log_event(
    db=session,
    action="approve",
    user="analyst_jane",
    playbook_id="PB-20260617-0001",
    details={"reason": "Verified threat indicators"},
    commit=False,  # defer to caller's transaction
)
```

---

### 3.3 Entity-Relationship Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                    sentinel_playbooks                         │
│──────────────────────────────────────────────────────────────│
│ PK  id               INTEGER  AUTO_INCREMENT                │
│     playbook_id       VARCHAR(64)  UNIQUE NOT NULL           │
│     created_at        DATETIME     NOT NULL                  │
│     updated_at        DATETIME     NOT NULL                  │
│ FK  parent_id ──────────────────┐  INTEGER  NULLABLE         │
│     version           INTEGER      NOT NULL  DEFAULT 1       │
│     is_latest         BOOLEAN      NOT NULL  DEFAULT TRUE    │
│     regeneration_reason VARCHAR(512) NULLABLE                │
│     src_ip            VARCHAR(45)  NULLABLE                  │
│     dst_port          INTEGER      NULLABLE                  │
│     protocol          VARCHAR(16)  NULLABLE                  │
│     attack_type       VARCHAR(128) NULLABLE                  │
│     threat_score      FLOAT        NULLABLE                  │
│     confidence_score  FLOAT        NULLABLE                  │
│     quality_score     FLOAT        NULLABLE                  │
│     severity          VARCHAR(16)  NULLABLE                  │
│     technique_id      VARCHAR(32)  NULLABLE                  │
│     technique_name    VARCHAR(256) NULLABLE                  │
│     tactic            VARCHAR(128) NULLABLE                  │
│     mitre_url         VARCHAR(512) NULLABLE                  │
│     snort_rule        TEXT         NULLABLE                  │
│     sigma_rule        TEXT         NULLABLE                  │
│     playbook_name     VARCHAR(256) NULLABLE                  │
│     playbook_content  TEXT         NULLABLE                  │
│     template_name     VARCHAR(128) NULLABLE                  │
│     llm_narrative     TEXT         NULLABLE                  │
│     status            VARCHAR(32)  NOT NULL  DEFAULT pending │
│     reviewed_by       VARCHAR(128) NULLABLE                  │
│     reviewed_at       DATETIME     NULLABLE                  │
└──────────────────────┬───────────────────────────────────────┘
       ▲               │ self-referential FK
       │               │ (version chain)
       └───────────────┘

┌──────────────────────────────────────────────────────────────┐
│                    sentinel_audit_logs                        │
│──────────────────────────────────────────────────────────────│
│ PK  id               INTEGER  AUTO_INCREMENT                │
│     playbook_id       VARCHAR(64)  NULLABLE  (logical FK)   │
│     action            VARCHAR(64)  NOT NULL                  │
│     user              VARCHAR(128) NOT NULL  DEFAULT system  │
│     details           TEXT         NULLABLE                  │
│     timestamp         DATETIME     NOT NULL                  │
└──────────────────────────────────────────────────────────────┘
```

---

## 4. Signature Extraction from Honeypot Payloads

Signature extraction bridges raw honeypot traffic to structured threat intelligence. The pipeline uses a three-layer inference process.

### 4.1 Port-to-Service Inference

The orchestrator maps incoming campaign `target_ports` to known honeypot service types:

| Port(s) | Service |
|---|---|
| 22, 2222 | SSH |
| 80, 443, 8080 | HTTP |
| 21, 2121 | FTP |
| 25, 2525 | SMTP |

```python
# sentinel_service.py
_PORT_SERVICE_MAP: Dict[int, str] = {
    2222: "SSH",  22: "SSH",
    8080: "HTTP", 80: "HTTP", 443: "HTTP",
    2121: "FTP",  21: "FTP",
    2525: "SMTP", 25: "SMTP",
}
```

The first matched port determines the service type. If no port matches, the service defaults to `"UNKNOWN"`.

### 4.2 SignatureEngine Analysis

Once the service type is inferred, `SentinelService._run_signature_analysis()` queries the `events` table for raw payloads matching the campaign's source IPs:

1. Query up to 200 recent events for the campaign's source IPs
2. For each event, construct a log entry dict:
   ```python
   log_entry = {
       "service_type": service_type,    # "SSH", "HTTP", etc.
       "payload": event.raw_data,       # Raw honeypot capture
       "status": "Failed" if SSH else "",
       "payload_size": len(raw_data),
   }
   ```
3. Run `SignatureEngine.check_signatures(log_entry)` which applies pattern-matching rules against the payload content
4. Collect all unique detected signature names into a deduplicated set

The `SignatureEngine` (from `ml/signatures.py`) applies protocol-specific regex patterns and heuristics:
- **SSH:** Failed authentication counts, command injection patterns
- **HTTP:** SQL injection keywords (`UNION`, `SELECT`, `DROP`), XSS payloads (`<script>`, `onerror=`), path traversal (`../`), scanner fingerprints
- **FTP:** Data volume anomalies, suspicious RETR/STOR commands
- **SMTP:** Payload size thresholds, attachment anomalies

### 4.3 Default Fallback Signatures

When no raw event data is available or `SignatureEngine` finds no patterns, the pipeline falls back to a service-based default signature:

| Service | Default Signature |
|---|---|
| SSH | `SSH_AUTH_FAILURE` |
| HTTP | `HTTP_SCANNER_BEHAVIOR` |
| FTP | `FTP_DATA_EXFILTRATION` |
| SMTP | `SMTP_LARGE_PAYLOAD` |

If the service is `UNKNOWN` and no signatures are found, the ultimate fallback maps to technique `T1046` (Network Service Discovery).

---

## 5. MITRE ATT&CK Technique Mapping

### 5.1 Mapping Table (12 Signatures)

All mappings are verified against **ATT&CK v14.1** (Enterprise matrix, October 2023).

| # | Signature Name | Technique ID | Technique Name | Tactic | Severity |
|---|---|---|---|---|---|
| 1 | `SSH_AUTH_FAILURE` | T1110.001 | Brute Force: Password Guessing | Credential Access | HIGH |
| 2 | `SSH_HIGH_ACTIVITY` | T1021.004 | Remote Services: SSH | Lateral Movement | MEDIUM |
| 3 | `HTTP_SQL_INJECTION` | T1190 | Exploit Public-Facing Application | Initial Access | CRITICAL |
| 4 | `HTTP_XSS_ATTEMPT` | T1059.007 | Command & Scripting Interpreter: JavaScript | Execution | HIGH |
| 5 | `HTTP_PATH_TRAVERSAL` | T1083 | File and Directory Discovery | Discovery | HIGH |
| 6 | `HTTP_SCANNER_BEHAVIOR` | T1046 | Network Service Discovery | Discovery | MEDIUM |
| 7 | `FTP_DATA_EXFILTRATION` | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | CRITICAL |
| 8 | `SMTP_LARGE_PAYLOAD` | T1071.003 | Application Layer Protocol: Mail Protocols | Command and Control | HIGH |
| 9 | `DISTRIBUTED_BRUTE_FORCE` | T1110.004 | Brute Force: Credential Stuffing | Credential Access | CRITICAL |
| 10 | `LOW_AND_SLOW_SCAN` | T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | MEDIUM |
| 11 | `MULTI_PROTOCOL_ATTACK` | T1046 | Network Service Discovery | Discovery | HIGH |
| 12 | `HIGH_FREQUENCY_ATTACK` | T1498 | Network Denial of Service | Impact | CRITICAL |

### 5.2 Mapping Rules & Resolution Logic

**Resolution order in `SentinelService.generate_playbook()` (Step 4):**

1. **Primary mapping:** Call `map_signatures(signature_names)` → returns deduplicated list of technique dicts keyed by `technique_id`
2. **First technique selection:** Use `techniques[0]` as the primary technique
3. **Service fallback:** If no technique matched, use the service's default signature to attempt mapping again via `map_signature(default_sig)`
4. **Ultimate fallback:** If still no match, hardcode `T1046 — Network Service Discovery` with `severity=MEDIUM`

**Deduplication:** Multiple signatures may map to the same technique ID (e.g., `HTTP_SCANNER_BEHAVIOR` and `MULTI_PROTOCOL_ATTACK` both map to `T1046`). The `map_signatures()` function deduplicates by `technique_id`, returning only one entry per unique technique.

### 5.3 Technique Object Schema

**Full schema** (returned by `map_signature()`):

```json
{
  "technique_id":   "T1110.001",
  "technique_name": "Brute Force: Password Guessing",
  "tactic":         "Credential Access",
  "tactic_id":      "TA0006",
  "description":    "Adversaries attempt to gain access...",
  "url":            "https://attack.mitre.org/techniques/T1110/001/",
  "severity":       "HIGH",
  "signature":      "SSH_AUTH_FAILURE"
}
```

**Slim schema** (returned by `get_technique()`):

```json
{
  "id":        "T1110.001",
  "name":      "Brute Force: Password Guessing",
  "tactic":    "Credential Access",
  "mitre_url": "https://attack.mitre.org/techniques/T1110/001/"
}
```

---

## 6. Playbook Generation Pipeline

### 6.1 9-Step Orchestration Flow

The `SentinelService.generate_playbook(campaign_data)` method executes the following steps:

| Step | Operation | Module | Output |
|---|---|---|---|
| **1** | Infer service from `target_ports` | `_infer_service()` | Service type string (`SSH`, `HTTP`, etc.) |
| **2** | Query `PacketLog` for matching IPs + timestamps | `_query_packet_logs()` | List of `PacketLog` ORM rows (≤500) |
| **2b** | Query `IOC` table for threat intel enrichment | `_query_iocs()` | List of `IOC` ORM rows |
| **2c** | Calculate composite confidence score | `confidence_scoring.calculate_confidence()` | `ConfidenceResult` (score + severity) |
| **2d** | Calculate quality score | `quality_scorer.calculate_quality_score()` | Float 0–100 |
| **3** | Run `SignatureEngine` on events | `_run_signature_analysis()` | List of detected signature names |
| **4** | Map signatures → MITRE ATT&CK | `mitre_mapper.map_signatures()` | List of technique dicts |
| **5** | Generate Snort + Sigma rules | `rule_generator.generate_rules_for_campaign()` | Rules dict with Snort/Sigma strings |
| **5b** | CVE mapping enrichment | `cve_mapper.get_cve_mappings()` | List of CVE dicts |
| **6** | Build STIX 2.1 bundle | `stix_enhanced.build_stix_bundle()` | `stix2.Bundle` object |
| **7** | Render Jinja2 playbook | `playbook_generator.generate()` | Markdown playbook string |
| **8** | Persist `SentinelPlaybook` row | ORM insert + commit | Database row with `playbook_id` |
| **8b** | Trigger background LLM narrative | `llm_service` (async) | Background thread/task |
| **8c** | Trigger email alert (if severity meets threshold) | `email_notifier` (async) | Background thread |
| **8d** | Trigger webhook alert (if CRITICAL) | `webhook_notifier` (async) | Background thread |
| **9** | Store `detected_signatures` in `PacketLog` rows | `_store_signatures()` | Count of updated rows |

**Campaign Data Input Schema:**

```python
{
    "source_ips":   ["192.168.1.100", "10.0.0.5"],  # Required
    "target_ports": [2222, 8080],                     # Required
    "protocols":    ["TCP"],                          # Optional, default ["TCP"]
    "event_count":  42,                               # Optional, default 0
    "time_range":   {"start": "...", "end": "..."},   # Optional
    "campaign_id":  "CAMP-001",                       # Optional
}
```

**Deduplication:** The `SentinelService` class maintains a `_seen_campaigns` dict. If a `campaign_id` is already processed, the existing playbook is returned without re-running the pipeline.

---

### 6.2 Confidence Scoring Engine

**Module:** `confidence_scoring.py`

Calculates a composite confidence score (0.0–1.0) from four weighted component signals:

#### Component Signals

| Signal | Weight | Description | Range |
|---|---|---|---|
| `cluster_size_score` | 0.35 | Normalised event count — more events = more certain | 0.0–1.0 (cap at 200 events) |
| `ml_avg_score` | 0.35 | Average ML anomaly score across cluster events | 0.0–1.0 (normalised from 0–100) |
| `ioc_density` | 0.20 | Ratio of unique IOC IPs to total events | 0.0–1.0 |
| `multi_proto_bonus` | 0.10 | Bonus when campaign spans multiple protocols | 0.0 or 1.0 |

#### Formula

```
confidence = (0.35 × cluster_size_score) + (0.35 × ml_avg_score) 
           + (0.20 × ioc_density) + (0.10 × multi_proto_bonus)
```

#### Severity Mapping

| Confidence Range | Severity |
|---|---|
| ≥ 0.80 | `CRITICAL` |
| ≥ 0.60 | `HIGH` |
| ≥ 0.40 | `MEDIUM` |
| < 0.40 | `LOW` |

#### Return Type

```python
ConfidenceResult(
    confidence=0.72,
    severity="HIGH",
    cluster_size_score=0.85,
    ml_avg_score=0.65,
    ioc_density=0.40,
    multi_proto_bonus=1.0,
    breakdown={...}  # full component detail
)
```

---

### 6.3 Quality Scoring Engine

**Module:** `quality_scorer.py`

Computes a 0–100 quality score for playbook ranking and badge assignment.

#### Base Score Composition (100 points max)

| Component | Max Points | Calculation |
|---|---|---|
| Model confidence | 40 | `confidence_score × 40` |
| IOC count | 20 | 5 pts per IOC, capped at 4 IOCs |
| Cluster volume | 20 | Proportional to `event_count` (cap 100 events) |
| Multi-source verification | 20 | Full bonus if IOC + ML data both present |

#### Extended Bonuses (applied by `calculate_playbook_quality_score()`)

| Criterion | Bonus |
|---|---|
| Snort rule present | +5 pts |
| Sigma rule present | +5 pts |
| Technique ID mapped | +5 pts |
| LLM narrative generated | +5 pts |
| High threat score (≥ 70) | +5 pts |
| `src_ip` present | +3 pts |
| Severity CRITICAL or HIGH | +2 pts |

#### Quality Badges

| Score Range | Badge |
|---|---|
| ≥ 80 | `High Quality` |
| ≥ 50 | `Standard Quality` |
| < 50 | `Low Quality` |

---

### 6.4 Jinja2 Template Selection

**Module:** `playbook_generator.py`

The `PlaybookGenerator` class configures a Jinja2 `Environment` with `FileSystemLoader` pointing at `sentinel/templates/`.

#### Markdown Templates (Primary)

| Attack Pattern Keywords | Template |
|---|---|
| `brute_force`, `brute-force`, `failed_login`, `ssh_brute` | `brute_force.md.j2` |
| `sqli`, `sql_injection`, `sqli_attempt` | `sqli_attempt.md.j2` |
| `port_scan`, `port-scan`, `scan`, `recon`, `reconnaissance` | `port_scan.md.j2` |
| `data_exfil`, `exfiltration`, `dlp`, `data_theft` | `data_exfiltration.md.j2` |
| *anything else* | `base_playbook.md.j2` |

#### Legacy YAML Templates

| Attack Pattern Keywords | Template |
|---|---|
| `brute_force`, `brute-force`, `failed_login` | `brute_force_response.yaml.j2` |
| `port_scan`, `port-scan`, `scan` | `port_scan_response.yaml.j2` |
| `credential_reuse`, `honeytoken` | `credential_reuse_response.yaml.j2` |
| `distributed_attack`, `distributed` | `distributed_attack_response.yaml.j2` |
| *anything else* | `{pattern}_response.yaml.j2` |

#### Service-to-Pattern Mapping

The orchestrator maps service types to attack patterns for template selection:

```python
{
    "SSH":  "brute_force",
    "HTTP": "port_scan",
    "FTP":  "credential_reuse",
    "SMTP": "distributed_attack",
}
```

#### Template Context Variables

```python
{
    "attack_pattern":  "brute_force",
    "source_ip":       "192.168.1.100",
    "target_ip":       "honeypot-cluster",
    "severity":        "HIGH",
    "generated_at":    "2026-06-17T14:30:22+00:00",
    "campaign_id":     "CAMP-001",
    "event_count":     42,
    "technique_id":    "T1110.001",
    "technique_name":  "Brute Force: Password Guessing",
    "source_ips":      ["192.168.1.100", "10.0.0.5"],
    "target_ports":    [2222],
    "protocols":       ["TCP"],
    "threat_score":    78.5,
    "cve_references":  [...],
    "cve_ids":         ["CVE-2023-34362"],
}
```

---

### 6.5 Detection Rule Generation (Snort & Sigma)

**Module:** `rule_generator.py`

#### Snort Rules

- Generated from ATT&CK technique data, source IPs, destination ports, and protocol
- Persistent SID tracking via `data/last_sid.txt` (starting at SID 1000001)
- IP validation supports IPv4, CIDR notation, and Snort keywords (`any`, `$HOME_NET`)
- Port validation supports integers 0–65535 and keyword `any`

**Example Output:**
```
alert tcp 192.168.1.100 any -> $HOME_NET 2222 (msg:"PhantomNet Sentinel - SSH Brute Force: Password Guessing [T1110.001]"; flow:to_server,established; content:"SSH"; sid:1000042; rev:1; reference:url,attack.mitre.org/techniques/T1110/001/; classtype:attempted-admin; priority:2;)
```

#### Sigma Rules

- Generated as valid YAML with standard fields: `title`, `logsource`, `detection`, `level`, `status`, `tags`
- ATT&CK tactic names mapped to Sigma tag format via `_TACTIC_SIGMA_TAG`:

| Tactic | Sigma Tag |
|---|---|
| Credential Access | `attack.credential_access` |
| Initial Access | `attack.initial_access` |
| Execution | `attack.execution` |
| Discovery | `attack.discovery` |
| Exfiltration | `attack.exfiltration` |
| *(all 14 tactics mapped)* | `attack.<tactic_slug>` |

---

### 6.6 STIX 2.1 Bundle Generation

**Module:** `stix_enhanced.py`

Produces standards-compliant STIX 2.1 bundles containing:

| Object Type | Count | Description |
|---|---|---|
| `identity` | 1 | PhantomNet Sentinel system anchor |
| `attack-pattern` | 1 | MITRE ATT&CK technique with ExternalReferences (including CVEs) |
| `indicator` | 1 per IOC | IP, domain, URL, hash, or email indicators |
| `relationship` | 1 per indicator | `indicates` link: indicator → attack-pattern |
| `marking-definition` | 1 | TLP colour marking |

**TLP Level Assignment:**

| Condition | TLP Level |
|---|---|
| IOC threat_level ∈ {Critical, High} OR threat_score ≥ 70 | `amber` |
| IOC threat_level = Medium OR threat_score ≥ 40 | `green` |
| Otherwise | `green` |

**Supported IOC Types:**

| IOC Type | STIX Pattern |
|---|---|
| `ip` | `[ipv4-addr:value = '...']` |
| `domain` | `[domain-name:value = '...']` |
| `url` | `[url:value = '...']` |
| `md5` | `[file:hashes.MD5 = '...']` |
| `sha256` | `[file:hashes.'SHA-256' = '...']` |
| `email` | `[email-addr:value = '...']` |

---

### 6.7 CVE Mapping & Enrichment

**Module:** `cve_mapper.py`

Maps attack types and MITRE technique IDs to known CVE references. The CVE catalog is maintained as an in-memory lookup table keyed by signature names and technique IDs.

**Public API:**
```python
cve_list = get_cve_mappings(
    attack_type="HTTP_SQL_INJECTION",
    technique_id="T1190"
)
# Returns: [{"cve_id": "CVE-2023-34362", "description": "...", "cvss": "9.8", "url": "..."}, ...]

stix_refs = format_cve_references(cve_list)
# Returns: [{"source_name": "cve", "external_id": "CVE-2023-34362", "url": "...", "description": "..."}, ...]
```

CVE references are embedded in both the STIX 2.1 `AttackPattern` objects and the Jinja2 playbook templates.

---

### 6.8 LLM Narrative Generation

**Module:** `llm_service.py`

Generates AI-enhanced narrative summaries via the Ollama inference engine, running asynchronously to avoid blocking the main pipeline.

**Architecture:**

1. After playbook persistence (Step 8), a background task is dispatched
2. The task creates a fresh `SessionLocal()` to avoid DB lock contention
3. Playbook context is serialised and sent to Ollama's API
4. The response is post-processed (Markdown cleanup) and persisted to `llm_narrative`

**Configuration:**

| Environment Variable | Default | Description |
|---|---|---|
| `SENTINEL_LLM_ENABLED` | `"false"` | Master on/off switch |
| `SENTINEL_LLM_HOST` | `"http://ollama:11434"` | Ollama server URL |
| `SENTINEL_LLM_MODEL` | `"mistral"` | Model name for inference |

**Dispatch Priority:**
1. FastAPI `BackgroundTasks` (preferred, if available)
2. `asyncio` event loop executor (fallback within async context)
3. Daemon thread (fallback for synchronous callers)

**Caching:** Responses are cached with SHA-256 content hashing via Redis (optional) to avoid redundant LLM calls for identical contexts.

---

## 7. Playbook Lifecycle & Workflows

### 7.1 Status State Machine

```
                  ┌───────────────────────────────────┐
                  │          pipeline creates          │
                  ▼                                    │
            ┌──────────┐                               │
            │ PENDING  │◄──── regenerate ──────────────┘
            └────┬─────┘
                 │
        ┌────────┼────────┐
        ▼                 ▼
  ┌──────────┐     ┌──────────┐
  │ APPROVED │     │ REJECTED │
  └────┬─────┘     └──────────┘
       │                 │
       ▼                 │ (purged after
  ┌──────────┐           │  30 days by
  │ EXPORTED │           │  retention
  └──────────┘           │  service)
                         ▼
                    ┌──────────┐
                    │  PURGED  │
                    └──────────┘
```

**Allowed Transitions:**

| From | To | Trigger |
|---|---|---|
| `pending` | `approved` | Analyst approve action |
| `pending` | `rejected` | Analyst reject action |
| `approved` | `exported` | Playbook exported |
| `pending` | `pending` (new version) | Regeneration |
| `rejected` | *(deleted)* | Retention service purge |
| *any non-latest* | *(deleted)* | Retention service purge |

---

### 7.2 Approval & Rejection

**Single Playbook Approval:**

```
PATCH /api/sentinel/playbooks/{id}/approve
Body: { "reviewed_by": "analyst_jane" }
```

- Sets `status = "approved"`, `reviewed_by`, `reviewed_at = utcnow()`
- Creates an audit log entry with `action = "approve"`
- Returns the updated playbook detail

**Single Playbook Rejection:**

```
PATCH /api/sentinel/playbooks/{id}/reject
Body: { "reviewed_by": "analyst_jane" }
```

- Sets `status = "rejected"`, `reviewed_by`, `reviewed_at = utcnow()`
- Creates an audit log entry with `action = "reject"`
- Rejected playbooks are subject to retention policy purge

**Validation:**
- `reviewed_by` is required, must be 1–128 characters, cannot be empty/whitespace
- Only playbooks with `status = "pending"` can be approved or rejected
- Returns HTTP 404 if playbook not found, HTTP 409 if already reviewed

---

### 7.3 Batch Operations

**Batch Approve:**

```
POST /api/sentinel/playbooks/batch/approve
Body: {
    "playbook_ids": [1, 2, 3, 5, 8],
    "reviewed_by": "analyst_jane"
}
```

**Batch Reject:**

```
POST /api/sentinel/playbooks/batch/reject
Body: {
    "playbook_ids": [4, 6, 7],
    "reviewed_by": "analyst_jane"
}
```

**Constraints:**
- Maximum 50 playbook IDs per batch request
- Each playbook must be in `pending` status
- Returns partial results: `{ "updated": [...], "skipped": [...], "not_found": [...] }`
- Each successful operation creates an individual audit log entry
- A single `batch_approve` or `batch_reject` audit log entry is also created for the batch

---

### 7.4 Playbook Regeneration & Version Tracking

When an analyst requests regeneration, a new playbook version is created while preserving the full history:

1. **Mark current version:** Set `is_latest = False` on the current row
2. **Run pipeline:** Execute the full 9-step pipeline with the original campaign data
3. **Create new row:** Insert a new `SentinelPlaybook` with:
   - `version = previous.version + 1`
   - `parent_id = previous.id`
   - `is_latest = True`
   - `regeneration_reason = analyst_provided_reason`
   - `status = "pending"` (reset to pending for re-review)
4. **Audit log:** Record a `regenerate` action

**Version History Query:**
```python
history = SentinelPlaybook.get_version_history(db, playbook_id="PB-20260617-0001")
# Returns: [v3 (latest), v2, v1] — newest first

latest = SentinelPlaybook.get_latest_version(db, parent_chain_id=42)
# Returns: the is_latest=True row in the chain
```

**Dashboard Filtering:** The list endpoint filters on `is_latest=True` by default to avoid showing superseded versions.

---

### 7.5 Rule Export

**Endpoint:** `POST /api/sentinel/playbooks/{id}/export`

**Supported Formats:**

| Format | Content-Type | Description |
|---|---|---|
| `md` | `text/markdown` | Markdown playbook content |
| `json` | `application/json` | Full playbook JSON with all fields |
| `stix` | `application/json` | STIX 2.1 bundle JSON |
| `pdf` | `application/pdf` | Rendered PDF document (streaming blob) |

**Export Workflow:**
1. Validate playbook exists
2. Generate the requested format
3. Create audit log entry with `action = "export"` and format metadata
4. Set `status = "exported"` (if currently `approved`)
5. Return the file as a streaming download with appropriate `Content-Disposition` header

**Snort Rule Export:**
```
GET /api/sentinel/rules/snort
```
Returns all generated Snort rules across all playbooks.

**Sigma Rule Export:**
```
GET /api/sentinel/rules/sigma
```
Returns all generated Sigma rules across all playbooks.

---

### 7.6 Retention Policies

**Module:** `retention_service.py`

The retention service automatically purges old playbooks to prevent unbounded table growth.

#### Policy Configuration

| Policy | Default | Target |
|---|---|---|
| Rejected playbook retention | **30 days** | Playbooks with `status = "rejected"` and `updated_at` older than threshold |
| Superseded version retention | **90 days** | Playbooks with `is_latest = False` and `updated_at` older than threshold |

#### Purge Process

```python
result = purge_expired_playbooks(
    db=session,
    rejected_retention_days=30,
    archived_retention_days=90,
)
# Returns: {"purged_rejected": 12, "purged_old_versions": 5}
```

1. **Identify expired rejected playbooks:** `status == "rejected"` AND `updated_at <= (now - 30 days)`
2. **Identify expired old versions:** `is_latest == False` AND `updated_at <= (now - 90 days)`
3. **For each purged playbook:**
   - Create a `SentinelAuditLog` entry with `action = "retention_purge"` and `user = "retention_service"`
   - Delete the row from `sentinel_playbooks`
4. **Commit** the transaction

> **⚠️ Warning:** Purged playbooks are permanently deleted. Ensure audit logs are preserved for compliance before enabling aggressive retention windows.

---

## 8. REST API Reference

**Router Prefix:** `/api/sentinel`  
**Tags:** `Sentinel`

| # | Method | Endpoint | Description | Auth |
|---|---|---|---|---|
| 1 | `GET` | `/playbooks` | List all playbooks (paginated, filterable) | Optional |
| 1b | `GET` | `/playbooks/compare` | Side-by-side playbook diff | Required |
| 2 | `GET` | `/playbooks/{id}` | Get single playbook detail | Optional |
| 3 | `GET` | `/stats` | Pipeline statistics (counts by status, severity, technique) | Optional |
| 4 | `GET` | `/mitre/mapping` | Full ATT&CK technique mapping table (12 entries) | Optional |
| 5 | `GET` | `/mitre/matrix` | Aggregated ATT&CK heatmap matrix with counts | Optional |
| 6 | `POST` | `/generate` | Trigger manual playbook generation | Optional |
| 7 | `PATCH` | `/playbooks/{id}/approve` | Approve a pending playbook | Optional |
| 8 | `PATCH` | `/playbooks/{id}/reject` | Reject a pending playbook | Optional |
| 9 | `POST` | `/playbooks/batch/approve` | Batch approve (≤50 playbooks) | Optional |
| 10 | `POST` | `/playbooks/batch/reject` | Batch reject (≤50 playbooks) | Optional |
| 11 | `POST` | `/playbooks/{id}/export` | Export as MD/JSON/STIX/PDF | Optional |
| 12 | `GET` | `/rules/snort` | List all generated Snort rules | Optional |
| 13 | `GET` | `/rules/sigma` | List all generated Sigma rules | Optional |
| 14 | `GET` | `/llm/status` | Check Ollama LLM service status | Optional |
| 15 | `POST` | `/playbooks/{id}/regenerate-llm` | Regenerate LLM narrative for a playbook | Optional |

#### List Playbooks Query Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number (1-indexed) |
| `per_page` | int | 20 | Results per page (1–100) |
| `status` | string | — | Filter: `pending` \| `approved` \| `rejected` \| `exported` |
| `attack_type` | string | — | Filter by ML attack classification label |
| `technique` | string | — | Filter by MITRE technique ID or name (fuzzy match) |
| `severity` | string | — | Filter: `critical` \| `high` \| `medium` \| `low` |
| `search` | string | — | Keyword search across playbook_id, name, technique, IP, attack_type |
| `date_from` | string | — | ISO-8601 start date filter |
| `date_to` | string | — | ISO-8601 end date filter |

#### Pydantic Schemas

**`GenerateRequest`** (POST `/generate`):
```json
{
    "source_ips": ["192.168.1.100"],
    "target_ports": [2222],
    "protocols": ["TCP"],
    "event_count": 42,
    "campaign_id": "CAMP-001",
    "time_range": {"start": "2026-06-17T00:00:00Z", "end": "2026-06-17T23:59:59Z"}
}
```

**`ReviewRequest`** (PATCH `/approve` and `/reject`):
```json
{
    "reviewed_by": "analyst_jane"
}
```

**`BatchReviewRequest`** (POST `/batch/approve` and `/batch/reject`):
```json
{
    "playbook_ids": [1, 2, 3, 5, 8],
    "reviewed_by": "analyst_jane"
}
```

---

## 9. Notification System

### 9.1 Email Alerts

**Module:** `email_notifier.py`

Dispatches HTML email notifications when high-severity playbooks are generated.

**Trigger Condition:** Playbook severity meets or exceeds the configured threshold (default: `CRITICAL`).

**Severity Ranking:** `LOW (1) < MEDIUM (2) < HIGH (3) < CRITICAL (4)`

**Email Content:**
- HTML template with playbook title, severity badge, summary, and direct dashboard link
- Sent asynchronously via background thread
- Graceful fallback: if email is disabled or SMTP misconfigured, pipeline continues

**Configuration:**

| Environment Variable | Default | Description |
|---|---|---|
| `SENTINEL_EMAIL_ALERTS_ENABLED` | `false` | Master switch |
| `SENTINEL_EMAIL_SMTP_HOST` | `localhost` | SMTP server hostname |
| `SENTINEL_EMAIL_SMTP_PORT` | `587` | SMTP server port |
| `SENTINEL_EMAIL_SMTP_USER` | — | SMTP auth username |
| `SENTINEL_EMAIL_SMTP_PASSWORD` | — | SMTP auth password |
| `SENTINEL_EMAIL_SMTP_USE_TLS` | `true` | Enable STARTTLS |
| `SENTINEL_EMAIL_FROM_ADDRESS` | — | Sender email address |
| `SENTINEL_EMAIL_RECIPIENTS` | — | Comma-separated recipient list |
| `SENTINEL_EMAIL_SEVERITY_THRESHOLD` | `CRITICAL` | Minimum severity to trigger |
| `SENTINEL_DASHBOARD_BASE_URL` | — | Base URL for dashboard deep links |

### 9.2 Webhook Alerts

**Module:** `webhook_notifier.py`

Sends HTTP POST webhook notifications to configured endpoints for CRITICAL playbooks.

**Trigger Condition:** Playbook severity equals `CRITICAL`.

**Payload:** JSON dictionary containing playbook ID, severity, attack type, technique, source IPs, and STIX bundle reference.

**Retry Logic:** Exponential backoff on HTTP failures.

**Configuration:** Webhook URL is stored in the `SystemConfig` database table under key `webhook_url`.

---

## 10. Observability & Metrics

**Module:** `metrics.py`

The `SentinelMetricsCollector` class provides Prometheus-compatible metrics:

| Metric | Type | Description |
|---|---|---|
| `sentinel_playbooks_total` | Counter | Total number of generated playbooks |
| `sentinel_approved_total` | Counter | Total number of approved playbooks |
| `sentinel_generation_seconds` | Histogram | Duration of playbook generation |

**Histogram Buckets:** 0.5s, 1.0s, 2.5s, 5.0s, 10.0s, 30.0s, 60.0s

**Usage:**
```python
from sentinel.metrics import sentinel_metrics

sentinel_metrics.inc_playbooks_total()
sentinel_metrics.observe_generation(duration_seconds=2.3)
print(sentinel_metrics.to_prometheus())
```

---

## 11. Configuration Reference

### Environment Variables Summary

| Variable | Module | Default | Description |
|---|---|---|---|
| `SENTINEL_LLM_ENABLED` | llm_service | `false` | Enable Ollama LLM narrative generation |
| `SENTINEL_LLM_HOST` | llm_service | `http://ollama:11434` | Ollama server URL |
| `SENTINEL_LLM_MODEL` | llm_service | `mistral` | Ollama model name |
| `SENTINEL_EMAIL_ALERTS_ENABLED` | email_notifier | `false` | Enable email alert dispatch |
| `SENTINEL_EMAIL_SMTP_HOST` | email_notifier | `localhost` | SMTP server hostname |
| `SENTINEL_EMAIL_SMTP_PORT` | email_notifier | `587` | SMTP server port |
| `SENTINEL_EMAIL_SMTP_USER` | email_notifier | — | SMTP auth username |
| `SENTINEL_EMAIL_SMTP_PASSWORD` | email_notifier | — | SMTP auth password |
| `SENTINEL_EMAIL_SMTP_USE_TLS` | email_notifier | `true` | Enable STARTTLS |
| `SENTINEL_EMAIL_FROM_ADDRESS` | email_notifier | — | Sender address |
| `SENTINEL_EMAIL_RECIPIENTS` | email_notifier | — | Recipient list (comma-separated) |
| `SENTINEL_EMAIL_SEVERITY_THRESHOLD` | email_notifier | `CRITICAL` | Minimum severity for email alerts |
| `SENTINEL_DASHBOARD_BASE_URL` | email_notifier | — | Dashboard URL for deep links |
| `ENVIRONMENT` | sentinel_service | — | Set to `test` to clear dedup cache |

### Database Tables

| Table | Model | Description |
|---|---|---|
| `sentinel_playbooks` | `SentinelPlaybook` | Core playbook storage (27+ columns) |
| `sentinel_audit_logs` | `SentinelAuditLog` | Analyst & system audit trail |
| `system_config` | `SystemConfig` | Runtime configuration (webhook_url, etc.) |

---

## 12. Appendices

### A. Playbook ID Format

```
PB-{YYYYMMDD}-{HHMMSS}-{XXXXXX}
```

- `YYYYMMDD` — UTC date
- `HHMMSS` — UTC time
- `XXXXXX` — 6-character uppercase hex string (UUID4-derived)

**Example:** `PB-20260617-143022-A1B2C3`

### B. ATT&CK Framework Version

- **Version:** 14.1
- **Spec Version:** 2.1.0
- **Matrix:** Enterprise
- **Reference:** https://attack.mitre.org/resources/updates/updates-october-2023/

### C. Quality Badge Thresholds

| Score | Badge | Colour |
|---|---|---|
| ≥ 80 | High Quality | Green |
| ≥ 50 | Standard Quality | Yellow |
| < 50 | Low Quality | Red |

### D. File Cross-Reference

| Source File | Purpose | Lines |
|---|---|---|
| `backend/sentinel/sentinel_service.py` | Pipeline orchestrator | ~1,127 |
| `backend/sentinel/models.py` | ORM models | ~582 |
| `backend/sentinel/mitre_mapper.py` | ATT&CK mapping | ~419 |
| `backend/sentinel/rule_generator.py` | Snort & Sigma rules | ~978 |
| `backend/sentinel/playbook_generator.py` | Jinja2 renderer | ~816 |
| `backend/sentinel/stix_enhanced.py` | STIX 2.1 bundles | ~569 |
| `backend/sentinel/cve_mapper.py` | CVE enrichment | ~334 |
| `backend/sentinel/confidence_scoring.py` | Confidence scoring | ~414 |
| `backend/sentinel/quality_scorer.py` | Quality scoring | ~188 |
| `backend/sentinel/llm_service.py` | LLM narratives | ~1,096 |
| `backend/sentinel/audit_logger.py` | Audit logging | ~67 |
| `backend/sentinel/retention_service.py` | Retention purge | ~79 |
| `backend/sentinel/email_notifier.py` | Email alerts | ~585 |
| `backend/sentinel/webhook_notifier.py` | Webhook alerts | ~202 |
| `backend/sentinel/pdf_exporter.py` | PDF export | ~51,785 bytes |
| `backend/sentinel/metrics.py` | Prometheus metrics | ~83 |
| `backend/api/sentinel.py` | REST API endpoints | ~2,177 |

---

*This document is maintained by the PhantomNet Security Development team. For questions or updates, reference Issue #1063.*
