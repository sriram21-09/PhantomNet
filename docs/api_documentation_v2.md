# PhantomNet Sentinel REST API Reference Documentation (v2)

**Version:** 3.0 (Month 6 - Production Delivery)  
**Base URL:** `http://localhost:8000` (or `https://api.phantomnet.internal`)  
**Specification Version:** OpenAPI 3.1.0 / TAXII 2.1 / STIX 2.1  
**Authentication:** HTTP Bearer JWT Token (`Authorization: Bearer <token>`) or Basic Auth (TAXII)  

---

## 1. Overview & Architecture

The **PhantomNet Sentinel REST API** provides automated incident response, active defense orchestration, MITRE ATT&CK technique mapping, rule generation (Snort & Sigma), compliance audit trails, and standards-compliant threat intelligence sharing via TAXII 2.1.

### API Architecture Highlights
- **High Performance:** Built on FastAPI with asynchronous request processing and connection pooling.
- **Role-Based Access Control (RBAC):** Admin, Analyst, and Read-Only roles for SOC workflows.
- **Multi-Format Export Engine:** High-fidelity PDF (xhtml2pdf / ReportLab), Markdown, JSON, and STIX 2.1 bundles.
- **Enterprise Rate Limiting:** Global and endpoint-specific token bucket throttling.
- **TAXII 2.1 Interoperability:** Content negotiation compliant with OASIS TAXII 2.1 and STIX 2.1 specifications.

---

## 2. Authentication & Common Headers

### Standard REST Endpoints
All `/api/sentinel/*` endpoints require standard HTTP headers:

| Header | Type | Description | Required |
| :--- | :--- | :--- | :--- |
| `Authorization` | `string` | `Bearer <JWT_ACCESS_TOKEN>` obtained from `/api/admin/login` | Yes (for protected endpoints) |
| `Content-Type` | `string` | `application/json` (or `application/pdf` / `application/zip` for file downloads) | Yes |
| `Accept` | `string` | `application/json` | No |

### TAXII 2.1 Endpoints
TAXII endpoints require strict media type content negotiation per TAXII 2.1 §1.6.4:

| Header | Type | Allowed Values |
| :--- | :--- | :--- |
| `Accept` | `string` | `application/taxii+json;version=2.1`, `application/vnd.oasis.taxii+json`, `*/*` |
| `Content-Type` | `string` | `application/taxii+json;version=2.1` |
| `Authorization` | `string` | Basic Auth (`Basic base64(username:password)`) or Bearer token |

---

## 3. Playbook Lifecycle & Management Endpoints

---

### 3.1 List Playbooks
`GET /api/sentinel/playbooks`

Retrieve a paginated list of Sentinel playbooks with extensive multi-criteria filtering.

#### Query Parameters
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `page` | `integer` | `1` | Page number (1-indexed, $\ge 1$). |
| `per_page` | `integer` | `20` | Results per page (1–100). |
| `status` | `string` | `null` | Filter by workflow status: `pending`, `approved`, `rejected`, `exported`. |
| `attack_type` | `string` | `null` | Filter by classified attack type (e.g. `SSH Brute Force`, `SQL Injection`). |
| `technique` | `string` | `null` | Filter by MITRE ATT&CK technique ID or name (e.g. `T1110.001`, `Brute Force`). |
| `severity` | `string` | `null` | Filter by severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. |
| `search` | `string` | `null` | Full-text search across playbook ID, name, attacker IP, technique, and attack type. |
| `date_from` | `string` | `null` | Filter creation date start (ISO-8601, e.g. `2026-08-01T00:00:00Z`). |
| `date_to` | `string` | `null` | Filter creation date end (ISO-8601, e.g. `2026-08-31T23:59:59Z`). |

#### Response (`200 OK`)
```json
{
  "status": "success",
  "total": 42,
  "page": 1,
  "per_page": 20,
  "playbooks": [
    {
      "id": 101,
      "playbook_id": "PB-SSH-20260831-001",
      "src_ip": "192.168.1.150",
      "dst_port": 22,
      "protocol": "TCP",
      "attack_type": "SSH Brute Force",
      "threat_score": 88.5,
      "quality_score": 92.0,
      "quality_badge": "High Quality",
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "tactic": "Credential Access",
      "playbook_name": "Incident Response: SSH Brute Force from 192.168.1.150",
      "status": "pending",
      "created_at": "2026-08-31T14:22:10.123456",
      "updated_at": "2026-08-31T14:22:10.123456",
      "version": 1,
      "parent_id": null,
      "is_latest": true
    }
  ]
}
```

#### Code Examples

##### cURL
```bash
curl -X GET "http://localhost:8000/api/sentinel/playbooks?page=1&per_page=10&status=pending&severity=HIGH" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Accept: application/json"
```

##### Python
```python
import requests

url = "http://localhost:8000/api/sentinel/playbooks"
headers = {
    "Authorization": "Bearer <TOKEN>",
    "Accept": "application/json"
}
params = {
    "page": 1,
    "per_page": 10,
    "status": "pending",
    "severity": "HIGH",
    "search": "SSH"
}

response = requests.get(url, headers=headers, params=params)
data = response.json()
print(f"Total playbooks: {data['total']}")
```

---

### 3.2 Get Playbook Details
`GET /api/sentinel/playbooks/{playbook_id}`

Retrieve the complete playbook record by database primary key ID, including markdown response steps, Snort rules, Sigma rules, CVE mappings, and LLM narrative.

#### Path Parameters
| Parameter | Type | Description |
| :--- | :--- | :--- |
| `playbook_id` | `integer` | Primary key database ID of the playbook ($\ge 1$). |

#### Response (`200 OK`)
```json
{
  "status": "success",
  "playbook": {
    "id": 101,
    "playbook_id": "PB-SSH-20260831-001",
    "src_ip": "192.168.1.150",
    "dst_port": 22,
    "protocol": "TCP",
    "attack_type": "SSH Brute Force",
    "threat_score": 88.5,
    "quality_score": 92.0,
    "quality_badge": "High Quality",
    "technique_id": "T1110.001",
    "technique_name": "Brute Force: Password Guessing",
    "tactic": "Credential Access",
    "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
    "playbook_name": "Incident Response: SSH Brute Force from 192.168.1.150",
    "status": "pending",
    "created_at": "2026-08-31T14:22:10.123456",
    "updated_at": "2026-08-31T14:22:10.123456",
    "version": 1,
    "parent_id": null,
    "is_latest": true,
    "snort_rule": "alert tcp 192.168.1.150 any -> $HOME_NET 22 (msg:\"PHANTOMNET Sentinel: SSH Brute Force [T1110.001]\"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:3000101; rev:1;)",
    "sigma_rule": "title: Automated Incident Response - SSH Brute Force\nid: 9a2f7c41-8e3b-419b-a342-d6b9c9f00101\nstatus: production\ndescription: Detects repetitive unauthorized SSH authentication attempts.\nauthor: PhantomNet Sentinel AutoGen\nlogsource:\n  category: authentication\n  product: linux\ndetection:\n  selection:\n    src_ip: '192.168.1.150'\n    dst_port: 22\n  condition: selection | count() > 5\nlevel: high",
    "playbook_content": "# INCIDENT RESPONSE PLAYBOOK: SSH Brute Force\n\n## 1. Executive Summary\nThreat score: 88.5/100. Rapid credential guessing targeting Port 22.\n\n## 2. Containment Steps\n- Block IP `192.168.1.150` at perimeter firewall.\n- Enforce fail2ban jail for Port 22.\n\n## 3. Eradication & Recovery\n- Rotate SSH keys and disable password authentication.\n",
    "template_name": "brute_force",
    "llm_narrative": "A high-velocity credential stuffing assault was detected originating from 192.168.1.150 against the Cowrie SSH honeypot. Automated analysis identified 142 distinct authentication attempts over a 90-second window.",
    "reviewed_by": null,
    "reviewed_at": null,
    "regeneration_reason": null
  }
}
```

#### Code Examples

##### cURL
```bash
curl -X GET "http://localhost:8000/api/sentinel/playbooks/101" \
  -H "Authorization: Bearer <TOKEN>"
```

##### Python
```python
import requests

res = requests.get(
    "http://localhost:8000/api/sentinel/playbooks/101",
    headers={"Authorization": "Bearer <TOKEN>"}
)
playbook = res.json()["playbook"]
print("Playbook Content:\n", playbook["playbook_content"])
```

---

### 3.3 Compare Playbooks Side-by-Side
`GET /api/sentinel/playbooks/compare`

Performs deep structural and metric comparison between two playbooks, returning IOC differentials, rule parity, and CVE delta analysis.

#### Query Parameters
| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `id1` | `integer` | **Yes** | Primary key database ID of the first playbook. |
| `id2` | `integer` | **Yes** | Primary key database ID of the second playbook. |

#### Response (`200 OK`)
```json
{
  "status": "success",
  "comparison": {
    "playbook_1": {
      "id": 101,
      "playbook_id": "PB-SSH-20260831-001",
      "attack_type": "SSH Brute Force",
      "technique_id": "T1110.001",
      "severity": "HIGH",
      "confidence_score": 0.92
    },
    "playbook_2": {
      "id": 102,
      "playbook_id": "PB-SSH-20260831-002",
      "attack_type": "SSH Brute Force",
      "technique_id": "T1110.001",
      "severity": "CRITICAL",
      "confidence_score": 0.96
    },
    "cve_1": ["CVE-2023-48795", "CVE-2024-6387"],
    "cve_2": ["CVE-2023-48795", "CVE-2024-6387"],
    "diff_summary": {
      "attack_type_match": true,
      "technique_match": true,
      "severity_match": false,
      "confidence_diff": 0.04,
      "snort_rules_identical": false,
      "sigma_rules_identical": false,
      "ioc_count_1": 1,
      "ioc_count_2": 2,
      "ioc_count_diff": 1
    }
  }
}
```

#### Code Examples

##### cURL
```bash
curl -X GET "http://localhost:8000/api/sentinel/playbooks/compare?id1=101&id2=102" \
  -H "Authorization: Bearer <TOKEN>"
```

##### Python
```python
import requests

url = "http://localhost:8000/api/sentinel/playbooks/compare"
params = {"id1": 101, "id2": 102}
headers = {"Authorization": "Bearer <TOKEN>"}

res = requests.get(url, params=params, headers=headers).json()
print("Diff Summary:", res["comparison"]["diff_summary"])
```

---

### 3.4 Trigger Manual Playbook Generation
`POST /api/sentinel/generate`

Triggers immediate execution of the end-to-end Sentinel pipeline against raw campaign telemetry.

#### Request Body Schema
```json
{
  "source_ips": ["192.168.1.150"],
  "target_ports": [22],
  "protocols": ["TCP"],
  "event_count": 142,
  "campaign_id": "CMP-SSH-2026-001",
  "time_range": {
    "start": "2026-08-31T14:00:00Z",
    "end": "2026-08-31T14:30:00Z"
  }
}
```

#### Response (`200 OK`)
```json
{
  "status": "success",
  "playbook_id": "PB-SSH-20260831-001",
  "db_record_id": 101,
  "service_type": "cowrie-ssh",
  "attack_type": "SSH Brute Force",
  "technique_id": "T1110.001",
  "technique_name": "Brute Force: Password Guessing",
  "threat_score": 88.5,
  "matched_logs_count": 142,
  "detected_signatures": ["SSH_AUTH_FAILURE", "REPETITIVE_CREDENTIAL_GUESSING"],
  "message": "Playbook PB-SSH-20260831-001 generated successfully"
}
```

#### Code Examples

##### cURL
```bash
curl -X POST "http://localhost:8000/api/sentinel/generate" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ips": ["192.168.1.150"],
    "target_ports": [22],
    "protocols": ["TCP"],
    "event_count": 142,
    "campaign_id": "CMP-SSH-2026-001"
  }'
```

##### Python
```python
import requests

payload = {
    "source_ips": ["192.168.1.150"],
    "target_ports": [22],
    "protocols": ["TCP"],
    "event_count": 142,
    "campaign_id": "CMP-SSH-2026-001"
}
res = requests.post(
    "http://localhost:8000/api/sentinel/generate",
    json=payload,
    headers={"Authorization": "Bearer <TOKEN>"}
)
print("Generated Record ID:", res.json()["db_record_id"])
```

---

### 3.5 Single Playbook Review (Approve / Reject)
`PATCH /api/sentinel/playbooks/{playbook_id}/approve`  
`PATCH /api/sentinel/playbooks/{playbook_id}/reject`

Approves or rejects a playbook and logs an immutable audit entry with analyst attribution.

#### Path Parameters
| Parameter | Type | Description |
| :--- | :--- | :--- |
| `playbook_id` | `integer` | Primary key database ID. |

#### Request Body Schema
```json
{
  "reviewed_by": "analyst_sarah"
}
```

#### Response (`200 OK`)
```json
{
  "status": "success",
  "message": "Playbook PB-SSH-20260831-001 approved by analyst_sarah",
  "playbook": {
    "id": 101,
    "playbook_id": "PB-SSH-20260831-001",
    "status": "approved",
    "reviewed_by": "analyst_sarah",
    "reviewed_at": "2026-08-31T15:00:00.000000"
  }
}
```

#### Code Examples

##### cURL
```bash
curl -X PATCH "http://localhost:8000/api/sentinel/playbooks/101/approve" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"reviewed_by": "analyst_sarah"}'
```

##### Python
```python
import requests

res = requests.patch(
    "http://localhost:8000/api/sentinel/playbooks/101/approve",
    json={"reviewed_by": "analyst_sarah"},
    headers={"Authorization": "Bearer <TOKEN>"}
)
print(res.json()["message"])
```

---

### 3.6 Batch Operations (Approve / Reject)
`POST /api/sentinel/playbooks/batch/approve`  
`POST /api/sentinel/playbooks/batch/reject`

Execute batch approval or rejection across up to 50 playbooks in an atomic transaction.

#### Request Body Schema
```json
{
  "playbook_ids": [101, 102, 103],
  "reviewed_by": "lead_analyst_mark"
}
```

#### Response (`200 OK`)
```json
{
  "status": "success",
  "message": "Processed 3 playbooks. 3 successful, 0 failed.",
  "results": {
    "successful": [101, 102, 103],
    "failed": []
  }
}
```

#### Code Examples

##### cURL
```bash
curl -X POST "http://localhost:8000/api/sentinel/playbooks/batch/approve" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "playbook_ids": [101, 102, 103],
    "reviewed_by": "lead_analyst_mark"
  }'
```

##### Python
```python
import requests

payload = {
    "playbook_ids": [101, 102, 103],
    "reviewed_by": "lead_analyst_mark"
}
res = requests.post(
    "http://localhost:8000/api/sentinel/playbooks/batch/approve",
    json=payload,
    headers={"Authorization": "Bearer <TOKEN>"}
)
print(res.json()["results"])
```

---

### 3.7 Playbook Regeneration & Version Lineage
`POST /api/sentinel/playbooks/{playbook_id}/regenerate`  
`GET /api/sentinel/playbooks/{playbook_id}/versions`

Regenerates a playbook with refreshed threat telemetry and preserves complete audit lineage.

#### Request Body (`POST .../regenerate`)
```json
{
  "reason": "Threat score updated with new honeypot signatures"
}
```

#### Response (`200 OK`)
```json
{
  "status": "success",
  "message": "Playbook regenerated successfully. New version: v2 (playbook_id=PB-SSH-20260831-001-v2)",
  "new_playbook": {
    "id": 104,
    "playbook_id": "PB-SSH-20260831-001-v2",
    "version": 2,
    "parent_id": 101,
    "is_latest": true,
    "status": "pending"
  },
  "old_playbook_id": 101,
  "new_version": 2,
  "parent_id": 101
}
```

---

## 4. Export & Multi-Format Endpoints

---

### 4.1 Export Playbook File
`POST /api/sentinel/playbooks/{playbook_id}/export`

Export a playbook as Markdown, JSON, STIX 2.1 Bundle, or PDF.

#### Query Parameters
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `format` | `string` | `markdown` | Options: `markdown`, `pdf`, `json`, `stix`. |

#### Response Headers
- `Content-Type`: `application/pdf`, `text/markdown`, `application/json`, or `application/octet-stream`
- `Content-Disposition`: `attachment; filename="PB-SSH-20260831-001.pdf"`
- `X-Playbook-Id`: `PB-SSH-20260831-001`
- `X-Export-Format`: `pdf`

#### Code Examples

##### cURL (Download PDF)
```bash
curl -X POST "http://localhost:8000/api/sentinel/playbooks/101/export?format=pdf" \
  -H "Authorization: Bearer <TOKEN>" \
  -o "PB-SSH-20260831-001.pdf"
```

##### Python (Download STIX 2.1 JSON)
```python
import requests

url = "http://localhost:8000/api/sentinel/playbooks/101/export"
params = {"format": "stix"}
headers = {"Authorization": "Bearer <TOKEN>"}

res = requests.post(url, params=params, headers=headers)
with open("threat_bundle.json", "wb") as f:
    f.write(res.content)
print("Downloaded STIX bundle.")
```

---

### 4.2 Stream Dedicated Branded PDF
`POST /api/sentinel/playbooks/{playbook_id}/export/pdf`

Dedicated streaming PDF endpoint with three-tier fallback architecture (`xhtml2pdf` $\rightarrow$ `ReportLab` $\rightarrow$ `Placeholder`). Guarantees zero 500 error responses during rendering.

#### Response Headers
- `Content-Type`: `application/pdf`
- `Content-Disposition`: `attachment; filename="PB-SSH-20260831-001.pdf"`
- `X-PDF-Generator`: `xhtml2pdf-or-reportlab`

---

### 4.3 Export All Rules (ZIP Archive)
`GET /api/sentinel/rules/export-all`

Packs all approved Snort (`.rules`) and Sigma (`.yml`) rules into a single sanitized, zip-slip protected ZIP bundle.

#### Code Examples

##### cURL
```bash
curl -X GET "http://localhost:8000/api/sentinel/rules/export-all" \
  -H "Authorization: Bearer <TOKEN>" \
  -o "phantomnet_rules_export.zip"
```

##### Python
```python
import requests

res = requests.get(
    "http://localhost:8000/api/sentinel/rules/export-all",
    headers={"Authorization": "Bearer <TOKEN>"}
)
with open("rules_bundle.zip", "wb") as f:
    f.write(res.content)
```

---

## 5. Detection Rules & ATT&CK Intelligence

---

### 5.1 Snort Rules Catalog
`GET /api/sentinel/rules/snort`

#### Query Parameters
- `limit` (`integer`, default `50`, $\le 200$)
- `offset` (`integer`, default `0`)
- `attack_type` (`string`, optional)

#### Response (`200 OK`)
```json
{
  "status": "success",
  "total": 35,
  "limit": 50,
  "offset": 0,
  "rules": [
    {
      "id": 101,
      "playbook_id": "PB-SSH-20260831-001",
      "attack_type": "SSH Brute Force",
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "src_ip": "192.168.1.150",
      "dst_port": 22,
      "threat_score": 88.5,
      "snort_rule": "alert tcp 192.168.1.150 any -> $HOME_NET 22 (msg:\"PHANTOMNET Sentinel: SSH Brute Force [T1110.001]\"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:3000101; rev:1;)",
      "created_at": "2026-08-31T14:22:10.123456"
    }
  ]
}
```

---

### 5.2 Sigma Rules Catalog
`GET /api/sentinel/rules/sigma`

#### Response (`200 OK`)
```json
{
  "status": "success",
  "total": 35,
  "limit": 50,
  "offset": 0,
  "rules": [
    {
      "id": 101,
      "playbook_id": "PB-SSH-20260831-001",
      "attack_type": "SSH Brute Force",
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "src_ip": "192.168.1.150",
      "dst_port": 22,
      "threat_score": 88.5,
      "sigma_rule": "title: Automated Incident Response - SSH Brute Force\nid: 9a2f7c41-8e3b-419b-a342-d6b9c9f00101\nstatus: production\nlevel: high",
      "created_at": "2026-08-31T14:22:10.123456"
    }
  ]
}
```

---

### 5.3 MITRE ATT&CK Matrix & Heatmap
`GET /api/sentinel/mitre/matrix`

Returns aggregated ATT&CK technique hit counts across the static catalogue for frontend heatmap rendering.

#### Response (`200 OK`)
```json
{
  "status": "success",
  "generated_at": "2026-09-01T12:00:00Z",
  "total_tactics": 12,
  "total_techniques": 48,
  "matrix": {
    "Credential Access": [
      {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic_id": "TA0006",
        "severity": "HIGH",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "description": "Adversaries may attempt to guess passwords...",
        "count": 14
      }
    ]
  },
  "frequency_map": {
    "T1110": 14,
    "T1046": 9,
    "T1190": 6
  }
}
```

---

### 5.4 Campaign Progression & Spike Timeline
`GET /api/sentinel/campaigns/{campaign_id}/timeline`

Time-series density breakdown for campaign activity, surge detection, and anomaly identification.

#### Query Parameters
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `interval` | `string` | `hourly` | Aggregation interval: `hourly` or `daily`. |

#### Response (`200 OK`)
```json
{
  "status": "success",
  "campaign_id": "CMP-SSH-2026-001",
  "interval": "hourly",
  "total_events": 1420,
  "peak_density": 135,
  "spike_count": 3,
  "anomaly_count": 5,
  "timeline": [
    {
      "timestamp": "2026-08-31 12:00:00",
      "count": 135,
      "density": 135,
      "is_spike": true,
      "is_anomaly": true,
      "anomaly_type": "Attack Density Surge Peak",
      "threat_level": "critical"
    }
  ]
}
```

---

## 6. Audit Logging & Compliance Endpoints

---

### 6.1 Sentinel Audit Trail
`GET /api/sentinel/audit-logs`  
`GET /api/v1/sentinel/audit-logs`

Query immutable activity logs for compliance tracking and audit readiness.

#### Query Parameters
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `limit` | `integer` | `50` | Maximum records (1–500). |
| `offset` | `integer` | `0` | Offset pagination index. |
| `action` | `string` | `null` | Action type: `generate`, `approve`, `reject`, `batch_approve`, `batch_reject`, `export`, `regenerate`. |
| `user` | `string` | `null` | Filter by user / service identifier. |
| `playbook_id` | `string` | `null` | Filter by playbook string ID or database ID. |

#### Response (`200 OK`)
```json
{
  "status": "success",
  "total": 128,
  "limit": 50,
  "offset": 0,
  "logs": [
    {
      "id": 501,
      "action": "approve",
      "user": "analyst_sarah",
      "playbook_id": "PB-SSH-20260831-001",
      "details": {
        "previous_status": "pending",
        "new_status": "approved"
      },
      "timestamp": "2026-08-31T15:00:00.123456"
    }
  ]
}
```

---

## 7. TAXII 2.1 Threat Sharing Endpoints

---

### 7.1 Server Discovery
`GET /taxii2/` (and `/taxii2`)

Returns the TAXII 2.1 Server Discovery object listing available API Roots.

#### Required Headers
- `Accept`: `application/taxii+json;version=2.1`

#### Response (`200 OK`, `Content-Type: application/taxii+json;version=2.1`)
```json
{
  "title": "PhantomNet TAXII 2.1 Server",
  "description": "PhantomNet Automated Honeypot Threat Intelligence Feed",
  "contact": "soc@phantomnet.internal",
  "default": "/taxii2/phantomnet/",
  "api_roots": [
    "/taxii2/phantomnet/"
  ]
}
```

---

### 7.2 API Root Information
`GET /taxii2/phantomnet/`

Returns capabilities and maximum content size for the `phantomnet` API root.

#### Response (`200 OK`, `Content-Type: application/taxii+json;version=2.1`)
```json
{
  "title": "PhantomNet Primary Threat Intel API Root",
  "description": "High-confidence honeypot indicators and automated incident response STIX objects.",
  "versions": ["application/taxii+json;version=2.1"],
  "max_content_length": 10485760
}
```

---

### 7.3 List Collections
`GET /taxii2/phantomnet/collections/`

Lists all STIX collections available under this API root.

#### Response (`200 OK`, `Content-Type: application/taxii+json;version=2.1`)
```json
{
  "collections": [
    {
      "id": "all-threats",
      "title": "All Threats Feed",
      "description": "All threat intelligence gathered across all honeypots.",
      "alias": "all",
      "can_read": true,
      "can_write": false,
      "media_types": [
        "application/stix+json;version=2.1"
      ]
    },
    {
      "id": "honeypot-cowrie-ssh",
      "title": "Cowrie SSH Honeypot Collection",
      "description": "Threat intelligence gathered from honeypot service running on port 22.",
      "alias": "cowrie-ssh",
      "can_read": true,
      "can_write": false,
      "media_types": [
        "application/stix+json;version=2.1"
      ]
    }
  ]
}
```

---

### 7.4 Get Collection STIX Objects
`GET /taxii2/phantomnet/collections/{collection_id}/objects/`

Retrieves a STIX 2.1 envelope containing indicator, attack-pattern, observed-data, and malware STIX objects.

#### Query Parameters
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `added_after` | `string` | `null` | RFC 3339 / ISO 8601 timestamp. Returns objects created strictly after this timestamp. |
| `limit` | `integer` | `100` | Max objects returned per page ($\le 1000$). |
| `next` | `integer` | `null` | Pagination offset token. |

#### Response (`200 OK`, `Content-Type: application/taxii+json;version=2.1`)
```json
{
  "more": false,
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--9f2c7a10-2b44-482a-89a1-8d234c9f1101",
      "created": "2026-08-31T14:22:10.000Z",
      "modified": "2026-08-31T14:22:10.000Z",
      "name": "Malicious Attacker IP 192.168.1.150",
      "description": "Identified in SSH Brute Force campaign against Cowrie SSH honeypot",
      "indicator_types": ["malicious-activity"],
      "pattern": "[ipv4-addr:value = '192.168.1.150']",
      "pattern_type": "stix",
      "valid_from": "2026-08-31T14:22:10.000Z",
      "confidence": 88
    },
    {
      "type": "attack-pattern",
      "spec_version": "2.1",
      "id": "attack-pattern--4a3d8b12-9c10-4122-83ef-d2188fa90012",
      "created": "2026-08-31T14:22:10.000Z",
      "modified": "2026-08-31T14:22:10.000Z",
      "name": "Brute Force: Password Guessing",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1110.001",
          "url": "https://attack.mitre.org/techniques/T1110/001/"
        }
      ]
    }
  ]
}
```

#### Code Examples

##### cURL (TAXII 2.1 Fetch Objects)
```bash
curl -X GET "http://localhost:8000/taxii2/phantomnet/collections/all-threats/objects/?limit=10" \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer <TOKEN>"
```

##### Python (`taxii2-client` / `requests`)
```python
import requests

url = "http://localhost:8000/taxii2/phantomnet/collections/all-threats/objects/"
headers = {
    "Accept": "application/taxii+json;version=2.1",
    "Authorization": "Bearer <TOKEN>"
}
params = {
    "limit": 50,
    "added_after": "2026-08-01T00:00:00Z"
}

response = requests.get(url, headers=headers, params=params)
bundle = response.json()
print(f"Retrieved {len(bundle.get('objects', []))} STIX objects.")
```

---

## 8. HTTP Status Codes & Error Handling

The API adheres to standard RFC HTTP status codes. Errors return a unified structured error schema:

```json
{
  "detail": "Descriptive human-readable error explanation",
  "error_code": "ERR_RESOURCE_NOT_FOUND",
  "timestamp": "2026-09-01T12:00:00Z"
}
```

### Status Code Reference Table
| HTTP Code | Name | Description |
| :--- | :--- | :--- |
| `200` | OK | Request succeeded. Returns data payload. |
| `201` | Created | Resource successfully created. |
| `400` | Bad Request | Malformed payload, invalid query parameter, or unsupported format. |
| `401` | Unauthorized | Missing or expired JWT / TAXII authentication token. |
| `403` | Forbidden | Insufficient user role permissions (e.g. Analyst approval requires Admin/Analyst role). |
| `404` | Not Found | Requested playbook, campaign, or collection ID does not exist. |
| `406` | Not Acceptable | Invalid `Accept` header on TAXII endpoints. |
| `409` | Conflict | State transition violation (e.g. attempting to approve an already approved playbook). |
| `415` | Unsupported Media Type | Invalid `Content-Type` header on TAXII endpoints. |
| `422` | Unprocessable Entity | Pydantic validation error in request body or query parameter types. |
| `429` | Too Many Requests | Rate limit threshold exceeded. |
| `500` | Internal Server Error | Unhandled server or database error. |
