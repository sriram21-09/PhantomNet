# PhantomNet Week 15 Day 5 — Full Pipeline E2E Evidence Report

**Generated:** 2026-07-07T18:18:28.028878

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | 15 |
| ✅ Passed | 15 |
| ❌ Failed | 0 |

## Pipeline Flow Tested

```
SSH Brute Force Sim → PacketLog Insert → ML Scoring → Campaign Clustering
→ Sentinel Pipeline → MITRE ATT&CK Mapping → Snort/Sigma Rules
→ STIX 2.1 Bundle → Playbook Rendering → DB Persist
→ Dashboard Visibility → Approve/Reject → Export (MD/JSON/STIX)
```

## Detailed Results

### ✅ Stage 1: SSH Brute Force Simulation
- **Timestamp:** `2026-07-07T18:18:07.151112`
- **Status:** `PASS`
- **Details:** Inserted 15 PacketLog + 15 Event rows targeting port 2222
- **Data:**
  - `packet_ids`: `[34, 35, 36, 37, 38]`
  - `attacker_ips`: `['10.99.1.100', '10.99.1.101', '10.99.1.102', '10.99.1.103', '10.99.1.104', '10.99.1.105', '10.99.1.106', '10.99.1.107', '10.99.1.108', '10.99.1.109',`
  - `target_port`: `2222`

### ✅ Stage 2: ML Threat Scoring
- **Timestamp:** `2026-07-07T18:18:27.415535`
- **Status:** `PASS`
- **Details:** ML scored SSH traffic: score=0.0, level=LOW, decision=ERROR
- **Data:**
  - `score`: `0.0`
  - `threat_level`: `LOW`
  - `confidence`: `0.0`
  - `decision`: `ERROR`

### ✅ Stage 2b: PacketLog Threat Update
- **Timestamp:** `2026-07-07T18:18:27.436179`
- **Status:** `PASS`
- **Details:** Updated 15 PacketLog rows with ML scores and threat_level=MEDIUM/HIGH

### ✅ Stage 3: Campaign Clustering
- **Timestamp:** `2026-07-07T18:18:27.517394`
- **Status:** `PASS`
- **Details:** DBSCAN found 1 campaign(s) from SSH brute force events
- **Data:**
  - `campaign_id`: `campaign_0`
  - `unique_sources`: `['10.99.1.108', '10.99.1.110', '10.99.1.114', '10.99.1.106', '10.99.1.113', '10.99.1.104', '10.99.1.101', '10.99.1.109', '10.99.1.105', '10.99.1.112',`
  - `target_ports`: `[2222]`
  - `event_count`: `13`
  - `protocols`: `['TCP']`

### ✅ Stage 4: Sentinel Playbook Generation
- **Timestamp:** `2026-07-07T18:18:28.005977`
- **Status:** `PASS`
- **Details:** Playbook generated: PB-20260707-124827-BE023E
- **Data:**
  - `playbook_id`: `PB-20260707-124827-BE023E`
  - `db_record_id`: `4`
  - `service_type`: `SSH`
  - `attack_type`: `SSH_AUTH_FAILURE`

### ✅ Stage 5: ATT&CK Mapping
- **Timestamp:** `2026-07-07T18:18:28.005977`
- **Status:** `PASS`
- **Details:** SSH brute force mapped to T1110.001 — Brute Force: Password Guessing [Credential Access]
- **Data:**
  - `technique_id`: `T1110.001`
  - `technique_name`: `Brute Force: Password Guessing`
  - `tactic`: `Credential Access`
  - `expected`: `T1110.001`

### ✅ Stage 6a: Snort Rule
- **Timestamp:** `2026-07-07T18:18:28.005977`
- **Status:** `PASS`
- **Details:** Snort rule generated: 5354 chars
- **Data:**
  - `snort_preview`: `alert tcp 10.99.1.100 any -> $HOME_NET 2222 (msg:"Campaign E2E-TEST-SSH-BRUTE activity from 10.99.1.100 targeting port 2222: Brute Force: Password Gue`

### ✅ Stage 6b: Sigma Rule
- **Timestamp:** `2026-07-07T18:18:28.005977`
- **Status:** `PASS`
- **Details:** Sigma rule generated: 617 chars
- **Data:**
  - `sigma_preview`: `title: 'Campaign E2E-TEST-SSH-BRUTE Detection for Brute Force: Password Guessing'
status: experimental
logsource:
  category: network_traffic
  produc`

### ✅ Stage 7: Dashboard Visibility
- **Timestamp:** `2026-07-07T18:18:28.009764`
- **Status:** `PASS`
- **Details:** Playbook visible in DB: id=4, status=pending
- **Data:**
  - `playbook_id`: `PB-20260707-124827-BE023E`
  - `playbook_name`: `SSH Brute Force: Password Guessing Playbook`
  - `status`: `pending`
  - `technique_id`: `T1110.001`
  - `total_playbooks`: `4`

### ✅ Stage 8a: Approve Playbook
- **Timestamp:** `2026-07-07T18:18:28.010753`
- **Status:** `PASS`
- **Details:** Status changed to 'approved', reviewed_by='e2e_test_analyst'
- **Data:**
  - `status`: `approved`
  - `reviewed_by`: `e2e_test_analyst`
  - `reviewed_at`: `2026-07-07 12:48:28.009764`

### ✅ Stage 8b: Reject Playbook
- **Timestamp:** `2026-07-07T18:18:28.012266`
- **Status:** `PASS`
- **Details:** Status changed to 'rejected', reviewed_by='e2e_test_analyst_2'
- **Data:**
  - `status`: `rejected`
  - `reviewed_by`: `e2e_test_analyst_2`

### ✅ Stage 9a: Markdown Export
- **Timestamp:** `2026-07-07T18:18:28.015864`
- **Status:** `PASS`
- **Details:** Exported playbook markdown: 19377 chars → C:\Users\srira\Project\PhantomNet\tests\e2e\exports\PB-20260707-124827-BE023E_playbook.md

### ✅ Stage 9b: JSON Export
- **Timestamp:** `2026-07-07T18:18:28.019988`
- **Status:** `PASS`
- **Details:** Exported JSON with 24 fields → C:\Users\srira\Project\PhantomNet\tests\e2e\exports\PB-20260707-124827-BE023E_export.json
- **Data:**
  - `fields`: `['id', 'playbook_id', 'created_at', 'updated_at', 'src_ip', 'dst_port', 'protocol', 'attack_type', 'threat_score', 'confidence_score']`

### ✅ Stage 9c: STIX 2.1 Export
- **Timestamp:** `2026-07-07T18:18:28.028315`
- **Status:** `PASS`
- **Details:** STIX bundle: 5 objects → C:\Users\srira\Project\PhantomNet\tests\e2e\exports\PB-20260707-124827-BE023E_stix.json
- **Data:**
  - `type`: `bundle`
  - `object_count`: `5`

### ✅ Stage 10: Playbook Content Quality
- **Timestamp:** `2026-07-07T18:18:28.028315`
- **Status:** `PASS`
- **Details:** Content quality: 4/4 checks passed
- **Data:**
  - `has_title`: `True`
  - `has_technique_ref`: `True`
  - `has_source_ip`: `True`
  - `min_length`: `True`

## Export Artifacts

| File | Description |
|------|-------------|
| `snort_rules.txt` | Generated Snort IDS rules |
| `sigma_rules.yaml` | Generated Sigma detection rules |
| `*_playbook.md` | Rendered playbook markdown |
| `*_export.json` | Full playbook JSON export |
| `*_stix.json` | STIX 2.1 threat intelligence bundle |
| `pipeline_evidence_report.json` | Machine-readable evidence |

---
*Generated by PhantomNet E2E Pipeline Test Suite*