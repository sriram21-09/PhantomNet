# PhantomNet Week 15 Day 5 — Full Pipeline E2E Evidence Report

**Generated:** 2026-10-06T19:31:36.564247

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | 14 |
| ✅ Passed | 14 |
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
- **Timestamp:** `2026-10-06T19:31:36.155876`
- **Status:** `PASS`
- **Details:** Inserted 15 PacketLog + 15 Event rows targeting port 2222
- **Data:**
  - `packet_ids`: `[1, 2, 3, 4, 5]`
  - `attacker_ips`: `['10.99.1.100', '10.99.1.101', '10.99.1.102', '10.99.1.103', '10.99.1.104', '10.99.1.105', '10.99.1.106', '10.99.1.107', '10.99.1.108', '10.99.1.109',`
  - `target_port`: `2222`

### ✅ Stage 2: Autonomous Threat Scoring
- **Timestamp:** `2026-10-06T19:31:36.203563`
- **Status:** `PASS`
- **Details:** ThreatAnalyzerService autonomously scored 15/15 PacketLog rows (avg_score=0.46, levels={'MEDIUM'})
- **Data:**
  - `scored_count`: `15`
  - `avg_score`: `0.46`
  - `sample_levels`: `['MEDIUM', 'MEDIUM', 'MEDIUM', 'MEDIUM', 'MEDIUM']`

### ✅ Stage 3: Campaign Clustering
- **Timestamp:** `2026-10-06T19:31:36.223570`
- **Status:** `PASS`
- **Details:** DBSCAN found 1 campaign(s) from SSH brute force events
- **Data:**
  - `campaign_id`: `campaign_0`
  - `unique_sources`: `['10.99.1.100', '10.99.1.101', '10.99.1.102', '10.99.1.103', '10.99.1.104', '10.99.1.105', '10.99.1.106', '10.99.1.107', '10.99.1.108', '10.99.1.109',`
  - `target_ports`: `[2222]`
  - `event_count`: `15`
  - `protocols`: `['TCP']`

### ✅ Stage 4: Sentinel Playbook Generation
- **Timestamp:** `2026-10-06T19:31:36.555328`
- **Status:** `PASS`
- **Details:** Playbook generated: PB-20261006-140136-A5C517
- **Data:**
  - `playbook_id`: `PB-20261006-140136-A5C517`
  - `db_record_id`: `1`
  - `service_type`: `SSH`
  - `attack_type`: `SSH_AUTH_FAILURE`

### ✅ Stage 5: ATT&CK Mapping
- **Timestamp:** `2026-10-06T19:31:36.555328`
- **Status:** `PASS`
- **Details:** SSH brute force mapped to T1110.001 — Brute Force: Password Guessing [Credential Access]
- **Data:**
  - `technique_id`: `T1110.001`
  - `technique_name`: `Brute Force: Password Guessing`
  - `tactic`: `Credential Access`
  - `expected`: `T1110.001`

### ✅ Stage 6a: Snort Rule
- **Timestamp:** `2026-10-06T19:31:36.555328`
- **Status:** `PASS`
- **Details:** Snort rule generated: 5369 chars
- **Data:**
  - `snort_preview`: `alert tcp 10.99.1.100 any -> $HOME_NET 2222 (msg:"Campaign E2E-TEST-SSH-BRUTE activity from 10.99.1.100 targeting port 2222: Brute Force: Password Gue`

### ✅ Stage 6b: Sigma Rule
- **Timestamp:** `2026-10-06T19:31:36.556320`
- **Status:** `PASS`
- **Details:** Sigma rule generated: 617 chars
- **Data:**
  - `sigma_preview`: `title: 'Campaign E2E-TEST-SSH-BRUTE Detection for Brute Force: Password Guessing'
status: experimental
logsource:
  category: network_traffic
  produc`

### ✅ Stage 7: Dashboard Visibility
- **Timestamp:** `2026-10-06T19:31:36.557250`
- **Status:** `PASS`
- **Details:** Playbook visible in DB: id=1, status=pending
- **Data:**
  - `playbook_id`: `PB-20261006-140136-A5C517`
  - `playbook_name`: `SSH Brute Force: Password Guessing Playbook`
  - `status`: `pending`
  - `technique_id`: `T1110.001`
  - `total_playbooks`: `1`

### ✅ Stage 8a: Approve Playbook
- **Timestamp:** `2026-10-06T19:31:36.558249`
- **Status:** `PASS`
- **Details:** Status changed to 'approved', reviewed_by='e2e_test_analyst'
- **Data:**
  - `status`: `approved`
  - `reviewed_by`: `e2e_test_analyst`
  - `reviewed_at`: `2026-10-06 14:01:36.557250`

### ✅ Stage 8b: Reject Playbook
- **Timestamp:** `2026-10-06T19:31:36.559249`
- **Status:** `PASS`
- **Details:** Status changed to 'rejected', reviewed_by='e2e_test_analyst_2'
- **Data:**
  - `status`: `rejected`
  - `reviewed_by`: `e2e_test_analyst_2`

### ✅ Stage 9a: Markdown Export
- **Timestamp:** `2026-10-06T19:31:36.561248`
- **Status:** `PASS`
- **Details:** Exported playbook markdown: 20278 chars → C:\Users\srira\Project\PhantomNet\tests\e2e\exports\PB-20261006-140136-A5C517_playbook.md

### ✅ Stage 9b: JSON Export
- **Timestamp:** `2026-10-06T19:31:36.561248`
- **Status:** `PASS`
- **Details:** Exported JSON with 30 fields → C:\Users\srira\Project\PhantomNet\tests\e2e\exports\PB-20261006-140136-A5C517_export.json
- **Data:**
  - `fields`: `['id', 'playbook_id', 'created_at', 'updated_at', 'version', 'parent_id', 'is_latest', 'regeneration_reason', 'src_ip', 'dst_port']`

### ✅ Stage 9c: STIX 2.1 Export
- **Timestamp:** `2026-10-06T19:31:36.564247`
- **Status:** `PASS`
- **Details:** STIX bundle: 5 objects → C:\Users\srira\Project\PhantomNet\tests\e2e\exports\PB-20261006-140136-A5C517_stix.json
- **Data:**
  - `type`: `bundle`
  - `object_count`: `5`

### ✅ Stage 10: Playbook Content Quality
- **Timestamp:** `2026-10-06T19:31:36.564247`
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