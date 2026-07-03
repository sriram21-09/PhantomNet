# Week 15 Day 1 — SSH Brute Force T1110.001 Validation Report

**Date:** 2026-07-01  
**Sprint:** Week 15 (Month 1, Week 3: Polish & Hardening)  
**Tester:** PhantomNet CI / Team Lead  
**Status:** ✅ ALL TESTS PASSED (62/62)  

---

## 🎯 Objective

Manually inject test PacketLogs simulating SSH brute force traffic (port 2222, repeated auth failures), trigger the Sentinel pipeline, and verify correct T1110.001 playbook generation with all expected fields.

---

## 📦 Test Data Specification

### Simulated SSH Brute Force Campaign

| Parameter | Value |
|-----------|-------|
| **Campaign ID** | `CAMP-W15-SSH-BF-001` |
| **Attacker IPs** | `203.0.113.45`, `203.0.113.46`, `198.51.100.77` |
| **Target Port** | `2222` (SSH honeypot) |
| **Protocol** | `TCP` |
| **Event Count** | `150` |
| **Time Window** | `2026-07-01T08:00:00Z` → `2026-07-01T12:00:00Z` |
| **Threat Score Range** | `65.0 – 94.0` |
| **Threat Level** | `High` |

### Injected Data

| Table | Records | Key Fields |
|-------|---------|------------|
| `packet_logs` | 50 | `src_ip`, `dst_port=2222`, `protocol=TCP`, `attack_type=SSH_AUTH_FAILURE` |
| `events` | 20 | SSH auth failure payloads (`Failed password for root/admin/user/test/ubuntu`) |
| `iocs` | 3 | IP-type IOCs for each attacker IP, `threat_level=High` |

---

## ✅ Test Results Summary

| Test Suite | Tests | Passed | Failed | Status |
|------------|-------|--------|--------|--------|
| **TestDataInjection** | 6 | 6 | 0 | ✅ |
| **TestPipelineExecution** | 6 | 6 | 0 | ✅ |
| **TestT1110001Mapping** | 5 | 5 | 0 | ✅ |
| **TestSnortRuleValidation** | 10 | 10 | 0 | ✅ |
| **TestSigmaRuleValidation** | 8 | 8 | 0 | ✅ |
| **TestStixBundleValidation** | 9 | 9 | 0 | ✅ |
| **TestPlaybookMarkdownSections** | 11 | 11 | 0 | ✅ |
| **TestDBPersistence** | 7 | 7 | 0 | ✅ |
| **TOTAL** | **62** | **62** | **0** | ✅ |

**Execution Time:** 1.18 seconds

---

## 📋 Detailed Validation Results

### Task 1 — Test Data Injection ✅

| Check | Expected | Actual | Status |
|-------|----------|--------|--------|
| PacketLog rows inserted | 50 | 50 | ✅ |
| All rows have `dst_port=2222` | Yes | Yes | ✅ |
| All rows have attacker IPs | Yes | Yes | ✅ |
| Event rows inserted | 20 | 20 | ✅ |
| Events contain SSH payloads | `Failed password` | Confirmed | ✅ |
| IOC rows inserted | 3 | 3 | ✅ |

### Task 2 — Pipeline Execution ✅

| Check | Expected | Actual | Status |
|-------|----------|--------|--------|
| Returns `SentinelPlaybook` | Yes | Yes | ✅ |
| Persisted to DB | Row exists | Confirmed | ✅ |
| Service type inferred | `SSH` | `SSH` | ✅ |
| Matched PacketLog rows | > 0 | > 0 | ✅ |
| IOC enrichment applied | > 0 IOCs | 3 IOCs | ✅ |
| Confidence score computed | > 0.0 | Computed | ✅ |

### Task 3 — MITRE T1110.001 Mapping ✅

| Field | Expected | Actual | Status |
|-------|----------|--------|--------|
| `technique_id` | `T1110.001` | `T1110.001` | ✅ |
| `technique_name` | `Brute Force: Password Guessing` | `Brute Force: Password Guessing` | ✅ |
| `tactic` | `Credential Access` | `Credential Access` | ✅ |
| `mitre_url` | Contains `T1110/001` | Confirmed | ✅ |
| `result_dict.technique` | All fields present | Confirmed | ✅ |

### Task 4 — Snort Rule Validation ✅

| Field | Expected | Actual | Status |
|-------|----------|--------|--------|
| `msg:` field | Present | Present | ✅ |
| `flow:to_server,established` | Present | Present | ✅ |
| `threshold:type limit` | Present | Present | ✅ |
| `track by_src` | Present | Present | ✅ |
| `count 5, seconds 60` | Present | Present | ✅ |
| `classtype:attempted-admin` | Present | Present | ✅ |
| MITRE reference URL | `attack.mitre.org/techniques/T1110/001` | Present | ✅ |
| `sid:` field | Present | Present | ✅ |
| Starts with `alert ` | Yes | Yes | ✅ |
| Protocol is `tcp` | Yes | Yes | ✅ |

**Sample Snort Rule:**
```
alert tcp 203.0.113.45 any -> $HOME_NET 2222 (msg:"Campaign CAMP-W15-SSH-BF-001 activity from 203.0.113.45 targeting port 2222: Brute Force: Password Guessing"; flow:to_server,established; threshold:type limit, track by_src, count 5, seconds 60; classtype:attempted-admin; reference:url,attack.mitre.org/techniques/T1110/001/; sid:XXXXXXX; rev:1;)
```

### Task 5 — Sigma Rule Validation ✅

| Field | Expected | Actual | Status |
|-------|----------|--------|--------|
| Valid YAML | Parseable | Parseable | ✅ |
| `title` | Contains campaign ID | Confirmed | ✅ |
| `logsource.category` | `network_traffic` | `network_traffic` | ✅ |
| `logsource.product` | `phantomnet` | `phantomnet` | ✅ |
| `detection.selection` | Present | Present | ✅ |
| `detection.condition` | Present | `selection` | ✅ |
| `detection.selection.dst_port` | Contains `2222` | Confirmed | ✅ |
| `level` | Valid Sigma level | `high` | ✅ |
| `tags` | Contains `attack.t1110.001` | Confirmed | ✅ |

**Sample Sigma Rule:**
```yaml
title: Campaign CAMP-W15-SSH-BF-001 Detection for Brute Force: Password Guessing
status: experimental
logsource:
  category: network_traffic
  product: phantomnet
detection:
  selection:
    src_ip: [203.0.113.45, 203.0.113.46, 198.51.100.77]
    dst_port: [2222]
    protocol: [tcp]
  condition: selection
level: high
tags:
  - attack.t1110.001
  - campaign
```

### Task 6 — STIX Bundle Validation ✅

| Check | Expected | Actual | Status |
|-------|----------|--------|--------|
| Bundle type | `bundle` | `bundle` | ✅ |
| Has `identity` object | Yes | Yes | ✅ |
| Has `attack-pattern` object | Yes | Yes | ✅ |
| Has `indicator` objects | Yes | Yes | ✅ |
| Has `relationship` objects | Yes | Yes | ✅ |
| AttackPattern `external_id` | `T1110.001` | `T1110.001` | ✅ |
| AttackPattern `source_name` | `mitre-attack` | `mitre-attack` | ✅ |
| AttackPattern URL | Contains `T1110/001` | Confirmed | ✅ |
| Indicators contain attacker IPs | `203.0.113.45` | Confirmed | ✅ |
| Relationships type | `indicates` | `indicates` | ✅ |

### Task 7 — Playbook Markdown Sections ✅

| Section | Expected | Actual | Status |
|---------|----------|--------|--------|
| **1. Header** | Title, severity, metadata table | Present | ✅ |
| **2. Summary** | Campaign overview, trigger context | Present | ✅ |
| **3. IOC Table** | Source IPs, ports, protocols | Present | ✅ |
| **4. ATT&CK Mapping** | T1110 technique table | Present | ✅ |
| **5. Containment Steps** | Ordered response checklist | Present | ✅ |
| **6. Artifacts** | Detection rules, log sources | Present | ✅ |
| **7. Appendix/Metadata** | Escalation contacts, context | Present | ✅ |
| Source IP embedded | `203.0.113.45` | Present | ✅ |
| Technique reference | `T1110` | Present | ✅ |

### Task 8 — DB Persistence (23 Columns) ✅

| Column Group | Columns | Populated | Status |
|-------------|---------|-----------|--------|
| **Core Identity (4)** | `id`, `playbook_id`, `created_at`, `updated_at` | All | ✅ |
| **Threat Context (7)** | `src_ip`, `dst_port`, `protocol`, `attack_type`, `threat_score`, `confidence_score`, `severity` | All | ✅ |
| **MITRE Mapping (4)** | `technique_id`, `technique_name`, `tactic`, `mitre_url` | All | ✅ |
| **Detection Rules (2)** | `snort_rule`, `sigma_rule` | Both | ✅ |
| **Playbook Content (3)** | `playbook_name`, `playbook_content`, `template_name` | All | ✅ |
| **Lifecycle (3)** | `status=pending`, `reviewed_by=null`, `reviewed_at=null` | Correct | ✅ |

---

## 📁 Test Artifacts

| Artifact | Location |
|----------|----------|
| Test script | `tests/test_week15_ssh_brute_force_validation.py` |
| Test report | `docs/week15_day1_ssh_brute_force_test_report.md` |
| Sentinel service (read-only) | `backend/sentinel/sentinel_service.py` |
| MITRE mapper | `backend/sentinel/mitre_mapper.py` |
| Rule generator | `backend/sentinel/rule_generator.py` |
| STIX enhanced | `backend/sentinel/stix_enhanced.py` |
| Playbook generator | `backend/sentinel/playbook_generator.py` |
| Brute force template | `backend/sentinel/templates/brute_force.md.j2` |

---

## ⚠️ Notes

- **No modifications** were made to `sentinel_service.py` — this is validation only
- Test data uses RFC 5737 (documentation) IP ranges (`203.0.113.x`, `198.51.100.x`)
- All tests use in-memory SQLite — no production database affected
- Playbook template inheritance (`brute_force.md.j2` → `base_playbook.md.j2`) confirmed working
- Confidence scoring engine correctly computed composite scores from injected ML threat scores

---

## ✅ Conclusion

**All 62 validation tests passed.** The Sentinel pipeline correctly:

1. ✅ Ingests SSH brute force PacketLog data on port 2222
2. ✅ Infers SSH service type and maps to `SSH_AUTH_FAILURE` signature
3. ✅ Maps to MITRE ATT&CK technique **T1110.001** (Brute Force: Password Guessing)
4. ✅ Generates valid Snort rules with correct `msg`, `flow`, `threshold`, and `classtype`
5. ✅ Generates valid Sigma rules with correct `logsource` and `detection` blocks
6. ✅ Builds STIX 2.1 bundles with correct `ExternalReferences` to ATT&CK T1110.001
7. ✅ Renders complete Markdown playbook with all 7 sections
8. ✅ Persists all 23 columns to the `sentinel_playbooks` table

**Week 15, Day 1 deliverables complete.**

---

*Report generated: 2026-07-01 | PhantomNet Sentinel Validation Suite v1.0*
