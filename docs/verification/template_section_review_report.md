# Template Section Review Report
**Date:** 2026-07-02 · **Branch:** `feat/template-section-review-and-fix`

---

## Executive Summary

All **5 Jinja2 templates** reviewed. All **7 sections** verified in every template. **194/194 tests pass.** No empty blocks found. All containment phases verified with specific step keywords. No unrendered Jinja2 tags in any output.

---

## Review Methodology

1. Read each template in full (line-by-line block analysis)
2. Run automated `check_sections.py` with real rendered output
3. Run 194-test suite (`tests/test_template_section_review.py`)
4. Verify specific containment phases and artifact sub-sections per template
5. Validate no `{{ }}` unrendered tags remain in any output

---

## Template Inventory

| Template File | Lines | Blocks | Total Rendered Size |
|---|---|---|---|
| `base_playbook.md.j2` | 427 | 7 blocks (all sections) | ~5,000 chars (generic) |
| `brute_force.md.j2` | 533 | 4 override blocks | **19,176 chars** |
| `sqli_attempt.md.j2` | 634 | 4 override blocks | **23,901 chars** |
| `port_scan.md.j2` | 559 | 4 override blocks | **21,754 chars** |
| `data_exfiltration.md.j2` | 864 | 4 override blocks | **29,736 chars** |

---

## 7-Section Verification Results

| Section | brute_force | sqli_attempt | port_scan | data_exfil | base (generic) |
|---|---|---|---|---|---|
| **S1 Header** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **S2 Summary** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **S3 IOC Table** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **S4 ATT&CK Mapping** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **S5 Containment Steps** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **S6 Artifacts** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **S7 Appendix** | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Section 1 — Header Review

All templates include a custom header block with attack-specific metadata:

| Template | Key Header Rows Verified |
|---|---|
| `brute_force` | PB-SSH-BRUTE-FORCE, SSH Port, Attacker IP, Failed Logins, Event Summary ✅ |
| `sqli_attempt` | PB-SQLI-001, HTTP Method, Target Endpoint, DB Engine, WAF Vendor, Event Summary ✅ |
| `port_scan` | PB-PORTSCAN-001, Scan Type, Scanner Tool, Ports Scanned, VLAN/Segment, Event Summary ✅ |
| `data_exfiltration` | PB-EXFIL-001, Exfil Vector, DLP Vendor, Breach Notification, Legal Hold, Event Summary ✅ |

**Event Summary row** (added in PR #755) present and correct in all 4 headers:
```
| **Event Summary** | **147 events detected between 08:15 and 08:47 UTC** |
```

---

## Section 2 — Summary Review

All templates inherit `{% block summary %}` from base. Key fields verified:

- ✅ Campaign Overview blockquote
- ✅ Trigger Context table (Detection Time, **Time Range**, Event Summary, Source IP, Target IP)
- ✅ Affected Assets list
- ✅ Incident Priority table (Confidentiality, Integrity, Availability, Blast Radius)

---

## Section 3 — IOC Table Review

All templates inherit `{% block ioc_table %}` from base. Verified:

- ✅ Source IPs table (IP, Port, Protocol, Hit Count, Threat Intel, First Seen, Last Seen)
- ✅ Additional IOC Hashes section (with fallback message if none provided)
- ✅ Domain / URL IOCs section (with fallback message if none provided)

---

## Section 4 — ATT&CK Mapping Review

Each child template overrides `{% block attack_mapping %}` with pinned techniques:

| Template | Techniques | Key IDs |
|---|---|---|
| `brute_force` | 7 rows | T1110 ×3, T1078, T1021, T1133, T1562 |
| `sqli_attempt` | 8 rows | T1190, T1059, T1005, T1552, T1213, T1565, T1110, T1078 |
| `port_scan` | 8 rows | T1595 ×2, T1046, T1590, T1592, T1018, T1049, T1571 |
| `data_exfiltration` | 12 rows | T1041, T1048, T1567, T1020, T1030, T1052, T1022, T1005, T1039, T1074, T1071, T1132 |

All include MITRE ATT&CK reference links. ✅

---

## Section 5 — Containment Steps Review

### brute_force.md.j2 — 4 Phases ✅

| Phase | Title | Time Window | Verified Keywords |
|---|---|---|---|
| Phase 1 | Immediate IP Blocking | T+0 → T+5 min | Block, tarpit, credentials ✅ |
| Phase 2 | SSH Key Rotation | T+5 → T+20 min | Key Rotation, authorized_keys ✅ |
| Phase 3 | Auth Log Review | T+20 → T+60 min | auth log, fail2ban ✅ |
| Phase 4 | Account Lockout & Password Policy | T+60 min → Close | Lockout, Password Policy, MFA ✅ |

### sqli_attempt.md.j2 — 4 Phases ✅

| Phase | Title | Time Window | Verified Keywords |
|---|---|---|---|
| Phase 1 | Immediate Triage & Traffic Block | T+0 → T+10 min | WAF, Block, Triage ✅ |
| Phase 2 | WAF Review & Hardening | T+10 → T+45 min | WAF Review, Rule Audit ✅ |
| Phase 3 | Input Validation Audit | T+45 min → T+3 hrs | Input Validation, Parameterised ✅ |
| Phase 4 | Database Integrity Check & Recovery | T+3 hrs → Close | DB, integrity, restoration ✅ |

### port_scan.md.j2 — 4 Phases ✅

| Phase | Title | Time Window | Verified Keywords |
|---|---|---|---|
| Phase 1 | Immediate Traffic Control & Evidence Capture | T+0 → T+10 min | Evidence, PCAP, Traffic ✅ |
| Phase 2 | Network Segmentation Review | T+10 → T+90 min | Segmentation, VLAN ✅ |
| Phase 3 | Exposed Service Audit | T+90 min → T+4 hrs | Exposed, Open Port, Service ✅ |
| Phase 4 | Deception Enhancement & Hardening | T+4 hrs → Close | Deception, Hardening ✅ |

### data_exfiltration.md.j2 — 5 Phases ✅

| Phase | Title | Time Window | Verified Keywords |
|---|---|---|---|
| Phase 1 | Immediate Isolation & Traffic Block | T+0 → T+15 min | Isolation, Block ✅ |
| Phase 2 | DLP Review & Policy Hardening | T+15 → T+90 min | DLP, Policy ✅ |
| Phase 3 | File Integrity Verification | T+90 min → T+4 hrs | File Integrity, FIM ✅ |
| Phase 4 | Outbound Traffic Analysis | T+4 → T+8 hrs | Outbound, NetFlow ✅ |
| Phase 5 | Data Classification & Impact Assessment | T+8 hrs → Close | Classification, Impact ✅ |

---

## Section 6 — Artifacts Review

All 4 child templates include ALL 4 artifact sub-sections:

| Sub-section | brute_force | sqli_attempt | port_scan | data_exfil |
|---|---|---|---|---|
| Detection Rules | ✅ (5 rules) | ✅ (7 rules) | ✅ (7 rules) | ✅ (10 rules) |
| Log Sources | ✅ (6 sources) | ✅ (7 sources) | ✅ (6 sources) | ✅ (9 sources) |
| SIEM Detection Queries | ✅ (4 queries) | ✅ (5 queries) | ✅ (5 queries) | ✅ (6 queries) |
| Evidence Collection Paths | ✅ (6 paths) | ✅ (6 paths) | ✅ (6 paths) | ✅ (11 paths) |

---

## Section 7 — Appendix Review

All templates inherit `{% block appendix %}` from base. Verified in all 4:

- ✅ Escalation Contacts table (Incident Commander, CISO, Network Team, Forensics Team)
- ✅ Rollback Procedures (3 default steps)
- ✅ SLA Targets table (TTD, TTR, TTC, TTRec)
- ✅ Context Metadata YAML block

---

## Issues Found & Fixed

| # | Issue | Status |
|---|---|---|
| 1 | `Event Summary` row missing from all 4 child template headers | Fixed in PR #755 (merged into this branch) |
| 2 | `Time Range` row missing from Summary section | Fixed in PR #755 (merged) |
| 3 | No issues in containment, ATT&CK, IOC, artifacts, or appendix sections | N/A |

---

## Test Results

```
tests/test_template_section_review.py::TestBaseTemplateAllSections         25 passed
tests/test_template_section_review.py::TestBruteForceAllSections           38 passed
tests/test_template_section_review.py::TestSQLiAllSections                 35 passed
tests/test_template_section_review.py::TestPortScanAllSections             35 passed
tests/test_template_section_review.py::TestDataExfilAllSections            37 passed
tests/test_template_section_review.py::TestCrossTemplateCompleteness       24 passed (×4 patterns)

TOTAL: 194 passed / 0 failed / 0.76s
```

---

## Conclusion

**All 5 templates are complete. All 7 sections render correctly with no empty blocks.**

- No `{{ }}` unrendered Jinja2 tags in any output
- All conditional `{% if %}` / `{% else %}` branches have real content
- All templates produce > 10,000 chars with real mock data
- Containment phases verified per attack type with specific keyword matching
- Event summary (time range enrichment) present in header + summary sections
