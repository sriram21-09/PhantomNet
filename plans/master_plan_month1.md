# PhantomNet V3 — Master Execution Plan

## Structure
- **3 months = 12 weeks = 60 working days** (Mon-Fri)
- Each month: **3 weeks building + 1 week testing/validation/catch-up**
- **4 developers**: Sriram (S), Vivek (V), Vikranth (K), Manideep (M)

## Pre-Build Checklist (Day 0 — All Developers)

Before writing any new code, verify the foundation is stable:

| # | Check | Command / Action | Pass Criteria |
|---|---|---|---|
| 1 | Backend starts | `cd backend && uvicorn main:app --reload` | No import errors, "PhantomNet Sniffer Started" printed |
| 2 | Database connects | Hit `http://localhost:8000/api/health` | Returns `{"status": "online"}` |
| 3 | Frontend starts | `cd frontend-dev/phantomnet-dashboard && npm run dev` | Dashboard loads at localhost:5173 |
| 4 | ML model loads | Hit `http://localhost:8000/api/model/metrics` | Returns model stats, no "model not found" |
| 5 | Honeypots respond | `ssh localhost -p 2222`, `curl localhost:8080` | Connection accepted (even if rejected auth) |
| 6 | Tests pass | `cd backend/tests && pytest -v` | All existing tests green |
| 7 | Git is clean | `git status` | No uncommitted changes on main branch |
| 8 | Create V3 branch | `git checkout -b feature/sentinel-layer` | All V3 work on this branch |

> If ANY check fails, fix it before starting. Do not build new features on a broken foundation.

### Dependencies (Day 0)

**Backend**: No new Python dependencies needed for Month 1. Jinja2, stix2, PyYAML — all already installed. (`taxii2-client` added in Month 2 when TAXII server is built. Ollama installed in Month 2.)

**Frontend**: `react-markdown` and `remark-gfm` will be installed in Week 2 Day 6 (new dependency, not currently in package.json).

---

# MONTH 1: CORE SENTINEL LAYER

**Goal**: By end of Month 1, a complete pipeline works: attack detected → ATT&CK mapped → Snort/Sigma rules generated → Markdown playbook created → stored in DB → visible on dashboard → approve/reject functional.

---

## WEEK 1: Foundation Modules (Days 1-5)

### Day 1 (Monday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Create `backend/sentinel/` package + add `detected_signatures` column to PacketLog | `sentinel/__init__.py`, `sentinel/templates/` dir, DB migration | Create package. In `database/models.py` add `detected_signatures = Column(String, nullable=True)` to PacketLog. **Important**: Do NOT try to populate this inside `_apply_threat_result()` — `SignatureEngine.check_signatures()` expects a dict with `service_type`, `payload`, `status` fields that PacketLog does NOT have. Instead, the `detected_signatures` column will be populated by `sentinel_service.py` (Day 5-6) which infers signature type from `dst_port` (2222→SSH, 8080→HTTP, 2121→FTP, 2525→SMTP) + queries the `events` table for matching `raw_data` payloads. |
| **S** | Build `sentinel/mitre_mapper.py` — Part 1 | Working mapper with first 6 technique mappings | Map: SSH_AUTH_FAILURE→T1110.001, SSH_HIGH_ACTIVITY→T1021.004, HTTP_SQL_INJECTION→T1190, HTTP_XSS_ATTEMPT→T1059.007, HTTP_PATH_TRAVERSAL→T1083, HTTP_SCANNER_BEHAVIOR→T1046 |
| **V** | Create `sentinel/rule_generator.py` — Snort scaffold | Function signature + Snort template string | `generate_snort_rule(src_ip, dst_port, protocol, attack_desc, technique_id, sid) -> str` |
| **K** | Create `sentinel/playbook_generator.py` — scaffold with Jinja2 setup | Class with `generate()` method, Jinja2 env configured | Use `template_dir = os.path.join(os.path.dirname(__file__), 'templates')` and `jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))` for template path resolution |
| **M** | Create `src/pages/SentinelDashboard.jsx` — empty page with routing | Route registered, blank page loads, nav link visible | In `App.jsx`: add `import SentinelDashboard from './pages/SentinelDashboard'` and `<Route path='/sentinel' element={<SentinelDashboard />} />`. In `Navbar.jsx`: add `{ path: '/sentinel', label: 'Sentinel', icon: FaShieldAlt }` to the `navLinks` array (FaShieldAlt already imported) |

### Day 2 (Tuesday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Complete `mitre_mapper.py` — all 12 mappings | Full mapper with lookup function | Add remaining: FTP_DATA_EXFILTRATION→T1048.003, SMTP_LARGE_PAYLOAD→T1071.003, DISTRIBUTED_BRUTE_FORCE→T1110.004, LOW_AND_SLOW_SCAN→T1595.001, MULTI_PROTOCOL_ATTACK→T1046, HIGH_FREQUENCY_ATTACK→T1498 |
| **S** | Add `get_technique(signature_name)` + `get_all_mappings()` functions | Two public API functions | Return dict with id, name, tactic, mitre_url |
| **V** | Complete Snort rule generator | `generate_snort_rule()` produces valid Snort syntax | Include: msg, flow, threshold, classtype, reference to ATT&CK URL, auto-increment SID |
| **K** | Create `sentinel/templates/base_playbook.md.j2` | Base Jinja2 template | Sections: Header, Summary, IOC Table, ATT&CK Mapping, Containment Steps, Artifacts |
| **M** | Build `src/components/sentinel/PlaybookCard.jsx` | Card component showing title, severity, technique, status, date | Use existing design patterns from MetricCard.jsx |

### Day 3 (Wednesday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Create `sentinel/models.py` — SentinelPlaybook DB model | SQLAlchemy model with all 21 columns | See blueprint for full schema. Import `Base` from `database.models`. Define model in `sentinel/models.py` |
| **S** | Register model in `main.py` imports | Table auto-creates on startup | Add `from sentinel.models import SentinelPlaybook` in `main.py` imports section (before line 96 where `Base.metadata.create_all(bind=engine)` runs). This ensures the table is created. Do NOT modify `database/models.py` — keep sentinel models in their own module |
| **V** | Build Sigma rule generator | `generate_sigma_rule()` produces valid Sigma YAML | Include: title, status, logsource, detection, level, tags with ATT&CK refs |
| **K** | Create `sentinel/templates/brute_force.md.j2` | Template extending base for SSH brute force | Specific containment steps for brute force: check key rotation, review auth logs, etc. |
| **M** | Build `src/components/sentinel/MitreTag.jsx` | Badge component showing technique ID + tactic | Color-coded by tactic (Credential Access = red, Discovery = blue, etc.) |

### Day 4 (Thursday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Create `sentinel/stix_enhanced.py` | Upgraded STIX generator with real ATT&CK ExternalReferences | Takes mitre_mapper output + IOCs → produces enriched STIX bundle |
| **V** | Add `generate_rules_for_campaign(cluster_data, mitre_info)` | Wrapper that generates both Snort + Sigma for a full campaign | Takes campaign cluster output + mapper output, returns dict with both rule strings |
| **K** | Create `sentinel/templates/sqli_attempt.md.j2` | Template for SQL injection playbook | Specific steps: WAF review, input validation audit, DB integrity check |
| **K** | Create `sentinel/templates/port_scan.md.j2` | Template for port scan / reconnaissance | Steps: network segmentation review, exposed service audit |
| **M** | Build `src/components/sentinel/RulePreview.jsx` | Component displaying Snort/Sigma rules with syntax highlighting | Use `<pre>` blocks with copy-to-clipboard button |

### Day 5 (Friday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Create `sentinel/sentinel_service.py` — orchestrator Part 1 | `SentinelService` class with `generate_playbook(campaign_data)` method | Wires together: mitre_mapper + rule_generator + stix_enhanced + playbook_generator. **Critical design**: This is where signature detection happens. Campaign clustering output has NO attack_type field — it only returns `source_ips, target_ports, protocols, event_count, time range`. The sentinel_service must: (1) Infer protocol from target_ports (2222→SSH, 8080→HTTP, 2121→FTP, 2525→SMTP), (2) Query PacketLog for matching IPs+timestamps to get threat_levels, (3) Optionally query `events` table for raw_data to run `SignatureEngine.check_signatures()`, (4) Use inferred signature name to call mitre_mapper. Store result in `PacketLog.detected_signatures` for the matched logs. |
| **V** | Write unit tests for rule_generator | `tests/test_rule_generator.py` | Test Snort syntax validity, Sigma YAML parsing, edge cases (empty IP, unknown protocol) |
| **K** | Create `sentinel/templates/data_exfiltration.md.j2` | Template for FTP exfiltration playbook | Steps: DLP review, file integrity check, outbound traffic analysis |
| **M** | Build `src/components/sentinel/PlaybookViewer.jsx` — scaffold | Modal/page component that renders Markdown playbook | Use a Markdown renderer library (react-markdown) or pre-formatted HTML |

**Week 1 Checkpoint**: mitre_mapper works (12 mappings), rule_generator outputs valid Snort+Sigma, 4 Jinja2 templates exist, SentinelPlaybook DB model registered, dashboard page route exists with card + tag + rule components.

---

## WEEK 2: Integration & API (Days 6-10)

### Day 6 (Monday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Complete `sentinel_service.py` — full orchestrator | `generate_playbook()` returns complete SentinelPlaybook object | Calls mapper → generator → rules → stix → saves to DB |
| **S** | Add DB session management in sentinel_service | Service reads from PacketLog, IOC tables; writes to SentinelPlaybook | Use existing `SessionLocal` pattern |
| **V** | Write unit tests for mitre_mapper | `tests/test_mitre_mapper.py` | Test all 12 mappings return correct technique IDs, test unknown signature returns None |
| **K** | Integrate playbook_generator with Jinja2 templates | `generate()` method selects correct template based on attack_pattern, fills context | Template selection: brute_force patterns → brute_force.md.j2, SQL → sqli.md.j2, etc. |
| **M** | Install react-markdown, complete PlaybookViewer | Full Markdown rendering with IOC tables, containment checkboxes | `npm install react-markdown remark-gfm` |

### Day 7 (Tuesday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Create `api/sentinel.py` — first 5 endpoints | GET /playbooks, GET /playbooks/{id}, GET /stats, GET /mitre/mapping, POST /generate | Create router with `router = APIRouter(prefix='/api/sentinel', tags=['Sentinel'])`. In `main.py`: add `from api.sentinel import router as sentinel_router` (near line 72) and `app.include_router(sentinel_router)` (near line 306) |
| **V** | Wire rule_generator into sentinel_service | Sentinel service calls rule_generator when generating playbook | Snort + Sigma rules stored in SentinelPlaybook.snort_rules / sigma_rules columns |
| **K** | Test playbook_generator end-to-end with mock data | Generate a complete playbook from fake cluster data | Verify all 7 sections render correctly in Markdown |
| **M** | Build `src/components/sentinel/ApprovalControls.jsx` | Approve/Reject buttons + status badge | Buttons call PATCH API, update card status visually |

### Day 8 (Wednesday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Add remaining API endpoints | PATCH approve, PATCH reject, POST export, GET rules/snort, GET rules/sigma | Approve/reject update status + reviewed_by + reviewed_at |
| **V** | Create background sentinel generation task in `main.py` | Periodic task that runs campaign clustering → feeds new clusters to sentinel | **Do NOT modify threat_analyzer.py.** Campaign clustering is NOT in the ThreatAnalyzer loop — it runs separately via API. Add `sentinel_generation_loop()` as an async background task in `main.py` lifespan (like `broadcast_live_metrics`). It runs every 5 minutes: calls `campaign_clusterer.identify_campaigns()` → for each new campaign found → calls `sentinel_service.generate_playbook()`. Toggle with `SENTINEL_ENABLED` env var. **Important**: `identify_campaigns()` is synchronous (opens its own DB session). Wrap in `asyncio.to_thread()` to avoid blocking the event loop: `result = await asyncio.to_thread(campaign_clusterer.identify_campaigns, 24)` |
| **K** | Write unit tests for playbook_generator | `tests/test_playbook_generator.py` | Test template selection, verify IOC table renders, verify ATT&CK section populated |
| **M** | Assemble SentinelDashboard.jsx — list view | Page shows list of PlaybookCards, with filter tabs: All / Draft / Approved / Rejected | Fetch from GET /api/sentinel/playbooks, filter by status |

### Day 9 (Thursday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Add `SENTINEL_ENABLED` env var + wire background task | Sentinel generation loop registered in lifespan | In `main.py` lifespan: if `SENTINEL_ENABLED=true`, start `asyncio.create_task(sentinel_generation_loop())`. Add dedup logic: track last processed campaign IDs to avoid regenerating playbooks for already-processed campaigns |
| **V** | Create export endpoint logic | POST /api/sentinel/playbooks/{id}/export returns file download | Support format param: `?format=markdown` or `?format=json` or `?format=stix` |
| **K** | Write `tests/test_stix_enhanced.py` | Test enhanced STIX bundles contain ATT&CK ExternalReferences | Verify bundle has correct technique URLs and relationship objects |
| **M** | Add PlaybookViewer modal/panel to dashboard | Click a PlaybookCard → opens PlaybookViewer showing full content | Show playbook Markdown + RulePreview tabs (Snort/Sigma) + ApprovalControls |

### Day 10 (Friday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Write `tests/test_sentinel_service.py` | Integration test: mock cluster data → sentinel generates complete playbook | Test the full chain: mapper + rules + playbook + stix + DB save |
| **V** | Add SID counter persistence | Snort SID auto-increment doesn't reset on restart | Store last SID in SystemConfig table or a simple file |
| **K** | Add confidence scoring logic to sentinel_service | Calculate confidence from: cluster size, ML score avg, IOC count, multi-protocol flag | `confidence = weighted_avg(cluster_size_score, ml_avg_score, ioc_density, multi_proto_bonus)` |
| **M** | Add Sentinel stats widgets on main Dashboard.jsx | Small widget: "X playbooks generated, Y pending review, Z approved" | Fetch from GET /api/sentinel/stats |

**Week 2 Checkpoint**: Full pipeline works end-to-end — campaign detected → sentinel generates playbook with ATT&CK + rules + STIX → stored in DB → visible on dashboard → approve/reject buttons work → export downloads file.

---

## WEEK 3: Polish & Hardening (Days 11-15)

### Day 11 (Monday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | End-to-end test #1: SSH brute force scenario | Manually insert test PacketLogs simulating SSH brute force → verify sentinel generates correct T1110.001 playbook | Document the test scenario and expected output |
| **V** | End-to-end test #2: SQL injection scenario | Insert HTTP PacketLogs with SQLi payloads → verify T1190 playbook + Snort rule | Verify Snort rule has correct msg and classtype |
| **K** | End-to-end test #3: Port scan scenario | Insert multi-port PacketLogs → verify T1046 playbook | Verify Sigma rule has correct detection logic |
| **M** | UI polish — loading states, error handling | Add spinners during API calls, error toasts on failure, empty state for no playbooks | Follow existing dashboard patterns |

### Day 12 (Tuesday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Fix any pipeline bugs from Day 11 tests | All 3 scenarios produce correct output | Priority: data flow issues, missing fields, DB save failures |
| **V** | Validate Snort rule syntax with Snort parser (if available) or manual review | Rules follow Snort 2.9/3.0 syntax correctly | Check: semicolons, parentheses, escape characters, SID uniqueness |
| **K** | Validate Sigma rules with `sigma check` or YAML parser | Rules are valid YAML with correct Sigma schema | Check: logsource structure, detection block, tag format |
| **M** | Add download buttons for Snort/Sigma/STIX/Markdown files | Each format downloads as correct file extension (.rules, .yml, .json, .md) | Use Blob + URL.createObjectURL pattern |

### Day 13 (Wednesday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Add pagination to GET /api/sentinel/playbooks | Support `?page=1&per_page=20` query params | Return: { total, page, per_page, playbooks[] } |
| **V** | Add severity-based Snort rule priority | CRITICAL → priority:1, HIGH → priority:2, MEDIUM → priority:3 | Map severity to Snort classtype appropriately |
| **K** | Add timestamp and event count to playbook context | Playbooks show time range and event count from cluster | "147 events detected between 08:15 and 08:47 UTC" |
| **M** | Add sorting (by date, severity, status) to playbook list | Column header click sorts, default: newest first | Client-side sort for now, can optimize later |

### Day 14 (Thursday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **S** | Code review all sentinel/ files for consistency | Docstrings, type hints, error handling, logging | Every function has docstring, logger calls on errors, type hints on signatures |
| **V** | Code review rule_generator edge cases | Handle: IPv6 addresses, port 0, empty attack_desc, very long IPs | Add input validation, return error dict if invalid |
| **K** | Code review playbook templates for completeness | Every template has all 7 sections filled, no empty blocks | Manual review of each .j2 file |
| **M** | Add notification badge to existing Sentinel nav link | Badge shows count of pending (draft) playbooks | The Sentinel link was added in Day 1. Now add a small badge/counter next to it showing draft count. Fetch from `/api/sentinel/stats` on Navbar mount using useEffect |

### Day 15 (Friday)

| Dev | Task | Deliverable | Details |
|---|---|---|---|
| **ALL** | Integration test — full system run | Start all services, trigger attacks, verify full pipeline | SSH brute force → ML scores → campaign clustered → sentinel playbook generated → visible on dashboard → approve → export |
| **ALL** | Document any remaining bugs | Create issues list for Week 4 | Priority: P0 (blocks demo), P1 (wrong output), P2 (cosmetic) |

**Week 3 Checkpoint**: 3 attack scenarios tested end-to-end. Pipeline is stable. UI is polished with loading states, error handling, download buttons, sorting, pagination.

---

## WEEK 4: Testing, Validation & Catch-Up (Days 16-20)

### Day 16 (Monday)

| Dev | Task |
|---|---|
| **S** | Fix P0 bugs from Week 3 integration test |
| **V** | Fix any rule generation bugs found in testing |
| **K** | Fix any playbook generation/template bugs |
| **M** | Fix any UI bugs — layout, responsiveness, data display |

### Day 17 (Tuesday)

| Dev | Task |
|---|---|
| **S** | Write comprehensive pytest suite: `tests/test_sentinel_integration.py` — tests full pipeline with test DB |
| **V** | Write edge case tests: empty clusters, single-event campaigns, unknown protocols |
| **K** | Write template rendering tests: verify all templates produce valid Markdown |
| **M** | Cross-browser test dashboard (Chrome, Firefox, Edge) — fix CSS issues |

### Day 18 (Wednesday)

| Dev | Task |
|---|---|
| **S** | Run full test suite (`pytest -v`), ensure all tests pass including new sentinel tests |
| **V** | Test sentinel with real honeypot traffic (if available) or realistic simulated data |
| **K** | Verify confidence scoring produces sensible values across different scenarios |
| **M** | Test all API integrations from frontend — error handling, empty states, loading |

### Day 19 (Thursday)

| Dev | Task |
|---|---|
| **S** | Update README.md — add Sentinel Layer section, new architecture diagram |
| **V** | Document Snort/Sigma rule format in `docs/rule_generation.md` |
| **K** | Document playbook template format in `docs/playbook_templates.md` |
| **M** | Screenshot new Sentinel Dashboard page for README |

### Day 20 (Friday)

| Dev | Task |
|---|---|
| **ALL** | Git commit + push feature/sentinel-layer branch |
| **ALL** | Merge to main via PR after review |
| **ALL** | Month 1 demo — record a screen recording of full pipeline working |
| **ALL** | Review Month 2 plan, adjust if needed based on Month 1 learnings |

---

**MONTH 1 COMPLETE**: Core Sentinel Layer operational. ATT&CK mapping (12 techniques), Snort + Sigma rule generation, Jinja2 playbook generation, enhanced STIX bundles, SentinelPlaybook database, 10 API endpoints, Sentinel Dashboard with approve/reject/export. 3 attack scenarios demonstrated.
