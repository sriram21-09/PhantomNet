# PhantomNet V3 — Master Plan: Months 2-3

---

# MONTH 2: LLM INTEGRATION + ADVANCED FEATURES

**Goal**: Add optional LLM narrative enhancement, TAXII feed server, ATT&CK visualization, PDF export, and batch operations.

**Pre-Month 2 Check**: Month 1 pipeline works — attack → playbook → dashboard → approve. If not, fix first.

**New Dependencies for Month 2**:
- **Backend**: Add `taxii2-client>=2.3.0` to `requirements.txt` (needed Week 6 for testing TAXII feed)
- **System**: Install Ollama (`curl -fsSL https://ollama.com/install.sh | sh` on Linux, or download from ollama.com on Windows). Then `ollama pull mistral`. Only needed on at least one team machine.

---

## WEEK 5: LLM Integration (Days 21-25)

### Day 21 (Monday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Design LLM integration architecture | Document: Ollama API contract, prompt template structure, fallback mechanism |
| **V** | Research + document Ollama installation steps for team | Setup guide: install Ollama, pull Mistral 7B, test with curl |
| **K** | Create `sentinel/llm_service.py` — scaffold | `LLMService` class with `generate_narrative(context_data) -> str`, env var toggle `SENTINEL_LLM_ENABLED` |
| **M** | Add LLM status indicator to Sentinel Dashboard | Badge showing "AI: Online/Offline", fetched from backend health check |

### Day 22 (Tuesday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add `/api/sentinel/llm/status` endpoint | Returns: enabled/disabled, model name, last response time |
| **V** | Install Ollama + Mistral 7B on development machine | Working `ollama run mistral` on at least one team machine |
| **K** | Build LLM prompt template | System prompt + structured context injection (cluster data, IOCs, ATT&CK, GeoIP, response actions) |
| **M** | Add "AI Summary" section toggle in PlaybookViewer | Show/hide LLM narrative section, visual distinction from template content |

### Day 23 (Wednesday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add LLM toggle to SystemConfig API | Admin can enable/disable LLM from admin panel |
| **V** | Test LLM output quality for SSH brute force scenario | Document: prompt sent, response received, quality assessment |
| **K** | Implement Ollama HTTP API call in llm_service.py | POST to `http://localhost:11434/api/generate`, parse response, handle timeout (60s max) |
| **M** | Style AI-generated narrative differently from template content | Subtle visual indicator (border, icon, label) showing "AI-Enhanced Summary" |

### Day 24 (Thursday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Integrate llm_service into sentinel_service orchestrator | If LLM enabled → call LLM for narrative → store in `llm_narrative` column. If disabled → skip |
| **V** | Test LLM output for SQLi and port scan scenarios | Document quality for each. Identify if prompt needs adjustment |
| **K** | Build fallback mechanism | If Ollama unreachable or times out → log warning, continue with template-only playbook, no crash |
| **M** | Add "Regenerate AI Summary" button in PlaybookViewer | Re-calls LLM for the same playbook data, updates narrative |

### Day 25 (Friday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Write `tests/test_llm_service.py` | Test: enabled/disabled toggle, timeout handling, fallback on error |
| **V** | Fine-tune prompt template based on test results | Improve prompt with few-shot examples if output quality is low |
| **K** | Add response time tracking to llm_service | Log and return generation time for each LLM call |
| **M** | End-to-end test: full pipeline with LLM enabled | Attack → playbook with AI narrative visible on dashboard |

**Week 5 Checkpoint**: LLM integration works. Optional toggle functional. Fallback reliable. AI narrative visually distinguished on dashboard.

---

## WEEK 6: TAXII Feed + ATT&CK Visualization (Days 26-30)

### Day 26 (Monday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Design TAXII 2.1 feed endpoint architecture | API spec: discovery, collections, objects endpoints per TAXII spec |
| **V** | Create `api/taxii.py` — TAXII discovery endpoint | `GET /taxii2/` returns discovery document with api_roots. **Note: this is building a TAXII SERVER (serving our STIX data to external tools). The `taxii2-client` library is only used for TESTING our server, not for building it. The server is custom FastAPI endpoints mimicking TAXII 2.1 API spec.** |
| **K** | Research ATT&CK matrix visualization libraries | Evaluate: d3-based matrix, custom CSS grid, or simple table approach |
| **M** | Build `src/components/sentinel/MitreMatrix.jsx` — scaffold | Component skeleton with tactic columns and technique cells |

### Day 27 (Tuesday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Build TAXII collections endpoint | `GET /taxii2/phantomnet/collections/` returns list of STIX collections |
| **V** | Build TAXII objects endpoint | `GET /taxii2/phantomnet/collections/{id}/objects/` returns STIX bundles |
| **K** | Create ATT&CK matrix data structure | JSON mapping: 12 tactics → techniques → detection count from our sentinel_playbooks |
| **M** | Build MitreMatrix with color-coded heatmap | Cells colored by detection frequency (gray=none, yellow=low, red=high) |

### Day 28 (Wednesday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add content-type negotiation to TAXII endpoints | Return `application/stix+json;version=2.1` headers per spec |
| **V** | Test TAXII endpoints with `taxii2-client` library | Use the `taxii2-client` pip package (installed at start of Month 2) to verify our TAXII server. A TAXII client should be able to discover and pull our STIX bundles |
| **K** | Add `/api/sentinel/mitre/matrix` API endpoint | Returns matrix data: techniques with counts, severities, last seen timestamps |
| **M** | Add MitreMatrix to SentinelDashboard as a tab/section | Toggle between "Playbooks List" and "ATT&CK Coverage" views |

### Day 29 (Thursday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add filtering to TAXII objects endpoint | Support `?added_after=` timestamp filter per TAXII spec |
| **V** | Write `tests/test_taxii.py` | Test discovery, collections, objects, content-type headers |
| **K** | Add click interaction to MitreMatrix | Click a technique cell → shows list of playbooks for that technique |
| **M** | Build technique detail popup/panel | Shows: technique description, detection count, recent playbooks, MITRE link |

### Day 30 (Friday)

| Dev | Task | Deliverable |
|---|---|---|
| **ALL** | Integration test: TAXII feed + Matrix visualization |
| **S** | Verify TAXII interoperability documentation |
| **V** | Test TAXII with external STIX viewer (if available) |
| **K** | Verify matrix updates when new playbooks are generated |
| **M** | Polish matrix colors, tooltips, responsive layout |

**Week 6 Checkpoint**: TAXII 2.1 feed serving STIX bundles. ATT&CK matrix visualization on dashboard showing detection coverage.

---

## WEEK 7: Batch Operations + PDF Export (Days 31-35)

### Day 31 (Monday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add batch approve/reject API endpoints | `POST /api/sentinel/playbooks/batch/approve` accepts list of IDs |
| **V** | Build PDF export — prefer existing `jspdf` | Evaluate client-side PDF with `jspdf` + `jspdf-autotable` (already in `package.json` devDependencies) before adding a Python PDF library. If client-side works: Manideep adds export button in React. If not: use `reportlab` or `weasyprint` server-side as fallback |
| **K** | Add playbook versioning — store revision history | When playbook is regenerated, keep previous version. Add `version` column |
| **M** | Add multi-select checkboxes to playbook list | Select multiple → batch approve/reject buttons appear |

### Day 32 (Tuesday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add search/filter to sentinel API | Support: `?search=brute`, `?technique=T1110`, `?severity=CRITICAL`, `?date_from=`, `?date_to=` |
| **V** | Build PDF export function | `generate_pdf(playbook_markdown) -> bytes` | Convert Markdown playbook to styled PDF with PhantomNet header/footer |
| **K** | Add automated sentinel generation scheduler | Option to run sentinel generation every N minutes via existing scheduler_service |
| **M** | Add search bar and advanced filters to Sentinel Dashboard | Text search + dropdowns for severity, status, technique |

### Day 33 (Wednesday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add dashboard analytics to sentinel stats | Stats: playbooks by severity chart, approval rate, avg confidence, generation trend |
| **V** | Integrate PDF export into API | `POST /api/sentinel/playbooks/{id}/export?format=pdf` returns PDF file |
| **K** | Add email notification on playbook generation (optional) | If email configured in SystemConfig, send notification when CRITICAL playbook generated |
| **M** | Build Sentinel stats panel | Charts: playbooks over time, severity breakdown pie chart, approval rate |

### Day 34 (Thursday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add sentinel metrics to Prometheus /metrics endpoint | Counters: sentinel_playbooks_total, sentinel_approved_total, sentinel_generation_seconds |
| **V** | Test PDF output quality | Verify: tables render, code blocks formatted, ATT&CK links clickable |
| **K** | Write comprehensive tests for scheduler integration | Test: auto-generation triggers, interval config, disable toggle |
| **M** | Add export format selector (Markdown/PDF/JSON/STIX) in PlaybookViewer | Dropdown menu, each triggers correct API call |

### Day 35 (Friday)

| Dev | Task | Deliverable |
|---|---|---|
| **ALL** | Integration test: batch operations + PDF + scheduler |
| **ALL** | Document any bugs for Week 8 |

**Week 7 Checkpoint**: Batch approve/reject, PDF export, scheduled auto-generation, search/filter, stats charts.

---

## WEEK 8: Testing, Validation & Catch-Up (Days 36-40)

### Day 36 (Monday)

| Dev | Task |
|---|---|
| **S** | Fix P0 bugs from Weeks 5-7. Run full test suite |
| **V** | Fix rule generation edge cases found in testing |
| **K** | Fix LLM/playbook issues. Verify fallback works reliably |
| **M** | Fix all UI bugs — responsive issues, data display errors |

### Day 37 (Tuesday)

| Dev | Task |
|---|---|
| **S** | Load test sentinel pipeline: generate 50 playbooks rapidly, verify no DB issues |
| **V** | Validate all Snort rules generated in Month 2 are syntactically correct |
| **K** | Validate all Sigma rules against Sigma schema |
| **M** | Performance test dashboard with 100+ playbooks in list — verify no lag |

### Day 38 (Wednesday)

| Dev | Task |
|---|---|
| **S** | Security review: sentinel API endpoints have proper error handling, no SQL injection in search |
| **V** | Test TAXII endpoints with different filter combinations |
| **K** | Test LLM with edge cases: very large clusters, single-event clusters, multi-protocol campaigns |
| **M** | Accessibility check: keyboard navigation, screen reader labels, color contrast |

### Day 39 (Thursday)

| Dev | Task |
|---|---|
| **S** | Update API documentation (OpenAPI spec `api/openapi.yaml`) with sentinel endpoints |
| **V** | Update `docs/` with TAXII feed documentation |
| **K** | Update `docs/` with LLM setup guide and prompt engineering notes |
| **M** | Final UI polish pass — consistent spacing, colors, fonts across sentinel components |

### Day 40 (Friday)

| Dev | Task |
|---|---|
| **ALL** | Git commit + push. Merge Month 2 work to main |
| **ALL** | Month 2 demo — record full pipeline with LLM, TAXII, PDF export |
| **ALL** | Review Month 3 plan |

**MONTH 2 COMPLETE**: LLM integration (optional), TAXII 2.1 feed server, ATT&CK matrix visualization, PDF export, batch operations, scheduled generation, search/filter, stats dashboard.

---

# MONTH 3: PRODUCTION POLISH + FINAL DELIVERY

**Goal**: Professional-grade finish. Comprehensive testing, documentation, demo preparation, performance optimization, and final submission.

---

## WEEK 9: Advanced Features + Edge Cases (Days 41-45)

### Day 41 (Monday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add playbook comparison view | Side-by-side view of two playbooks for same technique (different campaigns) |
| **V** | Add CVE mapping for known exploit patterns | Map HTTP_SQL_INJECTION → relevant CVE examples, HTTP_PATH_TRAVERSAL → CVE examples |
| **K** | Add playbook quality scoring | Score each playbook: IOC count, cluster size, confidence, multi-source bonus → display as quality badge |
| **M** | Verify Sentinel components respect existing dark/light theme | ThemeToggle.jsx already exists in Navbar, ThemeProvider wraps entire app in App.jsx. Sentinel components automatically inherit theme. **Do NOT rebuild dark mode.** Check each sentinel component uses CSS variables from theme context. Fix any hardcoded colors |

### Day 42 (Tuesday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add webhook notification support | POST to configurable URL when CRITICAL playbook generated |
| **V** | Add combined rule export | "Download All Rules" button → ZIP file with all approved Snort + Sigma rules |
| **K** | Add campaign timeline visualization data | API returns events-over-time for each campaign, for charting |
| **M** | Build campaign timeline chart in PlaybookViewer | Line chart showing event density over campaign duration |

### Day 43 (Wednesday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add audit log for sentinel actions | Log: who approved/rejected, when, what changed. Store in DB |
| **V** | Add rule deduplication | Don't generate duplicate Snort rules for same IP+port+technique |
| **K** | Add playbook template preview in admin panel | Admin can see available templates and their structure |
| **M** | Add export history to PlaybookViewer | Show when and in what format a playbook was exported |

### Day 44 (Thursday)

| Dev | Task | Deliverable |
|---|---|---|
| **S** | Add rate limiting to sentinel generation API | Prevent abuse: max 10 manual generations per hour |
| **V** | Final Snort/Sigma rule quality pass | Review every generated rule type for accuracy and best practices |
| **K** | Add automated playbook cleanup | Auto-archive rejected playbooks older than 30 days |
| **M** | Responsive design pass — test on tablet/mobile viewports |

### Day 45 (Friday)

| Dev | Task | Deliverable |
|---|---|---|
| **ALL** | Feature freeze — no new features after today |
| **ALL** | Create final bug list from all testing |
| **ALL** | Prioritize: P0 must fix, P1 should fix, P2 nice-to-fix |

---

## WEEK 10: Comprehensive Testing (Days 46-50)

### Day 46 (Monday)

| Dev | Task |
|---|---|
| **S** | Run full pytest suite — all tests must pass. Fix any failures |
| **V** | Stress test: 100 concurrent playbook generations. Check DB integrity |
| **K** | Test LLM with all 12 attack patterns. Document output quality for each |
| **M** | Full UI test: every button, every link, every filter, every export |

### Day 47 (Tuesday)

| Dev | Task |
|---|---|
| **S** | Security audit: check all API endpoints for auth (if required), input validation, error handling |
| **V** | Test TAXII feed with 500+ STIX objects. Verify pagination and performance |
| **K** | Test sentinel with real honeypot data (start honeypots, run attack simulations, verify pipeline) |
| **M** | Test with empty database — verify graceful empty states everywhere |

### Day 48 (Wednesday)

| Dev | Task |
|---|---|
| **S** | Fix all P0 and P1 bugs from testing |
| **V** | Fix all P0 and P1 bugs from testing |
| **K** | Fix all P0 and P1 bugs from testing |
| **M** | Fix all P0 and P1 bugs from testing |

### Day 49 (Thursday)

| Dev | Task |
|---|---|
| **S** | Run full regression test — everything still works after bug fixes |
| **V** | Docker build test — verify `docker-compose up` builds and runs clean |
| **K** | Verify LLM graceful degradation — system works perfectly without Ollama installed |
| **M** | Final visual QA — screenshots of every page for documentation |

### Day 50 (Friday)

| Dev | Task |
|---|---|
| **ALL** | Sign off on testing. All P0/P1 bugs fixed. P2 documented but acceptable |
| **ALL** | Commit "Release Candidate 1" |

---

## WEEK 11: Documentation + Demo Preparation (Days 51-55)

### Day 51 (Monday)

| Dev | Task |
|---|---|
| **S** | Rewrite README.md — complete project description with V3 architecture |
| **V** | Write `docs/sentinel_layer.md` — technical documentation for Sentinel module |
| **K** | Write `docs/llm_integration.md` — setup guide, prompt docs, model requirements |
| **M** | Create architecture diagram (draw.io or Mermaid) showing full pipeline |

### Day 52 (Tuesday)

| Dev | Task |
|---|---|
| **S** | Write API documentation — all sentinel endpoints with request/response examples |
| **V** | Write `docs/ids_rules.md` — explain Snort/Sigma rule format and how they're generated |
| **K** | Write `docs/playbook_templates.md` — how to add new templates, template variables |
| **M** | Create demo script — step-by-step what to show in a live demo |

### Day 53 (Wednesday)

| Dev | Task |
|---|---|
| **S** | Record demo video #1: Full pipeline — attack → playbook → approve → export |
| **V** | Record demo video #2: IDS rule generation + TAXII feed consumption |
| **K** | Record demo video #3: LLM enhancement + ATT&CK matrix coverage |
| **M** | Record demo video #4: Dashboard walkthrough — all pages including Sentinel |

### Day 54 (Thursday)

| Dev | Task |
|---|---|
| **S** | Write project report section: architecture and design decisions |
| **V** | Write project report section: security features and threat detection |
| **K** | Write project report section: ML pipeline and AI integration |
| **M** | Write project report section: dashboard design and user experience |

### Day 55 (Friday)

| Dev | Task |
|---|---|
| **ALL** | Review all documentation for accuracy and completeness |
| **ALL** | Compile demo videos into presentation |
| **ALL** | Update GitHub repo: README, docs/, demo GIFs |

---

## WEEK 12: Final Polish + Submission (Days 56-60)

### Day 56 (Monday)

| Dev | Task |
|---|---|
| **S** | Final code cleanup — remove debug prints, unused imports, TODO comments |
| **V** | Final code cleanup — rule_generator, TAXII, tests |
| **K** | Final code cleanup — playbook_generator, llm_service, templates |
| **M** | Final code cleanup — React components, remove console.logs, unused state |

### Day 57 (Tuesday)

| Dev | Task |
|---|---|
| **S** | Version bump, changelog, release notes |
| **V** | Verify Docker deployment works clean from scratch (`docker-compose up --build`) |
| **K** | Verify fresh install works: clone → install deps → run → see dashboard |
| **M** | Final screenshot set for README and report |

### Day 58 (Wednesday)

| Dev | Task |
|---|---|
| **ALL** | Full system test on clean environment — fresh database, no cached data |
| **ALL** | Run complete demo from start to finish, record for backup |

### Day 59 (Thursday)

| Dev | Task |
|---|---|
| **ALL** | Presentation rehearsal — each person presents their section |
| **ALL** | Fix any last-minute issues found during rehearsal |

### Day 60 (Friday)

| Dev | Task |
|---|---|
| **ALL** | Final git push — tag release `v3.0.0` |
| **ALL** | Submit project |
| **ALL** | 🎉 Done |

---

# DELIVERABLES SUMMARY

| Deliverable | Month |
|---|---|
| `detected_signatures` column in PacketLog + signature storage in ThreatAnalyzer | 1 |
| MITRE ATT&CK mapper (12 techniques) | 1 |
| Snort + Sigma rule auto-generation | 1 |
| Jinja2 playbook templates (4 attack patterns) | 1 |
| Enhanced STIX 2.1 bundles | 1 |
| SentinelPlaybook DB model + 10 API endpoints | 1 |
| Sentinel Dashboard (list, view, approve, reject, export) | 1 |
| 3 end-to-end demo scenarios | 1 |
| Ollama/Mistral LLM integration (optional toggle) | 2 |
| TAXII 2.1 feed server | 2 |
| ATT&CK matrix visualization | 2 |
| PDF export | 2 |
| Batch operations + search/filter | 2 |
| Scheduled auto-generation | 2 |
| CVE mapping | 3 |
| Campaign timeline visualization | 3 |
| Audit logging + webhook notifications | 3 |
| Comprehensive test suite | 3 |
| Full documentation + demo videos | 3 |
| Production-ready release v3.0.0 | 3 |

---

# RISK MITIGATION RULES

1. **If LLM doesn't work well by Week 5 Day 25** → Ship with templates only. LLM becomes documentation-only ("supports LLM enhancement"). Don't waste more time.
2. **If TAXII is too complex** → Simplify to a basic `/api/sentinel/stix/feed` endpoint returning STIX JSON. Skip full TAXII spec compliance.
3. **If PDF generation has library issues on Windows** → Skip PDF. Export Markdown + JSON only. It's a nice-to-have.
4. **If any developer is blocked** → Move to writing tests or documentation. No idle days.
5. **Week 4, 8, 12 are buffers** → Use them. Never skip testing weeks to add features.
6. **Feature freeze is Week 9 Day 45** → Absolutely no new features after this. Only fixes and polish.
