# 🎬 PhantomNet V3 — Comprehensive Live Demo Script & User Journey Storyboard

**Document Version:** 3.0.0  
**Target Audience:** SOC Managers, Lead Security Engineers, CISO Office, Technical Evaluators  
**Estimated Demo Duration:** 10 Minutes (Full Demonstration Walkthrough)  
**System Version:** PhantomNet V3.0 (Sentinel Layer Enabled)  

---

## 📌 Executive Summary & System Overview

**PhantomNet V3** is an enterprise-grade, active defense platform that combines containerized deception services, multi-model ML anomaly scoring, MITRE ATT&CK automated threat mapping, and zero-trust incident response orchestration.

This live demonstration script guides the presenter step-by-step through a complete cyber threat lifecycle:
1. **Deception Mesh Ingestion** — Trapping attackers on SSH (`:2222`), HTTP (`:8080`), FTP (`:2121`), and SMTP (`:2525`).
2. **Real-time Anomaly Scoring** — Executing 23D feature extraction and sub-15ms ML ensemble scoring with SHAP explainability.
3. **Sentinel Threat Mapping** — Grouping events into DBSCAN attack campaigns and mapping tactics/techniques to the MITRE ATT&CK matrix.
4. **Automated Playbook & Rule Generation** — Synthesizing production-ready Snort, Sigma rules, and Jinja2 response playbooks.
5. **Analyst Review & Diff Inspection** — Conducting side-by-side playbook diff comparisons and submitting digital approvals.
6. **Threat Intelligence Sharing** — Exporting STIX 2.1 JSON bundles and serving automated TAXII 2.1 collection feeds.

---

## 🗺️ User Journey Storyboard Matrix

| Time | Phase & Goal | Persona / Actor | Active UI Screen / View | Trigger / Action | System Reaction & Backend Event | Key Voiceover Narrative |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **00:00 - 01:00** | **Phase 0: Environment Initialization** | SOC Analyst | NOC Main Dashboard (`/dashboard`) | Access platform, switch theme to Dark Mode | Establish FastAPI WebSocket connection, render Deception Mesh status | *"Welcome to PhantomNet V3. We begin on our Dark-themed SOC Operations Center dashboard monitor."* |
| **01:00 - 02:30** | **Phase 1: Attack Vector Simulation** | Red Team / Attacker | Event Stream & Topology (`/events`, `/topology`) | Execute `python simulation/attack_campaign.py` | Honeypot proxies log session; PostgreSQL receives multi-protocol payload | *"We initiate a multi-staged attack campaign targeting our containerized SSH, HTTP, and FTP honeypots."* |
| **02:30 - 04:00** | **Phase 2: Real-time Detection & ML Scoring** | ML Engineer / SOC | Threat Analytics (`/ml-insights`) | Filter timeline by spikes; hover over SHAP tooltips | Feature vectorizer extracts 23 features; Isolation Forest + Random Forest score anomaly at 96.4/100 | *"In under 15 milliseconds, our ML ensemble detects anomalous velocity spikes and explains why via SHAP feature entropy."* |
| **04:00 - 05:30** | **Phase 3: Sentinel IR & ATT&CK Mapping** | Security Analyst | Sentinel Matrix (`/sentinel`) | Click ATT&CK Technique cell `T1110.001` on Heatmap | MitreMapper links campaign alerts to 12 ATT&CK techniques; renders confidence score (0.89 CRITICAL) | *"The Sentinel Engine correlates cluster events and dynamically illuminates affected tactics across the ATT&CK Matrix."* |
| **05:30 - 07:30** | **Phase 4: Playbook & Diff Comparison** | Senior SOC Lead | Playbook Viewer & Diff (`/sentinel/playbooks`) | Open proposed playbook; launch Side-by-Side Diff Modal | RuleGenerator produces Snort SIDs & Sigma YAML; Diff Modal highlights modified containment steps | *"Sentinel auto-synthesizes Snort rules and Jinja2 playbooks. We launch the split-screen diff viewer to verify rule changes."* |
| **07:30 - 08:30** | **Phase 5: Analyst Review & Approval** | SOC Lead | Approval Modal (`/sentinel/approve`) | Input signature `analyst_admin`, click **Approve Playbook** | API patches status to `APPROVED`, writes audit trail, updates nav badge count | *"With single-click analyst authorization, the incident status transitions from Pending to Approved."* |
| **08:30 - 10:00** | **Phase 6: TAXII Feed & Rule Export** | Security Architect | Export & TAXII (`/sentinel/export`) | Click **Export STIX 2.1 Bundle**; query TAXII endpoint | STIXBuilder outputs STIX 2.1 JSON; TAXII 2.1 server returns structured threat intelligence | *"Finally, our validated threat intelligence is exported as STIX 2.1 objects and published live to our TAXII 2.1 feed."* |

---

## ⏱️ Minute-by-Minute Demonstration Walkthrough

### 🕒 Minute 00:00 - 01:00 | Platform Initialization & Deception Mesh Overview

#### Objective
Establish the baseline operational posture of PhantomNet V3, showcasing the containerized honeypot mesh, dark cyber aesthetic, and active streaming telemetry.

#### Terminal / Environment Setup
```bash
# Ensure containers and FastAPI backend are operational
docker-compose -f docker-compose.prod.yml up -d
curl -s http://localhost:8000/api/v1/health | jq .
```

#### Step-by-Step Actions
1. Open browser to `http://localhost:5173/dashboard`.
2. Observe the dark theme palette (`#0F172A` background, glowing emerald `#00FF41` status indicators).
3. Point out the **Deception Mesh Status Widget** displaying active nodes:
   - **SSH Honeypot** (`:2222`) — Paramiko interactive shell
   - **HTTP Honeypot** (`:8080`) — Web application trap (SQLi, XSS, Path Traversal)
   - **FTP Honeypot** (`:2121`) — Data transfer sink
   - **SMTP Honeypot** (`:2525`) — Mail payload analyzer
4. Show the live connection counter at `0 active attacks / 100% Mesh Health`.

#### UI Callout Highlight
> 🎨 **UI HIGHLIGHT: Dark Cyber SOC Theme**  
> - **Primary Canvas:** Slate-900 background (`#0F172A`) with subtle cyber grid overlay  
> - **Accent Colors:** Electric Emerald (`#00FF41`) for healthy nodes, Warning Amber (`#FFB100`), Critical Red (`#FF0055`)  
> - **Typography:** Inter & JetBrains Mono monospace font for log streams  
> - **Navigation Header:** Glassmorphic translucent header with live ping indicator and pending alert badges  

#### Presenter Voiceover Script
> *"Good morning, team. Welcome to the live demonstration of PhantomNet V3. We begin here on our primary Operations Center dashboard. Designed with an ultra-clean, high-contrast dark theme, PhantomNet immediately provides SOC analysts with zero-noise visibility across our deception mesh. Operating on isolated container ports, our SSH, HTTP, FTP, and SMTP honeypots are actively deployed, awaiting potential adversary interaction with zero risk to production assets."*

---

### 🕒 Minute 01:00 - 02:30 | Phase 1: Multi-Protocol Attack Simulation

#### Objective
Trigger a realistic, multi-stage cyber attack scenario targeting multiple honeypot services simultaneously, generating synthetic traffic logs and alerting streams.

#### Terminal Execution
```bash
# Launch multi-protocol attack campaign from external attacker node (192.168.1.105)
python simulation/attack_campaign.py \
  --target-ip 127.0.0.1 \
  --scenarios ssh_brute,sqli,ftp_exfil \
  --intensity high \
  --duration 60
```

#### Step-by-Step Actions
1. Switch UI tab to **Live Event Stream** (`/events`).
2. Watch as real-time WebSocket log feeds instantly begin scrolling:
   - `[SSH] Auth Failure - User: admin, Pass: 123456 - Source: 192.168.1.105:44321`
   - `[HTTP] POST /login.php - Payload: ' OR '1'='1 - Source: 192.168.1.105:44322`
   - `[FTP] STOR sensitive_exfil.zip - Bytes: 14.2MB - Source: 192.168.1.105:44325`
3. Navigate to **Network Topology View** (`/topology`).
4. Highlight glowing red attack vectors connecting malicious IP `192.168.1.105` directly to SSH, HTTP, and FTP nodes.

#### Presenter Voiceover Script
> *"Now, we trigger a multi-protocol attack campaign using our automated simulation suite. From malicious source IP 192.168.1.105, an attacker executes high-frequency SSH password guessing, followed by web application SQL injection and FTP data exfiltration attempts. Notice how the WebSocket event stream captures raw packets instantaneously, without lagging or dropped frames."*

---

### 🕒 Minute 02:30 - 04:00 | Phase 2: Real-time Traffic Detection & ML Anomaly Scoring

#### Objective
Demonstrate sub-15ms machine learning inference, volume spike detection, 23D feature extraction, and SHAP explainability tooltips.

#### Step-by-Step Actions
1. Navigate to **Threat Analytics / ML Insights** (`/ml-insights`).
2. Observe the **Campaign Timeline Chart** displaying a prominent, steep velocity spike peaking at **450 events/minute**.
3. Click on the anomaly peak to bring up the **23D Feature Vector Card**.
4. Hover over the **SHAP Explainability Tooltip** on the score gauge:
   - **Ensemble Threat Score:** `96.4 / 100` (CRITICAL)
   - **Isolation Forest Anomaly Score:** `-0.42` (High Outlier)
   - **Random Forest Malicious Probability:** `98.7%`
   - **LSTM Volumetric Forecast:** `Attacking Trend: Escalating`
5. Highlight SHAP feature contributions displayed in the breakdown widget:
   - `payload_entropy`: `+42.1%` contribution
   - `request_velocity`: `+28.5%` contribution
   - `failed_auth_count`: `+18.9%` contribution

#### UI Callout Highlight
> 📈 **UI HIGHLIGHT: Timeline Spike & Anomaly Peak Analyzer**  
> - **Interactive Chart:** Dual-axis Recharts area plot comparing historical baseline traffic against incoming spike volume  
> - **Spike Markers:** Neon red pulse animation marking DBSCAN cluster initiation triggers  
> - **Hover Telemetry:** Micro-tooltip revealing 23D vector features (entropy, packet ratio, inter-arrival time)  
> - **SHAP Cards:** Dynamic bar graph illustrating positive/negative feature weights towards ML classification  

#### Presenter Voiceover Script
> *"Transitioning to our Threat Analytics console, we see our real-time ML pipeline in action. As traffic surges, our serialized Isolation Forest and Random Forest ensemble scores each event in under 15 milliseconds. Notice this dramatic velocity spike on the timeline chart. By clicking the peak, our SHAP explainability panel reveals exactly why this was flagged: high payload entropy contributed 42% to the score, while extreme request frequency contributed 28%."*

---

### 🕒 Minute 04:00 - 05:30 | Phase 3: Sentinel Incident Response & MITRE ATT&CK Mapping

#### Objective
Showcase automated correlation of raw alerts into DBSCAN attack campaigns and dynamic mapping to the interactive MITRE ATT&CK Matrix.

#### Step-by-Step Actions
1. Navigate to **Sentinel Dashboard** (`/sentinel`).
2. Point out the aggregate pipeline stats cards:
   - **Total Campaigns:** `14`
   - **Pending Review:** `3` (Highlighted in Warning Amber `#FFB100`)
   - **Approved Playbooks:** `11`
   - **Average Confidence:** `89.2%`
3. Scroll to the **Interactive MITRE ATT&CK Matrix** (`MitreMatrix.jsx`).
4. Observe how tactic columns light up based on detected activity:
   - **Credential Access:** `T1110.001 (Password Guessing)` — Glowing Red (Severity: HIGH)
   - **Initial Access:** `T1190 (Exploit Public-Facing App)` — Glowing Red (Severity: CRITICAL)
   - **Exfiltration:** `T1048.003 (Exfiltration Over Unencrypted Protocol)` — Glowing Red (Severity: CRITICAL)
5. Click on technique cell `T1110.001` to open the **Technique Detail Panel**, displaying associated IP IOCs, hit counts, and rule mapping references.

#### UI Callout Highlight
> 🧩 **UI HIGHLIGHT: Interactive MITRE ATT&CK Heatmap Grid**  
> - **Tactic Columns:** 8 standard MITRE tactics (Reconnaissance → Exfiltration) rendered in dark frosted glass tiles  
> - **Technique Badges:** Color-coded severity indicators (Red = Critical/High, Amber = Medium, Blue = Low)  
> - **Live Coverage Heatmap:** Heatmap density overlay calculating technique hit ratios  
> - **Detail Popover:** Slide-out drawer showing mapped Snort SIDs, Sigma tags (`attack.t1110.001`), and campaign IDs  

#### Presenter Voiceover Script
> *"Here in the Sentinel Console, PhantomNet shifts from passive detection to active threat intelligence synthesis. The correlation engine groups our multi-protocol alerts into Campaign #104. Looking at our live MITRE ATT&CK Heatmap, we see techniques across Credential Access, Initial Access, and Exfiltration automatically illuminate. Clicking T1110.001 reveals full context, including source IPs and associated Snort rule SIDs."*

---

### 🕒 Minute 05:30 - 07:30 | Phase 4: Playbook Generation & Side-by-Side Diff Comparison

#### Objective
Inspect auto-generated Snort rules, Sigma rules, Markdown playbooks, and perform a side-by-side diff comparison between baseline and updated playbooks.

#### Step-by-Step Actions
1. Locate **Campaign #104 Playbook** (`pb-104-ssh-sqli`) in the playbook list.
2. Click **View Playbook** to launch the **Playbook Viewer Modal** (`PlaybookViewer.jsx`).
3. Click through the preview tabs:
   - **Markdown Summary:** Jinja2-rendered narrative containing incident overview, IOC table, and containment steps.
   - **Snort Rules Tab:** Auto-generated rule syntax:
     ```snort
     alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"PHANTOMNET SSH Brute Force Attempt"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 10; reference:url,attack.mitre.org/techniques/T1110/001; classtype:attempted-admin; priority:1; sid:1000104; rev:1;)
     ```
   - **Sigma Rule Tab:** Standard YAML rule with `attack.t1110.001` tags.
4. Click **Compare with Active Baseline** button to open the **Side-by-Side Diff Comparison Modal** (`PlaybookCompareModal.jsx`).
5. Highlight the split-screen visual diff:
   - **Left Pane (Active Baseline v1):** Standard rate-limit threshold `count 10`.
   - **Right Pane (Proposed Campaign v2):** Aggressive containment threshold `count 5`, added IP `192.168.1.105` to auto-tarpit blocklist.
   - **Line Diffs:** Deletions highlighted in red background (`-`), additions highlighted in emerald green (`+`).

#### UI Callout Highlight
> 🔍 **UI HIGHLIGHT: Side-by-Side Playbook Diff Comparison Modal**  
> - **Split View Layout:** Synchronized two-column editor with side-by-side scrolling  
> - **Diff Highlight Colors:** Dark Emerald (`#064E3B`) for added lines, Dark Crimson (`#7F1D1D`) for removed lines  
> - **Syntax Highlighting:** Full syntax highlighting for Snort `.rules`, Sigma `.yml`, and Markdown `.md`  
> - **Change Summary Badge:** Visual pill badge displaying `+14 additions / -4 deletions`  

#### Presenter Voiceover Script
> *"Sentinel V3 automatically synthesizes Snort and Sigma detection signatures alongside Jinja2 containment playbooks. To ensure safety before deployment, SOC leads can click 'Compare with Active Baseline'. The Side-by-Side Diff viewer clearly contrasts our current baseline against the proposed update. Notice the highlighted green additions: Sentinel has lowered the threshold to 5 attempts and added the attacker IP directly to the automated tarpit block list."*

---

### 🕒 Minute 07:30 - 08:30 | Phase 5: SOC Analyst Review & Playbook Approval Workflow

#### Objective
Demonstrate analyst governance, digital signature entry, approval state transition, and notification badge updating.

#### Step-by-Step Actions
1. Inside the Playbook Viewer, scroll down to the **Analyst Governance Panel** (`ApprovalControls.jsx`).
2. Enter reviewer credentials:
   - **Analyst Name / ID:** `analyst_admin`
   - **Approval Note:** `Verified multi-protocol campaign. Approved for immediate perimeter enforcement.`
3. Click the glowing emerald **Approve Playbook** button.
4. Observe the smooth state transition:
   - Status badge morphs from `PENDING_REVIEW` (Amber) to `APPROVED` (Bright Emerald `#00FF41`).
   - Audit timestamp and digital signature hash are recorded in real-time.
5. Point out the top **Navbar Header**: The pending alert badge counter decrements from `3` to `2`.

#### Presenter Voiceover Script
> *"Governance remains central to PhantomNet. AI proposes, but humans authorize. As SOC Lead, I enter my analyst credentials and authorization notes, then click 'Approve Playbook'. Instantly, the state transitions from Pending to Approved with a cryptographically verifiable audit trail, and our global notification badges refresh across the platform."*

---

### 🕒 Minute 08:30 - 10:00 | Phase 6: Threat Intelligence Sharing & TAXII Feed / Rule Export

#### Objective
Demonstrate multi-format threat intelligence export, STIX 2.1 JSON bundle generation, and live TAXII 2.1 API collection polling.

#### Step-by-Step Actions
1. Navigate to **Export & Threat Sharing Panel** (`ExportHistoryPanel.jsx`).
2. Click **Export STIX 2.1 Bundle**.
3. View the generated STIX 2.1 JSON object in the preview drawer:
   - `type`: `bundle`
   - `objects`: `[Identity, AttackPattern (T1110.001), Indicator (192.168.1.105), Relationship]`
   - `marking_refs`: `[TLP:AMBER]`
4. Open terminal and query the live **TAXII 2.1 Collection API**:
   ```bash
   # Poll TAXII 2.1 Collection Objects Endpoint
   curl -X GET "http://localhost:8000/api/taxii/v2.1/collections/sentinel_feed/objects/" \
     -H "Accept: application/taxii+json;version=2.1" | jq .
   ```
5. Show the returning valid TAXII 2.1 JSON envelope containing the newly approved STIX 2.1 bundle objects.
6. Click **Download Snort Bundle (`.rules`)** and **Download Executive PDF Report**.

#### Presenter Voiceover Script
> *"In our final phase, PhantomNet converts internal mitigation into shared threat intelligence. With one click, the approved playbook is compiled into a STIX 2.1 bundle with TLP:AMBER markings. We can verify our live TAXII 2.1 endpoint using curl—returning structured threat objects instantly ready for sharing with ISACs, downstream SIEMs, or peer SOCs. This completes the full loop from attack ingestion to automated defense in under 10 minutes."*

---

## 🎨 UI Highlight Callout Specifications

### 1. Dark Theme Aesthetic Specification
```
-------------------------------------------------------------------------
[ PHANTOMNET V3 NOC CONSOLE ]                      [ STATUS: ONLINE ] 
-------------------------------------------------------------------------
Background: #0F172A (Slate-900)      Card Surface: #1E293B (Slate-800)
Accent Emerald: #00FF41              Accent Cyan: #00E5FF
Warning Amber: #FFB100               Critical Pink: #FF0055
Borders: 1px solid #334155           Font: Inter / JetBrains Mono
-------------------------------------------------------------------------
```

### 2. Interactive ATT&CK Heatmap Grid Layout
```
+-----------------------------------------------------------------------+
|  RECONNAISSANCE  | CREDENTIAL ACCESS | INITIAL ACCESS | EXFILTRATION  |
+------------------+-------------------+----------------+---------------+
| T1595.001        | T1110.001 [CRIT]  | T1190 [HIGH]   | T1048.003     |
| Active Scanning  | Password Guessing | Exploit App    | Exfil Unenc   |
| (Score: 45)      | (Hits: 142)       | (Hits: 28)     | (Hits: 12)    |
+------------------+-------------------+----------------+---------------+
```

### 3. Timeline Spike & Anomaly Peak Visual Blueprint
```
Req/sec
 500 |                                 /\  <-- Peak: 450 req/sec
 400 |                                /  \     (Score: 96.4 CRITICAL)
 300 |                               /    \
 200 |                              /      \
 100 |  ______/--------------------/        \___________
   0 +----------------------------------------------------> Time
     00:00    01:00    02:00    03:00    04:00    05:00
```

### 4. Side-by-Side Playbook Diff Comparison Blueprint
```
+------------------------------------+------------------------------------+
| BASELINE PLAYBOOK (v1.0.0)         | PROPOSED CAMPAIGN PLAYBOOK (v2.0)  |
+------------------------------------+------------------------------------+
| alert tcp $EXT any -> $HOME 22 (   | alert tcp $EXT any -> $HOME 22 (   |
|-  detection_filter: count 10, sec  |+  detection_filter: count 5, sec   |
|   10;                              |   10;                              |
|-  threshold: type limit, count 1;  |+  threshold: type limit, count 5;  |
|   sid:1000104; rev:1;)             |+  tag: attack.t1110.001;           |
|                                    |+  tarpit_target: 192.168.1.105;    |
|                                    |   sid:1000104; rev:2;)             |
+------------------------------------+------------------------------------+
```

---

## 🛠️ Demo Execution Checklist & Backup Contingency Plan

### Pre-Flight Verification Checklist
- [ ] Docker containers running (`docker ps` shows SSH, HTTP, FTP, SMTP honeypots active).
- [ ] FastAPI backend reachable at `http://localhost:8000/docs`.
- [ ] React frontend running at `http://localhost:5173`.
- [ ] Database populated with baseline dataset (`python populate_db.py`).
- [ ] Simulation script `simulation/attack_campaign.py` verified operational.
- [ ] Screen resolution set to **1080p (1920x1080)**, browser zoom at **100%**.

### Contingency Backup Plan (Live Demo Safety Nets)
1. **Network Latency or Slow ML Response:**  
   If live simulation takes > 5 seconds, trigger the instant mock seeding endpoint:  
   `POST http://localhost:8000/api/sentinel/generate?mock_campaign=true`
2. **WebSocket Disconnection:**  
   Click the **Reconnect Telemetry** button in the dashboard footer to re-establish Uvicorn WS stream.
3. **TAXII Server Endpoint Delay:**  
   Use cached STIX bundle file located at `tests/fixtures/sample_stix_bundle.json` for fallback demonstration.

---
*End of Demo Script — Author: PhantomNet V3 Engineering Team*
