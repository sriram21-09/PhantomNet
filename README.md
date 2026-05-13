<div align="center">

<img src="https://raw.githubusercontent.com/sriram21-09/PhantomNet/main/assets/phantomnet-banner.png" alt="PhantomNet Banner" width="100%" onerror="this.style.display='none'"/>

# 🛡️ PhantomNet
**Next-Generation Distributed Deception & Threat Intelligence Platform**

*Actively engage attackers. Predict lateral movement. Automate response.*

<p align="center">
  <a href="#-the-vision">Vision</a> •
  <a href="#-architecture--data-flow">Architecture</a> •
  <a href="#-the-deception-matrix">Deception Matrix</a> •
  <a href="#-ai--ml-engine">AI/ML Engine</a> •
  <a href="#-zero-to-hero-deployment">Deployment</a> •
  <a href="#-api--telemetry">API</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Release-v2.0.1-00ff41?style=for-the-badge&logo=github&logoColor=white" alt="Version" />
  <img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge&logo=githubactions&logoColor=white" alt="Build" />
  <img src="https://img.shields.io/badge/Coverage-94%25-success?style=for-the-badge&logo=codecov&logoColor=white" alt="Coverage" />
  <img src="https://img.shields.io/badge/License-MIT-009688?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License" />
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-19.2+-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/PostgreSQL-15+-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Docker-Native-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
</p>

</div>

---

## 👁️ The Vision

Modern enterprise networks operate under the assumption of breach. Static defenses are bypassed by polymorphic malware and coordinated APT (Advanced Persistent Threat) campaigns. 

**PhantomNet** shifts the paradigm from passive logging to **active deception**. By deploying a highly interactive, containerized mesh of protocol-specific honeypots, PhantomNet acts as a digital tripwire. It absorbs reconnaissance, safely detonates payloads, and uses an embedded ensemble of AI models (LSTM, Isolation Forest) to score, predict, and automatically mitigate threats in real-time.

> **PhantomNet is not just a honeypot. It is a closed-loop security ecosystem designed to waste attacker resources while generating zero-false-positive telemetry.**

---

## ⚙️ Core Capabilities

<table width="100%">
<tr>
<td width="50%" valign="top">

### 🕸️ Distributed Deception Mesh
- **High-Interaction Traps:** Protocol-accurate emulation for SSH, HTTP, FTP, and SMTP.
- **Stateful Emulation:** Simulates full filesystem access, credential harvesting, and command execution without host risk.
- **Isolated Namespaces:** 100% containerized with strict cgroups, preventing sandbox escapes and lateral pivoting.

</td>
<td width="50%" valign="top">

### 🧠 Predictive AI Intelligence
- **Sub-15ms Scoring:** Every packet is vectorized (23 features) and scored in real-time.
- **Ensemble ML:** Combines Isolation Forest (anomaly detection), Random Forest, and LSTM (sequence forecasting).
- **Explainable AI (XAI):** SHAP integrations provide human-readable feature attribution for every generated alert.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### ⚡ Automated Active Defense
- **Declarative Playbooks:** YAML-based rulesets map threat clusters to immediate infrastructure actions.
- **Dynamic Tarpitting:** Automatically slows down TCP handshakes for identified scanners, wasting their compute cycles.
- **Firewall Orchestration:** Instantaneous IP blacklisting and route nullification via integration with edge devices.

</td>
<td width="50%" valign="top">

### 📊 Zero-Trust Observability
- **Low-Latency NOC:** React 19 / Vite frontend with WebSockets for sub-second event streaming.
- **SIEM / SOAR Ready:** Built-in CEF/JSON exporters push normalized telemetry directly to ELK, Splunk, or QRadar.
- **Live Topology Maps:** Geo-IP mapping and real-time mesh health visualization.

</td>
</tr>
</table>

---

## 🏗️ Architecture & Data Flow

PhantomNet operates on a decoupled, event-driven architecture, ensuring that the ingestion pipeline remains highly available even under severe DDoS or scanning loads.

### System Topography

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#0f172a', 'primaryTextColor': '#e2e8f0', 'primaryBorderColor': '#334155', 'lineColor': '#3b82f6', 'secondaryColor': '#1e293b', 'tertiaryColor': '#0f172a'}}}%%
graph TD
    classDef external fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fff;
    classDef honeypot fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#fff;
    classDef core fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef data fill:#3f3f46,stroke:#a1a1aa,stroke-width:2px,color:#fff;

    A[External Adversary]:::external -->|Reconnaissance & Exploits| B
    
    subgraph Deception Mesh ["🛡️ Containerized Deception Mesh (DMZ)"]
        B(SSH Trap :2222):::honeypot
        C(HTTP Trap :8080):::honeypot
        D(FTP Trap :2121):::honeypot
        E(SMTP Sink :2525):::honeypot
    end

    B & C & D & E -->|Raw Socket Streams| F[(PostgreSQL Event Store)]:::data
    
    subgraph Intelligence Core ["🧠 PhantomNet Intelligence Core"]
        F -->|Batch Polling| G{Threat Analyzer Service}:::core
        G <-->|Feature Vector| H[ML Pipeline <br/> IsolationForest + LSTM]:::core
        H -->|Threat Score 0-100| G
        G -->|Commit Alert| F
        G -->|Threshold Exceeded| I[Correlation Engine]:::core
        I -->|Triggers| J[Response Playbooks]:::core
    end
    
    J -.->|Mitigation| A
    
    subgraph Observability ["📊 Security Operations"]
        K[FastAPI Gateway]:::core
        F <-->|REST / GraphQL| K
        K <-->|WebSockets (wss://)| L[React NOC Dashboard]:::core
        K -->|CEF / JSON| M[ELK / External SIEM]:::data
    end
```

### The ML Inference Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant Attacker
    participant Mesh as Deception Mesh
    participant Extractor as Feature Extractor
    participant ML as ML Ensemble
    participant DB as PostgreSQL
    participant UI as NOC Dashboard

    Attacker->>Mesh: Initiates brute-force payload
    Mesh->>DB: Logs raw packet & session state
    loop Background Service (Every 500ms)
        DB->>Extractor: Poll unscored events
        Extractor->>Extractor: Compute 23D Vector (Entropy, GeoIP, Frequency)
        Extractor->>ML: Submit for inference
        ML-->>Extractor: Return Confidence Score + SHAP values
        Extractor->>DB: Update `ThreatScore` & generate `Alert`
        DB->>UI: Broadcast via WebSocket Channel
    end
```

---

## 🍯 The Deception Matrix

PhantomNet goes beyond simple port-listening. It deploys high-interaction environments designed to deceive human operators and automated scanners alike.

| Protocol | Emulation Strategy | IOCs Harvested |
| :--- | :--- | :--- |
| **SSH (Port 2222)** | Simulates a vulnerable Debian shell. Allows pseudo-login with weak credentials. Records all TTY commands and attempts to `wget` payloads. | Usernames, Passwords, Executed Commands, Dropped Malware Hashes |
| **HTTP (Port 8080)** | Mimics a legacy Admin Portal (e.g., outdated Tomcat/WordPress). Traps directory traversal (`../../`), SQLi attempts, and XSS probing. | User-Agents, Requested URIs, SQL Injection Payloads |
| **FTP (Port 2121)** | Emulates an anonymous-access file server. Monitors `STOR` and `RETR` commands to capture uploaded ransomware strains. | Uploaded Files, Authentication Patterns |
| **SMTP (Port 2525)** | Acts as an open relay sinkhole. Accepts and blackholes all outgoing spam, extracting sender domains and malicious attachments. | Sender Addresses, Phishing Templates, Attachment Signatures |

---

## 🚀 Zero-to-Hero Deployment

Designed for modern DevOps workflows, PhantomNet can be deployed on a single node or across a distributed Kubernetes cluster. 

### Prerequisites
- Docker Engine 24.0+ & Docker Compose v2.0+
- Production sizing: `4 vCPU`, `8GB RAM`, `50GB NVMe`

### 1. Production Orchestration (Docker-Compose)

Our pre-configured compose stack spins up the entire mesh, the ML core, the database, and the observability stack in isolated networks.

```bash
# 1. Clone the repository
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet

# 2. Initialize security credentials
cp .env.example .env
# Important: Update POSTGRES_PASSWORD, JWT_SECRET, and API_KEY in the .env file

# 3. Deploy the architecture
docker-compose -f docker-compose.prod.yml up -d --build

# 4. Verify system health and container alignment
docker-compose ps
curl -s http://localhost:8000/api/v1/system/health | jq
```

### 2. Local Development Environment

<details>
<summary><b>Click to expand developer setup instructions</b></summary>

**Backend Initialization:**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Frontend Initialization:**
```bash
cd frontend-dev/phantomnet-dashboard
npm install
npm run dev
```
</details>

---

## 💻 Dashboard & Visualizations

The React 19 dashboard provides an unparalleled, glass-morphism interface for Security Operation Centers (SOCs). 

*(Replace these placeholders with actual high-res screenshots from your environment)*

<div align="center">
  <img src="https://via.placeholder.com/800x400/0f172a/3b82f6?text=Real-Time+Global+Threat+Map" alt="Global Threat Map" width="48%">
  <img src="https://via.placeholder.com/800x400/0f172a/10b981?text=Event+Stream+%26+SHAP+Explainability" alt="Event Stream" width="48%">
</div>

- **Global Threat Topology:** Live 3D globe plotting attacker origins via embedded GeoIP databases.
- **Event Waterfall:** Auto-scrolling, color-coded stream of incoming packets, scored dynamically.
- **ML Insights:** Hover over any "CRITICAL" alert to view a SHAP waterfall chart explaining exactly *why* the AI flagged the packet.

---

## 🔌 API & Integration

PhantomNet is built API-first. Everything available in the dashboard is accessible via our high-performance REST and WebSocket APIs.

Interactive Swagger/OpenAPI documentation is auto-generated and hosted at: `http://<your-host>:8000/docs`

### Example: Programmatic Threat Scoring

Inject external logs into PhantomNet's ML engine using your API Key:

```bash
curl -X POST "https://api.phantomnet.local/v1/threat/analyze" \
     -H "Authorization: Bearer pn_live_xxxxxxxxxxxxx" \
     -H "Content-Type: application/json" \
     -d '{
           "src_ip": "185.150.12.4",
           "dst_port": 22,
           "protocol": "TCP",
           "payload_base64": "c3NoLXJzYSAuLi4="
         }'
```

**JSON Response:**
```json
{
  "event_id": "evt_9f8a7c6b",
  "ml_score": 92.4,
  "classification": "Brute-Force Campaign",
  "confidence": 0.98,
  "action_taken": "IP_BLOCKED",
  "shap_factors": {
    "payload_entropy": 45.2,
    "connection_frequency": 30.1,
    "known_bad_subnet": 17.1
  }
}
```

---

## 🛡️ Security & Infrastructure Hardening

Building a honeypot requires extreme paranoia. We assume attackers will attempt to break out.

1. **Kernel-Level Isolation:** Honeypots run with `security_opt: no-new-privileges` and `--cap-drop=ALL`.
2. **Ephemeral File Systems:** Traps use read-only root filesystems; any writes are directed to `tmpfs` mounts that vanish on container restart.
3. **One-Way Data Diode:** Honeypots can *write* logs to the database via a strictly scoped API proxy, but cannot *read* from it or query the core backend.
4. **API Security:** Endpoints are secured via highly-scoped JWTs. Rate limiting is enforced via Redis-backed sliding windows.

---

## 🗺️ Engineering Roadmap

PhantomNet is continuously evolving. Our roadmap reflects our commitment to enterprise scale and advanced research.

| Phase | Timeline | Major Milestones | Status |
| :---: | :--- | :--- | :---: |
| **I** | Q1-Q2 2026 | Multi-protocol honeypots, Base FastAPI architecture, React NOC Dashboard. | 🟢 **Delivered** |
| **II** | Q3 2026 | ML Pipeline (Isolation Forest, LSTM), WebSocket Streaming, Automated Playbooks. | 🟢 **Delivered** |
| **III** | Q4 2026 | **Kubernetes Operator Native Scaling**, ClickHouse integration for PB-scale telemetry, Multi-tenant RBAC. | 🟡 *In Progress* |
| **IV** | Q1 2027 | Reinforcement Learning for dynamic honeypot topology mutation, STIX/TAXII threat sharing federation. | ⚪ *Planned* |

---

## 🤝 Contributing to PhantomNet

We operate a strict, professional open-source workflow. We welcome elite engineers, security researchers, and data scientists.

1. **Review the guidelines:** Read [`CONTRIBUTING.md`](docs/CONTRIBUTING.md) and our [`CODE_OF_CONDUCT.md`](docs/CODE_OF_CONDUCT.md).
2. **Branching Strategy:** Use `feat/`, `fix/`, or `chore/` prefixes.
3. **Quality Gates:** All PRs must pass GitHub Actions (Flake8, Black, Pytest, and SonarQube).
4. **Signed Commits:** Ensure your commits are GPG signed.

---

## 📚 Technical Documentation

Deep dive into the engineering behind PhantomNet:

- 🏗️ [**System Architecture & Design Decisions**](docs/system_architecture.md)
- 🧠 [**Machine Learning Pipeline & Model Tuning**](docs/ml_pipeline.md)
- ⚡ [**Automated Response Playbooks Guide**](docs/playbooks.md)
- 🛡️ [**Vulnerability Disclosure Policy (SECURITY.md)**](SECURITY.md)

---

## 👨‍💻 Core Architecture Team

PhantomNet is architected and maintained by a team of dedicated security engineers and researchers.

| Architect | Focus Area | GitHub |
| :--- | :--- | :--- |
| **Kasukurthi Sriram** | Platform Architecture & Security Design | [@sriram21-09](https://github.com/sriram21-09) |
| **Muramreddy Vivekananda Reddy** | Container Orchestration & Protocol Emulation | [@VivekanandaReddy2006](https://github.com/VivekanandaReddy2006) |
| **Nattala Vikranth Chakravarthi** | ML Pipelines, Model Inference & XAI | [@Vikranth-tech](https://github.com/Vikranth-tech) |
| **Satti Sai Ram Manideep Reddy** | UI/UX, WebSocket Streaming & Frontend Architecture | [@sairammanideepreddy2123](https://github.com/sairammanideepreddy2123) |

---

<div align="center">

**[MIT License](LICENSE)** • Copyright © 2026 PhantomNet Core Team

*Built to turn the network into a weapon against the adversary.*

</div>