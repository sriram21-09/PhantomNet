<div align="center">

  <h1>🛡️ PhantomNet</h1>
  <p><b>Enterprise-Grade Distributed Honeypot & Threat Intelligence Platform</b></p>

  <p>
    <img src="https://img.shields.io/badge/Version-2.0.0-00ff41?style=for-the-badge&logo=github" alt="Version" />
    <img src="https://img.shields.io/badge/License-MIT-009688?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License" />
    <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
    <img src="https://img.shields.io/badge/React-19.0+-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
    <img src="https://img.shields.io/badge/PostgreSQL-15+-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" />
    <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
    <img src="https://img.shields.io/badge/Status-Production_Ready-success?style=for-the-badge" alt="Status" />
  </p>

  <p>
    <a href="#-project-overview">Overview</a> •
    <a href="#-features--capabilities">Features</a> •
    <a href="#%EF%B8%8F-architecture">Architecture</a> •
    <a href="#-installation--setup">Setup</a> •
    <a href="#-api-reference--integration">API</a> •
    <a href="#-contributing">Contributing</a>
  </p>
</div>

---

## 📌 Project Overview

**PhantomNet** is a high-performance, distributed honeypot architecture engineered to provide real-time threat intelligence and active deception. Moving beyond traditional static honeypots, PhantomNet deploys an intelligent, multi-protocol mesh that actively engages attackers, records lateral movement attempts, and analyzes malicious behavior through an embedded AI/ML engine.

Designed for scalability and rapid deployment, the architecture leverages a microservices model orchestrated via Docker. It continuously scores network anomalies using predictive models and provides security operators with actionable telemetry through a low-latency WebSocket dashboard.

### Core Engineering Principles
* **Active Deception:** Engage attackers rather than passively logging them to increase dwell time and extract higher-quality Indicators of Compromise (IOCs).
* **Data-Driven Defense:** Every packet is processed, scored, and categorized for behavioral attribution.
* **Microservices Architecture:** Independently scalable protocol handlers ensure system resilience under heavy reconnaissance loads.
* **Zero-Trust Observability:** Full visibility into the deception network without exposing the core infrastructure.

---

## ✨ Features & Capabilities

### 🍯 Distributed Deception Network
*   **Protocol-Specific Handlers:** High-fidelity simulated environments for **SSH** (2222), **HTTP** (8080), **FTP** (2121), and **SMTP** (2525).
*   **Dynamic Response Engineering:** Adaptive honeypot behavior that mimics real system responses to increase attacker dwell time.
*   **Stateful Connection Tracking:** Captures full session data, including brute-force attempts, payload delivery, and directory traversal traps.

### 🧠 Threat Intelligence & Machine Learning
*   **Real-Time Threat Scoring:** Embedded `IsolationForest` and `RandomForest` pipelines that score packet anomalies (0-100) within milliseconds.
*   **Predictive Analytics (LSTM-V3):** Time-series forecasting of attack volumes and automated risk assessments.
*   **Behavioral Attribution:** Cross-references attacker behavior against known tool signatures to build comprehensive threat profiles.
*   **Automated Active Defense:** Configurable rule engine to issue automated ALLOW, ALERT, or BLOCK directives based on confidence thresholds.

### 📊 Observability & Telemetry
*   **Low-Latency NOC Dashboard:** React 19 based interface with WebSocket integration for real-time event streaming and auto-scrolling telemetry buffers.
*   **Advanced Analytics:** Interactive metrics, sparklines, and threat distribution charts.
*   **Threat Hunting Interface:** Comprehensive case management, IOC extraction, and historical data correlation.
*   **Role-Based Access Control (RBAC):** JWT-secured admin panel with granular permissions (Admin/Analyst/Viewer).

---

## 🏗️ Architecture

PhantomNet is built on a modular, decoupled architecture separating ingestion, processing, and visualization.

```mermaid
graph TD
    %% Core Nodes
    Attacker[External Attackers] -->|Scans / Exploits| Honeypots
    
    subgraph Deception Mesh ["🍯 Honeypot Network"]
        SSH[SSH :2222]
        HTTP[HTTP :8080]
        FTP[FTP :2121]
        SMTP[SMTP :2525]
    end
    
    Honeypots -->|Asynchronous Logging| DB[(PostgreSQL)]
    Sniffer[Traffic Sniffer] -->|Raw Packet Capture| DB
    
    DB -->|Batch Polling| Analyzer[Threat Analysis Engine]
    Analyzer -->|Feature Extraction| ML[ML Pipeline]
    ML -->|Risk Score| Analyzer
    Analyzer -->|Commit Updates| DB
    
    API[FastAPI Backend] -->|REST & WebSockets| DB
    Dashboard[React NOC] -->|Query| API
    Dashboard -->|Visualization| SecOps[SecOps Analyst]
```

<details>
<summary><b>📐 View Detailed Architecture Diagrams</b></summary>

#### 1. System Architecture
<img width="2328" height="3411" alt="System Architecture" src="https://github.com/user-attachments/assets/1a0eeeec-0e93-4d98-bcea-eb14b3d5f743" />

#### 2. Data Flow Diagram
<img width="1396" height="2052" alt="Data Flow Diagram" src="https://github.com/user-attachments/assets/e4bb15e0-4755-4ea9-a52c-075db8c7fa5c" />

#### 3. Deployment Architecture
<img width="2462" height="1176" alt="Deployment Architecture" src="https://github.com/user-attachments/assets/8c03a833-ab38-45d8-b93b-794c01bb1c73" />

#### 4. Database Schema (ERD)
<img width="1648" height="1787" alt="Database Schema" src="https://github.com/user-attachments/assets/52b4fb98-1777-468c-8afb-888968574e76" />
</details>

---

## 🛠️ Technology Stack

| Domain | Technologies | Purpose |
| :--- | :--- | :--- |
| **Backend API** | Python 3.11, FastAPI, Uvicorn | High-concurrency REST API, WebSocket streams |
| **Data Persistence** | PostgreSQL 15, SQLAlchemy 2.0 | Relational event storage, query optimization |
| **Machine Learning** | scikit-learn, joblib, MLflow | Threat scoring, model versioning, feature extraction |
| **Frontend UI** | React 19.2, Vite, Tailwind CSS | Reactive, component-driven security dashboard |
| **Infrastructure** | Docker, Docker Compose | Service orchestration and isolation |
| **Network Tools** | Scapy, Paramiko, pyftpdlib | Traffic sniffing, protocol simulation |

---

## 🚀 Installation & Setup

### Prerequisites
- Docker Engine 24.0+
- Docker Compose v2.0+
- Minimum Specifications: 2 CPU Cores, 4GB RAM

### Production Deployment (Recommended)

1. **Clone the Repository**
   ```bash
   git clone https://github.com/sriram21-09/PhantomNet.git
   cd PhantomNet
   ```

2. **Configure Environment Variables**
   ```bash
   cp .env.example .env
   # Edit .env with secure credentials
   ```

3. **Deploy the Deception Mesh**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

4. **Verify Service Health**
   ```bash
   docker-compose ps
   curl -X GET http://localhost:8000/health
   ```

### Local Development Setup

<details>
<summary><b>View Local Setup Instructions</b></summary>

**Backend Initialization:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Or venv\Scripts\Activate.ps1 on Windows
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

**Frontend Initialization:**
```bash
cd frontend-dev
npm install
npm run dev
```
</details>

---

## 🔌 API Reference & Integration

PhantomNet provides a fully documented REST API for seamless SIEM integration and external querying.

| Endpoint | Method | Description | Authentication |
| :--- | :--- | :--- | :--- |
| `/api/v1/events/stream` | `WS` | Low-latency WebSocket event stream | JWT Required |
| `/api/v1/threat/analyze` | `POST` | Synchronous packet anomaly scoring | API Key |
| `/api/v1/metrics/forecast`| `GET` | Retrieve LSTM-based attack forecasts | JWT Required |
| `/api/v1/system/health` | `GET` | Cluster health and connectivity status | None |

*Interactive OpenAPI 3.0 documentation is automatically generated and accessible at `http://localhost:8000/docs` when the backend is running.*

---

## 💻 Usage & Workflows

### 1. Interacting with Honeypots
Security operators can validate the deception mesh by simulating reconnaissance using standard networking tools:
```bash
# Test SSH Honeypot
ssh -p 2222 root@localhost

# Test HTTP Honeypot
curl -I http://localhost:8080/admin

# Test FTP Honeypot
ftp localhost 2121
```

### 2. Monitoring the Dashboard
Navigate to `http://localhost:3000` to access the NOC dashboard. The initial dashboard view provides:
- Live event stream parsing.
- ML threat scores on incoming packets.
- GeoIP mapping of attacker origins.

---

## 📂 Project Structure

```text
PhantomNet/
├── backend/                  # Core FastAPI application
│   ├── api/                  # REST routers and dependency injection
│   ├── core/                 # App configuration and security middleware
│   ├── models/               # SQLAlchemy ORM definitions
│   ├── services/             # Threat analysis and ML inference pipelines
│   └── main.py               # Application entrypoint
├── frontend-dev/             # React 19 Dashboard
│   ├── src/
│   │   ├── components/       # Reusable UI elements (Tailwind)
│   │   ├── pages/            # Dashboard views (Analytics, NOC, Settings)
│   │   └── services/         # Axios API clients and WebSocket hooks
├── honeypots/                # Protocol simulation modules
│   ├── ftp/                  # FTP trap implementation
│   ├── http/                 # Web application trap
│   └── ssh/                  # SSH authentication trap
├── ml_models/                # Serialized model artifacts (IsolationForest)
└── docker-compose.yml        # Multi-container orchestration
```

---

## 🛡️ Security & Hardening

PhantomNet is built with a defense-in-depth philosophy:
- **Container Isolation:** Every honeypot runs in a segregated Docker network to prevent lateral movement to the host machine.
- **Input Sanitization:** All incoming requests to the API are strictly validated using Pydantic v2 schemas.
- **Database Hardening:** Parameterized queries via SQLAlchemy prevent SQL injection.
- **Credential Management:** Secrets are strictly managed via environment variables and never committed to version control.

---

## 📈 Performance & Scalability

The system is architected to handle high-throughput network events:
- **Asynchronous Processing:** The FastAPI backend utilizes `asyncio` for non-blocking I/O operations, ensuring sub-15ms response times.
- **Batch Processing:** The `ThreatAnalyzerService` polls unscored logs in configurable batch sizes to eliminate database bottlenecking.
- **Stateless API:** Enables immediate horizontal scaling of the backend services behind a load balancer.

---

## 🗺️ Roadmap

- **Phase 1: Foundation (Completed)** - Architecture setup, multi-protocol honeypots, database schemas.
- **Phase 2: Intelligence (Completed)** - ML integration, predictive analytics, WebSocket streaming.
- **Phase 3: Hardening (Current)** - Multi-tenancy support, API rate limiting, RBAC refinement.
- **Phase 4: Scale (Upcoming)** - Kubernetes Operator for dynamic honeypot scaling, distributed database integration (e.g., ClickHouse) for high-volume logs.

---

## 🤝 Contributing

We welcome contributions from the open-source community. Please adhere to the following workflow:

1. **Fork the Repository**
2. **Create a Feature Branch:** `git checkout -b feature/enhanced-ssh-trap`
3. **Commit Changes:** Use conventional commits (e.g., `feat: implemented new ML pipeline`).
4. **Push to Branch:** `git push origin feature/enhanced-ssh-trap`
5. **Open a Pull Request:** Ensure all CI checks and tests pass before requesting review.

Refer to our [`CONTRIBUTING.md`](docs/CONTRIBUTING.md) for detailed guidelines and coding standards.

---

## 📚 Documentation

For deep technical dives, refer to our extended documentation:
- [System Architecture](docs/system_architecture.md)
- [API Design Specification](docs/api_design.md)
- [OpenAPI Specification](backend/api/openapi.yaml)
- [Integration Test Reports](docs/integration_test_week8.md)

---

## 📜 License

This project is licensed under the **MIT License**. See the `LICENSE` file for full details.

---

## 👥 Authors & Credits

Engineered with precision by the PhantomNet Core Team:
* **Kasukurthi Sriram** – Team Lead / Security Architect ([@sriram21-09](https://github.com/sriram21-09))
* **Muramreddy Vivekanandareddy** – Security Engineer ([@VivekanandaReddy2006](https://github.com/VivekanandaReddy2006))
* **Nattala Vikranth Chakravarthi** – AI/ML Engineer ([@Vikranth-tech](https://github.com/Vikranth-tech))
* **Satti Sai Ram Manideep Reddy** – Frontend Architect ([@sairammanideepreddy2123](https://github.com/sairammanideepreddy2123))

<br />
<div align="center">
  <b>"Detecting Threats Before They Strike"</b>
</div>