
# 🛡️ PhantomNet – AI-Driven Distributed Honeypot Deception Framework

<div align="center">

![PhantomNet](https://img.shields.io/badge/PhantomNet-v2.0-brightgreen?style=for-the-badge&logo=github)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-19.0+-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791?style=for-the-badge&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Phase](https://img.shields.io/badge/Phase_2-Complete-success?style=for-the-badge)

**An intelligent, distributed honeypot system powered by AI/ML that detects, analyzes, and responds to cyber threats in real-time.**

[Features](#-features) • [Architecture](#%EF%B8%8F-architecture) • [Quick Start](#-quick-start) • [API Reference](#-api-reference) • [Team](#-team-members)

</div>

---

## 📋 Table of Contents

- [🎯 About PhantomNet](#-about-phantomnet)
- [✨ Features](#-features)
- [🏗️ Architecture](#%EF%B8%8F-architecture)
- [🛠️ Technology Stack](#%EF%B8%8F-technology-stack)
- [⚡ Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [🔌 API Reference](#-api-reference)
- [🧪 Testing](#-testing)
- [📚 Documentation](#-documentation)
- [📈 Roadmap](#-roadmap)
- [👥 Team](#-team-members)
- [💡 Contributing](#-contributing)

---

## 🎯 About PhantomNet

**PhantomNet** is a final-year engineering capstone project that combines **distributed systems**, **cybersecurity**, and **artificial intelligence** to create an adaptive honeypot mesh. Unlike traditional static honeypots that attackers can easily detect and fingerprint, PhantomNet creates an **intelligent deception layer** that:

- 🔍 **Detects** cyber attacks across multiple protocols (SSH, HTTP, FTP, SMTP) in real-time
- 🧠 **Learns** attacker behavior using IsolationForest anomaly detection and supervised ML models
- 🎯 **Scores** every network packet with a threat probability (0–100) and recommended action
- 📊 **Visualizes** threats on a live cyberpunk-styled dashboard with auto-refresh
- 🔐 **Responds** with automated decisions: ALLOW, ALERT, or BLOCK

### 🎓 Educational Value

This project demonstrates:
- Advanced Python programming for security applications
- Microservices architecture with Docker Compose
- Machine learning in production cybersecurity workloads
- Full-stack development: FastAPI backend + React 19 frontend
- CI/CD with GitHub Actions and MLflow model registry

---

## ✨ Features

### 🍯 Multi-Protocol Honeypots

| Protocol | Port | Status | Capabilities |
|----------|------|--------|-------------|
| **SSH** | 2222 | ✅ Active | Full authentication simulation, command logging, brute-force detection |
| **HTTP** | 8080 | ✅ Active | Fake admin panels, login pages, file upload traps, flood detection |
| **FTP** | 2121 | ✅ Active | Directory traversal traps, file access logging, log rotation |
| **SMTP** | 2525 | ✅ Active | Email spoofing detection, spam trap |
| **Database** | 3306 | 🔮 Planned | SQL injection honeypot, credential theft detection |

### 🤖 AI/ML Threat Analysis Engine

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Threat Scoring** | IsolationForest / RandomForest | Real-time threat probability (0–100) per packet |
| **Feature Extraction** | Custom `FeatureExtractor` (15 features) | Packet size, protocol, port, entropy, rolling stats |
| **Background Analyzer** | `ThreatAnalyzerService` | Polls unscored logs every 5s, updates DB with scores |
| **Model Registry** | MLflow + joblib | Versioned model storage, Production/Staging stages |
| **Caching** | In-memory IP cache (60s TTL) | Avoids redundant scoring for repeat attackers |

### 📊 Protocol Analytics & Attack Detection

- **Brute-Force Detection**: Identifies IPs exceeding threshold within time window
- **HTTP Flood Detection**: Flags potential DDoS sources
- **Time-Series Trends**: Daily attack volume for the last N days
- **Top Attacker Ranking**: Per-protocol IP leaderboards

### 🖥️ Real-Time Dashboard

- **Cyberpunk UI**: Dark mode, matrix-style traffic log, auto-refresh every 2 seconds
- **Threat Charts**: Interactive score distribution visualization
- **Honeypot Status**: Live connectivity and last-seen monitoring
- **Event Filtering**: Filter by threat level (LOW/MEDIUM/HIGH) and protocol

### 🐳 Deployment & Scalability

- **7 Docker Services**: PostgreSQL, SSH, HTTP, FTP, SMTP honeypots, API, Frontend
- **One-Command Deploy**: `docker-compose up -d` brings up the entire platform
- **Production Config**: Resource limits, restart policies, health checks
- **API-First Design**: RESTful API with auto-generated OpenAPI/Swagger docs

---

## 🏗️ Architecture

### System Overview

```mermaid
graph TD
    Attacker[🎭 Attacker] -->|Scans / Attacks| Honeypots
    
    subgraph Honeypots["🍯 Honeypot Network"]
        SSH[SSH :2222]
        HTTP[HTTP :8080]
        FTP[FTP :2121]
        SMTP[SMTP :2525]
    end
    
    Honeypots -->|Log Events| DB[(PostgreSQL)]
    Sniffer[🔍 Traffic Sniffer] -->|Raw Packets| DB
    
    DB -->|Unscored Logs| Analyzer[🧠 Threat Analyzer]
    Analyzer -->|Feature Extraction| ML[ML Engine]
    ML -->|Score + Decision| Analyzer
    Analyzer -->|Update Records| DB
    
    API[⚡ FastAPI Backend] -->|Query| DB
    Dashboard[📊 React Dashboard] -->|REST API| API
    Dashboard -->|Visualize| Admin[👤 Security Admin]
```

### Architecture Diagrams

<details>
<summary>📐 Click to expand all architecture diagrams</summary>

#### 1. System Architecture
<img width="2328" height="3411" alt="System Architecture" src="https://github.com/user-attachments/assets/1a0eeeec-0e93-4d98-bcea-eb14b3d5f743" />

#### 2. Data Flow Diagram
<img width="1396" height="2052" alt="Data Flow Diagram" src="https://github.com/user-attachments/assets/e4bb15e0-4755-4ea9-a52c-075db8c7fa5c" />

#### 3. Component Interaction
<img width="559" height="1970" alt="Component Interaction" src="https://github.com/user-attachments/assets/0180e14a-b795-4255-b067-047002c813d6" />

#### 4. Deployment Architecture
<img width="2462" height="1176" alt="Deployment Architecture" src="https://github.com/user-attachments/assets/8c03a833-ab38-45d8-b93b-794c01bb1c73" />

#### 5. Database Schema (ERD)
<img width="1648" height="1787" alt="Database Schema" src="https://github.com/user-attachments/assets/52b4fb98-1777-468c-8afb-888968574e76" />

#### 6. Network Topology
<img width="1971" height="1354" alt="Network Topology" src="https://github.com/user-attachments/assets/abd39504-1750-43f3-a41a-7b770af7d023" />

#### 7. CI/CD Pipeline
<img width="3604" height="262" alt="CI/CD Pipeline" src="https://github.com/user-attachments/assets/5b2d2168-ac3b-4b5e-a949-46f5e0f9437c" />

#### 8. Security Architecture
<img width="636" height="3254" alt="Security Architecture" src="https://github.com/user-attachments/assets/1320379d-11bd-4c95-a3e6-19cf1d60bb00" />

#### 9. Technology Stack Diagram
<img width="471" height="3342" alt="Technology Stack" src="https://github.com/user-attachments/assets/1fa3c839-3ef6-489d-b4e0-ea37f12b94a2" />

#### 10. Attack Flow Sequence
<img width="3568" height="1326" alt="Attack Flow" src="https://github.com/user-attachments/assets/1e6c657d-51fb-439c-b4a2-fcc32ed190d0" />

</details>

---

## 🛠️ Technology Stack

### Backend

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Language** | Python 3.11 | Core development |
| **Framework** | FastAPI + Uvicorn | Async REST API with auto-docs |
| **ORM** | SQLAlchemy 2.0 | Database abstraction & migrations |
| **Database** | PostgreSQL 15 (Alpine) | Event storage, packet logs, threat scores |
| **ML** | scikit-learn, joblib, MLflow | Model training, serialization, registry |
| **Network** | Paramiko, Scapy, pyftpdlib | Protocol simulation & traffic capture |
| **Logging** | Python `logging` module | Structured JSON logging with rotation |

### Frontend

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Framework** | React 19.2 | Interactive UI components |
| **Build Tool** | Vite (Rolldown) | Sub-second HMR, optimized builds |
| **Styling** | Tailwind CSS | Utility-first responsive design |
| **Charts** | Recharts | Threat score visualization |
| **HTTP** | Axios | API communication |
| **Testing** | Vitest + Playwright | Unit & E2E testing |
| **Docs** | Storybook 10 | Component documentation |

### DevOps & Infrastructure

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Containerization** | Docker + Docker Compose | 7-service orchestration |
| **CI/CD** | GitHub Actions | Automated testing & deployment |
| **Load Testing** | Locust | Concurrent user simulation |
| **Model Tracking** | MLflow | Experiment tracking & model versioning |
| **Version Control** | Git / GitHub | Branching strategy with weekly releases |

---

## ⚡ Quick Start

### Prerequisites

```bash
python --version          # 3.11+
node --version            # 18+
docker --version          # 20+
docker compose version    # v2+
git --version
```

### Clone & Run (Docker — Recommended)

```bash
# Clone
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet

# Start all 7 services
docker-compose up -d

# Verify
docker-compose ps
```

### Access Services

| Service | URL | Description |
|---------|-----|-------------|
| **Dashboard** | http://localhost:3000 | React frontend |
| **API Docs (Swagger)** | http://localhost:8000/docs | Interactive API explorer |
| **API Health** | http://localhost:8000/health | JSON health check |
| **SSH Honeypot** | `ssh -p 2222 localhost` | SSH trap |
| **HTTP Honeypot** | http://localhost:8080 | Web trap |
| **FTP Honeypot** | `ftp localhost 2121` | FTP trap |

---

## 📦 Installation

### Local Development (Without Docker)

#### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate (Windows PowerShell)
venv\Scripts\Activate.ps1

# Activate (Linux/macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### 2. Environment Configuration

Create `backend/.env`:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/phantomnet
ENVIRONMENT=local
```

#### 3. Start Backend

```bash
cd backend
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

#### 4. Frontend Setup

```bash
cd frontend-dev
npm install
npm run dev
```

#### 5. Access

- **Frontend**: http://localhost:5173 (Vite dev server)
- **API Docs**: http://localhost:8000/docs
- **API Health**: http://localhost:8000/health

---

## 🔌 API Reference

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check (DB connectivity) |
| `GET` | `/api/events` | Paginated traffic events with filtering |
| `GET` | `/api/stats` | Dashboard aggregate statistics |
| `GET` | `/api/honeypots/status` | Live honeypot connectivity & last seen |
| `GET` | `/api/traffic` | Real-time traffic feed |

### Threat Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/analyze/threat-score` | Score a packet → returns threat level, confidence, decision |

**Request Body:**
```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.5",
  "dst_port": 80,
  "protocol": "TCP",
  "length": 512
}
```

**Response:**
```json
{
  "score": 85.0,
  "threat_level": "HIGH",
  "confidence": 0.85,
  "decision": "BLOCK"
}
```

### Protocol Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/analytics/ssh` | SSH stats + brute-force suspects |
| `GET` | `/api/v1/analytics/http` | HTTP stats + flood suspects |
| `GET` | `/api/v1/analytics/trends?days=7` | Daily attack volume (time-series) |

### Active Defense

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/active-defense/block/{ip}` | Block an attacker IP |

> 📖 **Full interactive API docs**: http://localhost:8000/docs

---

## 🧪 Testing

### Run Integration Tests

```bash
# From project root
cd backend
venv\Scripts\pytest tests/ -v
```

### Load Testing (Locust)

```bash
# Install Locust
pip install locust

# Run headless load test (50 concurrent users, 1 minute)
locust -f tests/load_test_config.py --headless -u 50 -r 5 -t 1m --host http://127.0.0.1:8000
```

### Test Results (Week 8)

| Test Type | Result | Details |
|-----------|--------|---------|
| **Integration** | ✅ 6/6 Passed | Health, Threat Scoring, SSH/HTTP Analytics, Trends, Honeypot Status |
| **Load Test** | ✅ 0% Error Rate | 50 concurrent users, ~13ms avg response, stable throughput |
| **Live Scoring** | ✅ Passed | ThreatAnalyzerService correctly scores and updates DB records |

---

## 📚 Documentation

### Project Documents

| Document | Description |
|----------|-------------|
| [`docs/system_architecture.md`](docs/system_architecture.md) | System diagrams and data flow |
| [`docs/phase2_completion_report.md`](docs/phase2_completion_report.md) | Phase 2 milestone summary |
| [`docs/integration_test_week8.md`](docs/integration_test_week8.md) | Integration & load test results |
| [`docs/protocol_analytics_api.md`](docs/protocol_analytics_api.md) | Analytics API reference |
| [`docs/api_design.md`](docs/api_design.md) | API design specification |
| [`docs/setup_guide.md`](docs/setup_guide.md) | Detailed installation guide |
| [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) | Contribution guidelines |
| [`backend/api/openapi.yaml`](backend/api/openapi.yaml) | OpenAPI 3.0 specification |

### External References

- [OWASP Honeypot Project](https://owasp.org/)
- [scikit-learn Documentation](https://scikit-learn.org/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://react.dev/)
- [Docker Documentation](https://docs.docker.com/)

---

## 🔒 Security

| Feature | Implementation |
|---------|---------------|
| **Input Validation** | Pydantic v2 schema enforcement on all API inputs |
| **CORS** | Configured allowlist for frontend origins |
| **SQL Injection** | Protected via SQLAlchemy ORM (parameterized queries) |
| **Honeypot Isolation** | Each honeypot runs in a separate Docker container |
| **Credential Safety** | Environment variables via `.env` (never committed) |
| **Log Sanitization** | Standardized JSON logging, no raw credential storage |

---

## 📈 Roadmap

### ✅ Phase 1: Foundation (Weeks 1–4) — Complete
- [x] Project setup, GitHub repo, CI/CD
- [x] PostgreSQL database schema (`packet_logs`, `traffic_stats`)
- [x] SSH honeypot (Paramiko) with authentication logging
- [x] Basic FastAPI backend with CRUD endpoints
- [x] React frontend skeleton

### ✅ Phase 2: Intelligence & Active Defense (Weeks 5–8) — Complete
- [x] HTTP & FTP honeypots (Dockerized, JSON logging)
- [x] SMTP honeypot
- [x] Traffic sniffer with Scapy (real-time packet capture)
- [x] ML threat scoring (IsolationForest, RandomForest)
- [x] ThreatAnalyzerService (background scoring every 5s)
- [x] Protocol Analytics API (SSH brute-force, HTTP flood detection)
- [x] Cyberpunk dashboard with Tailwind CSS
- [x] Integration & load testing (50 concurrent users, 0% errors)
- [x] Full documentation & OpenAPI spec

### 🔮 Phase 3: Hardening & Scale (Planned)
- [ ] SIEM integration (Splunk / Elastic)
- [ ] Advanced active defense (automated firewall rules)
- [ ] Kubernetes deployment
- [ ] Deep learning models (LSTM for sequence-based detection)
- [ ] Mobile monitoring app
- [ ] Distributed multi-node deployment

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| **Team Size** | 4 members |
| **Project Duration** | 8 months (32 weeks) |
| **Docker Services** | 7 (DB, 4 Honeypots, API, Frontend) |
| **API Endpoints** | 15+ |
| **ML Features Extracted** | 15 per packet |
| **Documentation Files** | 65+ |
| **Test Pass Rate** | 100% |

---

## 👥 Team Members

| Role | Name | GitHub | Email |
|------|------|--------|-------|
| **Team Lead / Architect** | Kasukurthi Sriram | [@sriram21-09](https://github.com/sriram21-09/) | sriramkasukurthi2109@gmail.com |
| **Security Developer** | Muramreddy Vivekanandareddy | [@VivekanandaReddy2006](https://github.com/VivekanandaReddy2006) | vivekuses2006@gmail.com |
| **AI/ML Developer** | Nattala Vikranth Chakravarthi | [@Vikranth-tech](https://github.com/Vikranth-tech) | nvikranth007@gmail.com |
| **Frontend Developer** | Satti Sai Ram Manideep Reddy | [@sairammanideepreddy2123](https://github.com/sairammanideepreddy2123) | sairammanideepreddy2123@gmail.com |

---

## 💡 Contributing

We welcome contributions! Please see [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for full guidelines.

```bash
# Fork & Clone
git clone https://github.com/sriram21-09/PhantomNet.git

# Create feature branch
git checkout -b feature/your-feature-name

# Commit (follow conventions)
git commit -m "[Role] type: description"
# Example: "[Security-Dev] feat: SSH honeypot hardening"

# Push & create PR
git push origin feature/your-feature-name
```

### Coding Standards
- **Python**: PEP 8, type hints, docstrings
- **JavaScript**: ESLint, functional components
- **Git**: Conventional commits, one feature per PR
- **Docs**: Update relevant docs with every feature

---

## 🙏 Acknowledgments

- **OWASP** for honeypot concepts and security guidelines
- **scikit-learn** for the machine learning library
- **FastAPI** for the high-performance async framework
- **React** community for the frontend ecosystem
- **Docker** for containerization platform
- **PostgreSQL** for the reliable database engine
- Our **faculty advisor** for guidance and support

---

<div align="center">

### 🚀 Built with ❤️ by the PhantomNet Team

**"Detecting Threats Before They Strike"**

![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/-React-61DAFB?style=flat-square&logo=react&logoColor=black)
![Docker](https://img.shields.io/badge/-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/-PostgreSQL-336791?style=flat-square&logo=postgresql&logoColor=white)
![scikit-learn](https://img.shields.io/badge/-scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white)

---

**Last Updated**: February 12, 2026  
**Status**: 🟢 Phase 2 Complete

</div>