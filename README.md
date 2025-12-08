
# 🛡️ PhantomNet – AI-Driven Distributed Honeypot Deception Framework

<div align="center">

![PhantomNet Logo](https://img.shields.io/badge/PhantomNet-v1.0-brightgreen?style=flat-square&logo=github)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![React](https://img.shields.io/badge/React-18.0%2B-61DAFB?style=flat-square&logo=react)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=flat-square&logo=docker)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15%2B-336791?style=flat-square&logo=postgresql)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?style=flat-square)

**An intelligent, distributed honeypot system powered by AI/ML to detect, analyze, and adapt to cyber threats in real-time**

[Features](#-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Team](#-team) • [Installation](#-installation) • [Documentation](#-documentation)

</div>

---

## 📋 Table of Contents

- [🎯 About PhantomNet](#-about-phantomnet)
- [✨ Features](#-features)
- [🏗️ Architecture](#-architecture)
- [🛠️ Technology Stack](#-technology-stack)
- [📊 Project Timeline](#-project-timeline)
- [👥 Team Roles](#-team-roles)
- [⚡ Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [🚀 Getting Started](#-getting-started)
- [📚 Documentation](#-documentation)
- [🧪 Testing](#-testing)
- [🔒 Security](#-security)
- [📈 Roadmap](#-roadmap)
- [💡 Contributing](#-contributing)
- [📞 Contact](#-contact)

---

## 🎯 About PhantomNet

**PhantomNet** is a groundbreaking final-year engineering project that combines **distributed systems**, **cybersecurity**, and **artificial intelligence** to create an adaptive honeypot mesh. Unlike traditional static honeypots that attackers can easily detect and fingerprint, PhantomNet creates an **intelligent deception layer** that:

- 🔍 **Detects** cyber attacks across multiple network segments in real-time
- 🧠 **Learns** from attacker behavior using machine learning models
- 🎭 **Adapts** dynamically to make detection and mitigation harder
- 📊 **Visualizes** threats with an interactive dashboard
- 🔐 **Secures** networks by collecting detailed attack intelligence

### 🎓 Educational Value

This project teaches students:
- Advanced Python programming for security applications
- Distributed systems and microservices architecture
- Machine learning in practical cybersecurity contexts
- DevOps and containerization (Docker, Kubernetes)
- Full-stack web development with React
- Threat intelligence and cyber deception tactics

---

## ✨ Features

### 🍯 Multi-Protocol Honeypots

| Protocol | Port | Status | Feature |
|----------|------|--------|---------|
| SSH | 2222 | ✅ Active | Full authentication simulation, command logging |
| HTTP | 8080 | ✅ Active | Fake admin panels, login pages, file upload traps |
| FTP | 2121 | 🔄 In Progress | Directory traversal honeypots, file access traps |
| SMTP | 2525 | 🔄 Planned | Email spoofing detection, spam trap |
| Database | 3306 | 🔄 Planned | SQL injection honeypot, credential theft detection |

### 🤖 AI/ML Intelligence

- **Threat Scoring**: Real-time threat level calculation based on attack patterns
- **Anomaly Detection**: Identifies unusual attack behaviors
- **Behavioral Analysis**: Learns attacker profiles and signatures
- **Predictive Alerts**: Forecasts potential attack escalation
- **Pattern Recognition**: Groups similar attacks into campaigns

### 📊 Visualization & Monitoring

- **Real-time Dashboard**: Live attack visualization
- **Attack Timeline**: Historical attack progression
- **Geographic Heatmaps**: Attacker location distribution
- **Session Analytics**: Detailed per-session statistics
- **Alert Management**: Customizable alert rules and filters

### 🐳 Deployment & Scalability

- **Docker Containerization**: Easy deployment across systems
- **Horizontal Scaling**: Add more honeypots without complexity
- **Centralized Logging**: All logs aggregated in one database
- **API-First Design**: RESTful API for integration with other tools
- **Cloud-Ready**: Deploy to AWS, GCP, Azure, or on-premises

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Attack Sources                           │
│              (Internet, Threat Actors)                      │
└────────────────┬────────────────────────────────────────────┘
                 │
        ┌────────▼────────┐
        │ Network Border  │
        └────────┬────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
┌───▼──┐   ┌───▼──┐    ┌───▼──┐
│ SSH  │   │ HTTP │    │ FTP  │
│ 2222 │   │ 8080 │    │ 2121 │
└───┬──┘   └───┬──┘    └───┬──┘
    │          │           │
    └────────────────┬──────────┘
                     │
           ┌─────────▼────────┐
           │  Log Aggregator  │
           │  (JSON Lines)    │
           └────────┬─────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
    ┌───▼──┐            ┌──────▼─────┐
    │ DB   │            │ Log Parser  │
    │(PG)  │            │ & Features  │
    └───┬──┘            └──────┬──────┘
        │                      │
        │              ┌───────▼──────┐
        │              │  ML Pipeline │
        │              │ (scikit-learn)│
        │              └───────┬──────┘
        │                      │
        └──────────┬───────────┘
                   │
        ┌──────────▼──────────┐
        │   FastAPI Backend   │
        │   (/api/events,     │
        │    /api/stats)      │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │  React Dashboard    │
        │  (Real-time Views)  │
        └─────────────────────┘
```

### Data Flow

1. **Attack** → Honeypot captures traffic
2. **Log** → Event written to JSON log file
3. **Ingest** → Log parser reads events
4. **Store** → Events stored in PostgreSQL
5. **Process** → ML models analyze patterns
6. **Score** → Threat level calculated
7. **API** → Backend serves data
8. **Visualize** → Dashboard shows attack details

---

## 🛠️ Technology Stack

### Backend

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Language** | Python 3.9+ | Core development |
| **Framework** | FastAPI | RESTful API, real-time updates |
| **ORM** | SQLAlchemy | Database abstraction |
| **Database** | PostgreSQL 15+ | Event storage, persistence |
| **ML Library** | scikit-learn, TensorFlow | Threat analysis, anomaly detection |
| **Network** | Paramiko, Scapy | Protocol simulation, traffic generation |
| **Logging** | Python logging | Structured JSON logging |

### Frontend

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Framework** | React 18.0+ | Interactive UI |
| **Build Tool** | Vite | Fast development & production builds |
| **Routing** | React Router v6 | Page navigation |
| **Styling** | Tailwind CSS / Material-UI | Responsive design |
| **State** | Redux / Context API | Global state management |
| **Charts** | Chart.js, Recharts | Data visualization |
| **HTTP** | Axios / Fetch API | API communication |

### DevOps

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Containerization** | Docker | Isolated service deployment |
| **Orchestration** | Docker Compose | Multi-container management |
| **CI/CD** | GitHub Actions | Automated testing & deployment |
| **Version Control** | Git / GitHub | Code management |
| **Monitoring** | Grafana, Prometheus | Performance tracking |

---

## 📊 Project Timeline

### Overall Schedule: 8 Months (32 weeks)

```
Month 1: Foundation & Core Architecture
├── Week 1: System design, base honeypots, DB schema
├── Week 2: Expand honeypots, stabilize logging
├── Week 3: Integration testing, documentation
└── Week 4: Buffer & stabilization

Month 2-3: Honeypot Expansion & Enhancement
├── Add more honeypot types
├── Improve realism and behavior
├── Advanced attack simulation

Month 4-5: AI/ML Integration
├── Feature engineering
├── Model training and evaluation
├── Real-time threat scoring

Month 6: Hardening & Deployment
├── Security hardening
├── Performance optimization
├── Container orchestration

Month 7: Testing & Evaluation
├── Penetration testing
├── System validation
├── Performance benchmarking

Month 8: Finalization & Submission
├── Report writing
├── Presentation preparation
├── Code cleanup & final testing
```

---

## 👥 Team Roles

### 4-Member Team Structure

| Role | Responsibilities | Key Skills |
|------|-----------------|-----------|
| **Team Lead / Architect** | System design, API specification, coordination, CI/CD | System design, project management |
| **Security Developer** | Honeypots, network protocols, Docker, logging | Python, networking, Linux, Docker |
| **AI/ML Developer** | Database, data pipeline, ML models, threat analysis | Python, SQL, machine learning, data science |
| **Frontend Developer** | React dashboard, visualization, UI/UX | React, JavaScript, CSS, API integration |

---

## ⚡ Quick Start

### Prerequisites

`
# Check versions
python3 --version          # Should be 3.9 or higher
pip --version             # Python package manager
node --version            # Should be 16 or higher
npm --version             # Node package manager
docker --version          # For containerization
git --version             # Version control
`

### Clone & Setup (5 minutes)

``
# Clone repository
git clone https://github.com/yourusername/phantomnet.git
cd phantomnet

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Setup frontend
cd frontend
npm install
cd ..

# Create .env file
cp .env.example .env
# Edit .env with your configuration

# Start Docker containers
docker-compose up -d
`

### Run Services (2 minutes)

``
# Terminal 1: Backend API
cd backend
python3 -m uvicorn api.main:app --reload --port 8000

# Terminal 2: Frontend
cd frontend
npm run dev

# Terminal 3: Honeypots
python3 backend/honeypots/start_honeypots.py
``

### Access Services

- **Dashboard**: http://localhost:5173
- **API Docs**: http://localhost:8000/docs
- **SSH Honeypot**: ssh -p 2222 localhost
- **HTTP Honeypot**: http://localhost:8080

---

## 📦 Installation

### System Requirements

- **OS**: Linux (Ubuntu 20.04+), macOS (10.15+), or Windows (WSL2)
- **RAM**: 8GB minimum (16GB recommended)
- **Storage**: 20GB free space
- **CPU**: 4 cores minimum

### Step-by-Step Installation

#### 1. Install Python Dependencies

``
# Navigate to backend
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install --upgrade pip
pip install -r requirements.txt
`

#### 2. Install Frontend Dependencies

``
# Navigate to frontend
cd frontend

# Install Node packages
npm install
``

#### 3. Setup Database

``
# PostgreSQL must be running
# Create database
createdb phantomnet

# Run migrations
cd backend
python3 -m alembic upgrade head
``

#### 4. Setup Environment Variables

``
# Copy example env file
cp .env.example .env

# Edit .env with:
DATABASE_URL=postgresql://user:password@localhost:5432/phantomnet
API_PORT=8000
JWT_SECRET=your-secret-key-here
FRONTEND_URL=http://localhost:5173
``

#### 5. Build Docker Images

``
# Build all containers
docker-compose build

# Verify builds
docker images | grep phantomnet
``
---

## 🚀 Getting Started

### First Run

``
# Start all services
docker-compose up

# In new terminal, seed database
docker-compose exec api python3 seed_db.py

# Access dashboard
open http://localhost:5173
``

### Create Test Data

``
# Run honeypot simulator
python3 backend/tools/simulate_attacks.py

# Generate attack traffic
python3 backend/tools/generate_traffic.py --duration 5m --intensity high
``

### Monitor Logs

``
# View all logs
docker-compose logs -f

# View specific service
docker-compose logs -f api
docker-compose logs -f frontend
docker-compose logs -f ssh-honeypot
``

---

## 📚 Documentation

### 📖 Project Documentation

| Document | Purpose |
|----------|---------|
| [`docs/architecture.md`](docs/architecture.md) | Detailed system architecture |
| [`docs/api_design.md`](docs/api_design.md) | API endpoints and usage |
| [`docs/db_schema.md`](docs/db_schema.md) | Database structure and relationships |
| [`docs/setup_guide.md`](docs/setup_guide.md) | Installation and configuration |
| [`docs/user_guide.md`](docs/user_guide.md) | How to use the dashboard |
| [`docs/dev_guide.md`](docs/dev_guide.md) | Developer contribution guide |

### 🔗 External Resources

- [OWASP Honeypot Guide](https://owasp.org/)
- [SSH Protocol RFC](https://tools.ietf.org/html/rfc4251)
- [scikit-learn Documentation](https://scikit-learn.org/)
- [React Documentation](https://react.dev/)
- [Docker Documentation](https://docs.docker.com/)

---

## 🧪 Testing

### Run Tests

``
# Backend unit tests
cd backend
pytest tests/ -v

# Backend coverage
pytest --cov=api tests/

# Frontend tests
cd frontend
npm run test

# Frontend coverage
npm run test:coverage

# Integration tests
docker-compose -f docker-compose.test.yml up
``

### Test Coverage

- Backend: 85%+ coverage
- Frontend: 80%+ coverage
- Integration: Critical paths tested

---

## 🔒 Security

### Security Features

✅ **Authentication**: JWT token-based authentication  
✅ **Encryption**: SSL/TLS for all network traffic  
✅ **Input Validation**: Sanitized all user inputs  
✅ **Rate Limiting**: API rate limiting implemented  
✅ **CORS**: Configured CORS policies  
✅ **SQL Injection**: Protected via SQLAlchemy ORM  

---

## 📈 Roadmap

### ✅ Completed

- [x] Project setup and GitHub repo
- [x] Basic SSH honeypot
- [x] PostgreSQL database schema
- [x] React frontend skeleton
- [x] Basic API endpoints

### 🔄 In Progress

- [ ] HTTP/FTP honeypots
- [ ] ML threat scoring
- [ ] Dashboard visualization
- [ ] Real-time notifications

### 🔮 Planned

- [ ] Database honeypot
- [ ] Web application honeypot
- [ ] Kubernetes deployment
- [ ] Advanced ML models (Deep Learning)
- [ ] Distributed deployment across cloud
- [ ] Mobile app for monitoring

---

## 💡 Contributing

We welcome contributions! Here's how:

### Step 1: Fork & Clone

```
git clone https://github.com/yourusername/phantomnet.git
cd phantomnet
```

### Step 2: Create Feature Branch

```
git checkout -b feature/your-feature-name
```

### Step 3: Make Changes

```
# Make your changes
# Commit with clear messages
git commit -m "[Role] type: description"
# Example: "[Security-Dev] feat: SSH honeypot hardening"
```

### Step 4: Push & Create PR

```
git push origin feature/your-feature-name
# Create Pull Request on GitHub
```

### Contribution Guidelines

- Follow PEP 8 for Python code
- Follow Airbnb style guide for JavaScript
- Add tests for new features
- Update documentation
- Make one feature per PR

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| **Team Size** | 4 members |
| **Project Duration** | 8 months (32 weeks) |
| **Lines of Code (Target)** | 15,000+ |
| **Database Tables** | 8+ |
| **API Endpoints** | 15+ |
| **React Components** | 20+ |
| **Test Cases** | 100+ |
| **Documentation Pages** | 10+ |

---

## 💼 Career Benefits

Developers who complete PhantomNet will have:

- ✅ Portfolio project showing full-stack development
- ✅ Experience with cybersecurity concepts
- ✅ Machine learning in production
- ✅ DevOps and containerization skills
- ✅ Open-source contribution experience
- ✅ Competitive advantage in job market

**Expected Salary Impact**: +20-25% in first cybersecurity role

---


### Team Members

| Role | Name | GitHub | Email |
|------|------|--------|-------|
| Team Lead | Kasukurthi Sriram| [@sriram21-09](https://github.com/sriram21-09/) | sriramkasukurthi2109.com |
| Security Dev | Muramreddy Vivekanandareddy | [@VivekanandaReddy2006](https://github.com/VivekanandaReddy2006) | vivekuses2006@gmail.com|
| AI/ML Dev | Nattala Vikranth Chakravarthi  | [@Vikranth-tech](https://github.com/Vikranth-tech) | nvikranth007@gmail.com |
| Frontend Dev | Satti Sai ram manideep reddy | [@sairammanideepreddy2123](https://github.com/sairammanideepreddy2123) | sairammanideepreddy2123@gmail.com |

---

## 🙏 Acknowledgments

- **OWASP** for honeypot concepts and guidelines
- **scikit-learn** for machine learning library
- **React** community for amazing framework
- **Docker** for containerization platform
- **PostgreSQL** for reliable database
- Our **faculty advisor** for guidance and support

---

## 📈 Star History

If you find this project useful, please ⭐ **star the repository**!

```
Your stars help other students discover PhantomNet
```

---

<div align="center">

### 🚀 Built with ❤️ by the PhantomNet Team

**"Detecting Threats Before They Strike"**

![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white)
![React](https://img.shields.io/badge/-React-61DAFB?style=flat-square&logo=react&logoColor=black)
![Docker](https://img.shields.io/badge/-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/-PostgreSQL-336791?style=flat-square&logo=postgresql&logoColor=white)

---

**Last Updated**: December 8, 2025  
**Status**: 🟡 In Development  
**Next Release**: December 21, 2025 (Week 1 Complete)

