# 🚀 PhantomNet Setup Guide

**Version**: 1.0  
**Date**: December 10, 2025  
**OS Support**: Linux, macOS, Windows (WSL2)

---

## 📑 Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Backend Setup](#backend-setup)
4. [Database Setup](#database-setup)
5. [Frontend Setup](#frontend-setup)
6. [Running the Project](#running-the-project)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)

---

## ✅ Prerequisites

### Software Required

| Software | Version | Purpose |
|----------|---------|---------|
| **Python** | 3.9+ | Backend runtime |
| **Node.js** | 16+ | Frontend runtime |
| **PostgreSQL** | 12+ | Database |
| **Git** | Latest | Version control |
| **Docker** | 20.10+ | Containerization (optional) |

### Development Tools

| Tool | Purpose |
|------|---------|
| **pip** | Python package manager |
| **npm** | Node package manager |
| **psql** | PostgreSQL client |
| **Git** | Clone repository |
| **VS Code** | Code editor (recommended) |

---

## 💻 System Requirements

### Minimum

| Component | Requirement |
|-----------|-------------|
| **CPU** | 2 cores |
| **RAM** | 4 GB |
| **Storage** | 5 GB free |
| **Network** | 5 Mbps internet |

### Recommended

| Component | Requirement |
|-----------|-------------|
| **CPU** | 4+ cores |
| **RAM** | 8 GB+ |
| **Storage** | 20 GB SSD |
| **Network** | Stable internet |

---

## 🔧 Backend Setup

### Step 1: Clone Repository

```bash
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet
```

### Step 2: Create Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 3: Install Python Dependencies

```bash
# Install requirements
pip install -r requirements.txt

# Verify installation
pip list
```

### Step 4: Configure Environment Variables

Create `.env` file in project root:

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/phantomnet
DB_USER=postgres
DB_PASSWORD=your_secure_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=phantomnet

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_ENV=development
LOG_LEVEL=INFO

# Frontend Configuration
FRONTEND_URL=http://localhost:5173
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
```

### Step 5: Verify Backend Setup

```bash
# Test Python installation
python --version

# Test pip packages
python -c "import fastapi; print('FastAPI ready')"

# Check environment file
cat .env
```

---

## 🗄️ Database Setup

### Option 1: PostgreSQL (Local)

#### Linux

```bash
# Install PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql

# Verify installation
psql --version
```

#### macOS

```bash
# Install PostgreSQL using Homebrew
brew install postgresql

# Start PostgreSQL service
brew services start postgresql

# Verify installation
psql --version
```

#### Windows

```bash
# Download from https://www.postgresql.org/download/windows/
# Or use Chocolatey:
choco install postgresql

# Verify installation
psql --version
```

### Step 1: Create Database User

```bash
# Connect to PostgreSQL
sudo -u postgres psql

# Create user (in psql):
CREATE USER phantomnet WITH PASSWORD 'your_secure_password';

# Grant privileges:
ALTER USER phantomnet CREATEDB;

# Exit psql:
\q
```

### Step 2: Create Database

```bash
# Create database
createdb -U phantomnet phantomnet

# Verify creation
psql -U phantomnet -d phantomnet -c "\dt"
```

### Step 3: Run Database Migrations

```bash
# From project root with venv activated
python -m alembic upgrade head

# Or manually create tables:
psql -U phantomnet -d phantomnet -f backend/db/schema.sql
```

### Step 4: Verify Database

```bash
# Connect to database
psql -U phantomnet -d phantomnet

# List tables
\dt

# Exit
\q
```

---

### Option 2: Docker PostgreSQL

```bash
# Run PostgreSQL container
docker run --name phantomnet-db \
  -e POSTGRES_USER=phantomnet \
  -e POSTGRES_PASSWORD=your_secure_password \
  -e POSTGRES_DB=phantomnet \
  -p 5432:5432 \
  -d postgres:13

# Verify container is running
docker ps | grep phantomnet-db

# Create tables
docker exec -i phantomnet-db psql -U phantomnet -d phantomnet < backend/db/schema.sql
```

---

## 🎨 Frontend Setup

### Step 1: Navigate to Frontend Directory

```bash
cd frontend
```

### Step 2: Install Node Dependencies

```bash
# Install npm packages
npm install

# Verify installation
npm list --depth=0
```

### Step 3: Configure Frontend Environment

Create `.env` file in `frontend` directory:

```bash
VITE_API_URL=http://localhost:8000
VITE_API_TIMEOUT=30000
VITE_LOG_LEVEL=info
```

### Step 4: Verify Frontend Setup

```bash
# Test Node installation
node --version

# Test npm installation
npm --version

# Check environment file
cat .env
```

---

## ▶️ Running the Project

### Method 1: Terminal Tabs (Development)

#### Terminal 1: Backend API

```bash
# From project root with venv activated
cd backend
python main.py

# Or using uvicorn:
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### Terminal 2: Frontend

```bash
# From project root in new terminal
cd frontend
npm run dev

# Frontend will run on http://localhost:5173
```

#### Terminal 3: Optional - Database Monitor

```bash
# Monitor database activity
psql -U phantomnet -d phantomnet

# List tables:
\dt

# Exit:
\q
```

### Method 2: Docker Compose (Production-like)

Create `docker-compose.yml` in project root:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_USER: phantomnet
      POSTGRES_PASSWORD: your_password
      POSTGRES_DB: phantomnet
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://phantomnet:your_password@postgres:5432/phantomnet
    depends_on:
      - postgres

  frontend:
    build: ./frontend
    ports:
      - "5173:5173"

volumes:
  postgres_data:
```

Run with Docker Compose:

```bash
# Start all services
docker-compose up

# Stop all services
docker-compose down

# View logs
docker-compose logs -f
```

---

## ✔️ Verification

### Step 1: Check Backend

```bash
# Test health endpoint
curl http://localhost:8000/health

# Expected response:
# {"status": "healthy", "database": "connected", "timestamp": "..."}
```

### Step 2: Check Frontend

```bash
# Open in browser
http://localhost:5173

# Should see login/dashboard page
```

### Step 3: Check Database

```bash
# Connect to database
psql -U phantomnet -d phantomnet

# Check tables exist
\dt

# Exit
\q
```

### Step 4: Test API Endpoints

```bash
# Get events
curl http://localhost:8000/events

# Get statistics
curl http://localhost:8000/stats

# Get threat level
curl http://localhost:8000/threat-level
```

---

## 🐛 Troubleshooting

### Backend Issues

**Problem**: `ModuleNotFoundError: No module named 'fastapi'`

```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

**Problem**: `Connection refused on port 8000`

```bash
# Solution: Check if port is in use
lsof -i :8000

# Kill process if needed
kill -9 <PID>

# Restart backend
python main.py
```

**Problem**: `Database connection error`

```bash
# Solution: Verify PostgreSQL is running
psql -U phantomnet -d phantomnet -c "SELECT 1"

# If failed, restart PostgreSQL:
# Linux:
sudo systemctl restart postgresql

# macOS:
brew services restart postgresql
```

### Frontend Issues

**Problem**: `npm ERR! code ERESOLVE`

```bash
# Solution: Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
```

**Problem**: `Port 5173 already in use`

```bash
# Solution: Kill existing process
lsof -i :5173
kill -9 <PID>

# Or use different port
npm run dev -- --port 5174
```

**Problem**: `CORS errors in browser console`

```bash
# Solution: Check backend CORS configuration in .env
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# Restart backend for changes to take effect
```

### Database Issues

**Problem**: `psql: error: could not connect to server`

```bash
# Solution: Check PostgreSQL service status
# Linux:
sudo systemctl status postgresql

# macOS:
brew services list | grep postgresql

# Start if not running:
# Linux:
sudo systemctl start postgresql

# macOS:
brew services start postgresql
```

**Problem**: `Database does not exist`

```bash
# Solution: Create database
createdb -U phantomnet phantomnet

# Run migrations
python -m alembic upgrade head
```

**Problem**: `Permission denied for schema public`

```bash
# Solution: Grant permissions
psql -U postgres -d phantomnet -c "GRANT ALL ON SCHEMA public TO phantomnet"
```

---

## 📋 Setup Checklist

### Prerequisites
- ✅ Python 3.9+ installed
- ✅ Node.js 16+ installed
- ✅ PostgreSQL 12+ installed
- ✅ Git installed
- ✅ Editor/IDE installed

### Backend
- ✅ Repository cloned
- ✅ Virtual environment created
- ✅ Dependencies installed
- ✅ `.env` file created
- ✅ Backend tested

### Database
- ✅ PostgreSQL service running
- ✅ User created
- ✅ Database created
- ✅ Tables created
- ✅ Database connection verified

### Frontend
- ✅ Navigation to frontend directory
- ✅ Dependencies installed
- ✅ `.env` file created
- ✅ Frontend tested

### Verification
- ✅ Backend health check passing
- ✅ Frontend loads in browser
- ✅ Database connection working
- ✅ API endpoints responding
- ✅ All ports available

---

## 🎯 Quick Start Command

For experienced developers:

```bash
# Clone and setup
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet

# Backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python main.py

# Frontend (new terminal)
cd frontend
npm install
npm run dev

# Database
createdb -U postgres phantomnet
psql -U postgres -d phantomnet -f ../backend/db/schema.sql
```

---

## 📚 Next Steps

After setup:

1. **Read Documentation**:
   - [API Design](./API_DESIGN.md)
   - [Implementation Guide](./API_IMPLEMENTATION.md)
   - [Contributing Guidelines](./CONTRIBUTING.md)

2. **Start Development**:
   - Create feature branch
   - Make changes
   - Run tests
   - Submit PR

3. **Learn More**:
   - Check [Architecture](./ARCHITECTURE.md)
   - Review [Database Schema](./db/schema.md)
   - Study [API Endpoints](./API_ENDPOINTS.md)

---

## 🆘 Getting Help

**Issues or Questions?**

1. Check troubleshooting section above
2. Review relevant documentation
3. Search GitHub issues
4. Ask in Discord #tech-help
5. Create GitHub issue with details

---

## ✅ Setup Complete!

Your PhantomNet development environment is now ready.

**Next**:
- ✅ Backend running on `http://localhost:8000`
- ✅ Frontend running on `http://localhost:5173`
- ✅ Database connected and ready
- ✅ API endpoints responding

**Happy coding!** 🚀

