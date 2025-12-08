# PhantomNet Setup Guide

## Prerequisites

- Python 3.9+
- Node.js 16+
- Docker & Docker Compose
- PostgreSQL 15+ (or use Docker)
- Git

## Installation Steps

### 1. Clone Repository

git clone https://github.com/yourusername/phantomnet.git
cd phantomnet

### 2. Setup Environment

cp .env.example .env
# Edit .env with your configuration

### 3. Start Services

docker-compose up -d

### 4.  Install Dependencies

# Backend
cd backend
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install

### 5. Start Development

# Terminal 1: Backend
cd backend
python -m uvicorn api.main:app --reload

# Terminal 2: Frontend
cd frontend
npm run dev

# Access Services
Frontend: http://localhost:5173

API Docs: http://localhost:8000/docs

SSH Honeypot: ssh -p 2222 localhost
