
# PhantomNet Setup Guide

This guide explains how to set up the PhantomNet development environment on a local machine using only free tools.

---

## 1. Prerequisites

Install the following before you start:

- Python 3.10 or newer  
- Node.js 18 or newer  
- Docker and Docker Compose  
- PostgreSQL (local instance or Docker)  
- Git  

Verify installed versions:

```bash
python --version
node --version
npm --version
docker --version
git --version
````

---

## 2. Clone Repository

```bash
git clone https://github.com/sriram21-09/phantomnet.git
cd phantomnet
```


---

## 3. Backend Setup (FastAPI)

From the project root:

```bash
cd backend
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the virtual environment:

Windows:

```bash
venv\Scripts\activate
```

macOS / Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the backend API:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at:

* Backend API: [http://localhost:8000](http://localhost:8000)
* API Docs (Swagger): [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 4. Database Setup (PostgreSQL)

### Create Database

```bash
psql -U postgres
CREATE DATABASE phantomnet;
\q
```

### Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env`:

```env
DATABASE_URL=postgresql://phantomnet:phantomnet123@localhost:5432/phantomnet
```

### Run Migrations / Initialize Tables

```bash
cd backend
python -m db.connection
```

or

```bash
alembic upgrade head
```

Verify tables using `psql` or a database GUI tool.

---

## 5. Honeypot Services (Docker)

From the project root:

```bash
docker compose up -d
```

Check running containers:

```bash
docker ps
```

---

## 6. Frontend Setup (React + Vite)

```bash
cd frontend
npm install
npm run dev
```

Vite runs on port **5173** by default.

---

## 7. Accessing the System

* Backend API: [http://localhost:8000](http://localhost:8000)
* API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
* Frontend Dashboard: [http://localhost:5173](http://localhost:5173)

Honeypot ports (Docker):

* SSH: 2222
* HTTP: 8080
* FTP: 2121

---

## 8. Basic Smoke Test

Health check:

```bash
http://localhost:8000/health
```

Expected response:

```json
{
  "status": "ok",
  "service": "phantomnet"
}
```

Frontend:

```bash
http://localhost:5173
```

---

## 9. Common Troubleshooting

* Port already in use → Change port or stop conflicting service
* Database connection error → Verify `DATABASE_URL` and PostgreSQL status
* Frontend cannot reach API → Confirm backend URL and Vite proxy configuration

---

```

This is **clean Markdown**, renders correctly on GitHub, and follows standard README/SETUP conventions.
```
