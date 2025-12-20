No confusion. No mixed days. Written so **even a beginner can run it**.

---

# 📘 PhantomNet Honeypots – Setup & Usage Documentation

## 1️⃣ Project Overview

**PhantomNet** is a multi-protocol honeypot system designed to detect, log, and analyze malicious activity targeting common network services.

### Honeypots Implemented

* SSH Honeypot (Sync & Async)
* HTTP Honeypot
* FTP Honeypot

Each honeypot:

* Simulates a real service
* Captures attacker behavior
* Stores logs in structured JSON format
* Supports ingestion into PostgreSQL for analysis

---

## 2️⃣ Folder Structure (Important)

```
PhantomNet/
│
├── backend/
│   ├── honeypots/
│   │   ├── ssh/
│   │   │   ├── ssh_honeypot.py
│   │   │   ├── async_ssh_honeypot.py
│   │   │   └── tests/
│   │   ├── http/
│   │   │   ├── http_honeypot.py
│   │   │   └── tests/
│   │   └── ftp/
│   │       ├── ftp_honeypot.py
│   │       └── tests/
│   │
│   ├── ingestor/
│   │   ├── sshlog_ingestor.py
│   │   ├── asyncssh_log_ingestor.py
│   │   ├── http_log_ingestor.py
│   │   └── ftp_log_ingestor.py
│   │
│   └── logs/
│       ├── ssh_logs.jsonl
│       ├── ssh_async.jsonl
│       ├── http_logs.jsonl
│       ├── ftp_logs.jsonl
│       └── *_error.log
```

---

## 3️⃣ Prerequisites

### Software Required

| Tool              | Why Needed       |
| ----------------- | ---------------- |
| Python 3.11+      | Run honeypots    |
| PostgreSQL        | Store logs       |
| Git               | Version control  |
| Docker (optional) | Isolated testing |
| curl / ftp / ssh  | Testing attacks  |

### Python Libraries

```bash
pip install asyncssh pyftpdlib psycopg2-binary requests pytest pytest-asyncio
```

---

## 4️⃣ SSH Honeypot (AsyncSSH)

### Purpose

* Capture **login attempts**
* Capture **valid logins**
* Capture **executed commands**
* Simulate real Linux shell

### Run

```bash
cd backend/honeypots/ssh
python async_ssh_honeypot.py
```

### Test

```bash
ssh PhantomNet@localhost -p 2222
```

### What is Logged

* Username
* Password
* Login status (attempt/success/failed)
* Commands executed
* Source IP
* Timestamp
* Log level

### Logs

```
backend/logs/ssh_async.jsonl
backend/logs/ssh_async_error.log
```

---

## 5️⃣ HTTP Honeypot

### Purpose

* Simulate fake admin login
* Detect scans, brute force & misuse
* Capture abnormal HTTP methods

### Run

```bash
cd backend/honeypots/http
python http_honeypot.py
```

### Test

```bash
curl http://localhost:8080/admin
curl -X POST http://localhost:8080/admin
curl -X PUT http://localhost:8080/admin
curl -X DELETE http://localhost:8080/admin
```

### Supported Responses

| Method | Response      |
| ------ | ------------- |
| GET    | 200 OK        |
| POST   | 403 Forbidden | or Invalid credentials
| PUT    | 403 Forbidden |
| DELETE | 404 Not Found |

### Security Features

* IP connection limits
* Request timeout
* Log levels (INFO / WARN / ERROR)
* Separate error log file

### Logs

```
backend/logs/http_logs.jsonl
backend/logs/http_error.log
```

---

## 6️⃣ FTP Honeypot

### Purpose

* Capture FTP login attempts
* Capture file uploads/downloads
* Capture FTP commands (ls, pwd, mkdir, etc.)

### Run

```bash
cd backend/honeypots/ftp
python ftp_honeypot.py
```

### Test

```bash
ftp localhost 2121
```

### Test Commands

```
USER PhantomNet
PASS 1234
ls
pwd
mkdir test
```

### What is Logged

* Login success/failure
* Commands executed
* File uploads/downloads
* Disconnect events

### Logs

```
backend/logs/ftp_logs.jsonl
backend/logs/ftp_error.log
```

---

## 7️⃣ Log Ingestion (Database)

### Purpose

* Move logs from JSON files → PostgreSQL
* Avoid duplicate entries
* Enable analytics & dashboards

### Run Ingestors

```bash
cd backend/ingestor
python sshlog_ingestor.py
python asyncssh_log_ingestor.py
python http_log_ingestor.py
python ftp_log_ingestor.py
```

### Database Tables

* ssh_logs
* asyncssh_logs
* http_logs
* ftp_logs

Each table stores:

* Timestamp
* Source IP
* Honeypot type
* Event type
* Raw data
* Hash (to avoid duplicates)

---

## 8️⃣ Testing

### Unit Tests

```bash
pytest backend/
```

### What is Tested

* Honeypot responses
* Log file creation
* Database insertion
* Invalid login handling
* Command capture

---

## 9️⃣ Security Notes

⚠️ **This system is a honeypot**

* Never expose real credentials
* Never deploy on production machines
* Run in VM / isolated server
* Monitor logs regularly

---

## 🔚 Conclusion

PhantomNet successfully:

* Simulates real services
* Captures attacker behavior
* Stores structured logs
* Supports database analysis
* Is fully testable and documented

---
