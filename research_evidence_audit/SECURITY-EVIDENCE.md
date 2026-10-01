# PhantomNet Security Evidence

## 1. Honeypot Isolation & Containment
- Services bind strictly to unprivileged ports (SSH: 2222, HTTP: 8080, FTP: 2121, SMTP: 2525).
- Interactive shell commands in SSH/FTP are parsed without executing on the underlying host OS.
- Attack payloads are safely logged to SQLite tables without shell execution risks.

## 2. Ingestion & Storage Defenses
- Parameterized queries (? syntax in Python sqlite3) are consistently used in ackend/database/db.py, successfully mitigating second-order SQL injection attacks from captured payloads.
- Output sanitization is enforced in dashboard API responses to mitigate stored cross-site scripting (XSS).

## 3. Vulnerability Findings
- **Checked-in Secrets:** A .env file containing database paths, default administrative credentials, and JWT secret tokens is tracked in the repository.
- **Remediation:** Remove .env from tracking, add to .gitignore, provide .env.example, and enforce runtime environment variables.
