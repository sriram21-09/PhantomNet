📄 Content
# PhantomNet Operator Guide

## Starting the System
```bash
docker compose up -d

Verifying Services

SSH: ssh PhantomNet@localhost -p 2222

HTTP: http://localhost:8080/admin

FTP: ftp localhost 2121

Viewing Logs
tail -f data/logs/ssh/ssh_async.jsonl
tail -f data/logs/http/http_logs.jsonl
tail -f data/logs/ftp/ftp_logs.jsonl

Running Tests
pytest backend/honeypots -v

Stopping Services
docker compose down

Safety Notes

Do not expose to the public internet

Intended for lab and educational use only