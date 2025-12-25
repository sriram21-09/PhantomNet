# 📘 FTP Documentation

## 📍 File: `docs/ftp_honeypot.md`


```markdown
# FTP Honeypot Documentation

## File Location
backend/honeypots/ftp/ftp_honeypot.py

---

## Purpose
The FTP honeypot emulates a misconfigured FTP server to:
- Capture credential reuse
- Observe file enumeration
- Detect data exfiltration attempts

---

## Authentication
- Supports authenticated and anonymous login
- Connection limit per IP
- Session timeout enforced

---

## Supported FTP Commands
PWD – Show current directory  
CWD – Change directory  
LIST – List fake files  
SIZE – Return fake file size  
RETR – Fake file download  

---

## Logging Example
```json
{
  "timestamp": "2025-01-01T12:10:33Z",
  "source_ip": "192.168.1.30",
  "honeypot_type": "ftp",
  "event": "command",
  "data": {
    "command": "RETR",
    "file": "config.tar.gz"
  },
  "level": "WARN"
}


Security Notes

No real file downloads

No real filesystem access

FTP protocol stability preserved