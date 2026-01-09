# 📘 FTP Documentation

## 📍 File: `docs/ftp_honeypot.md`


```markdown
# FTP Honeypot Documentation

## File Location
backend/honeypots/ftp/ftp_honeypot.py

```md
# FTP Honeypot – PhantomNet

## Purpose
The FTP honeypot simulates a misconfigured FTP server to detect:
- Unauthorized logins
- Directory listing attempts
- Data exfiltration attempts

## Port
- Listens on **port 2121**

## Technology Used
- pyftpdlib
- Custom FTPHandler

## Behavior
- Accepts valid and anonymous logins
- Allows navigation commands
- Blocks file downloads (RETR)
- LIST command intentionally disrupts data channel

## Important Note
The FTP LIST command:
- Sends `150 File status okay`
- Intentionally closes data connection

This behavior is **by design** to:
- Prevent real data exposure
- Still trigger attacker behavior

## Logged Fields
- timestamp
- honeypot_type: ftp
- source_ip
- username
- command
- file name (if applicable)

## Example Attack
```bash
ftp localhost 2121
ls
get config.tar.gz

Security Notes :- 

No real file downloads

No real filesystem access

FTP protocol stability preserved


Why This Matters :- 

FTP is still widely attacked in legacy systems.
This honeypot captures attacker intent without data leakage.