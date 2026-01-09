Week 5 – Day 5 Summary

✔ All services started successfully
✔ SSH brute-force attempts logged and blocked
✔ HTTP admin panel protected (501 on unsupported methods)
✔ FTP exfiltration blocked (RETR denied, LIST restricted)
✔ SMTP phishing attempts captured
✔ Central logging stable under load

Known Limitations:
- FTP LIST intentionally aborts data connection (honeypot behavior)
- SMTP accepts loose command order (intentional for attacker capture)

Performance:
- No container crashes
- Async logging handled >1000 events smoothly
