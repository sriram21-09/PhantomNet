# 🛡️ PhantomNet Honeypots

This folder contains two lightweight honeypots — **SSH** and **HTTP** — for capturing attack attempts and logging them in JSON format.

---

## ⚙️ 1. Run SSH Honeypot

### Run natively
```bash
python ssh_honeypot.py


👉RUN IN DOCKER :---
docker build -t phantomnet-ssh ./ssh
docker run -it -p 2222:2222 -v "C:\Users\vivekananda reddy\PhantomNet\backend\logs:/logs" phantomnet-ssh


🔍TESTING :- 
ssh -p 2222 localhost 
        (or)
telnet localhost 2222

📄LOGS :- 
json logs -> backend/logs/ssh.jsonl
error logs -> backend/logs/ssh_error.log

🤩EXPECTED LOG FORMAT :- 
(for SSH json file)
{"timestamp": "...", "source_ip": "127.0.0.1", "honeypot_type": "ssh", "status": "failed", "username": "user", "password": "1234"}



## ⚙️ 2. Run HTTP Honeypot

### Run natively
```bash
python http_honeypot.py

👉RUN IN DOCKER :----
docker build -t phantomnet-http ./http
docker run -it -p 8080:8080 -v "C:\Users\vivekananda reddy\PhantomNet\backend\logs:/logs" phantomnet-http

🔍TESTING :-- 
Open in browser → http://localhost:8080/admin
            (or) 
use curl , curl -X POST http://localhost:8080/admin -d "username=test&password=123"

📄LOGS :- 
JSON logs → backend/logs/http_logs.jsonl
Error logs → backend/logs/http_error.log  

🤩EXPEXTED LOG FORMAT :- 
(for HTTP json file)
{"timestamp": "...", "source_ip": "127.0.0.1", "honeypot_type": "http", "method": "POST", "url": "/admin", "submitted_data": {"username": "admin", "password": "123"}}


NOTE :- when you are running Docker container with the above given commands , your Docker desktop application should keep running and also replace this [ "C:\Users\vivekananda reddy\PhantomNet\backend\logs:/logs" phantomnet-ssh ] with your file structure in the command .