import socket
import json
import os
import requests
from datetime import datetime, timezone

# =====================================================
# PATHS & DIRECTORIES
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# backend/logs
LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../logs"))
os.makedirs(LOG_DIR, exist_ok=True)

TEXT_LOG = os.path.join(LOG_DIR, "ssh.log")
JSON_LOG = os.path.join(LOG_DIR, "ssh.jsonl")
ERROR_LOG = os.path.join(LOG_DIR, "ssh_error.log")
# =====================================================
# BACKEND API CONFIG
# =====================================================
BACKEND_API_URL = "http://127.0.0.1:8000/api/logs"

# =====================================================
# ERROR LOGGING
# =====================================================
def log_error(exc: Exception, context: str = ""):
    try:
        with open(ERROR_LOG, "a") as f:
            f.write(
                f"{datetime.now(timezone.utc).isoformat()} | {context} | {repr(exc)}\n"
            )
    except Exception:
        pass  # never crash honeypot on logging failure

# =====================================================
# FILE LOGGING
# =====================================================
def log_text(message: str):
    with open(TEXT_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} - {message}\n")


def log_json(entry: dict):
    """Local JSONL logging (research use)."""
    with open(JSON_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

# =====================================================
# BACKEND SENDER (DB EVENTS)
# =====================================================
def send_to_backend(ip: str, raw_data: str):
    payload = {
        "source_ip": ip,
        "honeypot_type": "ssh",
        "port": 2222,
        "raw_data": raw_data
    }
    try:
        requests.post(BACKEND_API_URL, json=payload, timeout=2)
    except Exception as e:
        log_error(e, "send_to_backend")

# =====================================================
# INPUT SANITIZATION
# =====================================================
def clean(text: str) -> str:
    if not text:
        return ""
    cleaned = ""
    for c in text:
        if c in ("\x08", "\x7f"):  # backspace/delete
            cleaned = cleaned[:-1]
        elif c.isprintable():
            cleaned += c
    return cleaned.strip()


def receive_line(client) -> str:
    buffer = b""
    while True:
        try:
            chunk = client.recv(1)
        except Exception as e:
            log_error(e, "receive_line")
            return ""
        if not chunk:
            return ""
        if chunk == b"\r":
            continue
        buffer += chunk
        if chunk == b"\n":
            break
    return buffer.decode(errors="ignore").strip()

# =====================================================
# SSH HONEYPOT CORE
# =====================================================
def start_ssh():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 2222))
    server.listen(5)

    print("[+] SSH Honeypot running on port 2222")
    log_text("SSH Honeypot started")

    while True:
        try:
            client, addr = server.accept()
            ip = addr[0]

            print(f"🔥 Connection from {ip}")
            log_text(f"Connection from {ip}")
            send_to_backend(ip, "SSH connection attempt detected")

            # Fake SSH banner
            try:
                client.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            except Exception as e:
                log_error(e, "banner_send")
                client.close()
                continue

            CORRECT_USER = "PhantomNet"
            CORRECT_PASS = "1234"

            attempts = 0
            authenticated = False

            while attempts < 3:
                client.send(b"Username: ")
                username = clean(receive_line(client))

                client.send(b"Password: ")
                password = clean(receive_line(client))

                # Local detailed logging
                log_text(f"Login attempt from {ip}: {username}")
                log_json({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": ip,
                    "honeypot_type": "ssh",
                    "username": username,
                    "password": password,
                    "status": "attempt"
                })

                # Backend (NO credentials)
                send_to_backend(ip, f"SSH login attempt for user: {username}")

                if username == CORRECT_USER and password == CORRECT_PASS:
                    authenticated = True
                    send_to_backend(ip, "SSH login success")
                    break

                attempts += 1
                client.send(b"Invalid username or password\n")
                send_to_backend(ip, "SSH login failed")

            if not authenticated:
                client.send(b"Access temporarily disabled.\n")
                client.close()
                continue

            # =================================================
            # FAKE SHELL
            # =================================================
            welcome = (
                "\nWelcome to Ubuntu 20.04 LTS\n"
                "Last login: Tue Dec 9 10:00:00 2025\n\n"
            )
            client.send(welcome.encode())

            cwd = f"/home/{username}"

            while True:
                try:
                    prompt = f"{username}@honeypot:{cwd}$ "
                    client.send(prompt.encode())

                    cmd = clean(receive_line(client))
                    if not cmd:
                        continue

                    log_text(f"CMD from {ip}: {cmd}")
                    send_to_backend(ip, f"SSH command executed: {cmd}")

                    if cmd == "ls":
                        response = "file1.txt  config.ini  secrets.log  projectteam.txt\n"
                    elif cmd == "pwd":
                        response = cwd + "\n"
                    elif cmd == "whoami":
                        response = username + "\n"
                    elif cmd.startswith("cd "):
                        folder = cmd.split(" ", 1)[1]
                        cwd = cwd.rstrip("/") + "/" + folder
                        response = ""
                    elif cmd in ["exit", "logout"]:
                        client.send(b"logout\n")
                        break
                    else:
                        response = f"{cmd}: command not found\n"

                    client.send(response.encode())

                except Exception as e:
                    log_error(e, "shell_loop")
                    break

            client.close()

        except Exception as e:
            log_error(e, "main_loop")

# =====================================================
# ENTRY POINT
# =====================================================
if __name__ == "__main__":
    start_ssh()
