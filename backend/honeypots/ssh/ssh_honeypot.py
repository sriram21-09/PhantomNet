import socket
import json
import os
from datetime import datetime, timezone

# Database logger for accurate last_seen
try:
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from db_logger import log_ssh_activity
    DB_ENABLED = True
except ImportError:
    DB_ENABLED = False
    print("[SSH] Database logger not available, using file-only logging")

# --------------------------
# Paths
# --------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../logs"))

TEXT_LOG = os.path.join(LOG_DIR, "ssh.log")
JSON_LOG = os.path.join(LOG_DIR, "ssh.jsonl")
ERROR_LOG = os.path.join(LOG_DIR, "ssh_error.log")

os.makedirs(LOG_DIR, exist_ok=True)

# --------------------------
# Logging Helpers
# --------------------------
def log_text(message):
    with open(TEXT_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} - {message}\n")


def log_json(ip, event, data=None):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip,
        "honeypot_type": "ssh",
        "port": 2222,
        "event": event,
        "data": data
    }
    with open(JSON_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    
    # Also log to database for accurate last_seen
    if DB_ENABLED:
        try:
            is_malicious = event in ["login_failed", "brute_force"]
            log_ssh_activity(ip, event, is_malicious=is_malicious)
        except Exception as e:
            print(f"[SSH] DB logging failed: {e}")


def log_error(exc, context=""):
    with open(ERROR_LOG, "a") as f:
        f.write(
            f"{datetime.now(timezone.utc).isoformat()} - {context} - {repr(exc)}\n"
        )

# --------------------------
# Utilities
# --------------------------
def clean(text):
    if not text:
        return ""
    cleaned = ""
    for c in text:
        if c in ("\x08", "\x7f"):
            cleaned = cleaned[:-1]
        elif c.isprintable():
            cleaned += c
    return cleaned.strip()


def receive_line(client):
    buf = b""
    while True:
        chunk = client.recv(1)
        if not chunk:
            return ""
        if chunk == b"\r":
            continue
        buf += chunk
        if chunk == b"\n":
            break
    return buf.decode(errors="ignore").strip()

# --------------------------
# SSH Honeypot
# --------------------------
def start_ssh():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 2222))
    server.listen(5)

    print("[+] SSH Honeypot running on port 2222")
    log_text("SSH Honeypot started")

    CORRECT_USER = "PhantomNet"
    CORRECT_PASS = "1234"

    while True:
        try:
            client, addr = server.accept()
            ip = addr[0]

            print(f"🔥 Connection from {ip}")
            log_json(ip, "connect")

            client.send(b"SSH-2.0-OpenSSH_7.4\r\n")

            attempts = 0
            login_success = False

            while attempts < 3:
                client.send(b"Username: ")
                username = clean(receive_line(client))

                client.send(b"Password: ")
                password = clean(receive_line(client))

                log_json(ip, "login_attempt", {
                    "username": username,
                    "password": password
                })

                if username == CORRECT_USER and password == CORRECT_PASS:
                    log_json(ip, "login_success", {"username": username})
                    login_success = True
                    break

                log_json(ip, "login_failed", {"username": username})
                client.send(b"Invalid credentials\n")
                attempts += 1

            if not login_success:
                client.send(b"Access denied\n")
                client.close()
                log_json(ip, "disconnect")
                continue

            # Fake shell
            client.send(b"\nWelcome to Ubuntu 20.04 LTS\n\n")
            cwd = f"/home/{username}"

            while True:
                try:
                    prompt = f"{username}@honeypot:{cwd}$ "
                    client.send(prompt.encode())

                    cmd = clean(receive_line(client))
                    if not cmd:
                        continue

                    log_json(ip, "command", {"cmd": cmd})

                    if cmd == "ls":
                        client.send(b"file1.txt  secrets.log  project.txt\n")
                    elif cmd == "pwd":
                        client.send((cwd + "\n").encode())
                    elif cmd == "whoami":
                        client.send((username + "\n").encode())
                    elif cmd.startswith("cd "):
                        folder = cmd.split(" ", 1)[1]
                        cwd = cwd.rstrip("/") + "/" + folder
                    elif cmd in ("exit", "logout"):
                        log_json(ip, "session_end")
                        client.send(b"logout\n")
                        break
                    else:
                        client.send(f"{cmd}: command not found\n".encode())

                except Exception as e:
                    log_error(e, "shell error")
                    break

            client.close()
            log_json(ip, "disconnect")

        except Exception as e:
            log_error(e, "server error")

# --------------------------
# Entry Point
# --------------------------
if __name__ == "__main__":
    start_ssh()
