import socket
import json
import os
from datetime import datetime, timezone

# --------------------------
# Log file paths
# --------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEXT_LOG = os.path.join(BASE_DIR, "../logs/ssh.log")
JSON_LOG = os.path.join(BASE_DIR, "../logs/ssh.jsonl")
os.makedirs(os.path.dirname(TEXT_LOG), exist_ok=True)

# Error log path
ERROR_LOG = os.path.join(BASE_DIR, "../logs/ssh_error.log")


def log_error(exc: Exception, context: str = ""):
    """Append exception info to an error log (with timestamp and context)."""
    try:
        with open(ERROR_LOG, "a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} - {context} - {repr(exc)}\n")
    except Exception as e:
        print("⚠️ Failed to write error log:", e)


# --------------------------
# Logging Helpers
# --------------------------
def log_text(message):
    with open(TEXT_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} - {message}\n")


def log_json(ip, username, password, status, raw):
    """Unified JSON logging (same format as HTTP honeypot)."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip,
        "honeypot_type": "ssh",
        "port": 2222,
        "raw_data": raw,
        "username": username,
        "password": password,
        "status": status
    }
    with open(JSON_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# --------------------------
# Input cleaning utilities
# --------------------------
def clean(text):
    if not text:
        return ""
    cleaned = ""
    for c in text:
        if c in ("\x08", "\x7f"):  # backspace/delete
            cleaned = cleaned[:-1]
        elif c.isprintable():
            cleaned += c
    return cleaned.strip()


def receive_line(client):
    """Read until newline, handling CR/LF."""
    buffer = b""
    while True:
        try:
            chunk = client.recv(1)
        except Exception as e:
            log_error(e, "receive_line()")
            return ""
        if not chunk:
            return ""
        if chunk == b"\r":
            continue
        buffer += chunk
        if chunk == b"\n":
            break
    return buffer.decode(errors="ignore").strip()


# --------------------------
# SSH Honeypot main logic
# --------------------------
def start_ssh():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 2222))
    server.listen(5)

    print("[+] SSH Honeypot running on port 2222")
    log_text("[+] SSH Honeypot started")

    while True:
        try:
            client, addr = server.accept()
            ip = addr[0]
            #raise ValueError("Simulated SSH error for testing")

            print(f"🔥 Connection from: {ip}")
            log_text(f"Connection from {ip}")

            try:
                client.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            except Exception as e:
                log_error(e, f"Banner send failed for {ip}")
                client.close()
                continue

            CORRECT_USER = "PhantomNet"
            CORRECT_PASS = "1234"

            attempts = 0
            login_success = False

            while attempts < 3:
                try:
                    client.send(b"Username: ")
                    username = clean(receive_line(client))

                    client.send(b"Password: ")
                    password = clean(receive_line(client))

                    log_text(f"Login attempt {attempts + 1} from {ip}: {username}/{password}")
                    log_json(ip, username, password, "attempt", f"{username}/{password}")

                    if username == CORRECT_USER and password == CORRECT_PASS:
                        login_success = True
                        log_json(ip, username, password, "success", "login success")
                        break

                    attempts += 1
                    client.send(b"Invalid Username or Password\n")
                    log_json(ip, username, password, "failed", "wrong credentials")

                except Exception as e:
                    log_error(e, f"login loop error from {ip}")
                    break

            if not login_success:
                client.send(b"Error :- Access temporarily disabled.\n")
                client.close()
                continue

            # Fake shell
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
                    if cmd == "":
                        continue

                    log_text(f"CMD from {ip}: {cmd}")
                    log_json(ip, username, password, "command", cmd)

                    if cmd == "ls":
                        response = "file1.txt  config.ini  secrets.log  projectteam.txt\n"
                    elif cmd == "pwd":
                        response = cwd + "\n"
                    elif cmd == "whoami":
                        response = username + "\n"
                    elif cmd.startswith("cd "):
                        folder = cmd.split(" ", 1)[1]
                        if folder:
                            cwd = cwd.rstrip("/") + "/" + folder
                            response = ""
                        else:
                            response = "cd: missing argument\n"
                    elif cmd in ["exit", "logout"]:
                        client.send(b"logout\n")
                        break
                    else:
                        response = f"{cmd}: command not found\n"

                    client.send(response.encode())

                except Exception as e:
                    log_error(e, f"shell error from {ip}")
                    break

            client.close()

        except Exception as e:
            log_error(e, "main accept loop")


if __name__ == "__main__":
    start_ssh()
