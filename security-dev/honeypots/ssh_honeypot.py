import socket
import json
from datetime import datetime
from datetime import datetime, timezone


# Files
TEXT_LOG = "../logs/ssh.log"
JSON_LOG = "../logs/ssh.jsonl"

# --------------------------
# Helpers
# --------------------------

def log_text(message):
    with open(TEXT_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} - {message}\n")


def log_json(ip, username, password, status, raw):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "srcip": ip,
        "dstport": 2222,
        "username": username,
        "password": password,
        "status": status,
        "honeypottype": "ssh",
        "rawlog": raw
    }
    with open(JSON_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

# Clean telnet input
def clean(text):
    if not text:
        return ""
    return "".join(c for c in text.strip() if c.isprintable())

# Fix telnet CRLF
def receive_line(client):
    buffer = b""
    while True:
        chunk = client.recv(1)
        if not chunk:
            return ""
        if chunk == b"\r":   # ignore CR
            continue
        buffer += chunk
        if chunk == b"\n":   # stop on LF
            break
    return buffer.decode(errors="ignore").strip()

# --------------------------
# Main SSH Honeypot
# --------------------------

def start_ssh():
    server = socket.socket()
    server.bind(("0.0.0.0", 2222))
    server.listen(5)

    print("[+] SSH Honeypot running on port 2222")
    log_text("[+] SSH Honeypot started on port 2222")

    while True:
        client, addr = server.accept()
        ip = addr[0]

        print(f"🔥 Connection from: {ip}")
        log_text(f"New connection from {ip}")

        client.send(b"SSH-2.0-OpenSSH_7.4\r\n")

        # --------------------------
        # Login system (3 attempts)
        # --------------------------
        CORRECT_USER = "PhantomNet"
        CORRECT_PASS = "1234"

        attempts = 0
        login_success = False

        while attempts < 3:

            client.send(b"Username: ")
            username = clean(receive_line(client))
            if username == "":
                continue

            client.send(b"Password: ")
            password = clean(receive_line(client))
            if password == "":
                continue

            log_text(f"Login attempt {attempts+1} {ip}: {username}/{password}")
            log_json(ip, username, password, "attempt", f"{username}/{password} attempt")

            # Check credentials
            if username == CORRECT_USER and password == CORRECT_PASS:
                login_success = True
                log_json(ip, username, password, "success", "login success")
                break

            attempts += 1
            client.send(b"Invalid Username or Password\n")
            log_json(ip, username, password, "failed", "wrong credentials")

        # Too many failures
        if not login_success:
            client.send(b"Error :- Access temporarily disabled due to excessive failed attempts. Try again after some time. Connection closed.\n")
            log_text(f"{ip} disconnected after 3 failed attempts")
            client.close()
            continue

        # --------------------------
        # Login success → fake shell
        # --------------------------
        welcome = (
            "\nWelcome to Ubuntu 20.04 LTS\n"
            "Last login: Tue Dec 9 10:00:00 2025\n\n"
        )
        client.send(welcome.encode())

        cwd = f"/home/{username}"

        # --------------------------
        # Fake command shell
        # --------------------------
        while True:
            try:
                prompt = f"{username}@honeypot:{cwd}$ "
                client.send(prompt.encode())

                cmd = clean(receive_line(client))
                if cmd == "":
                    continue

                log_text(f"CMD from {ip}: {cmd}")
                log_json(ip, username, password, "command", cmd)

                # Fake commands
                if cmd == "ls":
                    response = "file1.txt  config.ini  secrets.log  projectteam.txt\n"

                elif cmd == "pwd":
                    response = cwd + "\n"

                elif cmd == "whoami":
                    response = username + "\n"

                elif cmd.startswith("cd "):
                    parts = cmd.split()
                    if len(parts) == 2:
                        cwd = cwd + "/" + parts[1]
                        response = ""
                    else:
                        response = "cd: missing argument\n"

                elif cmd in ["exit", "logout"]:
                    client.send(b"logout\n")
                    break

                else:
                    response = f"{cmd}: command not found\n"

                client.send(response.encode())

            except:
                break

        client.close()

if __name__ == "__main__":

    start_ssh()