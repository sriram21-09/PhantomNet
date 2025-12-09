import socket
from datetime import datetime

LOG_FILE = "../logs/ssh.log"

def log_event(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {message}\n")

def receive_command(client):
    buffer = b""
    while True:
        chunk = client.recv(1)  # read byte-by-byte
        if not chunk:
            break
        buffer += chunk
        if chunk == b"\n":  # user pressed ENTER
            break
    return buffer

def start_ssh():
    server = socket.socket()
    server.bind(("0.0.0.0", 2222))
    server.listen(5)

    print("[+] SSH Honeypot running on port 2222")
    log_event("[+] SSH Honeypot started on port 2222")

    while True:
        client, addr = server.accept()
        ip = addr[0]

        print(f"🔥 Incoming connection from: {ip}")
        log_event(f"New connection from {ip}")

        client.send(b"SSH-2.0-OpenSSH_7.4\r\n")

        # Read full command
        data = receive_command(client)

        if data:
            decoded = data.decode(errors="ignore").strip()
            print(f"Attacker Sent: {decoded}")
            log_event(f"Attacker {ip} sent: {decoded}")

        client.close()

if __name__ == "__main__":
    start_ssh()
