import socket
import json
from datetime import datetime
import requests

BACKEND_API = "http://127.0.0.1:8000/api/logs"
PORT = 2121  # avoid real FTP port conflicts

def send_event(ip, raw):
    payload = {
        "source_ip": ip,
        "honeypot_type": "ftp",
        "port": PORT,
        "raw_data": raw
    }
    try:
        requests.post(BACKEND_API, json=payload, timeout=2)
    except:
        pass

def start_ftp():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", PORT))
    server.listen(5)

    print(f"[+] FTP Honeypot running on port {PORT}")

    while True:
        client, addr = server.accept()
        ip = addr[0]

        send_event(ip, "FTP connection attempt")
        client.send(b"220 FTP Server Ready\r\n")

        try:
            user = client.recv(1024).decode(errors="ignore").strip()
            send_event(ip, f"USER command: {user}")
            client.send(b"331 Username OK, need password\r\n")

            pwd = client.recv(1024).decode(errors="ignore").strip()
            send_event(ip, f"PASS command: {pwd}")
            client.send(b"530 Login incorrect\r\n")

        except Exception as e:
            send_event(ip, f"FTP error: {str(e)}")

        client.close()

if __name__ == "__main__":
    start_ftp()
