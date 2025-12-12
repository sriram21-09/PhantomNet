import socket

HOST = "127.0.0.1"
PORT = 8080

try:
    s = socket.create_connection((HOST, PORT), timeout=5)
    # build request containing byte 0x01 inside header value
    req = b"GET /admin HTTP/1.1\r\nHost: localhost:8080\r\nBad-Header: " + b"\x01" + b"\r\n\r\n"
    s.sendall(req)
    try:
        resp = s.recv(4096)
        print("Response (truncated):")
        print(resp.decode('latin1', errors='ignore')[:1000])
    except Exception as e:
        print("No or partial response:", e)
    s.close()
except Exception as e:
    print("Connection/send failed:", e)
