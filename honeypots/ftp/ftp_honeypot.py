import socket
import sys
import os

# Add deception module to sys.path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../security-dev"))
)
from deception.adaptive_behavior import AdaptiveEngine


def start_ftp_honeypot(host="0.0.0.0", port=2121):
    engine = AdaptiveEngine(profile="Interactive")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(f"FTP Honeypot listening on {port}...")

    while True:
        conn, addr = s.accept()
        print(f"FTP Probe from {addr}")

        engine.apply_delay()
        conn.send(b"220 vsFTPd 3.0.3\r\n")

        try:
            while True:
                data = conn.recv(1024).strip().decode(errors="ignore")
                if not data:
                    break

                if data.startswith("USER"):
                    conn.send(b"331 Please specify the password.\r\n")
                elif data.startswith("PASS"):
                    engine.tarpit(2)  # Fake authentication delay
                    conn.send(b"530 Login incorrect.\r\n")
                    break
                elif data.startswith("SYST"):
                    conn.send(b"215 UNIX Type: L8\r\n")
                elif data.startswith("QUIT"):
                    conn.send(b"221 Goodbye.\r\n")
                    break
                else:
                    conn.send(b"500 Unknown command.\r\n")
        except Exception:
            pass
        conn.close()


if __name__ == "__main__":
    start_ftp_honeypot()
