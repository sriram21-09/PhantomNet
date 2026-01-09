import socket
import time

SMTP_HOST = "localhost"
SMTP_PORT = 2525

def send_cmd(sock, cmd):
    sock.sendall((cmd + "\r\n").encode())
    time.sleep(0.2)
    return sock.recv(4096).decode()

def test_smtp_basic_flow():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SMTP_HOST, SMTP_PORT))

    banner = sock.recv(1024).decode()
    assert "SMTP" in banner

    assert "250" in send_cmd(sock, "HELO test.com")
    assert "250" in send_cmd(sock, "MAIL FROM:<attacker@test.com>")
    assert "250" in send_cmd(sock, "RCPT TO:<victim@test.com>")
    assert "354" in send_cmd(sock, "DATA")

    sock.sendall(b"Subject: Test Mail\r\n\r\nHello\r\n.\r\n")
    time.sleep(0.2)
    response = sock.recv(1024).decode()
    assert "250" in response

    assert "221" in send_cmd(sock, "QUIT")

    sock.close()
