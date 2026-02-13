import socket

def start_honeypot(host='0.0.0.0', port=2525):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f'SMTP Honeypot listening on {port}...')
    
    while True:
        conn, addr = s.accept()
        print(f'SMTP Probe from {addr}')
        conn.send(b'220 smtp.google.com ESMTP Postfix\r\n')
        conn.close()

if __name__ == "__main__":
    start_honeypot()
