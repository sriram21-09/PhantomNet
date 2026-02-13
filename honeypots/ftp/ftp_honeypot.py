import socket
import time

def start_honeypot(host='0.0.0.0', port=2121):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f'FTP Honeypot listening on {port}...')
    
    while True:
        conn, addr = s.accept()
        print(f'Connection from {addr}')
        try:
            conn.send(b'220 (vsFTPd 3.0.3)\r\n')
            data = conn.recv(1024)
            print(f'Received: {data}')
            conn.send(b'331 Please specify the password.\r\n')
            conn.close()
        except:
            pass
if __name__ == "__main__":
    start_honeypot()
