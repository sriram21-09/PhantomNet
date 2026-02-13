import socket

def start_honeypot(host='0.0.0.0', port=2222):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f'SSH Honeypot listening on {port}...')
    
    while True:
        conn, addr = s.accept()
        print(f'SSH Probe from {addr}')
        conn.send(b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n')
        conn.close()

if __name__ == "__main__":
    start_honeypot()
