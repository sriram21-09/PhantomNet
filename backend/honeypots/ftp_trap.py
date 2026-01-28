import socket
import threading
import psycopg2

# --- CONFIG ---
DB_CONFIG = {
    "dbname": "phantomnet", 
    "user": "phantom", 
    "password": "securepass", 
    "host": "/var/run/postgresql"
}

def log_attack(ip, user, password):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("INSERT INTO attack_logs (attacker_ip, target_node, service_type, username, password) VALUES (%s, %s, %s, %s, %s)",
                    (ip, "h4", "FTP", user, password))
        conn.commit()
        conn.close()
        print(f"✅ LOGGED: {user}/{password}")
    except Exception as e:
        print(f"❌ DB ERROR: {e}")

def handle_client(client_socket, addr):
    try:
        client_socket.send(b"220 PhantomNet Secure FTP Server Ready\r\n")
        username = ""
        
        while True:
            data = client_socket.recv(1024).decode('utf-8').strip()
            if not data: break
                
            if data.startswith("USER"):
                username = data.split(" ")[1]
                client_socket.send(b"331 Password required\r\n")
                
            elif data.startswith("PASS"):
                password = data.split(" ")[1]
                log_attack(addr[0], username, password)
                client_socket.send(b"530 Login incorrect.\r\n")
                break 
            
            elif data.startswith("QUIT"):
                client_socket.send(b"221 Goodbye.\r\n")
                break    
    except:
        pass
    finally:
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 21))
    server.listen(5)
    print("📂 FTP Trap Active on Port 21...")
    
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

if __name__ == "__main__":
    start_server()