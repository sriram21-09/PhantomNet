import socket
import threading
import paramiko
import psycopg2
import logging

# --- SETUP LOGGING ---
# Writes logs to a temporary file so we can see errors even if the console is silent
logging.basicConfig(filename='/tmp/ssh_debug.log', level=logging.DEBUG, format='%(asctime)s %(message)s')

# --- CONFIGURATION ---
DB_NAME = "phantomnet"
DB_USER = "phantom"
DB_PASS = "securepass"
# We use the socket folder because network phantomnet_postgres is isolated in Mininet
DB_HOST = "/var/run/postgresql" 

# Generate a host key (in a real app, you would load a saved key)
HOST_KEY = paramiko.RSAKey.generate(2048)

def log_attack_to_db(ip, username, password):
    """
    Connects to the PostgreSQL database and saves the attack details.
    """
    try:
        logging.info(f"🔌 Connecting to DB to log user: {username}...")
        
        # Connect to the Database via Unix Socket
        conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)
        cur = conn.cursor()
        
        # Insert the attack data
        cur.execute("""
            INSERT INTO attack_logs (attacker_ip, target_node, service_type, username, password)
            VALUES (%s, %s, %s, %s, %s)
        """, (ip, "h2", "SSH", username, password))
        
        conn.commit()
        cur.close()
        conn.close()
        
        logging.info("✅ SUCCESS: Attack saved to Database!")
        print(f"✅ Logged attack: {username}/{password}")
        
    except Exception as e:
        logging.error(f"❌ DB ERROR: {e}")
        print(f"❌ DB ERROR: {e}")

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        logging.info(f"🚨 PASSWORD ATTACK: IP={self.client_ip} User={username} Pass={password}")
        # SAVE TO DATABASE HERE
        log_attack_to_db(self.client_ip, username, password)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        logging.info(f"🚨 KEY ATTACK: IP={self.client_ip} User={username}")
        # Log key-based attacks as well
        log_attack_to_db(self.client_ip, username, "Used_Public_Key")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

def handle_connection(client, addr):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        server = SSHServer(addr[0])
        
        # Start the SSH session
        transport.start_server(server=server)
        
        # Wait for a channel (or auth failure)
        channel = transport.accept(20)
        if channel is not None:
            channel.close()
            
    except Exception as e:
        logging.error(f"⚠️ TRANSPORT ERROR: {e}")

def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 2222))
    sock.listen(100)
    
    logging.info("🪤 SSH Honeypot V2 STARTED")
    print("🪤 SMART SSH Honeypot Active on Port 2222 (Logging to DB & /tmp/ssh_debug.log)")

    while True:
        try:
            client, addr = sock.accept()
            threading.Thread(target=handle_connection, args=(client, addr)).start()
        except Exception as e:
            logging.error(f"Server loop error: {e}")

if __name__ == "__main__":
    start_server()
