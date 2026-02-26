import socket
import time
import requests
import paramiko
import json
import logging
from concurrent.futures import ThreadPoolExecutor

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Targets defined by SD-N topology
TARGETS = {
    "ssh": "10.0.2.31",
    "smtp": "10.0.2.30",
    "backend": "10.0.3.40"
}
PORTS = {
    "ssh": 2222,  # Using simulated ports typically mapped in the honeypots
    "smtp": 2525
}
BACKEND_API = f"http://{TARGETS['backend']}:8000"

class AttackSimulator:
    def __init__(self):
        self.session = requests.Session()

    # ==========================================
    # STAGE 1: RECONNAISSANCE / PORT SCANNING
    # ==========================================
    def simulate_port_scan(self, target_ip, start_port=20, end_port=100):
        logging.info(f"[*] Starting SYN/Connect Scan on {target_ip} ({start_port}-{end_port})")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    logging.info(f"[+] Port {port} is open on {target_ip}")
                sock.close()
            except Exception as e:
                pass

        with ThreadPoolExecutor(max_workers=20) as executor:
            for port in range(start_port, end_port + 1):
                executor.submit(scan_port, port)
                
        # Also ping specific honeypot ports to guarantee logs
        scan_port(PORTS["ssh"])
        scan_port(PORTS["smtp"])

        logging.info("[*] Port Scan completed.")

    # ==========================================
    # STAGE 2: SSH BRUTE FORCE
    # ==========================================
    def simulate_ssh_brute_force(self):
        target = TARGETS["ssh"]
        port = PORTS["ssh"]
        logging.info(f"[*] Starting SSH Brute Force on {target}:{port}")
        
        # Common weak credentials
        credentials = [
            ("root", "123456"),
            ("admin", "admin"),
            ("user", "password"),
            ("guest", "guest"),
            ("ubuntu", "ubuntu")
        ]
        
        for user, password in credentials:
            try:
                logging.info(f"    -> Trying {user}:{password}")
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                # Timeouts are short; we expect failures, we just want the honeypot to log the attempt
                ssh.connect(target, port=port, username=user, password=password, timeout=2)
                logging.warning(f"[!] SUCCESS: Logged in with {user}:{password}")
                ssh.close()
            except paramiko.AuthenticationException:
                # This is expected for honeypots
                pass
            except Exception as e:
                logging.error(f"[-] SSH Error: {e}")
            time.sleep(0.5)  # Slight delay to avoid completely crashing local test environments
            
        logging.info("[*] SSH Brute Force completed.")

    # ==========================================
    # STAGE 3: APT CAMPAIGN (SMTP EICAR/SPAM)
    # ==========================================
    def simulate_apt_smtp(self):
        target = TARGETS["smtp"]
        port = PORTS["smtp"]
        logging.info(f"[*] Starting APT SMTP Payload Delivery on {target}:{port}")
        
        # The standard EICAR test string
        eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        
        smtp_commands = [
            b"HELO attacker.com\r\n",
            b"MAIL FROM:<apt@darkweb.local>\r\n",
            b"RCPT TO:<admin@phantomnet.local>\r\n",
            b"DATA\r\n",
            f"Subject: URGENT: Q3 Financial Report\r\n\r\nAttached is the report.\r\nBEGIN PAYLOAD\r\n{eicar}\r\nEND PAYLOAD\r\n.\r\n".encode('utf-8'),
            b"QUIT\r\n"
        ]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            response = sock.recv(1024)
            logging.info(f"    <- {response.decode('utf-8').strip()}")
            
            for cmd in smtp_commands:
                logging.info(f"    -> {cmd.decode('utf-8').strip()}")
                sock.sendall(cmd)
                response = sock.recv(1024)
                logging.info(f"    <- {response.decode('utf-8').strip()}")
                time.sleep(1)
            sock.close()
        except Exception as e:
            logging.error(f"[-] SMTP APT Error: {e}")
            
        logging.info("[*] APT SMTP Campaign completed.")

    # ==========================================
    # VALIDATION: CHECK BACKEND ML PARSING
    # ==========================================
    def validate_detection(self):
        logging.info("[*] Verifying Threat Detection on PhantomNet Backend...")
        try:
            # Short wait to allow ML pipeline to process logs via Filebeat -> Logstash -> Backend
            logging.info("    -> Waiting 10 seconds for log ingestion & ML pipeline scoring...")
            time.sleep(10)
            
            response = self.session.get(f"{BACKEND_API}/analyze-traffic", timeout=5)
            if response.status_code == 200:
                data = response.json()
                logs = data.get("data", [])
                
                malicious_score = sum(1 for log in logs if log.get("ai_analysis", {}).get("prediction") == "MALICIOUS" or log.get("ai_analysis", {}).get("threat_score", 0) > 0.5)
                
                logging.info(f"[+] Successfully fetched {len(logs)} recent traffic logs from backend.")
                logging.info(f"[+] Out of the {len(logs)} recent packets, {malicious_score} were flagged as MALICIOUS by the ML Model.")
                
                if malicious_score > 0:
                    logging.info("[!] VALIDATION PASSED: ML Model successfully identified the simulated attacks.")
                else:
                    logging.warning("[-] VALIDATION FAILED: Backend did not classify recent events as MALICIOUS. Check Model thresholds or Logstash pipeline.")
            else:
                logging.error(f"[-] Backend returned HTTP {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            logging.error(f"[-] Could not connect to Backend API at {BACKEND_API}. Ensure the topology is running and backend is up.")
        except Exception as e:
            logging.error(f"[-] Validation Error: {e}")

if __name__ == "__main__":
    print("""
    =============================================
     PhantomNet Attack Simulation Framework
     -> Target: 3-Layer SD-N Mininet Topology
    =============================================
    """)
    simulator = AttackSimulator()

    simulator.simulate_port_scan(TARGETS["ssh"])
    time.sleep(2)
    
    simulator.simulate_ssh_brute_force()
    time.sleep(2)
    
    simulator.simulate_apt_smtp()
    time.sleep(2)
    
    simulator.validate_detection()
    print("\n[+] Simulation Campaign Finished.")
