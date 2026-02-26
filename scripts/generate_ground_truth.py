
import csv
import random
from datetime import datetime, timedelta, timezone

# Configuration
OUTPUT_FILE = "data/ground_truth.csv"
NUM_EVENTS = 200
MALICIOUS_RATIO = 0.3  # ~60 malicious events
START_TIME = datetime.now(timezone.utc) - timedelta(hours=1)

# Constants for synthetic data creation
PROTOCOLS = ["TCP", "UDP", "ICMP"]
HONEYPOTS = ["ssh", "http", "telnet", "ftp", "mysql"]
ATTACK_TYPES = ["brute_force", "sqli", "port_scan", "xss", "ddos"]
NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
ATTACKER_IPS = [f"203.0.113.{i}" for i in range(100, 110)]

def generate_benign_event(timestamp):
    """Generates a normal traffic event."""
    src_ip = random.choice(NORMAL_IPS)
    dst_ip = "10.0.0.5" # Internal server
    protocol = random.choices(["TCP", "UDP"], weights=[0.8, 0.2])[0]
    
    # Normal traffic characteristics
    length = random.randint(64, 1500)
    dst_port = random.choice([80, 443, 22])
    threat_score = random.uniform(0.0, 0.3)
    
    return {
        "timestamp": timestamp.isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
        "attack_type": "none",
        "honeypot_type": "none",
        "threat_score": round(threat_score, 2),
        "is_malicious": False
    }

def generate_malicious_event(timestamp):
    """Generates a malicious traffic event."""
    src_ip = random.choice(ATTACKER_IPS)
    dst_ip = "10.0.0.5"
    protocol = random.choice(PROTOCOLS)
    
    # Attack traffic characteristics
    attack = random.choice(ATTACK_TYPES)
    
    if attack == "ddos":
        length = random.randint(64, 128) # Small packets
        dst_port = 80
        threat_score = random.uniform(0.7, 0.9)
    elif attack == "port_scan":
        length = 64
        dst_port = random.randint(1024, 65535)
        threat_score = random.uniform(0.4, 0.7)
    else: # Exploits
        length = random.randint(500, 2048)
        dst_port = random.choice([80, 443, 22, 21, 3306])
        threat_score = random.uniform(0.6, 1.0)

    # Honeypot interaction is likely for attackers
    honeypot = random.choice(HONEYPOTS) if random.random() > 0.3 else "none"

    return {
        "timestamp": timestamp.isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
        "attack_type": attack,
        "honeypot_type": honeypot,
        "threat_score": round(threat_score, 2),
        "is_malicious": True
    }

def main():
    events = []
    
    # Generate events
    current_time = START_TIME
    for _ in range(NUM_EVENTS):
        # Time progression
        current_time += timedelta(seconds=random.uniform(0.1, 5.0))
        
        is_attack = random.random() < MALICIOUS_RATIO
        if is_attack:
            event = generate_malicious_event(current_time)
        else:
            event = generate_benign_event(current_time)
            
        events.append(event)

    # Write to CSV
    # Create header based on keys
    if not events:
        print("No events generated.")
        return

    keys = events[0].keys()
    
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(events)
        
    print(f"[SUCCESS] Generated {len(events)} events to {OUTPUT_FILE}")
    print(f"Malicious events: {sum(1 for e in events if e['is_malicious'])}")
    print(f"Benign events: {sum(1 for e in events if not e['is_malicious'])}")

if __name__ == "__main__":
    main()
