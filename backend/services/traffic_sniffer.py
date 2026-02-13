from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
from datetime import datetime

from db_core import SessionLocal
from database.models import PacketLog

# ✅ WEEK 6 ML PIPELINE
from ml.threat_correlation import ThreatCorrelator


class RealTimeSniffer:
    def __init__(self):
        self.threat_correlator = ThreatCorrelator()
        self.running = False

    def packet_callback(self, packet):
        if not packet.haslayer(IP):
            return

        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)

            if packet.haslayer(TCP):
                protocol = "TCP"
            elif packet.haslayer(UDP):
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = "OTHER"

            # -----------------------------
            # 1️⃣ BUILD LOG ENTRY
            # -----------------------------
            log_entry = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "packet_length": length,
                "attacker_ip": src_ip,   # required by threat correlator
                "timestamp": datetime.utcnow()
            }

            # -----------------------------
            # 2️⃣ THREAT CORRELATION (FULL PIPELINE)
            # -----------------------------
            threat = self.threat_correlator.evaluate(log_entry)

            attack_type = threat["verdict"]                 # SAFE / WARNING / HIGH / CRITICAL
            risk_score = threat["total_risk_score"]         # 0–100

            # Normalize attack_type for DB
            if attack_type == "CRITICAL":
                attack_label = "MALICIOUS"
            elif attack_type in ("HIGH", "WARNING"):
                attack_label = "SUSPICIOUS"
            else:
                attack_label = "BENIGN"

            # -----------------------------
            # 3️⃣ SAVE TO DATABASE
            # -----------------------------
            db = SessionLocal()
            new_log = PacketLog(
                timestamp=datetime.utcnow(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                length=length,
                is_malicious=(attack_label == "MALICIOUS"),
                threat_score=risk_score,
                attack_type=attack_label
            )
            db.add(new_log)
            db.commit()
            db.close()

            # -----------------------------
            # 4️⃣ CONSOLE OUTPUT
            # -----------------------------
            if attack_label != "BENIGN":
                print(
                    f"[{attack_label}] {src_ip} -> {dst_ip} | "
                    f"Risk: {risk_score:.1f}"
                )

        except Exception as e:
            print(f"[Sniffer Error] {e}")

    def start_background_sniffer(self):
        if not self.running:
            self.running = True
            t = threading.Thread(target=self._run_sniff, daemon=True)
            t.start()
            print("✅ Background Sniffer Started (ML-Driven)")

    def _run_sniff(self):
        sniff(prn=self.packet_callback, store=0)
