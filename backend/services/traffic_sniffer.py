from scapy.all import sniff, IP, TCP, UDP, ICMP
from services.feature_extractor import FeatureExtractor
from services.ai_predictor import ThreatDetector
from db_core import SessionLocal
from app_models import PacketLog
import threading
from datetime import datetime

class RealTimeSniffer:
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.detector = ThreatDetector()
        self.running = False

    def packet_callback(self, packet):
        if not packet.haslayer(IP):
            return

        try:
            # 1. Extract Data
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            
            if packet.haslayer(TCP): protocol = 'TCP'
            elif packet.haslayer(UDP): protocol = 'UDP'
            elif packet.haslayer(ICMP): protocol = 'ICMP'
            else: protocol = 'OTHER'

            # 2. AI Analysis
            norm_dur = self.extractor.normalize(0.1, 'duration') 
            proto_vec = self.extractor.encode_protocol(protocol)
            ip_vec = self.extractor.extract_ip_patterns(src_ip, dst_ip)
            features = [norm_dur, ip_vec[0], ip_vec[1]] + proto_vec

            label, score = self.detector.predict(features)
            
            # 3. Determine Status
            status = "BENIGN"
            if score > 0.80: status = "MALICIOUS"
            elif score > 0.50: status = "SUSPICIOUS"

            # 4. Save to Database
            db = SessionLocal()
            new_log = PacketLog(
                timestamp=datetime.utcnow(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                length=length,
                is_malicious=(status == "MALICIOUS"),
                threat_score=float(score),
                attack_type=status # Storing status (Malicious/Suspicious/Benign)
            )
            db.add(new_log)
            db.commit()
            db.close()

            # Optional: Print only Warnings to console
            if score > 0.5:
                print(f"[{status}] {src_ip} -> {dst_ip} | Score: {score:.2f} (Saved to DB)")

        except Exception as e:
            pass

    def start_background_sniffer(self):
        """Starts sniffing in a background thread so the API can run too."""
        if not self.running:
            self.running = True
            t = threading.Thread(target=self._run_sniff, daemon=True)
            t.start()
            print("✅ Background Sniffer Started")

    def _run_sniff(self):
        sniff(prn=self.packet_callback, store=0)