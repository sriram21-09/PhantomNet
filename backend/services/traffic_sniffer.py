from typing import Optional, Any, Tuple, List, Dict
import threading
import os
from datetime import datetime

from database.database import SessionLocal
from database.models import PacketLog
import asyncio
from api.realtime import push_realtime_event
from sqlalchemy.orm import Session

# ✅ WEEK 6 ML PIPELINE
from ml.threat_correlation import ThreatCorrelator


class RealTimeSniffer:
    def __init__(self, interface: Optional[str] = None) -> None:
        """
        Initializes the sniffer with a specific interface and DB session.
        """
        self.interface: Optional[str] = interface
        self.db: Session = SessionLocal()
        self.threat_correlator = ThreatCorrelator()
        self.running = False

    def packet_callback(self, packet: Any) -> None:
        """
        Processes a captured network packet, evaluates its threat level, 
        saves the log to the database, and pushes events via WebSockets.

        Args:
            packet: The scapy packet object to analyze.
        """
        from scapy.all import IP, TCP, UDP, ICMP  # type: ignore  # lazy import
        if not packet.haslayer(IP): # type: ignore
            return

        try:
            src_ip = packet[IP].src # type: ignore
            dst_ip = packet[IP].dst # type: ignore
            length = len(packet)

            src_port = 0
            dst_port = 0

            if packet.haslayer(TCP): # type: ignore
                protocol = "TCP"
                src_port = packet[TCP].sport # type: ignore
                dst_port = packet[TCP].dport # type: ignore
            elif packet.haslayer(UDP): # type: ignore
                protocol = "UDP"
                src_port = packet[UDP].sport # type: ignore
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = "OTHER"

            # Filter out internal infrastructure traffic to avoid feedback loops
            INTERNAL_PORTS = {5432, 6379, 8000, 11434}
            if src_port in INTERNAL_PORTS or dst_port in INTERNAL_PORTS:
                return
            if src_ip in ("127.0.0.1", "::1", "localhost") and dst_ip in ("127.0.0.1", "::1", "localhost"):
                return

            # -----------------------------
            # 1️⃣ BUILD LOG ENTRY
            # -----------------------------
            log_entry = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": length,
                "attacker_ip": src_ip,
                "timestamp": datetime.utcnow().isoformat(),
            }

            # -----------------------------
            # 2️⃣ THREAT CORRELATION (FULL PIPELINE)
            # -----------------------------
            try:
                threat = self.threat_correlator.evaluate(log_entry)
                attack_type = threat.get("verdict", "SAFE")
                risk_score = threat.get("total_risk_score", 0.0)
            except Exception:
                attack_type = "SAFE"
                risk_score = 0.0

            # Normalize attack_type for DB
            if attack_type == "CRITICAL":
                attack_label = "MALICIOUS"
                t_level = "CRITICAL"
            elif attack_type == "HIGH":
                attack_label = "SUSPICIOUS"
                t_level = "HIGH"
            elif attack_type == "WARNING":
                attack_label = "SUSPICIOUS"
                t_level = "MEDIUM"
            else:
                attack_label = "BENIGN"
                t_level = "LOW"

            risk_norm = float(risk_score) / 100.0 if risk_score is not None else 0.0
            if risk_norm >= 0.8:
                t_level = "CRITICAL"
            elif risk_norm >= 0.6 and t_level not in ("CRITICAL", "HIGH"):
                t_level = "HIGH"

            # -----------------------------
            # 3️⃣ SAVE TO DATABASE
            # -----------------------------
            db = SessionLocal()
            new_log = PacketLog(
                timestamp=datetime.utcnow(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=length,
                is_malicious=(attack_label == "MALICIOUS"),
                threat_score=risk_norm,
                threat_level=t_level,
                attack_type=attack_label,
            )
            db.add(new_log)
            db.commit()
            db.close()

            # -----------------------------
            # 3.5️⃣ PUSH TO REAL-TIME WS
            # -----------------------------
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(
                        push_realtime_event(
                            "EVENT_STREAM",
                            {
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "protocol": protocol,
                                "length": length,
                                "threat_score": risk_score,
                                "attack_type": attack_label,
                                "timestamp": datetime.utcnow().isoformat(),
                            },
                        )
                    )
                else:
                    asyncio.run(
                        push_realtime_event(
                            "EVENT_STREAM",
                            {
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "protocol": protocol,
                                "length": length,
                                "threat_score": risk_score,
                                "attack_type": attack_label,
                                "timestamp": datetime.utcnow().isoformat(),
                            },
                        )
                    )
            except Exception as e:
                pass  # Non-blocking for sniffer

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

    def start_background_sniffer(self) -> None:
        """
        Starts the scapy sniffer in a background thread if it's not already running.
        """
        if not self.running:
            self.running = True
            t = threading.Thread(target=self._run_sniff, daemon=True)
            t.start()
            print("[+] Background Sniffer Started (ML-Driven)")

    def _run_sniff(self) -> None:
        """
        Internal target for the sniffer thread; initiates scapy's sniff function.
        """
        try:
            from scapy.all import sniff  # type: ignore  # lazy import
            sniff(prn=self.packet_callback, store=0)
        except ImportError:
            print("[WARN] Scapy not available - sniffer disabled")
            self.running = False
        except OSError as e:
            print(f"[WARN] Sniffer requires admin privileges: {e}")
            self.running = False
