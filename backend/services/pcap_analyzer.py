"""
PhantomNet PCAP Analyzer Service
=================================
Deep packet inspection, malicious pattern detection, and automated
capture management integrated with the threat detection pipeline.
"""

import os
import json
import time
import glob
import logging
import threading
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import Counter, defaultdict

try:
    from scapy.all import (
        sniff,
        rdpcap,
        wrpcap,
        IP,
        TCP,
        UDP,
        ICMP,
        DNS,
        DNSQR,
        DNSRR,
        Raw,
        Ether,
    )

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("pcap_analyzer")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PCAP_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "..", "data", "pcaps"
)
DEFAULT_RETENTION_DAYS = 30
MAX_CAPTURE_DURATION = 300  # 5 minutes max per capture
SYN_FLOOD_THRESHOLD = 100  # SYNs from same IP in window
NULL_SCAN_THRESHOLD = 10  # NULL packets in window
BEACONING_INTERVAL_TOLERANCE = 2  # seconds tolerance for periodic beaconing
EXFIL_SIZE_THRESHOLD = 1_000_000  # 1 MB outbound threshold
BUFFER_OVERFLOW_SIZE = 2000  # payload size suggesting buffer overflow attempt


class PcapAnalyzer:
    """
    Automated PCAP capture and deep packet inspection engine.

    Responsibilities:
    - Start/stop packet captures on demand
    - Analyse PCAP files for protocol distribution & top talkers
    - Detect malicious patterns (port scans, C2 beaconing, exfiltration)
    - Extract IOCs (IPs, domains, URLs) from packet payloads
    - Manage PCAP retention (30-day default)
    """

    def __init__(self):
        os.makedirs(PCAP_DIR, exist_ok=True)
        self._active_captures: Dict[str, threading.Thread] = {}
        self._capture_results: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Capture management
    # ------------------------------------------------------------------
    def start_capture(
        self,
        event_id: int,
        interface: str = "any",
        duration: int = 60,
        bpf_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start a background packet capture for a given event."""
        capture_id = str(event_id)
        pcap_path = os.path.join(PCAP_DIR, f"{event_id}.pcap")

        with self._lock:
            if capture_id in self._active_captures:
                return {"status": "already_running", "event_id": event_id}

        duration = min(duration, MAX_CAPTURE_DURATION)

        def _do_capture():
            try:
                logger.info(
                    f"[PCAP] Starting capture for event {event_id} on {interface} ({duration}s)"
                )
                packets = sniff(
                    iface=interface if interface != "any" else None,
                    timeout=duration,
                    filter=bpf_filter,
                    store=True,
                )
                wrpcap(pcap_path, packets)
                analysis = self.analyze_pcap(pcap_path)
                with self._lock:
                    self._capture_results[capture_id] = {
                        "status": "complete",
                        "pcap_path": pcap_path,
                        "packet_count": len(packets),
                        "file_size": os.path.getsize(pcap_path),
                        "analysis": analysis,
                        "completed_at": datetime.utcnow().isoformat(),
                    }
                logger.info(
                    f"[PCAP] Capture for event {event_id} complete — {len(packets)} packets"
                )
            except Exception as exc:
                logger.error(f"[PCAP] Capture error for event {event_id}: {exc}")
                with self._lock:
                    self._capture_results[capture_id] = {
                        "status": "error",
                        "error": str(exc),
                    }
            finally:
                with self._lock:
                    self._active_captures.pop(capture_id, None)

        t = threading.Thread(target=_do_capture, daemon=True, name=f"pcap-{event_id}")
        with self._lock:
            self._active_captures[capture_id] = t
        t.start()

        return {
            "status": "started",
            "event_id": event_id,
            "pcap_path": pcap_path,
            "duration": duration,
        }

    def get_capture_status(self, event_id: int) -> Dict[str, Any]:
        """Return current status of a capture."""
        capture_id = str(event_id)
        with self._lock:
            if capture_id in self._active_captures:
                return {"status": "capturing", "event_id": event_id}
            if capture_id in self._capture_results:
                return self._capture_results[capture_id]
        # Check if file exists on disk from a previous run
        pcap_path = os.path.join(PCAP_DIR, f"{event_id}.pcap")
        if os.path.exists(pcap_path):
            return {
                "status": "complete",
                "pcap_path": pcap_path,
                "file_size": os.path.getsize(pcap_path),
            }
        return {"status": "not_found", "event_id": event_id}

    # ------------------------------------------------------------------
    # PCAP Analysis
    # ------------------------------------------------------------------
    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Parse a PCAP file and produce a full analysis report."""
        if not SCAPY_AVAILABLE:
            return self._mock_analysis()

        if not os.path.exists(pcap_path):
            return {"error": "PCAP file not found", "path": pcap_path}

        try:
            packets = rdpcap(pcap_path)
        except Exception as exc:
            return {"error": f"Failed to read PCAP: {exc}"}

        protocol_counts: Counter = Counter()
        src_ip_counts: Counter = Counter()
        dst_ip_counts: Counter = Counter()
        port_counts: Counter = Counter()
        total_bytes = 0
        packet_details: List[Dict] = []
        timestamps: List[float] = []

        for pkt in packets:
            total_bytes += len(pkt)

            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src_ip_counts[ip_layer.src] += 1
                dst_ip_counts[ip_layer.dst] += 1

                if pkt.haslayer(TCP):
                    protocol_counts["TCP"] += 1
                    port_counts[pkt[TCP].dport] += 1
                elif pkt.haslayer(UDP):
                    protocol_counts["UDP"] += 1
                    port_counts[pkt[UDP].dport] += 1
                elif pkt.haslayer(ICMP):
                    protocol_counts["ICMP"] += 1
                else:
                    protocol_counts["OTHER"] += 1

                if pkt.haslayer(DNS):
                    protocol_counts["DNS"] += 1
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    if payload[:4] in (b"HTTP", b"GET ", b"POST", b"PUT ", b"HEAD"):
                        protocol_counts["HTTP"] += 1
                    if pkt.haslayer(TCP) and pkt[TCP].dport == 22:
                        protocol_counts["SSH"] += 1

                timestamps.append(float(pkt.time))

        # Detect malicious patterns
        malicious = self.detect_malicious_patterns(packets)

        # Extract IOCs
        iocs = self.extract_iocs(packets)

        # Build DPI summaries
        dpi_results = [self.deep_packet_inspect(pkt) for pkt in packets[:200]]
        dpi_results = [d for d in dpi_results if d]

        # Protocol distribution
        total_proto = sum(protocol_counts.values()) or 1
        protocol_distribution = [
            {
                "protocol": proto,
                "count": cnt,
                "percentage": round(cnt / total_proto * 100, 1),
            }
            for proto, cnt in protocol_counts.most_common(10)
        ]

        # Top talkers
        top_talkers = [
            {"ip": ip, "packets": cnt, "direction": "source"}
            for ip, cnt in src_ip_counts.most_common(10)
        ]

        # Suspicious packets summary
        suspicious_packets = malicious.get("suspicious_packets", [])

        return {
            "total_packets": len(packets),
            "total_bytes": total_bytes,
            "duration_seconds": (
                round(max(timestamps) - min(timestamps), 2)
                if len(timestamps) >= 2
                else 0
            ),
            "protocol_distribution": protocol_distribution,
            "top_talkers": top_talkers,
            "top_destination_ports": [
                {"port": p, "count": c} for p, c in port_counts.most_common(10)
            ],
            "malicious_patterns": malicious.get("patterns", []),
            "suspicious_packets": suspicious_packets[:50],
            "iocs": iocs,
            "dpi_samples": dpi_results[:20],
            "analyzed_at": datetime.utcnow().isoformat(),
        }

    # ------------------------------------------------------------------
    # Malicious pattern detection
    # ------------------------------------------------------------------
    def detect_malicious_patterns(self, packets) -> Dict[str, Any]:
        """Scan packets for known malicious patterns."""
        patterns: List[Dict] = []
        suspicious: List[Dict] = []

        if not SCAPY_AVAILABLE or not packets:
            return {"patterns": patterns, "suspicious_packets": suspicious}

        syn_by_src: Counter = Counter()
        null_by_src: Counter = Counter()
        connection_times: defaultdict = defaultdict(list)
        outbound_bytes: Counter = Counter()
        ports_per_src: defaultdict = defaultdict(set)

        for idx, pkt in enumerate(packets):
            if not pkt.haslayer(IP):
                continue

            ip = pkt[IP]
            ts = float(pkt.time)

            # --- SYN flood detection ---
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                if tcp.flags == 0x02:  # SYN only
                    syn_by_src[ip.src] += 1
                    ports_per_src[ip.src].add(tcp.dport)

                # --- NULL scan detection ---
                if tcp.flags == 0:
                    null_by_src[ip.src] += 1
                    suspicious.append(
                        {
                            "index": idx,
                            "type": "NULL_SCAN",
                            "severity": "HIGH",
                            "src_ip": ip.src,
                            "dst_ip": ip.dst,
                            "detail": f"NULL scan packet (no TCP flags) → {ip.dst}:{tcp.dport}",
                        }
                    )

            # --- C2 beaconing ---
            connection_times[ip.src].append(ts)

            # --- Data exfiltration ---
            outbound_bytes[ip.src] += len(pkt)

            # --- Buffer overflow attempt ---
            if pkt.haslayer(Raw):
                payload_len = len(pkt[Raw].load)
                if payload_len > BUFFER_OVERFLOW_SIZE:
                    suspicious.append(
                        {
                            "index": idx,
                            "type": "BUFFER_OVERFLOW_ATTEMPT",
                            "severity": "CRITICAL",
                            "src_ip": ip.src,
                            "dst_ip": ip.dst,
                            "detail": f"Oversized payload ({payload_len} bytes) — possible buffer overflow",
                        }
                    )

        # Finalise SYN flood
        for src, count in syn_by_src.items():
            if count >= SYN_FLOOD_THRESHOLD:
                patterns.append(
                    {
                        "type": "SYN_FLOOD",
                        "severity": "CRITICAL",
                        "source_ip": src,
                        "syn_count": count,
                        "unique_ports": len(ports_per_src.get(src, set())),
                        "detail": f"{count} SYN packets from {src}",
                    }
                )

        # Finalise NULL scan
        for src, count in null_by_src.items():
            if count >= NULL_SCAN_THRESHOLD:
                patterns.append(
                    {
                        "type": "NULL_SCAN",
                        "severity": "HIGH",
                        "source_ip": src,
                        "null_count": count,
                        "detail": f"{count} NULL scan packets from {src}",
                    }
                )

        # Port scan detection (many unique ports from same source)
        for src, ports in ports_per_src.items():
            if len(ports) >= 20:
                patterns.append(
                    {
                        "type": "PORT_SCAN",
                        "severity": "HIGH",
                        "source_ip": src,
                        "ports_scanned": len(ports),
                        "detail": f"{src} probed {len(ports)} unique ports",
                    }
                )

        # C2 beaconing detection (regular intervals)
        for src, times in connection_times.items():
            if len(times) >= 10:
                times_sorted = sorted(times)
                intervals = [
                    times_sorted[i + 1] - times_sorted[i]
                    for i in range(len(times_sorted) - 1)
                ]
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    if avg_interval > 0:
                        deviations = [abs(i - avg_interval) for i in intervals]
                        avg_deviation = sum(deviations) / len(deviations)
                        if (
                            avg_deviation < BEACONING_INTERVAL_TOLERANCE
                            and avg_interval < 120
                        ):
                            patterns.append(
                                {
                                    "type": "C2_BEACONING",
                                    "severity": "CRITICAL",
                                    "source_ip": src,
                                    "avg_interval_sec": round(avg_interval, 2),
                                    "connection_count": len(times),
                                    "detail": f"Periodic connections every ~{avg_interval:.1f}s from {src}",
                                }
                            )

        # Data exfiltration
        for src, total in outbound_bytes.items():
            if total >= EXFIL_SIZE_THRESHOLD:
                patterns.append(
                    {
                        "type": "DATA_EXFILTRATION",
                        "severity": "HIGH",
                        "source_ip": src,
                        "total_bytes": total,
                        "detail": f"{total / 1_000_000:.2f} MB transferred from {src}",
                    }
                )

        return {"patterns": patterns, "suspicious_packets": suspicious}

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------
    def extract_iocs(self, packets) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from packet payloads."""
        iocs: Dict[str, set] = {
            "ips": set(),
            "domains": set(),
            "urls": set(),
        }

        if not SCAPY_AVAILABLE:
            return {k: list(v) for k, v in iocs.items()}

        for pkt in packets:
            if pkt.haslayer(IP):
                iocs["ips"].add(pkt[IP].src)
                iocs["ips"].add(pkt[IP].dst)

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    qname = (
                        pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    )
                    if qname and "." in qname:
                        iocs["domains"].add(qname)
                except Exception:
                    pass

            if pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                    # Extract URLs from HTTP payloads
                    for line in payload.split("\r\n"):
                        if line.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                            parts = line.split(" ")
                            if len(parts) >= 2:
                                iocs["urls"].add(parts[1])
                        if "Host: " in line:
                            host = line.split("Host: ", 1)[1].strip()
                            iocs["domains"].add(host)
                except Exception:
                    pass

        return {k: sorted(list(v))[:100] for k, v in iocs.items()}

    # ------------------------------------------------------------------
    # Deep Packet Inspection
    # ------------------------------------------------------------------
    def deep_packet_inspect(self, packet) -> Optional[Dict[str, Any]]:
        """Protocol-specific payload analysis for a single packet."""
        if not SCAPY_AVAILABLE or not packet.haslayer(IP):
            return None

        result: Dict[str, Any] = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "size": len(packet),
        }

        # HTTP DPI
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
            except Exception:
                payload = ""

            if any(
                payload.startswith(m)
                for m in ("GET ", "POST ", "PUT ", "HEAD ", "HTTP/")
            ):
                lines = payload.split("\r\n")
                result["protocol"] = "HTTP"
                result["method"] = lines[0].split(" ")[0] if lines else "UNKNOWN"
                result["path"] = (
                    lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "/"
                )
                headers = {}
                for line in lines[1:]:
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        headers[k] = v
                result["headers"] = headers
                return result

        # DNS DPI
        if packet.haslayer(DNS):
            result["protocol"] = "DNS"
            if packet.haslayer(DNSQR):
                result["query"] = (
                    packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                )
                result["query_type"] = str(packet[DNSQR].qtype)
            if packet.haslayer(DNSRR):
                result["answer"] = (
                    packet[DNSRR].rdata
                    if isinstance(packet[DNSRR].rdata, str)
                    else str(packet[DNSRR].rdata)
                )
            return result

        # SSH DPI
        if packet.haslayer(TCP) and packet[TCP].dport == 22:
            result["protocol"] = "SSH"
            if packet.haslayer(Raw):
                raw = packet[Raw].load
                if raw[:4] == b"SSH-":
                    result["banner"] = raw.decode("utf-8", errors="ignore").strip()
            return result

        return None

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------
    def generate_report(self, analysis: Dict) -> Dict[str, Any]:
        """Wrap analysis into a structured report."""
        severity = "LOW"
        patterns = analysis.get("malicious_patterns", [])
        if any(p.get("severity") == "CRITICAL" for p in patterns):
            severity = "CRITICAL"
        elif any(p.get("severity") == "HIGH" for p in patterns):
            severity = "HIGH"
        elif patterns:
            severity = "MEDIUM"

        return {
            "report_id": hashlib.md5(
                json.dumps(analysis, default=str).encode()
            ).hexdigest()[:12],
            "generated_at": datetime.utcnow().isoformat(),
            "overall_severity": severity,
            "summary": {
                "total_packets": analysis.get("total_packets", 0),
                "total_bytes": analysis.get("total_bytes", 0),
                "duration": analysis.get("duration_seconds", 0),
                "protocols": len(analysis.get("protocol_distribution", [])),
                "threats_detected": len(patterns),
                "iocs_found": sum(len(v) for v in analysis.get("iocs", {}).values()),
            },
            "details": analysis,
        }

    # ------------------------------------------------------------------
    # PCAP retention / cleanup
    # ------------------------------------------------------------------
    def cleanup_old_pcaps(
        self, retention_days: int = DEFAULT_RETENTION_DAYS
    ) -> Dict[str, Any]:
        """Delete PCAP files older than retention_days."""
        cutoff = time.time() - (retention_days * 86400)
        removed = 0
        freed_bytes = 0

        for pcap_file in glob.glob(os.path.join(PCAP_DIR, "*.pcap")):
            try:
                mtime = os.path.getmtime(pcap_file)
                if mtime < cutoff:
                    size = os.path.getsize(pcap_file)
                    os.remove(pcap_file)
                    removed += 1
                    freed_bytes += size
                    logger.info(f"[PCAP] Removed expired capture: {pcap_file}")
            except Exception as exc:
                logger.error(f"[PCAP] Failed to remove {pcap_file}: {exc}")

        return {
            "removed_files": removed,
            "freed_bytes": freed_bytes,
            "retention_days": retention_days,
        }

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------
    def get_stats(self) -> Dict[str, Any]:
        """Return overall capture system statistics."""
        pcap_files = glob.glob(os.path.join(PCAP_DIR, "*.pcap"))
        total_size = sum(os.path.getsize(f) for f in pcap_files) if pcap_files else 0

        with self._lock:
            active = len(self._active_captures)
            completed = len(self._capture_results)

        return {
            "total_captures": len(pcap_files),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / 1_000_000, 2),
            "active_captures": active,
            "completed_captures": completed,
            "pcap_directory": PCAP_DIR,
            "retention_days": DEFAULT_RETENTION_DAYS,
        }

    # ------------------------------------------------------------------
    # Mock fallback (when Scapy unavailable or no actual packets)
    # ------------------------------------------------------------------
    def _mock_analysis(self) -> Dict[str, Any]:
        """Return representative mock data for dashboard development."""
        return {
            "total_packets": 1247,
            "total_bytes": 892_340,
            "duration_seconds": 60.0,
            "protocol_distribution": [
                {"protocol": "TCP", "count": 680, "percentage": 54.5},
                {"protocol": "UDP", "count": 312, "percentage": 25.0},
                {"protocol": "HTTP", "count": 142, "percentage": 11.4},
                {"protocol": "DNS", "count": 78, "percentage": 6.3},
                {"protocol": "ICMP", "count": 23, "percentage": 1.8},
                {"protocol": "SSH", "count": 12, "percentage": 1.0},
            ],
            "top_talkers": [
                {"ip": "192.168.1.105", "packets": 234, "direction": "source"},
                {"ip": "10.0.0.45", "packets": 187, "direction": "source"},
                {"ip": "172.16.0.12", "packets": 156, "direction": "source"},
                {"ip": "192.168.1.200", "packets": 98, "direction": "source"},
                {"ip": "10.0.0.100", "packets": 67, "direction": "source"},
            ],
            "top_destination_ports": [
                {"port": 80, "count": 342},
                {"port": 443, "count": 215},
                {"port": 22, "count": 98},
                {"port": 53, "count": 78},
                {"port": 8080, "count": 45},
            ],
            "malicious_patterns": [
                {
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "source_ip": "10.0.0.45",
                    "ports_scanned": 47,
                    "detail": "10.0.0.45 probed 47 unique ports",
                },
                {
                    "type": "C2_BEACONING",
                    "severity": "CRITICAL",
                    "source_ip": "172.16.0.12",
                    "avg_interval_sec": 30.0,
                    "connection_count": 24,
                    "detail": "Periodic connections every ~30.0s from 172.16.0.12",
                },
            ],
            "suspicious_packets": [
                {
                    "index": 42,
                    "type": "NULL_SCAN",
                    "severity": "HIGH",
                    "src_ip": "10.0.0.45",
                    "dst_ip": "192.168.1.1",
                    "detail": "NULL scan packet → 192.168.1.1:445",
                },
                {
                    "index": 789,
                    "type": "BUFFER_OVERFLOW_ATTEMPT",
                    "severity": "CRITICAL",
                    "src_ip": "172.16.0.12",
                    "dst_ip": "192.168.1.105",
                    "detail": "Oversized payload (4096 bytes) — possible buffer overflow",
                },
            ],
            "iocs": {
                "ips": ["10.0.0.45", "172.16.0.12"],
                "domains": ["evil.example.com", "c2-server.net"],
                "urls": ["/admin/shell.php", "/cgi-bin/exploit"],
            },
            "dpi_samples": [],
            "analyzed_at": datetime.utcnow().isoformat(),
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
pcap_analyzer = PcapAnalyzer()
