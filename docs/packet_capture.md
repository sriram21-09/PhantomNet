# PhantomNet Packet Capture System

## Overview

PhantomNet's packet capture system provides automated PCAP recording, deep packet inspection (DPI), and malicious pattern detection integrated with the threat detection pipeline. When a HIGH or CRITICAL threat is detected, the system automatically captures network traffic, analyzes packets for malicious patterns, and extracts IOCs.

## Architecture

```
┌──────────────────────┐     ┌──────────────────────┐
│   Traffic Sniffer    │────▶│   Threat Analyzer    │
│  (Scapy real-time)   │     │  (ML scoring loop)   │
└──────────────────────┘     └──────────┬───────────┘
                                        │ HIGH/CRITICAL
                                        ▼
                             ┌──────────────────────┐
                             │   PCAP Analyzer      │
                             │  - start_capture()   │
                             │  - analyze_pcap()    │
                             │  - detect_patterns() │
                             │  - extract_iocs()    │
                             └──────────┬───────────┘
                                        │
                       ┌────────────────┼────────────────┐
                       ▼                ▼                ▼
              ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
              │  data/pcaps/ │ │   Database   │ │  Dashboard   │
              │  .pcap files │ │  PcapCapture │ │  React UI    │
              └──────────────┘ └──────────────┘ └──────────────┘
```

## Setup

### Prerequisites

- **Scapy** (included in `requirements.txt`) for packet parsing
- **tcpdump / libpcap** on the Mininet VM for raw capture
- **Wireshark** (optional) for offline PCAP analysis

### Infrastructure Setup

```bash
# Install tcpdump on Mininet VM
sudo apt-get install tcpdump

# Configure OpenVSwitch port mirroring
sudo ovs-vsctl -- set Bridge br0 mirrors=@m \
  -- --id=@p get Port eth0 -- --id=@m create Mirror name=mirror0 \
  select-all=true output-port=@p

# Test capture
sudo tcpdump -i any -w test.pcap -c 100

# Install Wireshark
sudo apt-get install wireshark
```

### Data Directory

PCAP files are stored in `data/pcaps/`. The directory is created automatically on first capture.

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/events/{id}/pcap` | GET | Download PCAP file for event |
| `/api/v1/pcap/analysis/{id}` | GET | Get analysis report (JSON) |
| `/api/v1/pcap/stats` | GET | Capture system statistics |
| `/api/v1/pcap/capture/{id}` | POST | Trigger manual capture |
| `/api/v1/pcap/capture/{id}/status` | GET | Check capture status |
| `/api/v1/pcap/cleanup` | POST | Manual retention cleanup |

### Example: Get Analysis

```bash
curl http://localhost:8000/api/v1/pcap/analysis/42
```

Response:
```json
{
  "status": "success",
  "event_id": 42,
  "report": {
    "overall_severity": "HIGH",
    "summary": {
      "total_packets": 1247,
      "threats_detected": 2,
      "iocs_found": 6
    },
    "details": {
      "protocol_distribution": [...],
      "top_talkers": [...],
      "malicious_patterns": [...],
      "iocs": {"ips": [...], "domains": [...], "urls": [...]}
    }
  }
}
```

## Detection Capabilities

### Malicious Patterns

| Pattern | Trigger | Severity |
|---|---|---|
| **SYN Flood** | ≥100 SYN packets from same IP | CRITICAL |
| **Port Scan** | ≥20 unique ports from same IP | HIGH |
| **NULL Scan** | ≥10 NULL (no TCP flags) packets | HIGH |
| **C2 Beaconing** | Periodic connections (<2s deviation, <120s interval) | CRITICAL |
| **Data Exfiltration** | ≥1 MB outbound from single IP | HIGH |
| **Buffer Overflow** | Payload >2000 bytes | CRITICAL |

### Deep Packet Inspection

- **HTTP**: Method, path, headers extraction
- **DNS**: Query name, type, answer records
- **SSH**: Banner extraction for version fingerprinting

### IOC Extraction

- **IPs**: All unique source/destination addresses
- **Domains**: DNS query names + HTTP Host headers
- **URLs**: HTTP request paths

## Dashboard

Navigate to **PCAP Analysis** in the PhantomNet dashboard (`/packet-analysis`) to view:

- **Stats Cards**: Total captures, disk usage, active captures, packets analyzed, threats detected
- **Protocol Distribution**: Pie chart of protocol breakdown
- **Top Talkers**: Table of top 10 source IPs by packet count
- **Malicious Patterns**: Cards with severity badges for each detected pattern
- **IOCs**: Grid of extracted indicators (IPs, domains, URLs)
- **Suspicious Packets**: Scrollable list with severity badges and packet details
- **Download PCAP**: Button to download for offline Wireshark analysis

## Retention Policy

- Default retention: **30 days**
- Automated cleanup runs daily via background scheduler
- Manual cleanup available via `POST /api/v1/pcap/cleanup`
- Configurable via `retention_days` parameter

## Wireshark Workflow

1. Trigger an attack against a honeypot
2. Threat analyzer detects HIGH/CRITICAL threat → auto-captures PCAP
3. Navigate to PCAP Analysis dashboard → click **Download PCAP**
4. Open downloaded `.pcap` file in Wireshark
5. Apply display filters: `tcp.flags.syn == 1 && tcp.flags.ack == 0` (SYN scans)
6. Export specific conversations for deeper forensic analysis

## Files

| File | Description |
|---|---|
| `backend/services/pcap_analyzer.py` | Core analysis engine (capture, DPI, patterns, IOCs) |
| `backend/api/pcap.py` | FastAPI router (download, analysis, stats) |
| `backend/database/models.py` | `PcapCapture` model + `pcap_path` on `Event` |
| `backend/services/threat_analyzer.py` | Integration — triggers capture on HIGH threats |
| `frontend-dev/.../components/PacketAnalysis.jsx` | React dashboard component |
| `frontend-dev/.../Styles/components/PacketAnalysis.css` | Component styles |
