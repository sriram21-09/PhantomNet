# 🛡️ PhantomNet System Architecture

## 1. Database Schema & Relationships
The system relies on a relational database (PostgreSQL) with two primary tables.

### Table: `packet_logs`
Stores individual network packets captured by the sniffer.
| Column | Type | Index? | Description |
| :--- | :--- | :---: | :--- |
| `id` | Integer | 🔑 | Primary Key |
| `timestamp` | DateTime | ✅ | Time of capture (UTC) |
| `src_ip` | String | ✅ | Source IPv4 Address |
| `dst_ip` | String | | Destination IPv4 Address |
| `protocol` | String | | TCP, UDP, or ICMP |
| `length` | Integer | | Packet size in bytes |
| `is_malicious` | Boolean | | AI Prediction flag |
| `threat_score` | Float | | 0.0 to 1.0 confidence score |
| `attack_type` | String | | e.g., "SYN Scan", "DDoS" |

### Table: `traffic_stats`
Stores aggregated metrics for the dashboard charts.
| Column | Type | Index? | Description |
| :--- | :--- | :---: | :--- |
| `id` | Integer | 🔑 | Primary Key |
| `timestamp` | DateTime | | Time of aggregation |
| `total_packets` | Integer | | Count of packets in time window |
| `malicious_packets` | Integer | | Count of threats in time window |

---

## 2. Ingestion & Transformation Pipeline
The data flows through the system in real-time steps:

1.  **Capture Layer (`sniffer.py`):** Uses `Scapy` to hook into the Network Interface Card (NIC) and capture raw packets.
2.  **Extraction Layer:** Key features (`src`, `dst`, `proto`, `size`) are stripped from the raw bytes.
3.  **Analysis Layer:** The extracted features are passed to the Random Forest AI model.
    * *Input:* `[protocol_id, length, port]`
    * *Output:* `Malicious (True/False)` + `Threat Score`
4.  **Ingestion Layer:** The enriched object is committed to the PostgreSQL database using SQLAlchemy.
5.  **Visualization Layer:** The React Dashboard polls the API every 2 seconds to fetch the latest rows.

---

## 3. API Documentation
The Backend exposes a REST API via **FastAPI** running on port `8000`.

### `GET /analyze-traffic`
Fetches the most recent packet logs for the live table.
* **Response:** JSON array of last 50 packets with Geolocation.
* **Latency Target:** < 50ms

### `GET /traffic-stats`
Fetches aggregated counts for the line charts.
* **Response:** `{ "total": 1500, "malicious": 45, "history": [...] }`

### `POST /block-ip`
Triggers the Active Defense mechanism.
* **Body:** `{ "ip": "192.168.1.5" }`
* **Action:** Executes OS-level Firewall rule (Netsh/Iptables) to drop traffic.

---

## 4. Common Analysis Queries (SQL)
Use these queries for manual forensic analysis.

**A. Find Top Attacking IPs**
```sql
SELECT src_ip, COUNT(*) as attack_count 
FROM packet_logs 
WHERE is_malicious = TRUE 
GROUP BY src_ip 
ORDER BY attack_count DESC 
LIMIT 10;
SELECT date_trunc('hour', timestamp) as hour, attack_type, COUNT(*) 
FROM packet_logs 
GROUP BY hour, attack_type 
ORDER BY hour DESC;
SELECT src_ip, COUNT(*) 
FROM packet_logs 
WHERE length < 64 AND protocol = 'TCP' 
GROUP BY src_ip 
HAVING COUNT(*) > 100;
---

## 5. Performance & Scaling Recommendations
Based on stress testing (Jan 2026), the system handles **50 concurrent threads** with **~8ms write latency**.

**Scaling Recommendations:**
1.  **Database Indexing:** Ensure `src_ip` and `timestamp` are indexed. This improved read speeds by **20%** in benchmarks.
2.  **Connection Pooling:** Keep SQLAlchemy `pool_size=10` and `max_overflow=20`. Do not increase indefinitely or the DB will choke.
3.  **Data Retention:** The `packet_logs` table grows fast. Schedule a cron job to archive/delete logs older than 30 days:
    * `DELETE FROM packet_logs WHERE timestamp < NOW() - INTERVAL '30 days';`