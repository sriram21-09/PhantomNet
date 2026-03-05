# PhantomNet — SIEM / ELK Stack Integration Guide

> Centralized security event monitoring via Elasticsearch, Logstash, and Kibana.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [ELK Stack Setup](#elk-stack-setup)
3. [Logstash Pipeline](#logstash-pipeline)
4. [SIEM Exporter Service](#siem-exporter-service)
5. [Kibana Dashboards](#kibana-dashboards)
6. [Environment Variables](#environment-variables)
7. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌──────────────┐     HTTP POST      ┌──────────────┐     Index      ┌──────────────────┐
│  PhantomNet  │  ─────────────►    │   Logstash   │  ──────────►   │  Elasticsearch   │
│  Backend     │   port 5044        │  (pipeline)  │                │  (phantomnet-     │
│              │   JSON / CEF       │              │                │   events-*)       │
└──────────────┘                    └──────────────┘                └──────────────────┘
       ▲                                   │                              │
       │                             GeoIP Filter                         │
  siem_exporter.py                   Threat Tagging                       ▼
  (APScheduler)                                                    ┌──────────────┐
  polls every 60s                                                  │   Kibana      │
  PacketLog + Alert                                                │  :5601        │
  tables                                                           └──────────────┘
```

---

## ELK Stack Setup

### Prerequisites

- Docker (recommended) or bare-metal Linux host
- 8 GB+ RAM for the ELK stack
- GeoLite2-City database (`/usr/share/GeoIP/GeoLite2-City.mmdb`)

### Elasticsearch 8.x

```bash
# Install
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.12.0-linux-x86_64.tar.gz
tar xzf elasticsearch-8.12.0-linux-x86_64.tar.gz
cd elasticsearch-8.12.0

# Configure cluster
cat >> config/elasticsearch.yml << EOF
cluster.name: phantomnet-cluster
node.name: phantomnet-node-1
network.host: 0.0.0.0
discovery.type: single-node
xpack.security.enabled: true
xpack.security.http.ssl.enabled: false
EOF

# Set JVM heap to 4 GB
sed -i 's/-Xms1g/-Xms4g/' config/jvm.options
sed -i 's/-Xmx1g/-Xmx4g/' config/jvm.options

# Start
./bin/elasticsearch -d

# Set password for elastic user
./bin/elasticsearch-reset-password -u elastic --interactive
```

### Logstash 8.x

```bash
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.12.0-linux-x86_64.tar.gz
tar xzf logstash-8.12.0-linux-x86_64.tar.gz
cd logstash-8.12.0

# Copy PhantomNet pipeline config
cp <project_root>/elk_config/logstash/phantomnet.conf config/conf.d/

# Start
./bin/logstash -f config/conf.d/phantomnet.conf
```

### Kibana 8.x

```bash
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.12.0-linux-x86_64.tar.gz
tar xzf kibana-8.12.0-linux-x86_64.tar.gz
cd kibana-8.12.0

cat >> config/kibana.yml << EOF
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "<your_password>"
EOF

./bin/kibana
```

### Docker Compose (Alternative)

For quick setup, add to your existing `docker-compose.yml`:

```yaml
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    environment:
      - cluster.name=phantomnet-cluster
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms4g -Xmx4g
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=changeme
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.0
    ports:
      - "5044:5044"
    volumes:
      - ./elk_config/logstash/phantomnet.conf:/usr/share/logstash/pipeline/phantomnet.conf
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=changeme
    depends_on:
      - elasticsearch

volumes:
  es_data:
```

---

## Logstash Pipeline

**Config file**: `elk_config/logstash/phantomnet.conf`

| Stage | Purpose |
|-------|---------|
| **Input** | HTTP listener on port `5044` with JSON codec |
| **Filter — Date** | Parses ISO8601 timestamps into `@timestamp` |
| **Filter — GeoIP** | Enriches `src_ip` with geographic coordinates |
| **Filter — Tags** | Adds `critical`, `high_threat`, `malicious` tags |
| **Filter — Mutate** | Normalizes protocol to uppercase, converts numeric types |
| **Output** | Writes to `phantomnet-events-YYYY.MM.dd` index with ILM |

### Deploying the Pipeline

```bash
# Copy to Logstash config directory
sudo cp elk_config/logstash/phantomnet.conf /etc/logstash/conf.d/

# Test configuration
sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/phantomnet.conf

# Restart Logstash
sudo systemctl restart logstash
```

---

## SIEM Exporter Service

**File**: `backend/services/siem_exporter.py`

### How It Works

1. **Scheduler** — APScheduler runs `_export_cycle()` every 60 seconds
2. **Query** — Fetches new `PacketLog` and `Alert` rows since last export (watermark cursor)
3. **Transform** — Converts to JSON or CEF format
4. **Ship** — HTTP POST to Logstash with retry (exponential backoff, max 5 attempts)

### Starting the Service

```python
from services.siem_exporter import siem_exporter

# Start with defaults (60s interval, JSON format)
siem_exporter.start()

# Check status
print(siem_exporter.status())

# Manual export trigger
siem_exporter.export_now()

# Stop
siem_exporter.stop()
```

### Output Formats

**JSON** (default):
```json
{
  "event_id": 12345,
  "timestamp": "2026-03-03T12:00:00Z",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.5",
  "protocol": "SSH",
  "threat_score": 0.85,
  "threat_level": "HIGH",
  "is_malicious": true,
  "source": "phantomnet",
  "event_type": "packet_log"
}
```

**CEF**:
```
CEF:0|PhantomNet|IDS|1.0|SUSPICIOUS|SSH event from 192.168.1.100|8|src=192.168.1.100 dst=10.0.0.5 spt=54321 dpt=22 proto=SSH cn1=0.85 cn1Label=ThreatScore cs1=HIGH cs1Label=ThreatLevel
```

---

## Kibana Dashboards

**Config file**: `elk_config/phantomnet_dashboard.json`

### Import Steps

1. Open Kibana at `http://localhost:5601`
2. Go to **Stack Management → Saved Objects**
3. Click **Import** and upload `phantomnet_dashboard.json`
4. Navigate to **Dashboard → PhantomNet Security Overview**

### Included Visualizations

| Panel | Type | Description |
|-------|------|-------------|
| **Events Timeline** | Date Histogram | Event volume over time, stacked by threat level |
| **Threat Level Distribution** | Donut Chart | CRITICAL / HIGH / MEDIUM / LOW breakdown |
| **Top Source IPs** | Horizontal Bar | Top 20 attacking source IPs |
| **Geographic Attack Map** | Tile Map | World map with attack origin markers |
| **Protocol Distribution** | Pie Chart | SSH / HTTP / FTP / SMTP mix |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOGSTASH_URL` | `http://localhost:5044` | Logstash HTTP input endpoint |
| `SIEM_EXPORT_INTERVAL` | `60` | Seconds between export cycles |
| `SIEM_BATCH_SIZE` | `1000` | Max events per batch |
| `SIEM_OUTPUT_FORMAT` | `json` | Output format (`json` or `cef`) |
| `SIEM_MAX_RETRIES` | `5` | Max retry attempts per batch |
| `SIEM_RETRY_BASE_DELAY` | `2.0` | Base delay for exponential backoff (seconds) |
| `ES_USER` | `elastic` | Elasticsearch username (in Logstash config) |
| `ES_PASSWORD` | `changeme` | Elasticsearch password (in Logstash config) |

---

## Troubleshooting

### Logstash not receiving events

```bash
# Verify Logstash is listening
curl -X POST http://localhost:5044 -H "Content-Type: application/json" -d '{"test": true}'

# Check Logstash logs
tail -f /var/log/logstash/logstash-plain.log
```

### Elasticsearch connection errors

```bash
# Verify Elasticsearch is running
curl -u elastic:changeme https://localhost:9200/_cluster/health?pretty

# Check index exists
curl -u elastic:changeme https://localhost:9200/_cat/indices/phantomnet-events-*?v
```

### No data in Kibana dashboard

1. Confirm the index pattern `phantomnet-events-*` exists in **Stack Management → Index Patterns**
2. Adjust the time range in Kibana (top-right) to cover when events were exported
3. Verify events in Elasticsearch:
   ```bash
   curl -u elastic:changeme "https://localhost:9200/phantomnet-events-*/_count"
   ```

### SIEM Exporter not shipping events

```python
# Check status
from services.siem_exporter import siem_exporter
print(siem_exporter.status())
# Look at total_exported / total_failed counts
```

- If `total_failed` is high → check Logstash endpoint connectivity
- If `last_packet_id` is 0 → no PacketLog rows exist in the database yet

### GeoIP not enriching

- Ensure the GeoLite2-City database is at `/usr/share/GeoIP/GeoLite2-City.mmdb`
- Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free, requires account)
