# PhantomNet — SIEM Integration Guide

> **Complete guide** for integrating PhantomNet with ELK Stack, Splunk, Syslog, and custom SIEM platforms.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Universal SIEM Framework](#universal-siem-framework)
3. [ELK Stack Integration](#elk-stack-integration)
4. [Splunk Integration](#splunk-integration)
5. [Syslog / CEF Integration](#syslog--cef-integration)
6. [Troubleshooting](#troubleshooting)
7. [Performance Tuning](#performance-tuning)

---

## Architecture Overview

```
┌─────────────────────┐
│  PhantomNet Backend  │
│  - PacketLog         │
│  - Alerts            │
└────────┬────────────┘
         │ APScheduler (every 60s)
         ▼
┌─────────────────────────────┐
│  SIEMExporterService        │
│  - Watermark-based cursor   │
│  - Batch processing (1000)  │
│  - Retry with backoff       │
└────────┬────────────────────┘
         │ get_siem_exporter()
         ▼
┌─────────────────────────────────────────────────┐
│  Universal SIEM Exporter (Abstract Factory)      │
│                                                   │
│  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────┐│
│  │ELKExport │ │SplunkExp │ │CEFExpt │ │SyslogEx││
│  │(Logstash)│ │ (HEC)    │ │ (HTTP) │ │(UDP/TCP││
│  └──────────┘ └──────────┘ └────────┘ └────────┘│
└──────────────────────────────────────────────────┘
```

**Key files:**

| File | Purpose |
|---|---|
| `backend/services/siem_exporter.py` | Main export scheduler service (APScheduler, watermarks) |
| `backend/services/universal_siem_exporter.py` | Abstract factory with ELK, CEF, Syslog exporters |
| `backend/services/splunk_exporter.py` | Splunk HEC client with batch support |
| `elk_config/logstash/phantomnet.conf` | Logstash pipeline configuration |
| `elk_config/phantomnet_dashboard.json` | Kibana dashboard export |

---

## Universal SIEM Framework

PhantomNet uses an **abstract factory pattern** to support multiple SIEM platforms through a single interface.

### Environment Configuration

```bash
# .env — Select your SIEM backend
SIEM_TYPE=elk                      # Options: elk, splunk, cef, syslog
SIEM_EXPORT_INTERVAL=60            # Export frequency (seconds)
SIEM_BATCH_SIZE=1000               # Events per batch
SIEM_MAX_RETRIES=5                 # Retry attempts
SIEM_RETRY_BASE_DELAY=2.0          # Base delay for exponential backoff
```

### Supported Output Formats

| SIEM_TYPE | Exporter Class | Transport | Format |
|---|---|---|---|
| `elk` | `ELKExporter` | HTTP → Logstash | JSON |
| `splunk` | `SplunkExporter` | HTTP → HEC | JSON (Splunk envelope) |
| `cef` | `CEFExporter` | HTTP → Logstash | CEF strings in JSON |
| `syslog` | `SyslogExporter` | UDP/TCP direct | CEF strings |

### Event Schema

Every exported event includes:

```json
{
  "event_id": 42,
  "timestamp": "2026-03-06T12:00:00Z",
  "src_ip": "10.0.0.45",
  "dst_ip": "192.168.1.1",
  "src_port": 54321,
  "dst_port": 22,
  "protocol": "SSH",
  "length": 128,
  "attack_type": "BRUTE_FORCE",
  "threat_score": 0.87,
  "threat_level": "HIGH",
  "confidence": 0.92,
  "is_malicious": true,
  "source": "phantomnet",
  "event_type": "packet_log"
}
```

### CEF Format Output

```
CEF:0|PhantomNet|IDS|1.0|BRUTE_FORCE|SSH event from 10.0.0.45|8|
  src=10.0.0.45 dst=192.168.1.1 spt=54321 dpt=22 proto=SSH
  cn1=0.87 cn1Label=ThreatScore cn2=0.92 cn2Label=Confidence
  cs1=HIGH cs1Label=ThreatLevel
```

---

## ELK Stack Integration

### Installation

```bash
# 1. Install Elasticsearch
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.12.0-linux-x86_64.tar.gz
tar xzf elasticsearch-8.12.0-linux-x86_64.tar.gz
cd elasticsearch-8.12.0 && ./bin/elasticsearch

# 2. Install Logstash
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.12.0-linux-x86_64.tar.gz
tar xzf logstash-8.12.0-linux-x86_64.tar.gz

# 3. Install Kibana
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.12.0-linux-x86_64.tar.gz
tar xzf kibana-8.12.0-linux-x86_64.tar.gz
cd kibana-8.12.0 && ./bin/kibana
```

### Logstash Pipeline

Deploy the PhantomNet pipeline configuration:

```bash
# Copy configuration
sudo cp elk_config/logstash/phantomnet.conf /etc/logstash/conf.d/

# Restart Logstash
sudo systemctl restart logstash
```

**Pipeline features** (from `phantomnet.conf`):

| Stage | Description |
|---|---|
| **Input** | HTTP input on port 5044 (JSON codec, 4 threads) |
| **Date** | ISO8601 timestamp parsing → `@timestamp` |
| **GeoIP** | Source IP enrichment via GeoLite2-City database |
| **Tagging** | Threat-level tags: `critical`, `high_threat`, `medium_threat`, `malicious` |
| **Normalize** | Protocol field uppercased |
| **Cleanup** | Removes transient `headers` and `host` fields |
| **Convert** | Ensures `threat_score`, `confidence`, ports, length are proper types |
| **Output** | Elasticsearch with ILM (daily rollover: `phantomnet-events-YYYY.MM.dd`) |

### Elasticsearch Index Configuration

```bash
# Create Index Lifecycle Policy
curl -X PUT "localhost:9200/_ilm/policy/phantomnet-ilm-policy" \
  -H 'Content-Type: application/json' -d '
{
  "policy": {
    "phases": {
      "hot":    { "actions": { "rollover": { "max_size": "10gb", "max_age": "7d" }}},
      "warm":   { "min_age": "7d", "actions": { "shrink": { "number_of_shards": 1 }}},
      "delete": { "min_age": "90d", "actions": { "delete": {} }}
    }
  }
}'

# Verify index pattern
curl "localhost:9200/phantomnet-events-*/_count"
```

### Kibana Dashboard Setup

```bash
# Import pre-built dashboard
curl -X POST "localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  --form file=@elk_config/phantomnet_dashboard.json
```

**Dashboard panels include:**

| Panel | Visualization |
|---|---|
| Threat Level Distribution | Pie chart (CRITICAL/HIGH/MEDIUM/LOW) |
| Events Over Time | Line chart with threat-level breakdown |
| Top Attacking IPs | Data table sorted by event count |
| GeoIP Attack Map | Coordinate map with src_ip locations |
| Protocol Distribution | Bar chart by protocol |
| Threat Score Histogram | Distribution of threat scores |
| Recent Critical Alerts | Searchable alert table |

### Index Patterns

Create the following index patterns in Kibana → Stack Management → Index Patterns:

| Pattern | Time Field | Purpose |
|---|---|---|
| `phantomnet-events-*` | `@timestamp` | All security events |
| `phantomnet-alerts-*` | `@timestamp` | Filtered alert events only |

---

## Splunk Integration

### HEC Configuration

```bash
# Environment variables
SIEM_TYPE=splunk
SPLUNK_HEC_URL=https://splunk-server:8088/services/collector/event
SPLUNK_HEC_TOKEN=your-hec-token-here
```

**Splunk-side setup:**

1. **Settings → Data Inputs → HTTP Event Collector** → New Token
2. **Name**: `phantomnet_honeypot`
3. **Source Type**: `phantomnet:event`
4. **Default Index**: `phantomnet`
5. **Enable** the token and copy the GUID

### Index Setup

```spl
# Create index in Splunk (via CLI or UI)
splunk add index phantomnet -maxTotalDataSizeMB 10240 -frozenTimePeriodInSecs 7776000
```

### Event Format

PhantomNet wraps events in Splunk HEC envelope:

```json
{
  "time": 1709712000.0,
  "host": "phantomnet_ids",
  "source": "phantomnet_honeypot",
  "sourcetype": "phantomnet:event",
  "event": {
    "event_id": 42,
    "src_ip": "10.0.0.45",
    "threat_level": "HIGH",
    "attack_type": "BRUTE_FORCE"
  }
}
```

### Search Examples

```spl
# All high-threat events in last 24h
index=phantomnet sourcetype="phantomnet:event" event.threat_level="HIGH" earliest=-24h

# Top attacking IPs
index=phantomnet | stats count by event.src_ip | sort -count | head 20

# Attack timeline
index=phantomnet event.is_malicious=true | timechart count by event.attack_type

# Protocol distribution
index=phantomnet | stats count by event.protocol | sort -count

# Threat score anomalies (>0.9)
index=phantomnet event.threat_score>0.9 | table _time event.src_ip event.attack_type event.threat_score
```

---

## Syslog / CEF Integration

For SIEM platforms that accept CEF over syslog (QRadar, ArcSight, etc.):

```bash
# Environment variables
SIEM_TYPE=syslog
SYSLOG_HOST=siem-server.internal
SYSLOG_PORT=514
SYSLOG_PROTO=UDP   # or TCP
```

Events are sent as CEF-formatted strings over raw UDP/TCP sockets.

---

## Troubleshooting

### Common Errors

| Error | Cause | Fix |
|---|---|---|
| `Connection refused to localhost:5044` | Logstash not running | `sudo systemctl start logstash` |
| `HTTP 401 Unauthorized` | Wrong credentials | Check `ES_USER` / `ES_PASSWORD` env vars |
| `Splunk HEC HTTP 403` | Invalid token | Regenerate HEC token in Splunk UI |
| `APScheduler not installed` | Missing dependency | `pip install apscheduler` |
| `No new events to export` | No unscored events | Verify `PacketLog` table has data |
| `Syslog export failed` | Firewall blocking | Allow port 514 UDP/TCP |

### Verification Commands

```bash
# Check Logstash is receiving events
curl -X POST http://localhost:5044 \
  -H "Content-Type: application/json" \
  -d '{"test": "phantomnet_ping", "timestamp": "2026-01-01T00:00:00Z"}'

# Verify Elasticsearch ingestion
curl "localhost:9200/phantomnet-events-*/_count"

# Check SIEM exporter status (API)
curl http://localhost:8000/api/siem/status

# View export logs
tail -f logs/siem_export.log

# Splunk HEC health check
curl -k https://splunk-server:8088/services/collector/health \
  -H "Authorization: Splunk YOUR_TOKEN"
```

---

## Performance Tuning

| Parameter | Default | Recommendation |
|---|---|---|
| `SIEM_EXPORT_INTERVAL` | 60s | 30s for high-volume, 120s for low-volume |
| `SIEM_BATCH_SIZE` | 1000 | 2000–5000 for high-throughput environments |
| `SIEM_MAX_RETRIES` | 5 | Reduce to 3 if timeout issues occur |
| Logstash threads | 4 | Match CPU core count |
| Logstash pipeline.batch.size | 125 | Increase to 500 for throughput |
| Elasticsearch shards | Auto | 1 primary + 1 replica per index |
| ILM rollover | 10GB / 7d | Adjust based on volume |

### High-Volume Deployment Tips

1. **Use bulk indexing** — Logstash HTTP input handles batches natively
2. **Enable ILM** — Automatic rollover prevents oversized indices
3. **GeoIP caching** — Logstash caches GeoIP lookups; ensure DB is updated monthly
4. **Monitor queue depth** — `curl localhost:9600/_node/stats/pipelines` shows queue health
5. **Dedicated Logstash node** — Separate from Elasticsearch for I/O isolation
