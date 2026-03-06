# PhantomNet — Production Deployment Guide

> **Step-by-step guide** for deploying PhantomNet in a production environment with security hardening, monitoring, and maintenance procedures.

---

## Table of Contents

1. [Hardware Requirements](#hardware-requirements)
2. [Installation](#installation)
3. [Security Hardening](#security-hardening)
4. [Monitoring & Maintenance](#monitoring--maintenance)

---

## Hardware Requirements

### Minimum (Small Deployment — up to 1,000 events/min)

| Component | Specification |
|---|---|
| CPU | 4 cores (x86_64) |
| RAM | 8 GB |
| Storage | 100 GB SSD |
| Network | 1 Gbps NIC |
| OS | Ubuntu 22.04 LTS |

### Recommended (Medium — up to 10,000 events/min)

| Component | Specification |
|---|---|
| CPU | 8 cores (x86_64) |
| RAM | 16 GB |
| Storage | 500 GB NVMe SSD |
| Network | 2 × 1 Gbps NIC (management + capture) |
| OS | Ubuntu 22.04 LTS |
| GPU | Optional — NVIDIA T4 for LSTM training |

### Scaling (Enterprise — 50,000+ events/min)

| Component | Specification |
|---|---|
| Backend API | 3× instances behind load balancer |
| Database | PostgreSQL HA (primary + replica) |
| Elasticsearch | 3-node cluster (32 GB RAM each) |
| Storage | 2 TB NVMe + NFS for PCAP archive |
| Network | 10 Gbps for capture interfaces |

---

## Installation

### Prerequisites

```bash
# System packages
sudo apt update && sudo apt install -y \
  python3.11 python3.11-venv python3-pip \
  postgresql postgresql-contrib \
  nodejs npm \
  tcpdump libpcap-dev \
  git curl wget

# Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Verify
python3.11 --version   # ≥ 3.11
node --version          # ≥ 18
psql --version          # ≥ 14
```

### 1. Clone Repository

```bash
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet
```

### 2. Environment Configuration

```bash
# Copy template and fill in values
cp .env.example .env
```

**Required `.env` variables:**

```bash
# Database
DATABASE_URL=postgresql://phantomnet:STRONG_PASSWORD@localhost:5432/phantomnet_db
ENVIRONMENT=production

# SIEM (optional)
SIEM_TYPE=elk
LOGSTASH_URL=http://logstash-server:5044

# Splunk (if using)
SPLUNK_HEC_URL=https://splunk:8088/services/collector/event
SPLUNK_HEC_TOKEN=your-token

# API Security
SECRET_KEY=generate-a-64-char-random-string
CORS_ORIGINS=https://your-domain.com

# GeoIP
GEOIP_DB_PATH=/usr/share/GeoIP/GeoLite2-City.mmdb
```

### 3. Database Setup

```bash
# Create database and user
sudo -u postgres psql <<EOF
CREATE USER phantomnet WITH PASSWORD 'STRONG_PASSWORD';
CREATE DATABASE phantomnet_db OWNER phantomnet;
GRANT ALL PRIVILEGES ON DATABASE phantomnet_db TO phantomnet;
EOF

# Tables are auto-created on first startup via SQLAlchemy
```

### 4. Backend Setup

```bash
cd backend

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Scapy for PCAP analysis
pip install scapy

# Create required directories
mkdir -p ../data/pcaps ../logs ../ml_models
```

### 5. Frontend Build

```bash
cd frontend-dev/phantomnet-dashboard

# Install dependencies
npm install

# Production build
npm run build

# Output: dist/ (serve via nginx)
```

### 6. Mininet VM Setup

```bash
# Install Mininet (on VM)
sudo apt install mininet openvswitch-switch

# Configure OVS port mirroring for PCAP capture
sudo ovs-vsctl -- set Bridge br0 mirrors=@m \
  -- --id=@p get Port eth0 \
  -- --id=@m create Mirror name=mirror0 select-all=true output-port=@p

# Test capture
sudo tcpdump -i any -w /tmp/test.pcap -c 100
```

### 7. Service Deployment

**Systemd service file** (`/etc/systemd/system/phantomnet.service`):

```ini
[Unit]
Description=PhantomNet Backend API
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=phantomnet
WorkingDirectory=/opt/phantomnet/backend
Environment=PATH=/opt/phantomnet/backend/venv/bin
ExecStart=/opt/phantomnet/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable phantomnet
sudo systemctl start phantomnet
```

**Nginx reverse proxy** (`/etc/nginx/sites-available/phantomnet`):

```nginx
server {
    listen 443 ssl;
    server_name phantomnet.yourdomain.com;

    ssl_certificate     /etc/ssl/certs/phantomnet.crt;
    ssl_certificate_key /etc/ssl/private/phantomnet.key;

    # Frontend
    location / {
        root /opt/phantomnet/frontend-dev/phantomnet-dashboard/dist;
        try_files $uri $uri/ /index.html;
    }

    # API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket proxy (real-time events)
    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## Security Hardening

### Checklist

| # | Action | Priority | Status |
|---|---|---|---|
| 1 | **Change all default passwords** (DB, API, ELK) | 🔴 Critical | ☐ |
| 2 | **Generate random SECRET_KEY** (`openssl rand -hex 32`) | 🔴 Critical | ☐ |
| 3 | **Enable HTTPS** (TLS 1.3 via nginx + Let's Encrypt) | 🔴 Critical | ☐ |
| 4 | **Configure firewall** (ufw / iptables) | 🔴 Critical | ☐ |
| 5 | **Restrict CORS origins** (set `CORS_ORIGINS` to domain) | 🟡 High | ☐ |
| 6 | **Set ENVIRONMENT=production** | 🟡 High | ☐ |
| 7 | **Disable debug endpoints** in production | 🟡 High | ☐ |
| 8 | **Enable PostgreSQL SSL** | 🟡 High | ☐ |
| 9 | **Rotate secrets regularly** (see `docs/secrets_rotation.md`) | 🟡 High | ☐ |
| 10 | **Enable audit logging** | 🟢 Medium | ☐ |
| 11 | **Configure log rotation** (logrotate for `logs/`) | 🟢 Medium | ☐ |
| 12 | **Set up automated backups** | 🟢 Medium | ☐ |
| 13 | **Harden SSH access** (key-only, disable root) | 🟢 Medium | ☐ |
| 14 | **Install fail2ban** for API brute-force protection | 🟢 Medium | ☐ |

### Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp      # SSH (management)
sudo ufw allow 443/tcp     # HTTPS (dashboard)
sudo ufw allow 8000/tcp    # API (internal only — restrict to LAN)
sudo ufw enable
```

### Secrets Management

```bash
# Generate secure values
export SECRET_KEY=$(openssl rand -hex 32)
export DB_PASSWORD=$(openssl rand -base64 24)

# Store in .env (permissions 600)
chmod 600 .env
```

### Backup Configuration

```bash
# PostgreSQL daily backup (cron)
0 2 * * * pg_dump -U phantomnet phantomnet_db | gzip > /backups/phantomnet_$(date +\%Y\%m\%d).sql.gz

# PCAP archive (weekly)
0 3 * * 0 tar czf /backups/pcaps_$(date +\%Y\%m\%d).tar.gz /opt/phantomnet/data/pcaps/

# ML models backup
0 4 * * 1 tar czf /backups/ml_models_$(date +\%Y\%m\%d).tar.gz /opt/phantomnet/ml_models/
```

---

## Monitoring & Maintenance

### Health Checks

```bash
# API health
curl -f http://localhost:8000/api/health || echo "API DOWN"

# Database connectivity
curl http://localhost:8000/api/stats | jq '.total_events'

# SIEM exporter status
curl http://localhost:8000/api/siem/status | jq '.running'

# PCAP system status
curl http://localhost:8000/api/v1/pcap/stats | jq '.'
```

### Log Monitoring

| Log File | Contents |
|---|---|
| `logs/phantomnet.log` | Main application log |
| `logs/siem_export.log` | SIEM exporter activity |
| `logs/retraining.log` | ML retraining pipeline |
| `logs/response_actions.log` | Automated threat response actions |

```bash
# Monitor threat detections in real-time
tail -f logs/phantomnet.log | grep "CRITICAL\|HIGH"

# Check for SIEM export failures
grep "Failed" logs/siem_export.log | tail -20
```

### Performance Monitoring

| Metric | Tool | Target |
|---|---|---|
| API response time | `/api/health` + prometheus | < 200ms p95 |
| Events/second throughput | Backend logs | > 500 events/s |
| Database connection pool | pgBouncer stats | < 80% utilization |
| Memory usage | `htop` / Grafana | < 70% of available |
| Disk usage | `df -h /data/pcaps` | < 80% capacity |
| ML inference latency | Backend logs | < 50ms per batch |

### Update Procedures

```bash
# 1. Pull latest code
cd /opt/phantomnet
git pull origin main

# 2. Update backend dependencies
cd backend
source venv/bin/activate
pip install -r requirements.txt

# 3. Rebuild frontend
cd ../frontend-dev/phantomnet-dashboard
npm install && npm run build

# 4. Run database migrations (auto via SQLAlchemy)
# Tables are created/extended on startup

# 5. Restart services
sudo systemctl restart phantomnet
sudo systemctl restart nginx
```

### Backup & Restore

```bash
# Full database restore
gunzip < /backups/phantomnet_20260306.sql.gz | psql -U phantomnet phantomnet_db

# ML model restore
tar xzf /backups/ml_models_20260306.tar.gz -C /opt/phantomnet/

# Verify after restore
curl http://localhost:8000/api/stats
```
