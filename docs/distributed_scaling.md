# PhantomNet — Distributed Scaling Architecture

> Scaling the honeypot mesh to 11+ nodes with load balancing, fault tolerance, and resource optimization.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Topology Design](#topology-design)
3. [Load Balancing](#load-balancing)
4. [Resource Allocation](#resource-allocation)
5. [Fault Tolerance](#fault-tolerance)
6. [Testing Procedures](#testing-procedures)
7. [Operations Guide](#operations-guide)

---

## Architecture Overview

```
                   ┌─────────────────────────────────────┐
                   │          SDN Controller (POX)        │
                   │   Round-Robin LB + Session Persist   │
                   │   Health Checks every 30s            │
                   └─────────┬──────────────┬────────────┘
                             │              │
                  ┌──────────┴──────┐  ┌────┴─────────────┐
                  │   s1 (Primary)  │──│  s2 (Replica)     │
                  │                 │  │                    │
                  │  h1  SSH        │  │  h7  SSH           │
                  │  h2  HTTP       │  │  h8  HTTP          │
                  │  h3  SMTP       │  │  h9  SMTP          │
                  │  h4  FTP        │  │  h10 SSH           │
                  │  h5  Coordinator│  │  h11 HTTP          │
                  │  h6  Attacker   │  │  h12 SMTP          │
                  │                 │  │  h13 FTP           │
                  │                 │  │  h14 Telnet        │
                  └─────────────────┘  └────────────────────┘
                        1 Gbps mesh link between s1 ↔ s2
```

---

## Topology Design

### Node Assignments

| Host | IP | Role | Switch | Service Port |
|------|-----|------|--------|-------------|
| h1 | 10.0.0.1 | SSH Honeypot (primary) | s1 | 2222 |
| h2 | 10.0.0.2 | HTTP Honeypot (primary) | s1 | 8080 |
| h3 | 10.0.0.3 | SMTP Honeypot (primary) | s1 | 2525 |
| h4 | 10.0.0.4 | FTP Honeypot (primary) | s1 | 2121 |
| h5 | 10.0.0.5 | Coordinator / Monitor | s1 | — |
| h6 | 10.0.0.6 | Attacker Node | s1 | — |
| h7 | 10.0.0.7 | SSH Honeypot (replica) | s2 | 2222 |
| h8 | 10.0.0.8 | HTTP Honeypot (replica) | s2 | 8080 |
| h9 | 10.0.0.9 | SMTP Honeypot (replica) | s2 | 2525 |
| h10 | 10.0.0.10 | SSH Honeypot (replica) | s2 | 2222 |
| h11 | 10.0.0.11 | HTTP Honeypot (replica) | s2 | 8080 |
| h12 | 10.0.0.12 | SMTP Honeypot (replica) | s2 | 2525 |
| h13 | 10.0.0.13 | FTP Honeypot (replica) | s2 | 2121 |
| h14 | 10.0.0.14 | Telnet Honeypot | s2 | 2323 |

### Switch Mesh

- **s1** (DPID `0000000000000001`): Primary switch — hosts core services, coordinator, and attacker
- **s2** (DPID `0000000000000002`): Replica switch — hosts scaled-out honeypot replicas
- **Mesh link**: s1 ↔ s2 at 1 Gbps, 1ms latency, 0% loss

---

## Load Balancing

### Protocol Pools

| Protocol | Pool Members | Strategy |
|----------|-------------|----------|
| SSH (2222) | h1, h7, h10 | Round-robin → least-loaded |
| HTTP (8080) | h2, h8, h11 | Round-robin → least-loaded |
| SMTP (2525) | h3, h9, h12 | Round-robin → least-loaded |
| FTP (2121) | h4, h13 | Round-robin → least-loaded |
| Telnet (2323) | h14 | Single node |

### Selection Algorithm

1. **Session persistence** — `(attacker_ip, protocol)` → fixed honeypot for the session duration
2. **Round-robin** — new sessions rotate across healthy nodes in the pool
3. **Least-loaded fallback** — if a node fails, route to the node with fewest active connections
4. **Unhealthy skip** — nodes marked unhealthy are excluded from selection

### Flow Rule Installation

```
Attacker (h6) → SSH:2222
  └─ Controller checks session table
  └─ No session → round-robin selects h7
  └─ Flow rule installed on s1:
       match: src=10.0.0.6, dst_port=2222
       action: rewrite dst to 10.0.0.7, forward via inter-switch link
  └─ Session persisted: (10.0.0.6, SSH) → h7
```

---

## Resource Allocation

### Per-Honeypot Limits

| Resource | Limit |
|----------|-------|
| CPU | 0.5 cores (50% of one core) |
| Memory | 512 MB |
| Network | 100 Mbps |

### Total Requirements

| Metric | Value |
|--------|-------|
| Honeypot nodes | 12 (excluding coordinator + attacker) |
| Total CPU | 6.0 cores |
| Total RAM | 6.0 GB |
| **Minimum VM spec** | **8 GB RAM, 4 cores** |

### Docker Resource Limits

```yaml
# Apply to each honeypot service in docker-compose.yml
deploy:
  resources:
    limits:
      cpus: "0.5"
      memory: 512M
    reservations:
      cpus: "0.25"
      memory: 256M
```

### Monitoring & Alerting

The controller tracks per-node CPU and memory usage. Alerts fire when:
- **CPU > 90%** of allocated limit
- **Memory > 90%** of allocated limit (>460 MB)

---

## Fault Tolerance

### Health Check Mechanism

- **Interval**: Every 30 seconds
- **Threshold**: Node marked unhealthy after 3 consecutive missed checks
- **Recovery**: Node automatically re-included when its switch reconnects

### Failure Scenarios

| Failure | Response |
|---------|----------|
| Honeypot process crash | Health check detects, traffic redirected to other pool members |
| Switch s2 disconnect | All s2 nodes marked unhealthy, s1 nodes handle full load |
| Attacker session node dies | Session invalidated, re-assigned to next healthy node |
| Resource exhaustion | Alert logged, node continues serving until explicitly removed |

### Recovery Procedure

```bash
# 1. Check mesh status from controller
# (via POX debug console or management API)

# 2. Restart failed honeypot
sudo docker restart phantomnet_ssh_h7

# 3. Node auto-recovers at next health check cycle (30s)
```

---

## Testing Procedures

### 1. Launch Topology

```bash
cd ~/PhantomNet
sudo python3 topology/phantomnet_topology.py
```

### 2. Verify Node Registration

```
mininet> nodes
# Should list: h1–h14, s1, s2, c0

mininet> pingall
# All 14 hosts should be reachable (0% dropped)
```

### 3. Distributed Attack Simulation

```bash
# From 5 attacker hosts (or multiple xterms)
mininet> xterm h6

# In h6 terminal — target SSH pool
for i in $(seq 1 100); do
  ncat -w 1 10.0.0.1 2222 </dev/null &
  ncat -w 1 10.0.0.7 2222 </dev/null &
  ncat -w 1 10.0.0.10 2222 </dev/null &
done

# Verify distribution in controller logs:
# [LB] 10.0.0.6 -> SSH:2222 routed to h1 (10.0.0.1) [conns: 34]
# [LB] 10.0.0.6 -> SSH:2222 routed to h7 (10.0.0.7) [conns: 33]
# [LB] 10.0.0.6 -> SSH:2222 routed to h10 (10.0.0.10) [conns: 33]
```

### 4. Failure Recovery Test

```bash
# Kill one honeypot
mininet> h7 kill %python3

# Wait 90 seconds (3 × 30s health check interval)
# Verify in controller logs:
# [HEALTH] SSH node 10.0.0.7 marked UNHEALTHY
# [LB] Traffic now routed only to h1, h10

# Restart
mininet> h7 python3 honeypots/ssh/ssh_honeypot.py &

# Verify recovery:
# [HEALTH] SSH node 10.0.0.7 marked HEALTHY
```

### 5. Measure Coordination Latency

```bash
# Inter-switch latency
mininet> h1 ping -c 10 h7
# Expected: ~2ms (1ms link delay each way)

# Coordinator reachability from all nodes
mininet> h7 ping -c 5 h5
mininet> h14 ping -c 5 h5
```
