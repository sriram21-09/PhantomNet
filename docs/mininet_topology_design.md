# Mininet Topology Design
## PhantomNet — Month 2 | Phase 4

---

## DOCUMENT STATUS

- **Type:** Authoritative Design Specification
- **Scope:** Mininet-based attack simulation topology
- **Applies To:** PhantomNet Month 2 (Weeks 5–8)
- **Change Control:** Any modification requires formal revision

This document is the **single source of truth** for the Mininet topology used in PhantomNet.

---

## 1. OBJECTIVE

The purpose of this topology is to:

- Simulate realistic network attack scenarios
- Deploy SMTP and SSH honeypots
- Generate real attack telemetry
- Validate PhantomNet’s detection, storage, and dashboard pipeline
- Support repeatable experiments and demonstrations

This topology is **not a demo mock**.  
It is a controlled cyber-range environment.

---

## 2. DESIGN PRINCIPLES

The topology follows these non-negotiable principles:

1. **Single Responsibility per Node**
2. **Clear Traffic Attribution**
3. **No Implicit Trust**
4. **Backend as Single Source of Truth**
5. **Failure Isolation**
6. **Low Complexity, High Observability**

---

## 3. TOPOLOGY OVERVIEW

### 3.1 Components

| Component | Count |
|---------|------|
| Hosts | 5 |
| Switches | 1 |
| Routers | 0 |
| Network Type | Flat L2 with logical segmentation |
| Platform | Mininet + Open vSwitch |

---

## 4. LOGICAL TOPOLOGY DIAGRAM

                +----------------------+
                |   External Attacker  |
                |        h1            |
                |      10.0.0.10       |
                +----------+-----------+
                           |
           +---------------+---------------+
           |               s1              |
           |         Open vSwitch           |
           +-------+-----------+------------+
                   |           |
    +--------------+--+     +--+--------------+
    |  SMTP Honeypot  |     |  SSH Honeypot   |
    |       h3        |     |       h4        |
    |   10.0.2.30     |     |   10.0.2.31     |
    +-----------------+     +-----------------+
                   |
            +------+-------+
            |   Backend    |
            |    h5        |
            | 10.0.3.40    |
            +--------------+

    +----------------------+
    |  Internal User Host  |
    |        h2            |
    |     10.0.1.20        |
    +----------------------+

---

## 5. NODE DEFINITIONS (STRICT)

Each node has **exactly one role**.

### 5.1 h1 — External Attacker
- **Hostname:** attacker
- **IP:** 10.0.0.10
- **Purpose:** Generate malicious traffic
- **Behavior:**
  - SMTP probing
  - SSH brute force
  - Port scanning
- **Trust Level:** None

---

### 5.2 h2 — Internal User
- **Hostname:** user
- **IP:** 10.0.1.20
- **Purpose:** Generate benign traffic
- **Behavior:**
  - Normal SMTP usage
  - Normal backend access
- **Trust Level:** Low (assumed compromised possible)

---

### 5.3 h3 — SMTP Honeypot
- **Hostname:** smtp-honeypot
- **IP:** 10.0.2.30
- **Purpose:** Capture SMTP-based attacks
- **Services:**
  - Fake SMTP server
- **Responsibilities:**
  - Log all SMTP interactions
  - Forward structured events to backend
- **Restrictions:**
  - No direct DB access

---

### 5.4 h4 — SSH Honeypot
- **Hostname:** ssh-honeypot
- **IP:** 10.0.2.31
- **Purpose:** Capture SSH-based attacks
- **Services:**
  - Fake SSH service
- **Responsibilities:**
  - Log authentication attempts
  - Forward structured events to backend
- **Restrictions:**
  - No direct DB access

---

### 5.5 h5 — Backend & SOC Node
- **Hostname:** monitor
- **IP:** 10.0.3.40
- **Purpose:** Central control and monitoring
- **Services:**
  - PhantomNet backend API
  - Database
- **Responsibilities:**
  - Store events
  - Aggregate stats
  - Serve dashboard APIs

---

## 6. IP ADDRESSING PLAN

All IPs are **static**.

| Node | Interface | IP Address |
|----|----|----|
| h1 | h1-eth0 | 10.0.0.10 |
| h2 | h2-eth0 | 10.0.1.20 |
| h3 | h3-eth0 | 10.0.2.30 |
| h4 | h4-eth0 | 10.0.2.31 |
| h5 | h5-eth0 | 10.0.3.40 |

No DHCP, NAT, or routing is permitted.

---

## 7. NETWORK SEGMENTS (LOGICAL)

| Segment | CIDR | Nodes |
|------|------|------|
| External | 10.0.0.0/24 | h1 |
| Internal | 10.0.1.0/24 | h2 |
| Honeypot DMZ | 10.0.2.0/24 | h3, h4 |
| Monitoring | 10.0.3.0/24 | h5 |

Segmentation is for **analysis and policy**, not routing.

---

## 8. EXPECTED TRAFFIC FLOWS

### 8.1 Malicious Traffic
- h1 → h3 (SMTP abuse)
- h1 → h4 (SSH brute force)
- h1 → h2 (scanning)

### 8.2 Benign Traffic
- h2 → h3 (legitimate SMTP)
- h2 → h5 (dashboard/API access)

### 8.3 Telemetry Flow
- h3 → h5 (SMTP events)
- h4 → h5 (SSH events)

---

## 9. DATA OWNERSHIP RULES

- Honeypots **produce** data
- Backend **owns** data
- Database **never accessed directly** by honeypots
- Frontend **never computes threat logic**

This rule is mandatory.

---

## 10. FAILURE ISOLATION

| Failure | Result |
|------|------|
| Honeypot failure | Backend remains functional |
| Backend failure | Honeypots continue logging |
| Attacker overload | No cascade impact |

No shared state exists between nodes.

---

## 11. SECURITY CONSTRAINTS

- No internet access
- No automatic trust
- No inline blocking
- No firewall rules (yet)
- No routing between subnets

---

## 12. OUT OF SCOPE (INTENTIONAL)

- IDS inline prevention
- Firewall enforcement
- Internet traffic
- Multi-switch routing
- Cloud deployment

These belong to later phases.

---

## 13. PHASE 4 COMPLETION CRITERIA

Phase 4 is complete when:

- Topology is defined
- Roles are fixed
- IPs are assigned
- Traffic flows are known
- Document is committed

All criteria are met here.

---

## 14. NEXT PHASE

**Phase 5 — Mininet Implementation**
- Python topology file
- Connectivity validation
- Traffic simulation scripts
