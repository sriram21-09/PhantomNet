# PhantomNet — Mininet SDN Deployment Guide

**Week 9 | Day 2 — Honeypot Deployment in SDN Topology**  
**Last Updated:** February 27, 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Prerequisites](#3-prerequisites)
4. [POX Controller Deployment](#4-pox-controller-deployment)
5. [Topology Deployment](#5-topology-deployment)
6. [End-to-End Connectivity Testing](#6-end-to-end-connectivity-testing)
7. [Attack Simulation](#7-attack-simulation)
8. [Flow Rules & Monitoring](#8-flow-rules--monitoring)
9. [Verification Checklist](#9-verification-checklist)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Overview

This guide covers deploying PhantomNet honeypots as fully operational services within a Mininet SDN topology, controlled by a custom POX controller with honeypot-aware flow rules.

**Key Components:**

| Component | File | Purpose |
|-----------|------|---------|
| POX Controller | `pox/ext/phantomnet_controller.py` | L2 learning + honeypot flow rules |
| Mininet Topology | `backend/network/mininet_topology.py` | 5-node star with `host.cmd()` integration |
| SSH Honeypot | `honeypots/ssh/ssh_honeypot.py` | Port 2222 — SSH trap |
| HTTP Honeypot | `honeypots/http/http_honeypot.py` | Port 8080 — HTTP trap |
| FTP Honeypot | `honeypots/ftp/ftp_honeypot.py` | Port 2121 — FTP trap |

---

## 2. Architecture

```
                    POX Controller
                   (127.0.0.1:6633)
                         │
                         │ OpenFlow
                         │
                    ┌────┴────┐
                    │   s1    │
                    │  OVS    │
                    └──┬┬┬┬┬──┘
           ┌──────────┘│││└──────────┐
           │      ┌────┘│└────┐      │
           │      │     │     │      │
       ┌───┴──┐┌──┴──┐┌─┴──┐┌┴───┐┌─┴───┐
       │  h1  ││ h2  ││ h3 ││ h4 ││ h5  │
       │Coord.││ SSH ││HTTP││FTP ││ ATK  │
       │.0.0.1││.0.0.2││.0.0.3││.0.0.4││.0.0.5│
       └──────┘└─────┘└────┘└────┘└─────┘
                :2222   :8080  :2121
```

**Flow Rule Strategy:**
- Attacker (h5) → Honeypot traffic gets **priority 100** rules with controller logging
- Honeypot → Attacker response traffic gets reverse flow rules
- All other traffic uses L2 learning switch at **priority 50**
- Unmatched packets go to controller via table-miss at **priority 10**

---

## 3. Prerequisites

- Mininet 2.3.1 installed (see `docs/mininet_setup.md`)
- Open vSwitch running
- POX controller cloned at `~/pox`
- PhantomNet repo cloned at `~/PhantomNet`

Verify:

```bash
sudo mn --version                    # 2.3.1
sudo systemctl status openvswitch-switch  # active
ls ~/pox/pox.py                      # exists
ls ~/PhantomNet/honeypots/           # ssh/ http/ ftp/
```

---

## 4. POX Controller Deployment

### 4.1 Copy Controller to POX Extensions

The controller must be in POX's `ext/` directory to be discoverable:

```bash
cp ~/PhantomNet/pox/ext/phantomnet_controller.py ~/pox/ext/
```

### 4.2 Start the Controller

```bash
cd ~/pox
python3 pox.py log.level --DEBUG phantomnet_controller
```

**Expected output:**

```
POX 0.7.0 (dart) ...
============================================================
  PhantomNet SDN Controller v1.0
  Starting POX module...
============================================================
[LAUNCHER] PhantomNet Controller module loaded
[LAUNCHER] Waiting for switch connections...
```

> **Leave this terminal running.** Open a new terminal for the topology.

### 4.3 Controller Features

| Feature | Description |
|---------|-------------|
| L2 Learning | Learns MAC→port mappings, installs forwarding rules |
| Honeypot Rules | Priority flow rules for attacker→honeypot traffic |
| Traffic Logging | Logs all TCP connections to honeypot ports |
| Attack Detection | Flags traffic from attacker IP (10.0.0.5) |
| Flow Stats | Receives periodic flow statistics from OVS |

---

## 5. Topology Deployment

### 5.1 Launch the Topology

In a **second terminal**:

```bash
cd ~/PhantomNet
sudo python3 backend/network/mininet_topology.py
```

### 5.2 What Happens on Startup

The topology script automatically:

1. **Creates the network** — 5 hosts + 1 OVS switch
2. **Connects to POX** — Remote controller on `127.0.0.1:6633`
3. **Deploys honeypots** — Runs `host.cmd()` to start services on h2, h3, h4
4. **Verifies connectivity** — Runs `pingall`
5. **Verifies services** — Checks each honeypot is listening on its port
6. **Prints banner** — Shows all IPs, ports, and test commands

**Expected output:**

```
*** Deploying Honeypot Services
  ✅ SSH Honeypot started on h2 (port 2222)
  ✅ HTTP Honeypot started on h3 (port 8080)
  ✅ FTP Honeypot started on h4 (port 2121)
*** Waiting for services to start...

*** Verifying Connectivity (Ping All)
*** Results: 0% dropped (20/20 received)

*** Verifying Honeypot Services
  ✅ SSH Honeypot (h2:2222) — LISTENING
  ✅ HTTP Honeypot (h3:8080) — LISTENING
  ✅ FTP Honeypot (h4:2121) — LISTENING

============================================================
  🚀 PhantomNet SDN Simulation Running
============================================================
```

### 5.3 host.cmd() Integration Details

Each honeypot is launched as a background process on its Mininet host:

| Host | Command | Log File |
|------|---------|----------|
| h2 | `python3 honeypots/ssh/ssh_honeypot.py &` | `/tmp/h2_honeypot.log` |
| h3 | `python3 honeypots/http/http_honeypot.py &` | `/tmp/h3_honeypot.log` |
| h4 | `python3 honeypots/ftp/ftp_honeypot.py &` | `/tmp/h4_honeypot.log` |

---

## 6. End-to-End Connectivity Testing

### 6.1 Ping Tests

```
mininet> pingall
mininet> h5 ping -c 3 10.0.0.2
mininet> h5 ping -c 3 10.0.0.3
mininet> h5 ping -c 3 10.0.0.4
mininet> h1 ping -c 3 10.0.0.5
```

### 6.2 Service Reachability

```
mininet> h2 ss -tlnp | grep 2222
mininet> h3 ss -tlnp | grep 8080
mininet> h4 ss -tlnp | grep 2121
```

### 6.3 Network Information

```
mininet> net
mininet> dump
mininet> links
```

---

## 7. Attack Simulation

### 7.1 HTTP Attack (h5 → h3)

```
mininet> h5 curl -s 10.0.0.3:8080
```

Expected: `404 Not Found` (honeypot response)

### 7.2 SSH Probe (h5 → h2)

```
mininet> h5 echo "test" | nc -w 3 10.0.0.2 2222
```

Expected: SSH banner `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`

### 7.3 FTP Probe (h5 → h4)

```
mininet> h5 echo "USER admin" | nc -w 3 10.0.0.4 2121
```

Expected: FTP banner `220 (vsFTPd 3.0.3)` then `331 Please specify the password.`

### 7.4 Multi-Protocol Scan

```
mininet> h5 bash -c "echo 'HTTP:'; curl -s 10.0.0.3:8080; echo; echo 'SSH:'; echo test | nc -w 2 10.0.0.2 2222; echo; echo 'FTP:'; echo USER admin | nc -w 2 10.0.0.4 2121"
```

---

## 8. Flow Rules & Monitoring

### 8.1 View Installed Flow Rules

```
mininet> sh ovs-ofctl dump-flows s1
```

**Expected rules include:**

| Priority | Match | Action |
|----------|-------|--------|
| 100 | `nw_src=10.0.0.5, nw_dst=10.0.0.2, tp_dst=2222` | CONTROLLER + output:2 |
| 100 | `nw_src=10.0.0.5, nw_dst=10.0.0.3, tp_dst=8080` | CONTROLLER + output:3 |
| 100 | `nw_src=10.0.0.5, nw_dst=10.0.0.4, tp_dst=2121` | CONTROLLER + output:4 |
| 100 | `nw_src=10.0.0.2, nw_dst=10.0.0.5` | output:5 |
| 100 | `nw_src=10.0.0.3, nw_dst=10.0.0.5` | output:5 |
| 100 | `nw_src=10.0.0.4, nw_dst=10.0.0.5` | output:5 |
| 10 | (any) | CONTROLLER (table-miss) |

### 8.2 Monitor POX Controller Logs

In the POX terminal, you'll see real-time traffic logs:

```
[HONEYPOT TRAFFIC] 10.0.0.5:xxxxx → 10.0.0.3:8080 (port 5)
[ATTACK] Attacker 10.0.0.5 targeting honeypot 10.0.0.3:8080
```

### 8.3 View Switch Information

```
mininet> sh ovs-vsctl show
mininet> sh ovs-ofctl show s1
```

---

## 9. Verification Checklist

| # | Check | Command | Expected |
|---|-------|---------|----------|
| 1 | POX controller running | Check Terminal 1 | `POX ... is up` |
| 2 | Switch connected to POX | POX log | `Switch connected` |
| 3 | All hosts created | `dump` | 5 hosts, 1 switch |
| 4 | All links OK | `links` | 5x `OK OK` |
| 5 | Full connectivity | `pingall` | 0% dropped |
| 6 | SSH honeypot listening | `h2 ss -tlnp \| grep 2222` | Port bound |
| 7 | HTTP honeypot listening | `h3 ss -tlnp \| grep 8080` | Port bound |
| 8 | FTP honeypot listening | `h4 ss -tlnp \| grep 2121` | Port bound |
| 9 | HTTP attack works | `h5 curl 10.0.0.3:8080` | `404 Not Found` |
| 10 | SSH probe works | `h5 nc -w 2 10.0.0.2 2222` | SSH banner |
| 11 | FTP probe works | `h5 nc -w 2 10.0.0.4 2121` | FTP banner |
| 12 | Flow rules installed | `sh ovs-ofctl dump-flows s1` | Priority 100 rules |
| 13 | POX logs attacks | Check POX terminal | `[ATTACK]` entries |

---

## 10. Troubleshooting

### Controller Not Connecting

```bash
# Ensure POX is running BEFORE starting Mininet
cd ~/pox && python3 pox.py log.level --DEBUG phantomnet_controller

# Verify controller is listening
ss -tlnp | grep 6633
```

### Honeypots Not Starting

```bash
# Check honeypot logs inside Mininet
mininet> h2 cat /tmp/h2_honeypot.log
mininet> h3 cat /tmp/h3_honeypot.log
mininet> h4 cat /tmp/h4_honeypot.log

# Verify scripts exist
ls ~/PhantomNet/honeypots/ssh/ssh_honeypot.py
ls ~/PhantomNet/honeypots/http/http_honeypot.py
ls ~/PhantomNet/honeypots/ftp/ftp_honeypot.py
```

### Cleanup After Failed Run

```bash
sudo mn -c
sudo systemctl restart openvswitch-switch
```

### Port Already in Use

```bash
# Kill any existing Mininet processes
sudo killall -9 python3
sudo mn -c
```

---

## References

- PhantomNet Setup Guide: `docs/mininet_setup.md`
- Topology Design Spec: `docs/mininet_topology_design.md`
- [POX Documentation](https://noxrepo.github.io/pox-doc/html/)
- [Mininet Walkthrough](http://mininet.org/walkthrough/)
