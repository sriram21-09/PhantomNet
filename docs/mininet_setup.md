# PhantomNet — Mininet Environment Setup Guide

**Week 9 | Day 1 — Environment Provisioning**  
**Last Updated:** February 25, 2026

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Ubuntu 22.04 LTS VM Setup](#2-ubuntu-2204-lts-vm-setup)
3. [Mininet 2.3.1 Installation](#3-mininet-231-installation)
4. [Open vSwitch Installation](#4-open-vswitch-installation)
5. [POX Controller Setup](#5-pox-controller-setup)
6. [Network Connectivity Configuration](#6-network-connectivity-configuration)
7. [PhantomNet Topology Deployment](#7-phantomnet-topology-deployment)
8. [Verification Checklist](#8-verification-checklist)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Prerequisites

### Host Machine Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB | 40 GB |
| OS | Windows 10/11 | Windows 10/11 |

### Software Required on Host

- **VirtualBox 7.x** — [Download](https://www.virtualbox.org/wiki/Downloads) (free, recommended)  
  *or* **VMware Workstation Player** — [Download](https://www.vmware.com/products/workstation-player.html)
- **Ubuntu 22.04.4 LTS ISO** — [Download](https://releases.ubuntu.com/22.04/)
- **Git** (on host machine for repo access)
- **SSH client** (Windows Terminal / PuTTY for VM access)

> **Note:** All Mininet operations take place inside the Linux VM, not on your Windows host.

---

## 2. Ubuntu 22.04 LTS VM Setup

### 2.1 Create the Virtual Machine

**VirtualBox:**

1. Open VirtualBox → Click **New**
2. Configure:
   - **Name:** `PhantomNet-Mininet`
   - **Type:** Linux
   - **Version:** Ubuntu (64-bit)
   - **RAM:** 4096 MB
   - **Hard Disk:** Create a virtual hard disk (VDI, dynamically allocated, 30 GB)
3. Click **Create**

### 2.2 Configure VM Settings

Before first boot, adjust the following:

```
Settings → System → Processor → 2 CPUs
Settings → Display → Video Memory → 64 MB
Settings → Network → Adapter 1 → NAT (for internet access)
Settings → Network → Adapter 2 → Enable → Host-Only Adapter (for SSH from host)
```

> **Important:** You need **two network adapters**:
> - **Adapter 1 (NAT):** Provides internet access for package installation
> - **Adapter 2 (Host-Only):** Allows SSH from your Windows host into the VM

### 2.3 Install Ubuntu 22.04 LTS

1. Mount the Ubuntu 22.04 ISO in **Storage → Controller: IDE → Optical Drive**
2. Start the VM → Follow the installer:
   - **Installation Type:** Minimal Installation
   - **Username:** `phantomnet` (or your preference)
   - **Hostname:** `phantomnet-mininet`
3. After installation, reboot and remove the ISO

### 2.4 Post-Install System Update

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential git curl wget net-tools openssh-server
```

### 2.5 Enable SSH Server

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh
```

Verify SSH is running:

```bash
ss -tlnp | grep 22
```

### 2.6 Get VM IP Address (for SSH from Host)

```bash
ip addr show
```

Look for the **Host-Only adapter** IP (usually `enp0s8` or `eth1`, in the `192.168.56.x` range).

From your **Windows host**, test SSH:

```powershell
ssh phantomnet@<VM_HOST_ONLY_IP>
```

---

## 3. Mininet 2.3.1 Installation

### 3.1 Install from Source (Recommended)

Installing from source ensures you get the exact version with all components:

```bash
cd ~
git clone https://github.com/mininet/mininet.git
cd mininet
git checkout -b mininet-2.3.1 2.3.1
```

### 3.2 Run the Install Script

Install Mininet with all dependencies (includes Open vSwitch and Wireshark):

```bash
cd ~/mininet
sudo PYTHON=python3 util/install.sh -a
```

> **Note:** The `-a` flag installs everything: Mininet core, Open vSwitch, Wireshark dissector, POX, and dependencies. This may take 10–15 minutes.

If you prefer a minimal install (Mininet + OVS only):

```bash
sudo PYTHON=python3 util/install.sh -nfv
```

Flags:
- `-n` — Mininet core
- `-f` — OpenFlow reference switch
- `-v` — Open vSwitch

### 3.3 Verify Mininet Installation

```bash
sudo mn --version
```

**Expected output:**

```
2.3.1
```

### 3.4 Quick Sanity Test

```bash
sudo mn --test pingall
```

**Expected output:**

```
*** Ping: testing ping reachability
h1 -> h2
h2 -> h1
*** Results: 0% dropped (2/2 received)
```

If this passes, Mininet is correctly installed. ✅

---

## 4. Open vSwitch Installation

> If you used `install.sh -a` in Step 3, OVS is already installed. Verify and skip to 4.2.

### 4.1 Install Open vSwitch (if not already installed)

```bash
sudo apt install -y openvswitch-switch openvswitch-common
```

### 4.2 Verify Installation

```bash
sudo ovs-vsctl --version
```

**Expected output (example):**

```
ovs-vsctl (Open vSwitch) 2.17.x
```

### 4.3 Verify OVS Service is Running

```bash
sudo systemctl status openvswitch-switch
```

Should show `active (running)`. If not:

```bash
sudo systemctl enable openvswitch-switch
sudo systemctl start openvswitch-switch
```

### 4.4 Verify OVS Kernel Module

```bash
lsmod | grep openvswitch
```

Should return a line showing `openvswitch` is loaded.

---

## 5. POX Controller Setup

POX is a Python-based SDN controller used for OpenFlow network control.

### 5.1 Install POX

```bash
cd ~
git clone https://github.com/noxrepo/pox.git
cd pox
git checkout dart
```

> The `dart` branch is the stable release branch for POX.

### 5.2 Verify POX Installation

```bash
cd ~/pox
python3 pox.py --version
```

### 5.3 Run POX with L2 Learning Switch

To start the POX controller with a basic Layer 2 forwarding module:

```bash
cd ~/pox
python3 pox.py log.level --DEBUG forwarding.l2_learning
```

**Expected output:**

```
POX 0.7.0 (dart) / Copyright ...
INFO:core:POX 0.7.0 (dart) is up.
INFO:openflow.of_01:[00-00-00-00-00-01 1] connected
```

> **Leave this terminal running** while you deploy topologies in a separate terminal.

### 5.4 Test POX with Mininet

Open a **second terminal** (SSH session) and run:

```bash
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk --topo tree,depth=2
```

In the Mininet CLI:

```
mininet> pingall
```

All hosts should be reachable (0% dropped). ✅

---

## 6. Network Connectivity Configuration

### 6.1 VM Network Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Windows Host                        │
│                                                       │
│   VirtualBox Host-Only Network: 192.168.56.0/24      │
│   ┌───────────────────────────────────────────┐      │
│   │  PhantomNet-Mininet VM                     │      │
│   │                                            │      │
│   │  enp0s3 (NAT)      → Internet access      │      │
│   │  enp0s8 (Host-Only) → 192.168.56.x        │      │
│   │                                            │      │
│   │  Mininet Internal:                         │      │
│   │    10.0.0.0/24  — External segment         │      │
│   │    10.0.1.0/24  — Internal segment         │      │
│   │    10.0.2.0/24  — Honeypot DMZ             │      │
│   │    10.0.3.0/24  — Monitoring segment       │      │
│   └───────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────┘
```

### 6.2 Configure Host-Only Network (VirtualBox)

On **Windows host**:

1. Open VirtualBox → **File → Host Network Manager**
2. Create a new network (if not exists):
   - **Adapter:** `192.168.56.1` / `255.255.255.0`
   - **DHCP Server:** Enable
     - Server Address: `192.168.56.100`
     - Lower Bound: `192.168.56.101`
     - Upper Bound: `192.168.56.254`

### 6.3 Configure Static IP on Host-Only Adapter (Inside VM)

For a stable SSH connection, assign a static IP:

```bash
sudo nano /etc/netplan/01-host-only.yaml
```

Add:

```yaml
network:
  version: 2
  ethernets:
    enp0s8:
      dhcp4: no
      addresses:
        - 192.168.56.10/24
```

Apply:

```bash
sudo netplan apply
```

Verify:

```bash
ip addr show enp0s8
```

### 6.4 Test Host ↔ VM Connectivity

From **Windows host**:

```powershell
ping 192.168.56.10
ssh phantomnet@192.168.56.10
```

From **VM**:

```bash
ping -c 3 8.8.8.8          # Internet (via NAT adapter)
ping -c 3 192.168.56.1     # Windows host (via Host-Only)
```

---

## 7. PhantomNet Topology Deployment

### 7.1 Clone the Repository Inside the VM

```bash
cd ~
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet
```

### 7.2 Deploy the PhantomNet Topology

The project includes two topology scripts. Use the **primary topology** from the `mininet/` directory:

**Option A — Simple Topology (No Controller)**

```bash
cd ~/PhantomNet
sudo python3 mininet/phantomnet_topology.py
```

This deploys a 5-node star topology with:

| Node | IP | Role |
|------|----|------|
| h1 | 10.0.0.10 | Traffic Generator / External Attacker |
| h2 | 10.0.1.20 | Benign Client / Internal User |
| h3 | 10.0.2.30 | SMTP Honeypot |
| h4 | 10.0.2.31 | SSH Honeypot |
| h5 | 10.0.3.40 | Backend / Attacker Simulation |

**Option B — Class-Based Topology (With Controller)**

First, start POX in one terminal:

```bash
cd ~/pox
python3 pox.py forwarding.l2_learning
```

Then in a second terminal:

```bash
cd ~/PhantomNet
sudo python3 backend/network/mininet_topology.py
```

This deploys:

| Node | IP | Role |
|------|----|------|
| h1 | 10.0.0.1 | Coordinator (Database + Dashboard) |
| h2 | 10.0.0.2 | SSH Honeypot |
| h3 | 10.0.0.3 | HTTP Honeypot |
| h4 | 10.0.0.4 | FTP Honeypot |
| h5 | 10.0.0.5 | Attacker (Kali Simulator) |

Link constraints: 100 Mbps bandwidth, 10ms latency.

### 7.3 Verify Connectivity Inside Mininet

Once the Mininet CLI starts:

```
mininet> pingall
mininet> net
mininet> dump
mininet> links
```

### 7.4 Useful Mininet Commands

| Command | Description |
|---------|-------------|
| `pingall` | Test reachability between all hosts |
| `net` | Show network topology |
| `dump` | Show all node details (IPs, interfaces) |
| `links` | Show all links and their status |
| `h1 ping h3` | Ping from h1 to h3 |
| `h1 ifconfig` | Show h1 interface configuration |
| `xterm h1` | Open a terminal for h1 (requires X11) |
| `exit` | Stop the simulation and clean up |

---

## 8. Verification Checklist

Run through each check after completing setup:

| # | Check | Command | Expected Result |
|---|-------|---------|-----------------|
| 1 | Ubuntu version | `lsb_release -a` | Ubuntu 22.04.x LTS |
| 2 | Mininet version | `sudo mn --version` | 2.3.1 |
| 3 | OVS version | `sudo ovs-vsctl --version` | 2.17.x+ |
| 4 | OVS service | `sudo systemctl status openvswitch-switch` | active (running) |
| 5 | POX available | `ls ~/pox/pox.py` | File exists |
| 6 | Mininet ping test | `sudo mn --test pingall` | 0% dropped |
| 7 | SSH from host | `ssh phantomnet@192.168.56.10` | Login success |
| 8 | Internet from VM | `ping -c 3 8.8.8.8` | 3 packets received |
| 9 | Topology deploys | `sudo python3 mininet/phantomnet_topology.py` | CLI prompt appears |
| 10 | Topology ping | `pingall` (inside Mininet) | All hosts reachable |

---

## 9. Troubleshooting

### Mininet Won't Start

```bash
# Clean up any previous Mininet state
sudo mn -c

# Check OVS is running
sudo systemctl restart openvswitch-switch
```

### "RTNETLINK answers: File exists" Error

This means a previous Mininet session wasn't cleaned up:

```bash
sudo mn -c
```

### POX Controller Connection Refused

Ensure POX is running **before** starting Mininet with `--controller=remote`:

```bash
# Terminal 1: Start POX
cd ~/pox && python3 pox.py forwarding.l2_learning

# Terminal 2: Start Mininet
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk
```

### Host-Only Network Not Working

```bash
# Check if the adapter is up
ip link show enp0s8

# Bring it up manually if needed
sudo ip link set enp0s8 up
sudo dhclient enp0s8
```

### Mininet Hosts Can't Ping Each Other

```bash
# Inside Mininet CLI, check interfaces:
mininet> h1 ifconfig
mininet> h3 ifconfig

# Verify switch flows:
mininet> sh ovs-ofctl dump-flows s1
```

If using a controller, ensure the controller is connected:

```
mininet> sh ovs-vsctl show
```

### Permission Denied Errors

Mininet **must** run as root:

```bash
sudo python3 mininet/phantomnet_topology.py
```

### Python Import Errors

If `from mininet.net import Mininet` fails:

```bash
# Verify Mininet Python package is installed
python3 -c "from mininet.net import Mininet; print('OK')"

# If not found, reinstall:
cd ~/mininet
sudo PYTHON=python3 util/install.sh -n
```

---

## References

- [Mininet Documentation](http://mininet.org/walkthrough/)
- [Open vSwitch Documentation](https://docs.openvswitch.org/)
- [POX Controller Wiki](https://noxrepo.github.io/pox-doc/html/)
- PhantomNet Topology Design: `docs/mininet_topology_design.md`
- PhantomNet Network Design: `docs/network_topology_design.md`
