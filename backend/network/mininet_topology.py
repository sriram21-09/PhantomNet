#!/usr/bin/env python3
"""
PhantomNet Mininet Topology — SDN Deployment
=============================================

Deploys a 5-node star topology with integrated honeypot services.
Connects to a remote POX controller for SDN flow management.

Architecture:
    h1 (10.0.0.1) — Coordinator (Database + Dashboard)
    h2 (10.0.0.2) — SSH Honeypot  (port 2222)
    h3 (10.0.0.3) — HTTP Honeypot (port 8080)
    h4 (10.0.0.4) — FTP Honeypot  (port 2121)
    h5 (10.0.0.5) — Attacker Node

Usage:
    # Terminal 1: Start POX controller
    cd ~/pox && python3 pox.py log.level --DEBUG phantomnet_controller

    # Terminal 2: Deploy topology
    sudo python3 backend/network/mininet_topology.py
"""

import os
import sys
import time
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink
from mininet.topo import Topo


# ──────────────────────────────────────────────
# Topology Definition
# ──────────────────────────────────────────────

class PhantomTopo(Topo):
    """PhantomNet 5-Node Star Topology with Honeypot Integration"""

    def build(self):
        # 1. Create the Central Switch
        info('*** Adding Switch\n')
        switch = self.addSwitch('s1')

        # 2. Define Node Specifications
        # H1 = Coordinator (Database + Dashboard)
        # H2-H4 = Honeypots (Traps)
        # H5 = Attacker (Kali Simulator)
        hosts_config = [
            {"name": "h1", "ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "desc": "Coordinator"},
            {"name": "h2", "ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "desc": "SSH-Honeypot"},
            {"name": "h3", "ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "desc": "HTTP-Honeypot"},
            {"name": "h4", "ip": "10.0.0.4", "mac": "00:00:00:00:00:04", "desc": "FTP-Honeypot"},
            {"name": "h5", "ip": "10.0.0.5", "mac": "00:00:00:00:00:05", "desc": "Attacker"},
        ]

        # 3. Create Hosts and Links
        info('*** Adding Hosts & Links\n')
        for host_conf in hosts_config:
            node = self.addHost(
                host_conf["name"],
                ip=host_conf["ip"],
                mac=host_conf["mac"],
            )
            # Link with constraints (100Mbps, 10ms latency)
            # Simulates a real corporate LAN environment
            self.addLink(node, switch, cls=TCLink, bw=100, delay='10ms')


# ──────────────────────────────────────────────
# Honeypot Service Deployment via host.cmd()
# ──────────────────────────────────────────────

# Path to honeypot scripts (relative to project root)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HONEYPOT_SERVICES = [
    {
        "host": "h2",
        "name": "SSH Honeypot",
        "script": os.path.join(PROJECT_ROOT, "honeypots", "ssh", "ssh_honeypot.py"),
        "port": 2222,
    },
    {
        "host": "h3",
        "name": "HTTP Honeypot",
        "script": os.path.join(PROJECT_ROOT, "honeypots", "http", "http_honeypot.py"),
        "port": 8080,
    },
    {
        "host": "h4",
        "name": "FTP Honeypot",
        "script": os.path.join(PROJECT_ROOT, "honeypots", "ftp", "ftp_honeypot.py"),
        "port": 2121,
    },
]


def deploy_honeypots(net):
    """
    Start honeypot services on their respective Mininet hosts
    using host.cmd() to run each honeypot as a background process.
    """
    info('\n*** Deploying Honeypot Services\n')

    for svc in HONEYPOT_SERVICES:
        host = net.get(svc["host"])
        script = svc["script"]

        if not os.path.exists(script):
            error(f'  ❌ Script not found: {script}\n')
            continue

        # Start honeypot as background process
        cmd = f'python3 {script} > /tmp/{svc["host"]}_honeypot.log 2>&1 &'
        host.cmd(cmd)
        info(f'  ✅ {svc["name"]} started on {svc["host"]} (port {svc["port"]})\n')

    # Allow services to initialize
    info('*** Waiting for services to start...\n')
    time.sleep(2)


def verify_honeypots(net):
    """
    Verify that all honeypot services are listening on their expected ports.
    Returns True if all services are verified.
    """
    info('\n*** Verifying Honeypot Services\n')
    all_ok = True

    for svc in HONEYPOT_SERVICES:
        host = net.get(svc["host"])
        port = svc["port"]

        # Check if the port is listening
        result = host.cmd(f'ss -tlnp | grep :{port}')

        if str(port) in result:
            info(f'  ✅ {svc["name"]} ({svc["host"]}:{port}) — LISTENING\n')
        else:
            error(f'  ❌ {svc["name"]} ({svc["host"]}:{port}) — NOT LISTENING\n')
            # Show log for debugging
            log_output = host.cmd(f'cat /tmp/{svc["host"]}_honeypot.log 2>/dev/null | tail -5')
            if log_output.strip():
                error(f'     Log: {log_output.strip()}\n')
            all_ok = False

    return all_ok


def print_banner(net):
    """Print the deployment status banner."""
    print("\n" + "=" * 60)
    print("  🚀 PhantomNet SDN Simulation Running")
    print("=" * 60)
    print(f"  Coordinator (H1) : 10.0.0.1")
    print(f"  SSH Honeypot (H2): 10.0.0.2:2222")
    print(f"  HTTP Honeypot(H3): 10.0.0.3:8080")
    print(f"  FTP Honeypot (H4): 10.0.0.4:2121")
    print(f"  Attacker     (H5): 10.0.0.5")
    print("=" * 60)
    print("  Commands to test:")
    print("    h5 curl 10.0.0.3:8080           # HTTP attack")
    print("    h5 nmap -p 2222 10.0.0.2        # SSH scan")
    print("    h5 nc 10.0.0.4 2121             # FTP probe")
    print("    pingall                          # Connectivity")
    print("    sh ovs-ofctl dump-flows s1       # View flow rules")
    print("  Type 'exit' to stop")
    print("=" * 60 + "\n")


# ──────────────────────────────────────────────
# Main Simulation Runner
# ──────────────────────────────────────────────

def run_simulation():
    """Boot up the PhantomNet SDN Network with integrated honeypots."""

    topo = PhantomTopo()

    # Initialize with remote POX controller
    # Falls back to default controller if POX is not running
    info('*** Connecting to POX controller on 127.0.0.1:6633\n')
    net = Mininet(
        topo=topo,
        link=TCLink,
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
    )

    info('*** Starting Network\n')
    net.start()

    # Deploy honeypot services on Mininet hosts
    deploy_honeypots(net)

    # Verify connectivity
    info('\n*** Verifying Connectivity (Ping All)\n')
    net.pingAll()

    # Verify honeypot services
    services_ok = verify_honeypots(net)

    if not services_ok:
        info('\n⚠️  Some honeypot services failed to start. Check logs above.\n')

    # Print deployment banner
    print_banner(net)

    # Drop into CLI
    CLI(net)

    # Cleanup on exit
    info('*** Stopping Network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')

    # Check for root privileges (Mininet needs root)
    if os.geteuid() != 0:
        print("❌ Error: Mininet must be run as root")
        print("   Usage: sudo python3 backend/network/mininet_topology.py")
        sys.exit(1)

    run_simulation()
