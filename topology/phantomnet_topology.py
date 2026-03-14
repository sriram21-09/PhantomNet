#!/usr/bin/env python3
"""
PhantomNet Distributed Honeypot Mesh Topology
==============================================

Scaled 14-host topology with dual SDN switches for load-balanced
honeypot deployment across SSH, HTTP, SMTP, FTP, and Telnet protocols.

Topology:
                  ┌────────────────────────────────┐
                  │        s1 (Core Switch)         │
                  │  h1(SSH) h2(HTTP) h3(SMTP)      │
                  │  h4(FTP) h5(Coord) h6(Attacker) │
                  └───────────┬────────────────────┘
                              │  1 Gbps mesh link
                  ┌───────────┴────────────────────┐
                  │     s2 (Load-Balance Switch)    │
                  │  h7(SSH) h8(HTTP) h9(SMTP)      │
                  │  h10(SSH) h11(HTTP) h12(SMTP)   │
                  │  h13(FTP) h14(Telnet)           │
                  └────────────────────────────────┘

Usage:
    sudo python3 phantomnet_topology.py
"""

import os
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

# ═══════════════════════════════════════════════════════════════════════════
# Node Definitions
# ═══════════════════════════════════════════════════════════════════════════

HONEYPOT_NODES = {
    # ── Switch s1 — Primary Honeypots ──
    "h1": {
        "ip": "10.0.0.1/24",
        "mac": "00:00:00:00:00:01",
        "role": "ssh_honeypot",
        "switch": "s1",
    },
    "h2": {
        "ip": "10.0.0.2/24",
        "mac": "00:00:00:00:00:02",
        "role": "http_honeypot",
        "switch": "s1",
    },
    "h3": {
        "ip": "10.0.0.3/24",
        "mac": "00:00:00:00:00:03",
        "role": "smtp_honeypot",
        "switch": "s1",
    },
    "h4": {
        "ip": "10.0.0.4/24",
        "mac": "00:00:00:00:00:04",
        "role": "ftp_honeypot",
        "switch": "s1",
    },
    "h5": {
        "ip": "10.0.0.5/24",
        "mac": "00:00:00:00:00:05",
        "role": "coordinator",
        "switch": "s1",
    },
    "h6": {
        "ip": "10.0.0.6/24",
        "mac": "00:00:00:00:00:06",
        "role": "attacker",
        "switch": "s1",
    },
    # ── Switch s2 — Replica Honeypots ──
    "h7": {
        "ip": "10.0.0.7/24",
        "mac": "00:00:00:00:00:07",
        "role": "ssh_honeypot",
        "switch": "s2",
    },
    "h8": {
        "ip": "10.0.0.8/24",
        "mac": "00:00:00:00:00:08",
        "role": "http_honeypot",
        "switch": "s2",
    },
    "h9": {
        "ip": "10.0.0.9/24",
        "mac": "00:00:00:00:00:09",
        "role": "smtp_honeypot",
        "switch": "s2",
    },
    "h10": {
        "ip": "10.0.0.10/24",
        "mac": "00:00:00:00:00:0a",
        "role": "ssh_honeypot",
        "switch": "s2",
    },
    "h11": {
        "ip": "10.0.0.11/24",
        "mac": "00:00:00:00:00:0b",
        "role": "http_honeypot",
        "switch": "s2",
    },
    "h12": {
        "ip": "10.0.0.12/24",
        "mac": "00:00:00:00:00:0c",
        "role": "smtp_honeypot",
        "switch": "s2",
    },
    "h13": {
        "ip": "10.0.0.13/24",
        "mac": "00:00:00:00:00:0d",
        "role": "ftp_honeypot",
        "switch": "s2",
    },
    "h14": {
        "ip": "10.0.0.14/24",
        "mac": "00:00:00:00:00:0e",
        "role": "telnet_honeypot",
        "switch": "s2",
    },
}

# Protocol → service port mapping
SERVICE_PORTS = {
    "ssh_honeypot": 2222,
    "http_honeypot": 8080,
    "smtp_honeypot": 2525,
    "ftp_honeypot": 2121,
    "telnet_honeypot": 2323,
}

# Docker resource limits per honeypot container
RESOURCE_LIMITS = {
    "cpu_quota": 50000,  # 0.5 CPU (50% of one core)
    "mem_limit": "512m",  # 512 MB RAM
}


# ═══════════════════════════════════════════════════════════════════════════
# Topology Class
# ═══════════════════════════════════════════════════════════════════════════


class PhantomNetMeshTopo(Topo):
    """
    Dual-switch honeypot mesh topology with 14 hosts.

    s1 hosts primary honeypots + coordinator + attacker.
    s2 hosts replica honeypots for load balancing.
    s1 and s2 are interconnected with a high-bandwidth mesh link.
    """

    def build(self):
        # ── Switches ──
        s1 = self.addSwitch("s1", dpid="0000000000000001", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", dpid="0000000000000002", protocols="OpenFlow13")

        # ── Inter-switch mesh link (high bandwidth, low latency) ──
        self.addLink(s1, s2, bw=1000, delay="1ms", loss=0)

        # ── Hosts ──
        for host_name, cfg in HONEYPOT_NODES.items():
            host = self.addHost(
                host_name,
                ip=cfg["ip"],
                mac=cfg["mac"],
            )

            # Link to assigned switch
            switch = s1 if cfg["switch"] == "s1" else s2

            # Honeypots get 100 Mbps, coordinator/attacker get 200 Mbps
            bw = 200 if cfg["role"] in ("coordinator", "attacker") else 100
            delay = "10ms" if cfg["role"] == "attacker" else "1ms"

            self.addLink(host, switch, bw=bw, delay=delay)

        info("*** Topology: 2 switches, %d hosts\n" % len(HONEYPOT_NODES))


# ═══════════════════════════════════════════════════════════════════════════
# Port Mirroring
# ═══════════════════════════════════════════════════════════════════════════


def add_traffic_mirror():
    """
    Configure port mirroring on both switches.
    Mirrors all traffic to the coordinator node (h5) for monitoring.
    """
    info("*** Configuring port mirroring for distributed monitoring...\n")

    # Mirror all traffic on s1 to the coordinator port
    cmd_s1 = (
        "ovs-vsctl "
        "-- set Bridge s1 mirrors=@m "
        "-- --id=@coord get Port s1-eth7 "  # h5's port on s1
        "-- --id=@m create Mirror name=s1_mirror select-all=true output-port=@coord"
    )

    # Mirror all traffic on s2 — send to the inter-switch link port
    # so it reaches the coordinator through s1
    cmd_s2 = (
        "ovs-vsctl "
        "-- set Bridge s2 mirrors=@m "
        "-- --id=@uplink get Port s2-eth1 "  # inter-switch link port
        "-- --id=@m create Mirror name=s2_mirror select-all=true output-port=@uplink"
    )

    for label, cmd in [("s1", cmd_s1), ("s2", cmd_s2)]:
        info("*** Mirroring on %s\n" % label)
        os.system(cmd)

    info("*** Port mirroring active on both switches.\n")


# ═══════════════════════════════════════════════════════════════════════════
# Resource Monitoring
# ═══════════════════════════════════════════════════════════════════════════


def print_resource_summary():
    """Print calculated resource requirements for the mesh."""
    honeypot_count = sum(
        1
        for cfg in HONEYPOT_NODES.values()
        if cfg["role"] not in ("coordinator", "attacker")
    )
    total_cpu = honeypot_count * 0.5
    total_ram_mb = honeypot_count * 512
    total_ram_gb = total_ram_mb / 1024

    info("\n")
    info("=" * 60 + "\n")
    info("  PhantomNet Resource Requirements\n")
    info("=" * 60 + "\n")
    info("  Honeypot nodes    : %d\n" % honeypot_count)
    info("  CPU per node      : 0.5 cores\n")
    info("  RAM per node      : 512 MB\n")
    info("  Total CPU needed  : %.1f cores\n" % total_cpu)
    info("  Total RAM needed  : %.1f GB\n" % total_ram_gb)
    info("  Minimum VM spec   : 8 GB RAM, 4 cores\n")
    info("=" * 60 + "\n")
    info("\n")


# ═══════════════════════════════════════════════════════════════════════════
# Connectivity Test
# ═══════════════════════════════════════════════════════════════════════════


def test_mesh_connectivity(net):
    """
    Verify all honeypot nodes can communicate with the coordinator.
    Returns True if all nodes are reachable.
    """
    info("*** Testing mesh connectivity...\n")
    coordinator = net.get("h5")
    failures = 0

    for host_name in HONEYPOT_NODES:
        if host_name == "h5":
            continue
        host = net.get(host_name)
        result = host.cmd("ping -c 1 -W 2 %s" % coordinator.IP())
        if "1 received" in result:
            info("  %s (%s) -> coordinator: OK\n" % (host_name, host.IP()))
        else:
            info("  %s (%s) -> coordinator: FAILED\n" % (host_name, host.IP()))
            failures += 1

    if failures == 0:
        info("*** All %d nodes connected successfully.\n" % (len(HONEYPOT_NODES) - 1))
    else:
        info("*** WARNING: %d node(s) failed connectivity test.\n" % failures)

    return failures == 0


# ═══════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════


def run_topology():
    setLogLevel("info")

    info("*** Creating PhantomNet Distributed Honeypot Mesh\n")
    print_resource_summary()

    topo = PhantomNetMeshTopo()

    info("*** Starting network with remote SDN controller\n")
    net = Mininet(
        topo=topo,
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
    )
    net.start()

    # Configure port mirroring
    add_traffic_mirror()

    # Connectivity test
    test_mesh_connectivity(net)

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    run_topology()
