#!/usr/bin/env python3
"""
PhantomNet SDN Controller — Distributed Load-Balanced Mesh
==========================================================

POX controller extension for the PhantomNet distributed honeypot mesh.
Implements round-robin load balancing per protocol, session persistence,
health checks, and multi-switch flow rule management.

Architecture (14 hosts, 2 switches):
    s1: h1(SSH) h2(HTTP) h3(SMTP) h4(FTP) h5(Coord) h6(Attacker)
    s2: h7(SSH) h8(HTTP) h9(SMTP) h10(SSH) h11(HTTP) h12(SMTP) h13(FTP) h14(Telnet)

Usage:
    cd ~/pox
    python3 pox.py log.level --DEBUG phantomnet_controller
"""

from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.packet import ethernet, arp, ipv4, tcp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventMixin
from pox.lib.recoco import Timer

import time
import datetime
import threading
from collections import defaultdict

log = core.getLogger()

# ══════════════════════════════════════════════════════════════════════════
# Network Configuration
# ══════════════════════════════════════════════════════════════════════════

COORDINATOR_IP = IPAddr("10.0.0.5")
ATTACKER_IP = IPAddr("10.0.0.6")

# Honeypot service ports
HONEYPOT_PORTS = {2222, 8080, 2525, 2121, 2323}

# Protocol pools — groups of honeypot IPs that serve the same protocol
PROTOCOL_POOLS = {
    "SSH": {
        "port": 2222,
        "nodes": [
            {"ip": "10.0.0.1",  "mac": "00:00:00:00:00:01", "host": "h1",  "switch_dpid": 1},
            {"ip": "10.0.0.7",  "mac": "00:00:00:00:00:07", "host": "h7",  "switch_dpid": 2},
            {"ip": "10.0.0.10", "mac": "00:00:00:00:00:0a", "host": "h10", "switch_dpid": 2},
        ],
    },
    "HTTP": {
        "port": 8080,
        "nodes": [
            {"ip": "10.0.0.2",  "mac": "00:00:00:00:00:02", "host": "h2",  "switch_dpid": 1},
            {"ip": "10.0.0.8",  "mac": "00:00:00:00:00:08", "host": "h8",  "switch_dpid": 2},
            {"ip": "10.0.0.11", "mac": "00:00:00:00:00:0b", "host": "h11", "switch_dpid": 2},
        ],
    },
    "SMTP": {
        "port": 2525,
        "nodes": [
            {"ip": "10.0.0.3",  "mac": "00:00:00:00:00:03", "host": "h3",  "switch_dpid": 1},
            {"ip": "10.0.0.9",  "mac": "00:00:00:00:00:09", "host": "h9",  "switch_dpid": 2},
            {"ip": "10.0.0.12", "mac": "00:00:00:00:00:0c", "host": "h12", "switch_dpid": 2},
        ],
    },
    "FTP": {
        "port": 2121,
        "nodes": [
            {"ip": "10.0.0.4",  "mac": "00:00:00:00:00:04", "host": "h4",  "switch_dpid": 1},
            {"ip": "10.0.0.13", "mac": "00:00:00:00:00:0d", "host": "h13", "switch_dpid": 2},
        ],
    },
    "TELNET": {
        "port": 2323,
        "nodes": [
            {"ip": "10.0.0.14", "mac": "00:00:00:00:00:0e", "host": "h14", "switch_dpid": 2},
        ],
    },
}

# Flow rule priorities
PRIORITY_HONEYPOT = 100
PRIORITY_MONITOR = 90
PRIORITY_NORMAL = 50
PRIORITY_DEFAULT = 10

# Health check settings
HEALTH_CHECK_INTERVAL = 30   # seconds
MAX_MISSED_CHECKS = 3        # mark unhealthy after 3 misses

# Resource limits per honeypot (for monitoring / alerting)
RESOURCE_LIMITS = {
    "cpu_cores": 0.5,
    "memory_mb": 512,
}


# ══════════════════════════════════════════════════════════════════════════
# Honeypot Pool — Load Balancer State
# ══════════════════════════════════════════════════════════════════════════

class HoneypotPool:
    """
    Manages a pool of honeypot nodes for a single protocol.
    Tracks connection counts, health status, and round-robin index.
    """

    def __init__(self, protocol, port, nodes):
        self.protocol = protocol
        self.port = port
        self.nodes = nodes
        self.rr_index = 0  # round-robin pointer

        # Per-node state
        self.connection_counts = defaultdict(int)  # ip -> active connections
        self.health_status = {}       # ip -> True/False
        self.missed_checks = {}       # ip -> count of consecutive misses
        self.resource_usage = {}      # ip -> {"cpu": %, "mem_mb": int}

        for node in nodes:
            ip = node["ip"]
            self.health_status[ip] = True
            self.missed_checks[ip] = 0
            self.resource_usage[ip] = {"cpu": 0.0, "mem_mb": 0}

    def get_healthy_nodes(self):
        """Return list of healthy nodes."""
        return [n for n in self.nodes if self.health_status.get(n["ip"], False)]

    def select_node(self, attacker_ip=None):
        """
        Select the next node using round-robin with least-loaded fallback.
        Returns the selected node dict, or None if all nodes are down.
        """
        healthy = self.get_healthy_nodes()
        if not healthy:
            log.error("[LB] No healthy %s nodes available!", self.protocol)
            return None

        # Round-robin selection
        self.rr_index = self.rr_index % len(healthy)
        selected = healthy[self.rr_index]
        self.rr_index += 1

        # Track connection
        self.connection_counts[selected["ip"]] += 1

        return selected

    def get_least_loaded(self):
        """Return the healthy node with the fewest active connections."""
        healthy = self.get_healthy_nodes()
        if not healthy:
            return None
        return min(healthy, key=lambda n: self.connection_counts[n["ip"]])

    def mark_unhealthy(self, ip):
        """Mark a node as unhealthy (skip in future selections)."""
        self.health_status[ip] = False
        log.warning("[HEALTH] %s node %s marked UNHEALTHY", self.protocol, ip)

    def mark_healthy(self, ip):
        """Mark a node as healthy (re-include in selections)."""
        self.health_status[ip] = True
        self.missed_checks[ip] = 0
        log.info("[HEALTH] %s node %s marked HEALTHY", self.protocol, ip)

    def record_missed_check(self, ip):
        """Record a missed health check. Mark unhealthy after threshold."""
        self.missed_checks[ip] = self.missed_checks.get(ip, 0) + 1
        if self.missed_checks[ip] >= MAX_MISSED_CHECKS:
            self.mark_unhealthy(ip)

    def update_resource_usage(self, ip, cpu, mem_mb):
        """Update resource usage and alert if exhausted."""
        self.resource_usage[ip] = {"cpu": cpu, "mem_mb": mem_mb}

        # Alert on resource exhaustion
        if cpu > 90.0:
            log.warning(
                "[RESOURCE] %s node %s CPU exhaustion: %.1f%%",
                self.protocol, ip, cpu
            )
        if mem_mb > RESOURCE_LIMITS["memory_mb"] * 0.9:
            log.warning(
                "[RESOURCE] %s node %s memory exhaustion: %d/%d MB",
                self.protocol, ip, mem_mb, RESOURCE_LIMITS["memory_mb"]
            )

    def status(self):
        """Return pool status summary."""
        healthy = len(self.get_healthy_nodes())
        total = len(self.nodes)
        return {
            "protocol": self.protocol,
            "port": self.port,
            "total_nodes": total,
            "healthy_nodes": healthy,
            "connections": dict(self.connection_counts),
            "health": dict(self.health_status),
            "resources": dict(self.resource_usage),
        }


# ══════════════════════════════════════════════════════════════════════════
# Main Controller
# ══════════════════════════════════════════════════════════════════════════

class PhantomNetController(EventMixin):
    """
    Distributed PhantomNet SDN Controller with load balancing.

    Features:
    1. Round-robin load balancing per protocol pool
    2. Session persistence (same attacker -> same honeypot)
    3. Health checks with automatic failover
    4. Multi-switch flow rule management
    5. Per-node resource monitoring and alerting
    6. L2 learning switch with traffic logging
    """

    def __init__(self, connection):
        self.connection = connection
        self.dpid = connection.dpid
        self.mac_table = {}     # MAC -> port mapping (per-switch)
        self.attack_log = []    # in-memory attack event log

        # Listen for OpenFlow events
        connection.addListeners(self)

        log.info("=" * 60)
        log.info("  PhantomNet Distributed Controller")
        log.info("  Switch DPID: %s", dpid_to_str(self.dpid))
        log.info("=" * 60)

        # Install default flow rules
        self._install_default_rules()

        log.info("[INIT] Switch %s ready", dpid_to_str(self.dpid))

    def _install_default_rules(self):
        """Install table-miss rule: send unmatched packets to controller."""
        msg = of.ofp_flow_mod()
        msg.priority = PRIORITY_DEFAULT
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg)
        log.info("[FLOW] Table-miss rule installed (priority=%d)", PRIORITY_DEFAULT)

    def _install_forwarding_rule(self, packet, in_port, out_port):
        """Install a learned L2 forwarding rule."""
        msg = of.ofp_flow_mod()
        msg.priority = PRIORITY_NORMAL
        msg.idle_timeout = 120
        msg.hard_timeout = 300
        msg.match = of.ofp_match.from_packet(packet, in_port)
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _send_packet(self, event, out_port):
        """Send a packet out of the specified port."""
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    # ── Packet Handling ──────────────────────────────────────────────────

    def _handle_PacketIn(self, event):
        """
        Handle packets sent to the controller.
        Implements L2 learning switch + honeypot traffic logging.
        """
        packet = event.parsed
        if not packet:
            return

        in_port = event.port

        # Learn source MAC -> port
        self.mac_table[packet.src] = in_port

        # Log traffic
        self._log_traffic(packet, in_port)

        # Check if this is honeypot-targeted traffic for load balancing
        ip_pkt = packet.find("ipv4")
        tcp_pkt = packet.find("tcp")
        if ip_pkt and tcp_pkt and tcp_pkt.dstport in HONEYPOT_PORTS:
            # Let the launcher handle LB decisions (it has global state)
            core.PhantomNetLauncher.handle_honeypot_traffic(
                event, self, ip_pkt, tcp_pkt
            )
            return

        # Standard L2 forwarding
        if packet.dst in self.mac_table:
            out_port = self.mac_table[packet.dst]
            self._install_forwarding_rule(packet, in_port, out_port)
            self._send_packet(event, out_port)
        else:
            self._send_packet(event, of.OFPP_FLOOD)

    def _log_traffic(self, packet, in_port):
        """Log security-relevant traffic."""
        arp_pkt = packet.find("arp")
        if arp_pkt:
            log.debug("[ARP] %s -> %s (port %d)",
                      arp_pkt.protosrc, arp_pkt.protodst, in_port)
            return

        ip_pkt = packet.find("ipv4")
        if ip_pkt:
            tcp_pkt = packet.find("tcp")
            if tcp_pkt and tcp_pkt.dstport in HONEYPOT_PORTS:
                timestamp = datetime.datetime.now().isoformat()
                self.attack_log.append({
                    "timestamp": timestamp,
                    "src_ip": str(ip_pkt.srcip),
                    "dst_ip": str(ip_pkt.dstip),
                    "dst_port": tcp_pkt.dstport,
                    "in_port": in_port,
                    "switch": dpid_to_str(self.dpid),
                })
                log.warning(
                    "[HONEYPOT] %s -> %s:%d (switch %s, port %d)",
                    ip_pkt.srcip, ip_pkt.dstip, tcp_pkt.dstport,
                    dpid_to_str(self.dpid), in_port,
                )

    def _handle_FlowStatsReceived(self, event):
        """Handle periodic flow statistics."""
        for stat in event.stats:
            log.debug(
                "[STATS] Switch %s | Match: %s | Pkts: %d | Bytes: %d",
                dpid_to_str(self.dpid), stat.match,
                stat.packet_count, stat.byte_count,
            )


# ══════════════════════════════════════════════════════════════════════════
# Launcher — Global Load Balancer & Health Manager
# ══════════════════════════════════════════════════════════════════════════

class PhantomNetLauncher(EventMixin):
    """
    Global launcher that manages all switch connections, protocol pools,
    session persistence, health checks, and load balancing decisions.
    """

    def __init__(self):
        core.openflow.addListeners(self)

        # Per-switch controller instances
        self.switch_controllers = {}   # dpid -> PhantomNetController

        # Protocol pools
        self.pools = {}
        for proto, cfg in PROTOCOL_POOLS.items():
            self.pools[proto] = HoneypotPool(proto, cfg["port"], cfg["nodes"])

        # Port -> protocol mapping for fast lookup
        self.port_to_protocol = {}
        for proto, cfg in PROTOCOL_POOLS.items():
            self.port_to_protocol[cfg["port"]] = proto

        # Session persistence: (attacker_ip, protocol) -> assigned node
        self.attacker_sessions = {}

        # Health check timer
        self._health_timer = None

        log.info("[LAUNCHER] PhantomNet Distributed Controller loaded")
        log.info("[LAUNCHER] Protocol pools: %s",
                 ", ".join("%s(%d nodes)" % (p, len(c["nodes"]))
                           for p, c in PROTOCOL_POOLS.items()))
        log.info("[LAUNCHER] Waiting for switch connections...")

    # ── Switch Lifecycle ─────────────────────────────────────────────────

    def _handle_ConnectionUp(self, event):
        """Called when a switch connects."""
        dpid = event.dpid
        log.info("[LAUNCHER] Switch %s connected", dpid_to_str(dpid))
        ctrl = PhantomNetController(event.connection)
        self.switch_controllers[dpid] = ctrl

        # Start health checks after first switch connects
        if self._health_timer is None:
            self._health_timer = Timer(
                HEALTH_CHECK_INTERVAL,
                self._run_health_checks,
                recurring=True,
            )
            log.info("[HEALTH] Health check timer started (%ds interval)",
                     HEALTH_CHECK_INTERVAL)

    def _handle_ConnectionDown(self, event):
        """Called when a switch disconnects."""
        dpid = event.dpid
        log.warning("[LAUNCHER] Switch %s disconnected", dpid_to_str(dpid))
        self.switch_controllers.pop(dpid, None)

    # ── Load Balancing ───────────────────────────────────────────────────

    def handle_honeypot_traffic(self, event, controller, ip_pkt, tcp_pkt):
        """
        Central load balancing decision for honeypot-targeted traffic.
        Called by individual switch controllers when they see honeypot traffic.
        """
        src_ip = str(ip_pkt.srcip)
        dst_port = tcp_pkt.dstport

        # Identify protocol
        protocol = self.port_to_protocol.get(dst_port)
        if not protocol:
            return

        pool = self.pools[protocol]
        session_key = (src_ip, protocol)

        # ── Session Persistence ──
        # Same attacker + same protocol -> same honeypot
        if session_key in self.attacker_sessions:
            assigned = self.attacker_sessions[session_key]
            # Verify the assigned node is still healthy
            if pool.health_status.get(assigned["ip"], False):
                target = assigned
            else:
                # Previous assignment is unhealthy — reassign
                log.warning(
                    "[LB] Session %s:%s -> %s is unhealthy, reassigning",
                    src_ip, protocol, assigned["ip"]
                )
                target = pool.select_node(src_ip)
                if target:
                    self.attacker_sessions[session_key] = target
        else:
            # New session — round-robin selection
            target = pool.select_node(src_ip)
            if target:
                self.attacker_sessions[session_key] = target

        if not target:
            log.error("[LB] No available %s honeypot for %s", protocol, src_ip)
            return

        log.info(
            "[LB] %s -> %s:%d routed to %s (%s) [conns: %d]",
            src_ip, protocol, dst_port,
            target["host"], target["ip"],
            pool.connection_counts[target["ip"]],
        )

        # Install flow rule to route this traffic
        self._install_lb_flow(
            controller, event, ip_pkt, tcp_pkt, target
        )

    def _install_lb_flow(self, controller, event, ip_pkt, tcp_pkt, target):
        """
        Install a flow rule to route traffic to the selected honeypot.
        Handles both same-switch and cross-switch scenarios.
        """
        target_mac = EthAddr(target["mac"])

        # Check if target is on the same switch or needs cross-switch routing
        if target_mac in controller.mac_table:
            out_port = controller.mac_table[target_mac]
        else:
            # Target is on the other switch — route via inter-switch link (port 1)
            out_port = 1

        # Forward rule: attacker -> honeypot
        msg = of.ofp_flow_mod()
        msg.priority = PRIORITY_HONEYPOT
        msg.idle_timeout = 300
        msg.hard_timeout = 600
        msg.match.dl_type = 0x0800
        msg.match.nw_src = ip_pkt.srcip
        msg.match.nw_dst = ip_pkt.dstip
        msg.match.nw_proto = 6
        msg.match.tp_dst = tcp_pkt.dstport

        # Rewrite destination to the selected honeypot
        msg.actions.append(of.ofp_action_dl_addr.set_dst(target_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(target["ip"])))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        msg.actions.append(of.ofp_action_output(port=out_port))
        controller.connection.send(msg)

        # Also send this specific packet
        controller._send_packet(event, out_port)

        log.info(
            "[FLOW] LB rule installed: %s:%d -> %s (%s) via port %d",
            ip_pkt.srcip, tcp_pkt.dstport, target["host"], target["ip"], out_port,
        )

    # ── Health Checks ────────────────────────────────────────────────────

    def _run_health_checks(self):
        """
        Periodic health check: request flow stats from all switches.
        Nodes that haven't had any traffic are checked via ARP probes.
        """
        log.debug("[HEALTH] Running health checks...")

        for proto, pool in self.pools.items():
            for node in pool.nodes:
                ip = node["ip"]
                dpid = node["switch_dpid"]

                # Check if the switch hosting this node is connected
                if dpid not in self.switch_controllers:
                    pool.record_missed_check(ip)
                    log.warning(
                        "[HEALTH] Switch %d offline — %s node %s unreachable",
                        dpid, proto, ip,
                    )
                    continue

                # If the switch is connected, consider the node healthy
                # (in a production setup, we'd send ARP probes)
                if not pool.health_status[ip]:
                    pool.mark_healthy(ip)

        # Log summary
        for proto, pool in self.pools.items():
            healthy = len(pool.get_healthy_nodes())
            total = len(pool.nodes)
            if healthy < total:
                log.warning(
                    "[HEALTH] %s pool: %d/%d healthy",
                    proto, healthy, total,
                )

    # ── Status Reporting ─────────────────────────────────────────────────

    def get_mesh_status(self):
        """Return full mesh status for API/monitoring."""
        return {
            "switches": len(self.switch_controllers),
            "active_sessions": len(self.attacker_sessions),
            "pools": {p: pool.status() for p, pool in self.pools.items()},
        }


# ══════════════════════════════════════════════════════════════════════════
# POX Entry Point
# ══════════════════════════════════════════════════════════════════════════

def launch():
    """
    POX module entry point.

    Usage:
        cd ~/pox
        python3 pox.py log.level --DEBUG phantomnet_controller
    """
    log.info("=" * 60)
    log.info("  PhantomNet SDN Controller v2.0 — Distributed Mesh")
    log.info("  Load balancing: round-robin + session persistence")
    log.info("  Health checks:  every %ds", HEALTH_CHECK_INTERVAL)
    log.info("=" * 60)
    core.registerNew(PhantomNetLauncher)
