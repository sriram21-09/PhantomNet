#!/usr/bin/env python3
"""
PhantomNet SDN Controller — POX Extension
==========================================

Custom POX controller for the PhantomNet honeypot network.
Implements L2 learning switch with honeypot-aware flow rules
and traffic logging for security monitoring.

Usage:
    cd ~/pox
    python3 pox.py log.level --DEBUG phantomnet_controller

Architecture:
    h1 (10.0.0.1) — Coordinator (Database + Dashboard)
    h2 (10.0.0.2) — SSH Honeypot  (port 2222)
    h3 (10.0.0.3) — HTTP Honeypot (port 8080)
    h4 (10.0.0.4) — FTP Honeypot  (port 2121)
    h5 (10.0.0.5) — Attacker Node
"""

from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.packet import ethernet, arp, ipv4, tcp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventMixin

import time
import datetime

log = core.getLogger()

# ──────────────────────────────────────────────
# PhantomNet Network Configuration
# ──────────────────────────────────────────────

NETWORK_CONFIG = {
    "coordinator": {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "host": "h1"},
    "ssh_honeypot": {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "host": "h2", "port": 2222},
    "http_honeypot": {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "host": "h3", "port": 8080},
    "ftp_honeypot": {"ip": "10.0.0.4", "mac": "00:00:00:00:00:04", "host": "h4", "port": 2121},
    "attacker": {"ip": "10.0.0.5", "mac": "00:00:00:00:00:05", "host": "h5"},
}

# Honeypot service ports (traffic to these ports gets priority routing)
HONEYPOT_PORTS = {2222, 8080, 2121, 2525}

# Attacker IP for targeted flow rules
ATTACKER_IP = IPAddr("10.0.0.5")

# Flow rule priorities
PRIORITY_HONEYPOT = 100    # High priority for honeypot traffic
PRIORITY_MONITOR = 90      # Monitoring/logging traffic
PRIORITY_NORMAL = 50       # Normal L2 forwarding
PRIORITY_DEFAULT = 10      # Default fallback


class PhantomNetController(EventMixin):
    """
    PhantomNet SDN Controller

    Features:
    1. L2 Learning Switch — MAC address table for efficient forwarding
    2. Honeypot Flow Rules — Priority routing for attacker → honeypot traffic
    3. Traffic Logging    — Logs all connections for security analysis
    4. Flow Statistics    — Periodic flow stat collection from switches
    """

    def __init__(self, connection):
        self.connection = connection
        self.mac_table = {}  # MAC → port mapping
        self.attack_log = []  # In-memory attack event log

        # Listen for OpenFlow events
        connection.addListeners(self)

        log.info("=" * 60)
        log.info("  PhantomNet SDN Controller Active")
        log.info("  Switch DPID: %s", dpid_to_str(connection.dpid))
        log.info("=" * 60)

        # Install default flow rules
        self._install_default_rules()
        self._install_honeypot_rules()

        log.info("[INIT] Controller ready — monitoring traffic")

    def _install_default_rules(self):
        """Install baseline flow rules on the switch."""

        # Rule: Send all unmatched packets to the controller (table-miss)
        msg = of.ofp_flow_mod()
        msg.priority = PRIORITY_DEFAULT
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg)

        log.info("[FLOW] Installed table-miss rule (priority=%d)", PRIORITY_DEFAULT)

    def _install_honeypot_rules(self):
        """
        Install priority flow rules for honeypot traffic.

        These rules ensure that traffic from the attacker (h5) to honeypot
        service ports is forwarded with high priority and logged.
        """
        honeypot_targets = [
            {"name": "SSH",  "ip": "10.0.0.2", "port": 2222, "switch_port": 2},
            {"name": "HTTP", "ip": "10.0.0.3", "port": 8080, "switch_port": 3},
            {"name": "FTP",  "ip": "10.0.0.4", "port": 2121, "switch_port": 4},
        ]

        for target in honeypot_targets:
            # Forward attacker → honeypot traffic
            msg = of.ofp_flow_mod()
            msg.priority = PRIORITY_HONEYPOT
            msg.idle_timeout = 300  # 5 minutes
            msg.hard_timeout = 600  # 10 minutes

            # Match: attacker IP → honeypot IP on service port
            msg.match.dl_type = 0x0800  # IPv4
            msg.match.nw_src = ATTACKER_IP
            msg.match.nw_dst = IPAddr(target["ip"])
            msg.match.nw_proto = 6  # TCP
            msg.match.tp_dst = target["port"]

            # Action: Forward to correct switch port + send copy to controller
            msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            msg.actions.append(of.ofp_action_output(port=target["switch_port"]))
            self.connection.send(msg)

            log.info("[FLOW] Honeypot rule: attacker → %s (port %d, sw_port %d)",
                     target["name"], target["port"], target["switch_port"])

        # Reverse path: honeypot → attacker (for response traffic)
        for target in honeypot_targets:
            msg = of.ofp_flow_mod()
            msg.priority = PRIORITY_HONEYPOT
            msg.idle_timeout = 300
            msg.hard_timeout = 600

            msg.match.dl_type = 0x0800
            msg.match.nw_src = IPAddr(target["ip"])
            msg.match.nw_dst = ATTACKER_IP
            msg.match.nw_proto = 6

            msg.actions.append(of.ofp_action_output(port=5))  # h5 switch port
            self.connection.send(msg)

            log.info("[FLOW] Reverse rule: %s → attacker (sw_port 5)", target["name"])

    def _handle_PacketIn(self, event):
        """
        Handle packets sent to the controller.
        Implements L2 learning switch + traffic logging.
        """
        packet = event.parsed
        if not packet:
            return

        in_port = event.port

        # Learn the source MAC → port mapping
        src_mac = packet.src
        dst_mac = packet.dst
        self.mac_table[src_mac] = in_port

        # ── Traffic Logging ──
        self._log_traffic(packet, in_port)

        # ── L2 Forwarding Decision ──
        if dst_mac in self.mac_table:
            # Known destination — forward directly
            out_port = self.mac_table[dst_mac]
            self._install_forwarding_rule(packet, in_port, out_port)
            self._send_packet(event, out_port)
        else:
            # Unknown destination — flood
            self._send_packet(event, of.OFPP_FLOOD)

    def _log_traffic(self, packet, in_port):
        """Log interesting traffic for security monitoring."""

        # Log ARP traffic
        arp_pkt = packet.find('arp')
        if arp_pkt:
            log.debug("[ARP] %s → %s (port %d)",
                      arp_pkt.protosrc, arp_pkt.protodst, in_port)
            return

        # Log IPv4 traffic
        ip_pkt = packet.find('ipv4')
        if ip_pkt:
            tcp_pkt = packet.find('tcp')
            if tcp_pkt:
                src_ip = ip_pkt.srcip
                dst_ip = ip_pkt.dstip
                dst_port = tcp_pkt.dstport

                # Check if this is honeypot-targeted traffic
                if dst_port in HONEYPOT_PORTS:
                    timestamp = datetime.datetime.now().isoformat()
                    event_entry = {
                        "timestamp": timestamp,
                        "src_ip": str(src_ip),
                        "dst_ip": str(dst_ip),
                        "dst_port": dst_port,
                        "in_port": in_port,
                    }
                    self.attack_log.append(event_entry)

                    log.warning("[HONEYPOT TRAFFIC] %s:%d → %s:%d (port %d)",
                                src_ip, tcp_pkt.srcport, dst_ip, dst_port, in_port)

                    # Flag attacker traffic specifically
                    if src_ip == ATTACKER_IP:
                        log.warning("[ATTACK] Attacker %s targeting honeypot %s:%d",
                                    src_ip, dst_ip, dst_port)
                else:
                    log.debug("[TCP] %s → %s:%d (port %d)",
                              src_ip, dst_ip, dst_port, in_port)

    def _install_forwarding_rule(self, packet, in_port, out_port):
        """Install a forwarding rule in the switch for learned traffic."""
        msg = of.ofp_flow_mod()
        msg.priority = PRIORITY_NORMAL
        msg.idle_timeout = 120  # 2 minutes
        msg.hard_timeout = 300  # 5 minutes

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

    def _handle_FlowStatsReceived(self, event):
        """Handle flow statistics from the switch."""
        log.info("[STATS] Flow statistics received:")
        for stat in event.stats:
            log.info("  Match: %s | Packets: %d | Bytes: %d",
                     stat.match, stat.packet_count, stat.byte_count)


class PhantomNetLauncher(EventMixin):
    """
    Launcher that listens for new switch connections
    and creates a controller instance for each.
    """

    def __init__(self):
        core.openflow.addListeners(self)
        log.info("[LAUNCHER] PhantomNet Controller module loaded")
        log.info("[LAUNCHER] Waiting for switch connections...")

    def _handle_ConnectionUp(self, event):
        """Called when a switch connects to the controller."""
        log.info("[LAUNCHER] Switch %s connected", dpid_to_str(event.dpid))
        PhantomNetController(event.connection)

    def _handle_ConnectionDown(self, event):
        """Called when a switch disconnects."""
        log.warning("[LAUNCHER] Switch %s disconnected", dpid_to_str(event.dpid))


def launch():
    """
    POX module entry point.

    Usage:
        cd ~/pox
        python3 pox.py log.level --DEBUG phantomnet_controller
    """
    log.info("=" * 60)
    log.info("  PhantomNet SDN Controller v1.0")
    log.info("  Starting POX module...")
    log.info("=" * 60)
    core.registerNew(PhantomNetLauncher)
