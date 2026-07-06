"""
tests/unit/test_port_scan_template.py
---------------------------------------
Unit tests for sentinel/templates/port_scan.md.j2

Covers every deliverable:
  ✅ Template exists and extends base_playbook.md.j2
  ✅ Header – scan-specific fields (scan type, scanner tool, ports, VLAN, zone)
  ✅ ATT&CK – All 8 techniques with correct IDs, tactics
  ✅ Phase 1 – Traffic control (PCAP capture, rate-limit, block, SDN, honeypots, deception)
  ✅ Phase 2 – Network segmentation review (segment map, ACLs, zone policy, hardening)
  ✅ Phase 3 – Exposed service audit (nmap, CMDB, service hardening, IDS update)
  ✅ Phase 4 – Deception & hardening (TI extraction, honeypot promotion, egress filter)
  ✅ Artifacts – 7 detection rules, 6 log sources, 5 SIEM queries, evidence paths
  ✅ Inherited blocks (summary, ioc_table, appendix)
  ✅ All defaults applied when optional context keys omitted
  ✅ All lists: network_segments, exposed_services, allowed_ports, evidence_paths
"""

import os
import pytest
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "backend", "sentinel", "templates")
)
TEMPLATE_NAME = "port_scan.md.j2"


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def env():
    return Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


@pytest.fixture(scope="module")
def template(env):
    return env.get_template(TEMPLATE_NAME)


def render(template, **ctx):
    ctx.setdefault("generated_at", "2026-06-22T12:00:00Z")
    ctx.setdefault("attack_pattern", "port_scan")
    ctx.setdefault("severity", "HIGH")
    return template.render(**ctx)


@pytest.fixture
def minimal_ctx():
    return {
        "attack_pattern": "port_scan",
        "severity": "HIGH",
        "generated_at": "2026-06-22T12:00:00Z",
        "source_ip": "9.8.7.6",
        "target_subnet": "10.0.2.0/24",
        "target_ip": "10.0.2.50",
        "port_count": 250,
        "port_count_threshold": 50,
    }


@pytest.fixture
def full_ctx():
    return {
        "title": "External Port Scan – Production Network",
        "attack_pattern": "port_scan",
        "severity": "CRITICAL",
        "generated_at": "2026-06-22T12:00:00Z",
        "playbook_id": "PB-SCAN-PROD-001",
        "version": "2.0.0",
        "classification": "TLP:RED",
        "source_ip": "2.3.4.5",
        "target_subnet": "192.168.1.0/24",
        "target_ip": "192.168.1.10",
        "scan_type": "XMAS",
        "ports_scanned": "1-65535",
        "port_count": 500,
        "port_count_threshold": 100,
        "alert_level": "CRITICAL",
        "block_duration": "86400",
        "honeypot_count": 5,
        "honeypot_type": "cowrie",
        "deception_mode": "aggressive_deception",
        "capture_duration": "600s",
        "vlan_id": "VLAN-100",
        "firewall_zone": "DMZ",
        "iids_sensor": "PhantomNet-IDS-01",
        "scanner_tool_fingerprint": "nmap",
        "ticket_system": "ServiceNow",
        "ticket_project": "NETOPS",
        "audit_period_hours": 72,
        "escalate_to_ciso": True,
        "sdn_enabled": True,
        "geo_block_country": "ZZ",
        "network_segments": ["VLAN-100", "VLAN-200", "MGMT-VLAN"],
        "exposed_services": ["telnet:23", "ftp:21", "redis:6379"],
        "allowed_ports": ["80", "443", "22"],
        "evidence_paths": ["/data/scan/case200/"],
    }


# ── Template existence ────────────────────────────────────────────────────

class TestTemplateExists:
    def test_file_on_disk(self):
        assert os.path.isfile(os.path.join(TEMPLATES_DIR, TEMPLATE_NAME))

    def test_template_loads(self, template):
        assert template is not None

    def test_template_name(self, template):
        assert template.name == TEMPLATE_NAME

    def test_extends_base(self):
        with open(os.path.join(TEMPLATES_DIR, TEMPLATE_NAME), encoding="utf-8") as f:
            content = f.read()
        assert 'extends "base_playbook.md.j2"' in content or \
               "extends 'base_playbook.md.j2'" in content

    def test_renders_without_error(self, template, minimal_ctx):
        out = template.render(**minimal_ctx)
        assert isinstance(out, str) and len(out) > 200


# ── Section 1: Header ─────────────────────────────────────────────────────

class TestHeader:
    def test_scan_icon_in_title(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "🔭" in out or "Port Scan" in out

    def test_custom_title(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "External Port Scan" in out

    def test_severity_critical(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "🔴 **CRITICAL**" in out

    def test_severity_high(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "🟠 **HIGH**" in out

    def test_severity_medium(self, template, minimal_ctx):
        out = render(template, **{**minimal_ctx, "severity": "MEDIUM"})
        assert "🟡 **MEDIUM**" in out

    def test_severity_low(self, template, minimal_ctx):
        out = render(template, **{**minimal_ctx, "severity": "LOW"})
        assert "🟢 **LOW**" in out

    def test_scan_type_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "SYN" in out

    def test_scan_type_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "XMAS" in out

    def test_scanner_ip(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "9.8.7.6" in out

    def test_target_subnet(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "10.0.2.0/24" in out

    def test_port_count(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "250" in out

    def test_vlan_id(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "VLAN-100" in out

    def test_firewall_zone(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "DMZ" in out

    def test_ids_sensor(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "PhantomNet-IDS-01" in out

    def test_scanner_tool(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "nmap" in out

    def test_playbook_id_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PB-PORTSCAN-001" in out

    def test_playbook_id_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "PB-SCAN-PROD-001" in out

    def test_ticket_system_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Jira" in out

    def test_ticket_system_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "ServiceNow" in out

    def test_classification_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "TLP:AMBER" in out


# ── Section 4: ATT&CK Mapping ─────────────────────────────────────────────

class TestATTACKMapping:
    def test_attack_section_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "MITRE ATT" in out and ("Port Scan" in out or "Reconnaissance" in out)

    def test_t1595_active_scanning(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1595" in out
        assert "Active Scanning" in out

    def test_t1595_001_ip_blocks(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1595.001" in out or "T1595/001" in out
        assert "Scanning IP Blocks" in out

    def test_t1595_002_vuln_scanning(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1595.002" in out or "T1595/002" in out
        assert "Vulnerability Scanning" in out

    def test_t1046_network_service_discovery(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1046" in out
        assert "Network Service Discovery" in out

    def test_t1590_gather_network_info(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1590" in out
        assert "Gather Victim Network" in out

    def test_t1592_gather_host_info(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1592" in out

    def test_t1018_remote_system_discovery(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1018" in out
        assert "Remote System Discovery" in out

    def test_t1049_connections_discovery(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1049" in out

    def test_t1571_non_standard_port(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1571" in out
        assert "Non-Standard Port" in out

    def test_reconnaissance_tactic(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Reconnaissance" in out

    def test_discovery_tactic(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Discovery" in out

    def test_mitre_attack_link(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "attack.mitre.org/techniques/T1595" in out

    def test_target_subnet_in_description(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "10.0.2.0/24" in out


# ── Phase 1: Traffic Control & Evidence ────────────────────────────────────

class TestPhase1TrafficControl:
    def test_phase1_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 1" in out and ("Traffic" in out or "Evidence" in out or "Capture" in out)

    def test_pcap_capture_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "tcpdump" in out or "packet capture" in out.lower() or "PCAP" in out

    def test_pcap_source_ip(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "9.8.7.6" in out

    def test_capture_duration_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "300" in out

    def test_capture_duration_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "600" in out

    def test_fingerprint_scanner_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "fingerprint" in out.lower() or "scanner" in out.lower()

    def test_p0f_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "p0f" in out or "nmap" in out or "masscan" in out

    def test_rate_limit_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "rate" in out.lower() and "limit" in out.lower()

    def test_iptables_rate_limit(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "iptables" in out and ("limit" in out.lower() or "DROP" in out)

    def test_block_scanner_ip(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Block" in out and "9.8.7.6" in out

    def test_block_duration_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "3600" in out

    def test_block_duration_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "86400" in out

    def test_sdn_flow_rule(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "SDN" in out or "phantomnet-sdn" in out

    def test_deploy_honeypots(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "honeypot" in out.lower()

    def test_honeypot_count_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "3" in out

    def test_honeypot_count_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "5" in out

    def test_honeypot_type_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "deception_mesh" in out

    def test_honeypot_type_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "cowrie" in out

    def test_deception_mode(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "aggressive_deception" in out or "deception" in out.lower()

    def test_geo_block_when_set(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "geo-block" in out.lower() or "ZZ" in out

    def test_ciso_escalation(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "CISO" in out

    def test_soc_alert(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "alert" in out.lower() and "SOC" in out

    def test_checkboxes(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "- [ ]" in out


# ── Phase 2: Network Segmentation Review ──────────────────────────────────

class TestPhase2NetworkSegmentation:
    def test_phase2_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 2" in out and ("Segment" in out or "Network" in out)

    def test_netflow_reachability_analysis(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "nfdump" in out or "NetFlow" in out or "netflow" in out.lower()

    def test_cross_segment_flow_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "segment" in out.lower() or "cross" in out.lower()

    def test_network_segments_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "VLAN-100" in out
        assert "VLAN-200" in out
        assert "MGMT-VLAN" in out

    def test_segments_fallback_firewall_query(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "firewall" in out.lower() or "fw_log" in out.lower()

    def test_inter_vlan_acl_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ACL" in out or "acl" in out.lower() or "access-list" in out.lower()

    def test_firewall_zone_policy_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "firewall" in out.lower() and ("zone" in out.lower() or "policy" in out.lower())

    def test_iptables_forward_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "FORWARD" in out or "iptables" in out

    def test_inter_vlan_hardening(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "deny" in out.lower() or "DROP" in out or "hardening" in out.lower()

    def test_port_security_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "port security" in out.lower() or "MAC" in out

    def test_micro_segmentation_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "micro-segment" in out.lower() or "NSX" in out or "ACI" in out

    def test_internal_vs_external_classification(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "internal" in out.lower() or "external" in out.lower()

    def test_rfc1918_check_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "is_private" in out or "RFC1918" in out or "192.168" in out

    def test_internal_scan_isolation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "isolate" in out.lower() or "shutdown" in out.lower()


# ── Phase 3: Exposed Service Audit ────────────────────────────────────────

class TestPhase3ExposedServiceAudit:
    def test_phase3_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 3" in out and ("Service" in out or "Audit" in out)

    def test_authorised_nmap_scan(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "nmap" in out

    def test_nmap_target_subnet(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "10.0.2.0/24" in out

    def test_ndiff_comparison(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ndiff" in out or "baseline" in out.lower()

    def test_cmdb_cross_reference(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "CMDB" in out or "asset inventory" in out.lower()

    def test_exposed_services_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "telnet:23" in out
        assert "ftp:21" in out
        assert "redis:6379" in out

    def test_allowed_ports_fallback(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "80" in out and "443" in out and "22" in out

    def test_disable_service_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "systemctl stop" in out or "disable" in out.lower()

    def test_telnet_must_be_disabled(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Telnet" in out or "telnet" in out.lower() or "23" in out

    def test_ftp_must_be_disabled(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "FTP" in out or "ftp" in out.lower() or "21" in out

    def test_snmp_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "SNMP" in out or "snmp" in out.lower()

    def test_rdp_exposure_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RDP" in out or "3389" in out

    def test_db_port_exposure_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "3306" in out or "5432" in out or "1433" in out

    def test_banner_hardening_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "banner" in out.lower() and ("harden" in out.lower() or "remov" in out.lower())

    def test_nginx_server_tokens_off(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "server_tokens off" in out

    def test_default_deny_iptables_policy(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "policy DROP" in out or "-P INPUT DROP" in out

    def test_syn_cookies_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "tcp_syncookies" in out or "SYN cookie" in out.lower()

    def test_ids_signature_update(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "IDS" in out or "snort" in out.lower() or "suricata" in out.lower()

    def test_snort_rule_added(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "local.rules" in out or "snort" in out.lower()

    def test_honeypot_log_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "honeypot" in out.lower() and "log" in out.lower()


# ── Phase 4: Deception & Hardening ────────────────────────────────────────

class TestPhase4DeceptionHardening:
    def test_phase4_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 4" in out and ("Deception" in out or "Hardening" in out)

    def test_threat_intel_submission(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "VirusTotal" in out
        assert "AbuseIPDB" in out

    def test_shodan_lookup(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Shodan" in out

    def test_shadowserver_reference(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Shadowserver" in out or "Censys" in out or "scanner" in out.lower()

    def test_high_interaction_honeypot_promotion(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "high-interaction" in out.lower() or "high interaction" in out.lower() or "honeypot" in out.lower()

    def test_bait_services_deployment(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "bait" in out.lower() or "fake service" in out.lower() or "netcat" in out.lower()

    def test_egress_filtering(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "egress" in out.lower() or "OUTPUT" in out

    def test_iptables_output_rule(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "OUTPUT" in out and ("SYN" in out or "syn" in out.lower())

    def test_periodic_scan_schedule(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "periodic" in out.lower() or "monthly" in out.lower() or "schedule" in out.lower()

    def test_incident_ticket_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "incident ticket" in out.lower() or "Create incident" in out

    def test_ticket_system_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Jira" in out

    def test_ticket_system_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "ServiceNow" in out

    def test_stix_ioc_export(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "STIX" in out or "IOC" in out

    def test_asset_inventory_update(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "asset inventory" in out.lower() or "CMDB" in out

    def test_post_incident_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "debrief" in out.lower() or "post-incident" in out.lower()


# ── Artifacts ─────────────────────────────────────────────────────────────

class TestArtifacts:
    def test_artifacts_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Artifacts" in out

    def test_rule_scan_001_syn(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SCAN-001" in out

    def test_rule_scan_002_udp(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SCAN-002" in out

    def test_rule_scan_003_xmas(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SCAN-003" in out

    def test_rule_scan_004_nmap_os(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SCAN-004" in out

    def test_rule_scan_005_masscan(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SCAN-005" in out

    def test_rule_scan_006_honeypot(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SCAN-006" in out

    def test_rule_scan_007_sequential(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SCAN-007" in out

    def test_custom_detection_rule(self, template, minimal_ctx):
        ctx = {**minimal_ctx, "detection_rules": [
            {"id": "RULE-CUSTOM-88", "name": "Custom Scan Rule",
             "source": "Zeek", "threshold": "> 100 ports", "status": "✅ Active"}
        ]}
        out = render(template, **ctx)
        assert "RULE-CUSTOM-88" in out

    def test_log_source_firewall(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Firewall" in out

    def test_log_source_ids(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "IDS" in out or "ids-alerts" in out

    def test_log_source_netflow(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "NetFlow" in out or "netflow" in out.lower()

    def test_log_source_honeypot(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Honeypot" in out or "honeypot" in out.lower()

    def test_log_source_pcap(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert ".pcap" in out or "PCAP" in out

    def test_siem_query_1_syn_scan(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=netflow" in out
        assert "unique_ports" in out

    def test_siem_query_1_threshold(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "50" in out  # default port_count_threshold

    def test_siem_query_2_sequential_pattern(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=firewall-logs" in out
        assert "sequential" in out.lower() or "sorted_ports" in out

    def test_siem_query_3_honeypot_correlation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=honeypot-events" in out
        assert "honeypot_hits" in out

    def test_siem_query_4_ids_alerts(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=ids-alerts" in out
        assert "SCAN" in out

    def test_siem_query_5_cross_segment(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "src_zone" in out or "dest_zone" in out or "cross" in out.lower()

    def test_evidence_paths_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "reports/incidents/port_scan" in out
        assert "9.8.7.6" in out

    def test_evidence_pcap_path(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert ".pcap" in out

    def test_evidence_nmap_xml(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert ".xml" in out or "nmap" in out

    def test_evidence_honeypot_json(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "honeypot" in out and ".json" in out

    def test_evidence_paths_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "/data/scan/case200/" in out


# ── Inherited blocks ──────────────────────────────────────────────────────

class TestInheritedBlocks:
    def test_summary_inherited(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "## 📋 Summary" in out

    def test_ioc_table_inherited(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Indicators of Compromise" in out

    def test_appendix_inherited(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "## 📎 Appendix" in out

    def test_escalation_contacts_inherited(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Incident Commander" in out

    def test_sla_targets_inherited(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Time to Detect" in out

    def test_metadata_block_inherited(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "attack_pattern:" in out
