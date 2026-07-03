"""
tests/e2e/test_playbook_e2e_verification.py
---------------------------------------------
End-to-end verification that PlaybookGenerator.generate() renders
all 7 standard playbook sections from mock campaign cluster data
matching the real SentinelService.generate_playbook() input format.

Campaign cluster format (from sentinel_service.py):
    source_ips:   list[str]
    target_ports: list[int]
    protocols:    list[str]
    event_count:  int
    time_range:   dict with start/end
    campaign_id:  str

This suite builds 5 complete mock clusters:
    1. SSH Brute Force         — brute_force.md.j2
    2. SQL Injection           — sqli_attempt.md.j2
    3. Port Scan / Recon       — port_scan.md.j2
    4. Data Exfiltration       — data_exfiltration.md.j2
    5. Unknown (custom)        — base_playbook.md.j2 (fallback)

For each, it verifies all 7 playbook sections render valid Markdown.
"""

import os
import re
import sys
import pytest
from datetime import datetime, timezone

# Ensure project root is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
for _p in (PROJECT_ROOT, BACKEND_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from sentinel.playbook_generator import PlaybookGenerator


# ============================================================
# Mock campaign cluster data — matching real cluster format
# ============================================================

BRUTE_FORCE_CLUSTER = {
    # --- Campaign cluster fields (real format) ---
    "source_ips": ["185.220.101.42", "185.220.101.43", "91.240.118.5"],
    "target_ports": [2222, 22],
    "protocols": ["TCP"],
    "event_count": 4872,
    "time_range": {
        "start": "2026-06-24T08:00:00Z",
        "end": "2026-06-24T12:30:00Z",
    },
    "campaign_id": "CAMP-BRUTE-20260624-001",
    # --- Playbook context fields ---
    "attack_pattern": "brute_force",
    "title": "SSH Brute Force Campaign – Eastern Europe Botnet",
    "severity": "CRITICAL",
    "source_ip": "185.220.101.42",
    "target_ip": "10.0.2.15",
    "ssh_port": 2222,
    "failed_logins_threshold": 4872,
    "timeframe": "4 hours 30 minutes",
    "timeframe_seconds": "16200s",
    "block_duration": "86400",
    "tarpit_delay_ms": 10000,
    "alert_level": "CRITICAL",
    "targeted_usernames": ["root", "admin", "ubuntu", "deploy", "postgres"],
    "key_rotation_hosts": ["10.0.2.15", "10.0.2.16", "10.0.2.17"],
    "lockout_policy_threshold": 3,
    "min_password_length": 20,
    "ticket_system": "Jira",
    "ticket_project": "SOC",
    "on_call_engineer": "Sriram K.",
    "escalate_to_ciso": True,
    "geo_block_country": "RU",
    "audit_period_hours": 72,
    "iocs": [
        {"ip": "185.220.101.42", "ports": "2222", "protocol": "TCP",
         "hit_count": 3200, "threat_intel": "🔴 Tor Exit Node (AbuseIPDB 100%)",
         "first_seen": "2026-06-24T08:02:14Z", "last_seen": "2026-06-24T12:28:55Z"},
        {"ip": "185.220.101.43", "ports": "2222", "protocol": "TCP",
         "hit_count": 1200, "threat_intel": "🔴 Tor Exit Node (AbuseIPDB 98%)",
         "first_seen": "2026-06-24T08:15:00Z", "last_seen": "2026-06-24T12:30:00Z"},
        {"ip": "91.240.118.5", "ports": "22", "protocol": "TCP",
         "hit_count": 472, "threat_intel": "🟠 Known Scanner (Shodan)",
         "first_seen": "2026-06-24T09:00:00Z", "last_seen": "2026-06-24T11:45:00Z"},
    ],
}

SQLI_CLUSTER = {
    "source_ips": ["103.152.220.44"],
    "target_ports": [8080, 443],
    "protocols": ["TCP"],
    "event_count": 347,
    "time_range": {
        "start": "2026-06-24T14:00:00Z",
        "end": "2026-06-24T14:45:00Z",
    },
    "campaign_id": "CAMP-SQLI-20260624-002",
    "attack_pattern": "sqli_attempt",
    "title": "SQL Injection – Customer API Endpoint",
    "severity": "CRITICAL",
    "source_ip": "103.152.220.44",
    "target_ip": "10.0.5.80",
    "target_url": "/api/v2/customers?id=1' OR 1=1--",
    "http_method": "GET",
    "db_engine": "PostgreSQL",
    "db_host": "db-primary.internal",
    "db_name": "customer_db",
    "db_port": 5432,
    "waf_vendor": "Cloudflare WAF",
    "waf_mode": "detection",
    "sqli_payload": "1' OR 1=1; DROP TABLE users;--",
    "affected_tables": ["users", "orders", "payment_methods"],
    "block_duration": "7200",
    "alert_level": "CRITICAL",
    "audit_period_hours": 96,
    "ticket_system": "ServiceNow",
    "ticket_project": "CSIRT",
    "iocs": [
        {"ip": "103.152.220.44", "ports": "8080, 443", "protocol": "TCP",
         "hit_count": 347, "threat_intel": "🔴 Known SQLi Scanner (OTX)",
         "first_seen": "2026-06-24T14:00:12Z", "last_seen": "2026-06-24T14:44:58Z"},
    ],
}

PORT_SCAN_CLUSTER = {
    "source_ips": ["45.33.32.156", "45.33.32.157"],
    "target_ports": [22, 80, 443, 2222, 3306, 5432, 6379, 8080, 8443, 9200],
    "protocols": ["TCP", "UDP"],
    "event_count": 15420,
    "time_range": {
        "start": "2026-06-24T02:00:00Z",
        "end": "2026-06-24T02:12:00Z",
    },
    "campaign_id": "CAMP-SCAN-20260624-003",
    "attack_pattern": "port_scan",
    "title": "Aggressive Port Scan – Full /24 Subnet Enumeration",
    "severity": "HIGH",
    "source_ip": "45.33.32.156",
    "target_ip": "10.0.2.0/24",
    "target_subnet": "10.0.2.0/24",
    "scan_type": "SYN",
    "port_count": 1024,
    "port_count_threshold": 50,
    "honeypot_count": 5,
    "honeypot_type": "deception_mesh",
    "deception_mode": "aggressive_deception",
    "capture_duration": "900s",
    "sdn_enabled": True,
    "block_duration": "3600",
    "alert_level": "HIGH",
    "audit_period_hours": 48,
    "ticket_system": "Jira",
    "ticket_project": "SOC",
    "iocs": [
        {"ip": "45.33.32.156", "ports": "1-65535", "protocol": "TCP",
         "hit_count": 12000, "threat_intel": "🟠 Nmap Scanner (Shodan)",
         "first_seen": "2026-06-24T02:00:01Z", "last_seen": "2026-06-24T02:11:58Z"},
        {"ip": "45.33.32.157", "ports": "1-1024", "protocol": "TCP/UDP",
         "hit_count": 3420, "threat_intel": "🟠 Masscan Fingerprint",
         "first_seen": "2026-06-24T02:00:03Z", "last_seen": "2026-06-24T02:11:55Z"},
    ],
}

DATA_EXFIL_CLUSTER = {
    "source_ips": ["10.0.3.77"],
    "target_ports": [443, 53],
    "protocols": ["TCP", "UDP"],
    "event_count": 892,
    "time_range": {
        "start": "2026-06-23T22:00:00Z",
        "end": "2026-06-24T04:00:00Z",
    },
    "campaign_id": "CAMP-EXFIL-20260624-004",
    "attack_pattern": "data_exfiltration",
    "title": "Data Exfiltration – DNS Tunnelling to External C2",
    "severity": "CRITICAL",
    "source_ip": "10.0.3.77",
    "destination_ip": "198.51.100.42",
    "destination_domain": "c2.darkoperator.xyz",
    "destination_country": "CN",
    "exfil_vector": "dns",
    "exfil_bytes": 1073741824,
    "exfil_bytes_hr": "1 GB",
    "exfil_duration": "6 hours",
    "data_classification": "SECRET",
    "dlp_vendor": "Microsoft Purview",
    "dlp_mode": "monitor",
    "dlp_policy_name": "PII Outbound Detection",
    "breach_notif_required": True,
    "legal_hold_required": True,
    "insider_threat": True,
    "c2_suspected": True,
    "cloud_provider": "AWS",
    "cloud_bucket": "s3://corp-data-staging",
    "encryption_used": True,
    "exfil_protocol_detail": "iodine DNS tunnelling over TXT records",
    "baseline_bytes_per_day": "25 MB",
    "dpo_contact": "dpo@phantomnet.local",
    "legal_contact": "legal@phantomnet.local",
    "ciso_contact": "ciso@phantomnet.local",
    "forensic_image_path": "/dev/sda",
    "affected_systems": ["10.0.3.77", "10.0.3.78", "fileserver.corp.local"],
    "affected_data_types": ["PII", "PCI", "trade_secrets", "source_code"],
    "affected_files": [
        "/data/exports/customer_dump_2026.csv",
        "/home/jdoe/.cache/staging.tar.gz",
        "/tmp/.hidden/exfil_queue.enc",
    ],
    "evidence_paths": ["/forensics/case-EXFIL-004/"],
    "audit_period_hours": 168,
    "ticket_system": "ServiceNow",
    "ticket_project": "CSIRT",
    "iocs": [
        {"ip": "10.0.3.77", "ports": "53, 443", "protocol": "TCP/UDP",
         "hit_count": 892, "threat_intel": "🔴 Internal – Compromised Host",
         "first_seen": "2026-06-23T22:00:14Z", "last_seen": "2026-06-24T04:00:00Z"},
        {"ip": "198.51.100.42", "ports": "53", "protocol": "UDP",
         "hit_count": 780, "threat_intel": "🔴 Known C2 (OTX + VirusTotal)",
         "first_seen": "2026-06-23T22:01:00Z", "last_seen": "2026-06-24T03:58:00Z"},
    ],
    "ioc_domains": [
        {"domain": "c2.darkoperator.xyz", "resolved_ip": "198.51.100.42",
         "category": "🔴 C2 Infrastructure"},
        {"domain": "*.darkoperator.xyz", "resolved_ip": "198.51.100.42",
         "category": "🔴 DNS Tunnelling Endpoint"},
    ],
}

UNKNOWN_CLUSTER = {
    "source_ips": ["172.16.0.99"],
    "target_ports": [9999],
    "protocols": ["TCP"],
    "event_count": 42,
    "time_range": {
        "start": "2026-06-24T18:00:00Z",
        "end": "2026-06-24T18:05:00Z",
    },
    "campaign_id": "CAMP-UNK-20260624-005",
    "attack_pattern": "custom_zero_day",
    "title": "Unknown Activity — Requires Manual Investigation",
    "severity": "MEDIUM",
    "source_ip": "172.16.0.99",
    "target_ip": "10.0.9.1",
}

ALL_CLUSTERS = {
    "brute_force": BRUTE_FORCE_CLUSTER,
    "sqli_attempt": SQLI_CLUSTER,
    "port_scan": PORT_SCAN_CLUSTER,
    "data_exfiltration": DATA_EXFIL_CLUSTER,
    "unknown": UNKNOWN_CLUSTER,
}


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture(scope="module")
def gen():
    return PlaybookGenerator()


@pytest.fixture(scope="module")
def rendered_playbooks(gen):
    """Render all 5 playbooks once and cache for the entire module."""
    results = {}
    for name, cluster in ALL_CLUSTERS.items():
        results[name] = gen.generate(cluster)
    return results


# ============================================================
# Markdown syntax validators
# ============================================================

def has_h1_heading(text: str) -> bool:
    """Check for at least one H1 (# ) heading."""
    return bool(re.search(r"^# .+", text, re.MULTILINE))


def has_h2_heading(text: str, keyword: str = "") -> bool:
    """Check for H2 (## ) heading optionally containing a keyword."""
    if keyword:
        return bool(re.search(rf"^## .*{re.escape(keyword)}", text, re.MULTILINE | re.IGNORECASE))
    return bool(re.search(r"^## .+", text, re.MULTILINE))


def has_markdown_table(text: str) -> bool:
    """Check for at least one Markdown table (| col | col |)."""
    return bool(re.search(r"^\|.+\|.+\|", text, re.MULTILINE))


def has_checkbox(text: str) -> bool:
    """Check for at least one Markdown checkbox (- [ ])."""
    return "- [ ]" in text


def has_horizontal_rule(text: str) -> bool:
    """Check for horizontal rule (---)."""
    return bool(re.search(r"^---\s*$", text, re.MULTILINE))


def count_h2_headings(text: str) -> int:
    """Count number of H2 headings."""
    return len(re.findall(r"^## .+", text, re.MULTILINE))


def has_code_block(text: str) -> bool:
    """Check for fenced code block (```)."""
    return "```" in text


def has_link(text: str) -> bool:
    """Check for Markdown link [text](url)."""
    return bool(re.search(r"\[.+?\]\(.+?\)", text))


# ============================================================
# 1. Rendering succeeds for all patterns
# ============================================================

class TestRenderingSucceeds:
    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_renders_without_error(self, rendered_playbooks, name):
        assert isinstance(rendered_playbooks[name], str)

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_output_not_empty(self, rendered_playbooks, name):
        assert len(rendered_playbooks[name]) > 500

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_is_markdown_not_yaml(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert out.strip().startswith("#")


# ============================================================
# 2. Section 1 — Header verification
# ============================================================

class TestSection1Header:
    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_h1_heading(self, rendered_playbooks, name):
        assert has_h1_heading(rendered_playbooks[name])

    def test_brute_force_title(self, rendered_playbooks):
        assert "SSH Brute Force Campaign" in rendered_playbooks["brute_force"]

    def test_sqli_title(self, rendered_playbooks):
        assert "SQL Injection" in rendered_playbooks["sqli_attempt"]

    def test_port_scan_title(self, rendered_playbooks):
        assert "Port Scan" in rendered_playbooks["port_scan"]

    def test_exfil_title(self, rendered_playbooks):
        assert "Data Exfiltration" in rendered_playbooks["data_exfiltration"]

    def test_unknown_title(self, rendered_playbooks):
        assert "Unknown Activity" in rendered_playbooks["unknown"]

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_severity_badge(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert any(badge in out for badge in
                   ["🔴 **CRITICAL**", "🟠 **HIGH**", "🟡 **MEDIUM**", "🟢 **LOW**"])

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_metadata_table(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "Playbook ID" in out
        assert "Version" in out

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_timestamp(self, rendered_playbooks, name):
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                         rendered_playbooks[name])

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_attack_pattern(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "attack_pattern" in out.lower() or "Attack Pattern" in out

    def test_brute_force_severity_critical(self, rendered_playbooks):
        assert "🔴 **CRITICAL**" in rendered_playbooks["brute_force"]

    def test_exfil_severity_critical(self, rendered_playbooks):
        assert "🔴 **CRITICAL**" in rendered_playbooks["data_exfiltration"]

    def test_port_scan_severity_high(self, rendered_playbooks):
        assert "🟠 **HIGH**" in rendered_playbooks["port_scan"]

    def test_unknown_severity_medium(self, rendered_playbooks):
        assert "🟡 **MEDIUM**" in rendered_playbooks["unknown"]

    def test_exfil_tlp_red(self, rendered_playbooks):
        assert "TLP:RED" in rendered_playbooks["data_exfiltration"]

    def test_brute_force_ssh_icon(self, rendered_playbooks):
        assert "🔐" in rendered_playbooks["brute_force"]


# ============================================================
# 3. Section 2 — Summary verification
# ============================================================

class TestSection2Summary:
    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_summary_heading_present(self, rendered_playbooks, name):
        assert "## 📋 Summary" in rendered_playbooks[name]

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_trigger_context_table(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "Trigger" in out
        assert "Source IP" in out

    def test_brute_force_source_ip_in_summary(self, rendered_playbooks):
        assert "185.220.101.42" in rendered_playbooks["brute_force"]

    def test_sqli_source_ip_in_summary(self, rendered_playbooks):
        assert "103.152.220.44" in rendered_playbooks["sqli_attempt"]

    def test_port_scan_source_ip_in_summary(self, rendered_playbooks):
        assert "45.33.32.156" in rendered_playbooks["port_scan"]

    def test_exfil_source_ip_in_summary(self, rendered_playbooks):
        assert "10.0.3.77" in rendered_playbooks["data_exfiltration"]

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_affected_assets_section(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "Affected" in out or "Target" in out


# ============================================================
# 4. Section 3 — IOC Table verification
# ============================================================

class TestSection3IOCTable:
    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_ioc_heading_present(self, rendered_playbooks, name):
        assert "Indicators of Compromise" in rendered_playbooks[name]

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_ioc_table_has_markdown_table(self, rendered_playbooks, name):
        assert has_markdown_table(rendered_playbooks[name])

    def test_brute_force_all_3_iocs(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "185.220.101.42" in out
        assert "185.220.101.43" in out
        assert "91.240.118.5" in out

    def test_brute_force_hit_counts(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "3200" in out
        assert "1200" in out

    def test_brute_force_threat_intel(self, rendered_playbooks):
        assert "Tor Exit Node" in rendered_playbooks["brute_force"]

    def test_sqli_ioc_listed(self, rendered_playbooks):
        assert "103.152.220.44" in rendered_playbooks["sqli_attempt"]
        assert "347" in rendered_playbooks["sqli_attempt"]

    def test_port_scan_iocs(self, rendered_playbooks):
        out = rendered_playbooks["port_scan"]
        assert "45.33.32.156" in out
        assert "45.33.32.157" in out

    def test_exfil_both_iocs(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "10.0.3.77" in out
        assert "198.51.100.42" in out

    def test_exfil_domain_iocs(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "c2.darkoperator.xyz" in out

    def test_exfil_threat_intel_labels(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "C2" in out


# ============================================================
# 5. Section 4 — ATT&CK Mapping verification
# ============================================================

class TestSection4ATTACKMapping:
    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_attack_heading_present(self, rendered_playbooks, name):
        assert "MITRE ATT" in rendered_playbooks[name]

    def test_brute_force_t1110(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "T1110" in out
        assert "Brute Force" in out

    def test_brute_force_t1078(self, rendered_playbooks):
        assert "T1078" in rendered_playbooks["brute_force"]

    def test_brute_force_t1021(self, rendered_playbooks):
        assert "T1021" in rendered_playbooks["brute_force"]

    def test_sqli_t1190(self, rendered_playbooks):
        out = rendered_playbooks["sqli_attempt"]
        assert "T1190" in out
        assert "Exploit" in out or "Public-Facing" in out

    def test_port_scan_t1595(self, rendered_playbooks):
        out = rendered_playbooks["port_scan"]
        assert "T1595" in out
        assert "Scanning" in out or "Active" in out

    def test_port_scan_t1046(self, rendered_playbooks):
        assert "T1046" in rendered_playbooks["port_scan"]

    def test_exfil_t1041(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "T1041" in out

    def test_exfil_t1048(self, rendered_playbooks):
        assert "T1048" in rendered_playbooks["data_exfiltration"]

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_mitre_link_present(self, rendered_playbooks, name):
        assert "attack.mitre.org" in rendered_playbooks[name]

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_attack_table_format(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "Technique" in out and "Tactic" in out


# ============================================================
# 6. Section 5 — Containment Steps verification
# ============================================================

class TestSection5Containment:
    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_containment_heading_present(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "Containment" in out

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_actionable_checkboxes(self, rendered_playbooks, name):
        assert has_checkbox(rendered_playbooks[name])

    def test_brute_force_ip_blocking(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "185.220.101.42" in out
        assert "block" in out.lower() or "Block" in out

    def test_brute_force_key_rotation(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "Key Rotation" in out or "key rotation" in out

    def test_brute_force_auth_log_review(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "Auth Log" in out or "auth log" in out

    def test_brute_force_account_lockout(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "lockout" in out.lower() or "Lockout" in out

    def test_brute_force_password_policy(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "password" in out.lower() and "policy" in out.lower()

    def test_sqli_waf_review(self, rendered_playbooks):
        out = rendered_playbooks["sqli_attempt"]
        assert "WAF" in out

    def test_sqli_input_validation(self, rendered_playbooks):
        out = rendered_playbooks["sqli_attempt"]
        assert "Input" in out and "Validation" in out or "input validation" in out.lower()

    def test_sqli_db_integrity(self, rendered_playbooks):
        out = rendered_playbooks["sqli_attempt"]
        assert "Database" in out or "DB" in out

    def test_port_scan_network_segmentation(self, rendered_playbooks):
        out = rendered_playbooks["port_scan"]
        assert "Segmentation" in out or "segmentation" in out

    def test_port_scan_exposed_services(self, rendered_playbooks):
        out = rendered_playbooks["port_scan"]
        assert "Service" in out

    def test_exfil_dlp_review(self, rendered_playbooks):
        assert "DLP" in rendered_playbooks["data_exfiltration"]

    def test_exfil_file_integrity(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "Integrity" in out or "integrity" in out

    def test_exfil_outbound_traffic(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "traffic" in out.lower() or "Traffic" in out

    def test_exfil_data_classification(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "Classification" in out or "classification" in out

    def test_exfil_affected_files_rendered(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "customer_dump_2026.csv" in out

    def test_exfil_affected_systems_rendered(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "fileserver.corp.local" in out

    def test_exfil_insider_threat_flag(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "INSIDER" in out or "insider" in out.lower()

    def test_exfil_c2_suspected_flag(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "C2" in out

    def test_exfil_breach_notification(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "GDPR" in out or "breach" in out.lower()


# ============================================================
# 7. Section 6 — Artifacts verification
# ============================================================

class TestSection6Artifacts:
    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_artifacts_section_present(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "Artifacts" in out or "Rule" in out or "RULE-" in out

    def test_brute_force_detection_rules(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "RULE-" in out

    def test_sqli_detection_rules(self, rendered_playbooks):
        out = rendered_playbooks["sqli_attempt"]
        assert "RULE-" in out

    def test_port_scan_detection_rules(self, rendered_playbooks):
        out = rendered_playbooks["port_scan"]
        assert "RULE-" in out

    def test_exfil_10_detection_rules(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        for i in range(1, 11):
            assert f"RULE-EXFIL-{i:03d}" in out

    def test_exfil_siem_queries(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "index=" in out

    def test_exfil_log_sources(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "NetFlow" in out or "IPFIX" in out
        assert "DLP" in out

    def test_exfil_evidence_paths(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "/forensics/case-EXFIL-004/" in out

    @pytest.mark.parametrize("name", ["brute_force", "sqli_attempt", "port_scan", "data_exfiltration"])
    def test_siem_query_present(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "SIEM" in out or "index=" in out or "query" in out.lower()


# ============================================================
# 8. Section 7 — Appendix verification
# ============================================================

class TestSection7Appendix:
    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_appendix_heading_present(self, rendered_playbooks, name):
        assert "## 📎 Appendix" in rendered_playbooks[name]

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_escalation_contacts(self, rendered_playbooks, name):
        assert "Incident Commander" in rendered_playbooks[name]

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_sla_targets(self, rendered_playbooks, name):
        assert "Time to Detect" in rendered_playbooks[name]

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_metadata_block(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "attack_pattern:" in out


# ============================================================
# 9. Valid Markdown syntax checks
# ============================================================

class TestValidMarkdownSyntax:
    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_h1(self, rendered_playbooks, name):
        assert has_h1_heading(rendered_playbooks[name])

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_multiple_h2(self, rendered_playbooks, name):
        assert count_h2_headings(rendered_playbooks[name]) >= 5

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_tables(self, rendered_playbooks, name):
        assert has_markdown_table(rendered_playbooks[name])

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_horizontal_rules(self, rendered_playbooks, name):
        assert has_horizontal_rule(rendered_playbooks[name])

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_has_checkboxes(self, rendered_playbooks, name):
        assert has_checkbox(rendered_playbooks[name])

    @pytest.mark.parametrize("name", ["brute_force", "sqli_attempt", "port_scan", "data_exfiltration"])
    def test_has_code_blocks(self, rendered_playbooks, name):
        assert has_code_block(rendered_playbooks[name])

    @pytest.mark.parametrize("name", ["brute_force", "sqli_attempt", "port_scan", "data_exfiltration"])
    def test_has_links(self, rendered_playbooks, name):
        assert has_link(rendered_playbooks[name])

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_no_raw_jinja_tags(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "{%" not in out, "Raw Jinja2 block tag found in output"
        assert "{{" not in out, "Raw Jinja2 variable tag found in output"

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_no_jinja_undefined(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        assert "Undefined" not in out, "Jinja2 Undefined found in output"

    @pytest.mark.parametrize("name", list(ALL_CLUSTERS.keys()))
    def test_no_empty_table_cells_with_none(self, rendered_playbooks, name):
        out = rendered_playbooks[name]
        # None should never appear raw in rendered output
        assert "| None |" not in out


# ============================================================
# 10. Cross-pattern campaign data integrity
# ============================================================

class TestCampaignDataIntegrity:
    """Verify that cluster-level campaign fields pass through correctly."""

    def test_brute_force_event_count(self, rendered_playbooks):
        assert "4872" in rendered_playbooks["brute_force"]

    def test_sqli_event_count(self, rendered_playbooks):
        assert "347" in rendered_playbooks["sqli_attempt"]

    def test_port_scan_port_count(self, rendered_playbooks):
        assert "1024" in rendered_playbooks["port_scan"]

    def test_exfil_volume(self, rendered_playbooks):
        assert "1 GB" in rendered_playbooks["data_exfiltration"]

    def test_brute_force_targeted_usernames(self, rendered_playbooks):
        out = rendered_playbooks["brute_force"]
        assert "root" in out
        assert "admin" in out

    def test_sqli_payload_context(self, rendered_playbooks):
        out = rendered_playbooks["sqli_attempt"]
        assert "PostgreSQL" in out
        assert "customer_db" in out

    def test_port_scan_subnet(self, rendered_playbooks):
        assert "10.0.2.0/24" in rendered_playbooks["port_scan"]

    def test_exfil_dns_tunnelling(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "DNS" in out
        assert "iodine" in out or "tunnell" in out.lower()

    def test_exfil_destination_country(self, rendered_playbooks):
        assert "CN" in rendered_playbooks["data_exfiltration"]

    def test_exfil_regulatory_frameworks(self, rendered_playbooks):
        out = rendered_playbooks["data_exfiltration"]
        assert "GDPR" in out
        assert "PCI" in out
