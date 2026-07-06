"""
tests/unit/test_data_exfiltration_template.py
-----------------------------------------------
Unit tests for sentinel/templates/data_exfiltration.md.j2

Covers every task deliverable:
  ✅ Template exists and extends base_playbook.md.j2
  ✅ Header  – exfil-specific fields (vector, volume, destination, DLP, classification,
               breach notification, legal hold, insider/C2 flags)
  ✅ ATT&CK  – All 12 techniques with correct IDs and tactics
  ✅ Phase 1 – Immediate isolation (memory dump, host isolation, destination block,
               PCAP, netstat, credential revoke, DPO notification)
  ✅ Phase 2 – DLP review (log pull, gap analysis, policy switch to block mode,
               egress hardening, cloud storage block)
  ✅ Phase 3 – File integrity verification (accessed-files audit, archive detection,
               AIDE/Wazuh FIM, auditd, deleted-file detection, bash history, data-at-rest encryption)
  ✅ Phase 4 – Outbound traffic analysis (NetFlow, baseline comparison, exfil timeline,
               protocol-specific DNS/HTTP/SMTP, cloud API analysis, lateral correlation)
  ✅ Phase 5 – Data classification & impact assessment (data types table, record count SQL,
               regulatory notifications, legal hold, impact matrix, rebuild, credential reset)
  ✅ Artifacts – 10 detection rules, 9 log sources, 6 SIEM queries, evidence paths
  ✅ Inherited blocks (summary, ioc_table, appendix)
  ✅ All defaults applied when optional context keys omitted
  ✅ All conditional blocks: exfil_vector, breach_notif_required, legal_hold_required,
     insider_threat, c2_suspected, encryption_used, cloud_provider,
     affected_files, affected_data_types, affected_systems
"""

import os
import pytest
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "backend", "sentinel", "templates")
)
TEMPLATE_NAME = "data_exfiltration.md.j2"


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
    ctx.setdefault("attack_pattern", "data_exfiltration")
    ctx.setdefault("severity", "CRITICAL")
    return template.render(**ctx)


@pytest.fixture
def minimal_ctx():
    return {
        "attack_pattern": "data_exfiltration",
        "severity": "CRITICAL",
        "generated_at": "2026-06-22T12:00:00Z",
        "source_ip": "10.0.1.50",
        "destination_ip": "203.0.113.99",
        "destination_domain": "evil.attacker.com",
        "exfil_vector": "https",
        "data_classification": "CONFIDENTIAL",
    }


@pytest.fixture
def full_ctx():
    return {
        "title": "Data Exfiltration – Production Breach",
        "attack_pattern": "data_exfiltration",
        "severity": "CRITICAL",
        "generated_at": "2026-06-22T12:00:00Z",
        "playbook_id": "PB-EXFIL-PROD-001",
        "version": "2.0.0",
        "classification": "TLP:RED",
        "source_ip": "10.0.2.77",
        "destination_ip": "45.55.66.77",
        "destination_domain": "exfil.badactor.io",
        "destination_country": "RU",
        "exfil_vector": "dns",
        "exfil_bytes": 524288000,
        "exfil_bytes_hr": "500 MB",
        "exfil_duration": "6 hours",
        "data_classification": "SECRET",
        "dlp_vendor": "Symantec DLP",
        "dlp_mode": "monitor",
        "dlp_policy_name": "Sensitive Data Outbound Policy",
        "breach_notif_required": True,
        "legal_hold_required": True,
        "insider_threat": True,
        "c2_suspected": True,
        "cloud_provider": "AWS",
        "cloud_bucket": "corp-exfil-bucket",
        "encryption_used": True,
        "exfil_protocol_detail": "iodine DNS tunnelling",
        "baseline_bytes_per_day": "50 MB",
        "ticket_system": "ServiceNow",
        "ticket_project": "CSIRT",
        "audit_period_hours": 96,
        "dpo_contact": "dpo@corp.example.com",
        "legal_contact": "legal@corp.example.com",
        "forensic_image_path": "/dev/sda",
        "affected_systems": ["10.0.2.77", "10.0.2.78", "fileserver.corp"],
        "affected_data_types": ["PII", "PCI", "trade_secrets"],
        "affected_files": ["/data/customer_export.csv", "/home/user/finance.zip"],
        "evidence_paths": ["/forensics/case300/"],
        "ciso_contact": "ciso@corp.example.com",
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

    def test_base_template_exists(self):
        assert os.path.isfile(os.path.join(TEMPLATES_DIR, "base_playbook.md.j2"))


# ── Section 1: Header ─────────────────────────────────────────────────────

class TestHeader:
    def test_exfil_icon_in_title(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "📤" in out or "Data Exfiltration" in out

    def test_custom_title(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "Data Exfiltration – Production Breach" in out

    def test_severity_critical_badge(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "🔴 **CRITICAL**" in out

    def test_severity_high_badge(self, template, minimal_ctx):
        ctx = {**minimal_ctx, "severity": "HIGH"}
        out = render(template, **ctx)
        assert "🟠 **HIGH**" in out

    def test_severity_medium_badge(self, template, minimal_ctx):
        ctx = {**minimal_ctx, "severity": "MEDIUM"}
        out = render(template, **ctx)
        assert "🟡 **MEDIUM**" in out

    def test_exfil_vector_in_header(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "HTTPS" in out or "https" in out

    def test_exfil_vector_dns_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "DNS" in out

    def test_source_ip_in_header(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "10.0.1.50" in out

    def test_destination_ip_in_header(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "203.0.113.99" in out

    def test_destination_domain_in_header(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "evil.attacker.com" in out

    def test_destination_country(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "RU" in out

    def test_exfil_volume_bytes(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "524288000" in out

    def test_exfil_volume_hr(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "500 MB" in out

    def test_exfil_duration(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "6 hours" in out

    def test_data_classification_confidential(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "CONFIDENTIAL" in out

    def test_data_classification_secret(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "SECRET" in out

    def test_dlp_vendor_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "None / Unknown" in out or "DLP" in out

    def test_dlp_vendor_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "Symantec DLP" in out

    def test_dlp_mode_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "monitor" in out

    def test_dlp_policy_name(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "Sensitive Data Outbound Policy" in out

    def test_breach_notification_required(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "REQUIRED" in out

    def test_breach_notification_under_assessment_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Under Assessment" in out or "Not Required" in out or "Assessment" in out

    def test_legal_hold_required(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "REQUIRED" in out

    def test_insider_threat_suspected(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "SUSPECTED" in out

    def test_insider_threat_not_suspected_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Not Suspected" in out

    def test_c2_suspected_flag(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "SUSPECTED" in out

    def test_playbook_id_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PB-EXFIL-001" in out

    def test_playbook_id_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "PB-EXFIL-PROD-001" in out

    def test_classification_tlp_red_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "TLP:RED" in out

    def test_ticket_system_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Jira" in out

    def test_ticket_system_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "ServiceNow" in out

    def test_ticket_project_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "CSIRT" in out


# ── Section 4: ATT&CK Mapping ─────────────────────────────────────────────

class TestATTACKMapping:
    def test_attack_section_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "MITRE ATT" in out and "Exfiltration" in out

    def test_t1041_c2_channel(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1041" in out
        assert "Exfiltration Over C2 Channel" in out

    def test_t1048_alternative_protocol(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1048" in out
        assert "Alternative Protocol" in out

    def test_t1048_003_subtechnique(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1048.003" in out or "T1048/003" in out

    def test_t1567_web_service(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1567" in out
        assert "Web Service" in out

    def test_t1567_002_cloud_storage(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1567.002" in out or "T1567/002" in out

    def test_t1020_automated_exfil(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1020" in out
        assert "Automated Exfiltration" in out

    def test_t1030_size_limits(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1030" in out
        assert "Size Limits" in out

    def test_t1052_physical_medium(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1052" in out
        assert "Physical Medium" in out

    def test_t1022_data_encrypted(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1022" in out
        assert "Data Encrypted" in out

    def test_t1005_data_from_local(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1005" in out

    def test_t1039_network_share(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1039" in out
        assert "Network Shared Drive" in out

    def test_t1074_data_staged(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1074" in out
        assert "Data Staged" in out

    def test_t1071_dns_protocol(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1071" in out
        assert "DNS" in out

    def test_t1132_data_encoding(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1132" in out
        assert "Data Encoding" in out

    def test_exfiltration_tactic_reference(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Exfiltration" in out

    def test_collection_tactic_reference(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Collection" in out

    def test_mitre_tactic_link(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "attack.mitre.org/tactics/TA0010" in out

    def test_destination_in_technique_description(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "evil.attacker.com" in out or "203.0.113.99" in out


# ── Phase 1: Immediate Isolation ──────────────────────────────────────────

class TestPhase1ImmediateIsolation:
    def test_phase1_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 1" in out and ("Isolation" in out or "Block" in out)

    def test_do_not_reboot_warning(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "DO NOT reboot" in out or "Do not" in out.lower() or "reboot" in out

    def test_memory_dump_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "memory" in out.lower() or "mem_dump" in out or "LiME" in out

    def test_lime_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "lime" in out.lower() or "LiME" in out

    def test_winpmem_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "winpmem" in out.lower() or "WinPmem" in out

    def test_memory_hash_verification(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "sha256sum" in out

    def test_isolate_source_host(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Isolate" in out or "isolate" in out
        assert "10.0.1.50" in out

    def test_iptables_output_block(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "iptables -I OUTPUT" in out

    def test_sdn_isolate_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "phantomnet-sdn isolate" in out or "SDN" in out

    def test_block_destination(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Block destination" in out or "203.0.113.99" in out

    def test_dns_sinkhole_destination(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "sinkhole" in out.lower() or "/etc/hosts" in out

    def test_dns_exfil_block_when_vector_dns(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "DNS" in out and ("block" in out.lower() or "restrict" in out.lower())

    def test_pcap_capture_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "tcpdump" in out and ".pcap" in out

    def test_netstat_preservation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ss -antp" in out or "netstat" in out.lower()

    def test_process_snapshot(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ps auxf" in out or "process" in out.lower()

    def test_revoke_credentials_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Revoke" in out or "revoke" in out

    def test_aws_credential_revoke(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "aws iam delete-access-key" in out or "AWS" in out

    def test_dpo_notification_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "DPO" in out or "Data Protection Officer" in out

    def test_legal_notification_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Legal" in out or "legal" in out

    def test_dpo_contact_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "dpo@phantomnet.local" in out

    def test_dpo_contact_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "dpo@corp.example.com" in out

    def test_insider_threat_protocol(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "INSIDER THREAT" in out or "insider" in out.lower()

    def test_usb_disable_insider_threat(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "usb_storage" in out or "USB" in out

    def test_c2_suspected_warning(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "C2 SUSPECTED" in out or "C2" in out

    def test_checkboxes_in_phase1(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "- [ ]" in out


# ── Phase 2: DLP Review ───────────────────────────────────────────────────

class TestPhase2DLPReview:
    def test_phase2_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 2" in out and "DLP" in out

    def test_dlp_log_pull_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "DLP" in out and ("log" in out.lower() or "alert" in out.lower())

    def test_audit_period_hours_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "72" in out

    def test_audit_period_hours_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "96" in out

    def test_symantec_dlp_api_call(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ProtectManager" in out or "Symantec" in out or "dlp" in out.lower()

    def test_purview_powershell(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Purview" in out or "Get-DlpDetailReport" in out

    def test_dlp_gap_analysis_vector_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "gap" in out.lower() or "vector" in out.lower() or "coverage" in out.lower()

    def test_dlp_gap_https_coverage(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "HTTP/HTTPS" in out or "HTTPS" in out

    def test_dlp_gap_email_coverage(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Email" in out or "SMTP" in out

    def test_dlp_gap_cloud_coverage(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Cloud Storage" in out or "cloud" in out.lower()

    def test_dlp_gap_dns_coverage(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "DNS" in out and ("tunnel" in out.lower() or "exfil" in out.lower())

    def test_dlp_gap_usb_coverage(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "USB" in out or "Removable Media" in out

    def test_switch_dlp_to_block(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "block" in out.lower() and ("DLP" in out or "mode" in out.lower())

    def test_purview_block_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "BlockWithNotify" in out or "Set-DlpCompliancePolicy" in out

    def test_encryption_ssl_inspection(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "SSL" in out or "ssl_bump" in out or "inspection" in out.lower()

    def test_dlp_endpoint_agent_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "endpoint" in out.lower() and "agent" in out.lower()

    def test_egress_filtering_hardening(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "egress" in out.lower() or "outbound" in out.lower()

    def test_cloud_storage_block_personal(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Dropbox" in out or "dropbox.com" in out or "personal" in out.lower()

    def test_proxy_allowlist_audit(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "proxy" in out.lower() or "allow-list" in out.lower()


# ── Phase 3: File Integrity Verification ──────────────────────────────────

class TestPhase3FileIntegrity:
    def test_phase3_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 3" in out and ("File" in out or "Integrity" in out)

    def test_recently_accessed_files_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "accessed" in out.lower() and "file" in out.lower()

    def test_find_atime_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "find /" in out and "-atime" in out

    def test_archive_detection_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "archive" in out.lower() or "zip" in out.lower() or ".tar" in out

    def test_find_zip_tar_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert ".zip" in out and ".tar" in out

    def test_affected_files_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "/data/customer_export.csv" in out
        assert "/home/user/finance.zip" in out

    def test_sha256_hash_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "sha256sum" in out

    def test_aide_baseline_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "aide" in out.lower() or "AIDE" in out

    def test_fim_review_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "FIM" in out or "File Integrity" in out or "integrity" in out.lower()

    def test_wazuh_ossec_fim(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Wazuh" in out or "OSSEC" in out or "ossec" in out.lower()

    def test_windows_event_4663(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "4663" in out

    def test_deleted_files_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "deleted" in out.lower() or "shred" in out.lower() or "wipe" in out.lower()

    def test_bash_history_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "bash_history" in out or ".bash_history" in out

    def test_bash_history_grep_exfil_commands(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "curl" in out and "wget" in out and "scp" in out

    def test_auditd_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ausearch" in out or "auditd" in out

    def test_data_at_rest_encryption_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "BitLocker" in out or "LUKS" in out or "encrypt" in out.lower()

    def test_luks_check_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "lsblk" in out or "crypto" in out.lower()

    def test_manage_bde_windows(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "manage-bde" in out or "BitLocker" in out


# ── Phase 4: Outbound Traffic Analysis ────────────────────────────────────

class TestPhase4OutboundTraffic:
    def test_phase4_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 4" in out and ("Traffic" in out or "Outbound" in out)

    def test_netflow_pull_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "nfdump" in out or "NetFlow" in out or "IPFIX" in out

    def test_baseline_comparison_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "baseline" in out.lower()

    def test_exfil_timeline_reconstruction(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "timeline" in out.lower()

    def test_tshark_pcap_analysis(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "tshark" in out

    def test_baseline_bytes_per_day_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "rolling average" in out or "baseline" in out.lower()

    def test_baseline_bytes_per_day_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "50 MB" in out

    def test_exfil_bytes_hr_in_comparison(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "500 MB" in out

    def test_dns_tunnelling_analysis_when_vector_dns(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "DNS Tunnelling" in out or "dns" in out.lower()

    def test_dns_entropy_calculation(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "entropy" in out.lower() or "Entropy" in out

    def test_iodine_dnscat_fingerprint_check(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "iodine" in out or "dnscat" in out

    def test_all_external_destinations(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "external" in out.lower() and "destination" in out.lower()

    def test_cloud_storage_api_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "cloud" in out.lower() and ("storage" in out.lower() or "bucket" in out.lower())

    def test_aws_cloudtrail_lookup(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "cloudtrail" in out.lower() or "PutObject" in out or "AWS" in out

    def test_lateral_correlation_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "lateral" in out.lower() or "other internal hosts" in out.lower() or "correlation" in out.lower()


# ── Phase 5: Data Classification & Impact ─────────────────────────────────

class TestPhase5DataClassificationImpact:
    def test_phase5_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 5" in out and ("Classification" in out or "Impact" in out or "Assessment" in out)

    def test_data_classification_review_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Data Classification" in out

    def test_affected_data_types_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "PII" in out
        assert "PCI" in out
        assert "trade_secrets" in out

    def test_default_data_types_table(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PII" in out or "Financial" in out or "Healthcare" in out

    def test_record_count_sql(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "COUNT" in out or "count" in out

    def test_data_subjects_count(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "subject" in out.lower() or "individual" in out.lower()

    def test_gdpr_notification(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "GDPR" in out

    def test_hipaa_notification(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "HIPAA" in out

    def test_pci_dss_notification(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PCI" in out

    def test_breach_notif_mandatory_when_flag(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "MANDATORY" in out or "BREACH NOTIFICATION REQUIRED" in out

    def test_gdpr_72h_deadline(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "72 hours" in out

    def test_hipaa_60_day_deadline(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "60 days" in out

    def test_legal_hold_dd_command(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "dd if=" in out or "legal_hold" in out.lower()

    def test_legal_hold_chattr(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "chattr +i" in out

    def test_forensic_image_hash(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "sha256sum" in out and "forensics" in out.lower()

    def test_impact_matrix_table(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Impact" in out and ("TBD" in out or "matrix" in out.lower())

    def test_affected_systems_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "10.0.2.78" in out
        assert "fileserver.corp" in out

    def test_reimage_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "reimage" in out.lower() or "rebuild" in out.lower() or "golden image" in out.lower()

    def test_credential_reset_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Reset all credentials" in out or "password reset" in out.lower() or "credential" in out.lower()

    def test_ueba_recommendation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "UEBA" in out or "behaviour analytics" in out.lower() or "anomalous" in out.lower()

    def test_incident_ticket_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "incident ticket" in out.lower() or "Create incident" in out

    def test_breach_report_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "breach report" in out.lower() or "formal" in out.lower()

    def test_post_incident_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "debrief" in out.lower() or "post-incident" in out.lower()

    def test_ticket_system_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Jira" in out

    def test_ticket_system_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "ServiceNow" in out


# ── Section 6: Artifacts ──────────────────────────────────────────────────

class TestArtifacts:
    def test_artifacts_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Artifacts" in out

    def test_rule_exfil_001_volume_spike(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-001" in out

    def test_rule_exfil_002_dlp(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-002" in out

    def test_rule_exfil_003_dns_tunnelling(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-003" in out

    def test_rule_exfil_004_large_https_post(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-004" in out

    def test_rule_exfil_005_staging(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-005" in out

    def test_rule_exfil_006_credential_in_http(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-006" in out

    def test_rule_exfil_007_cloud_personal(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-007" in out

    def test_rule_exfil_008_usb(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-008" in out

    def test_rule_exfil_009_email_attach(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-009" in out

    def test_rule_exfil_010_ueba(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-EXFIL-010" in out

    def test_custom_rule_appended(self, template, minimal_ctx):
        ctx = {**minimal_ctx, "detection_rules": [
            {"id": "RULE-CUSTOM-77", "name": "Custom Exfil Rule",
             "source": "CASB", "threshold": "> 100 MB", "status": "✅ Active"}
        ]}
        out = render(template, **ctx)
        assert "RULE-CUSTOM-77" in out

    def test_log_source_netflow(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "NetFlow" in out or "IPFIX" in out

    def test_log_source_proxy(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Proxy" in out or "proxy" in out.lower()

    def test_log_source_dlp(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "DLP" in out

    def test_log_source_edr_fim(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "EDR" in out or "FIM" in out

    def test_log_source_dns(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "DNS" in out

    def test_log_source_email(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Email" in out or "email" in out.lower()

    def test_log_source_casb(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "CASB" in out or "Cloud" in out

    def test_log_source_auditd(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Auditd" in out or "WinEvent" in out or "audit" in out.lower()

    def test_siem_query_1_volume_anomaly(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=netflow" in out
        assert "total_bytes" in out

    def test_siem_query_2_baseline_deviation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "z_score" in out or "avg_baseline" in out or "stdev" in out

    def test_siem_query_3_dns_tunnelling(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=dns-queries" in out
        assert "subdomain" in out

    def test_siem_query_4_dlp_correlation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=dlp-alerts" in out

    def test_siem_query_5_staging(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=edr-events" in out
        assert "file_ext" in out

    def test_siem_query_6_cloud_upload(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=proxy-access" in out
        assert "amazonaws.com" in out

    def test_evidence_memory_dump(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "mem_dump" in out or "memory" in out.lower()

    def test_evidence_disk_image(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "disk_image" in out or ".img" in out

    def test_evidence_pcap(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert ".pcap" in out

    def test_evidence_accessed_files(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "accessed_files" in out

    def test_evidence_breach_report(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "breach_report" in out or "breach report" in out.lower()

    def test_evidence_dlp_incidents(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "dlp_incidents" in out or "dlp" in out.lower()

    def test_evidence_fim_aide_delta(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "aide_delta" in out or "fim" in out.lower()

    def test_evidence_paths_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "/forensics/case300/" in out


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
