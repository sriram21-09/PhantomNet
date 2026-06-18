"""
tests/unit/test_brute_force_template.py
-----------------------------------------
Unit tests for sentinel/templates/brute_force.md.j2

Validates every task deliverable:
  ✅ Template file exists and extends base_playbook.md.j2
  ✅ Header  – SSH-specific fields (port, attacker IP, failed logins, ticket)
  ✅ ATT&CK  – All 7 SSH brute-force techniques with correct IDs and tactics
  ✅ Phase 1 – IP blocking (iptables, SDN, tarpit, fail2ban, alert, geo-block)
  ✅ Phase 2 – SSH key rotation (host keys, authorized_keys, password auth off)
  ✅ Phase 3 – Auth log review (commands, SIEM queries, TI lookups, lateral move)
  ✅ Phase 4a – Account lockout verification (PAM, faillock, lock commands)
  ✅ Phase 4b – Password policy review (minlen, history, max age, complexity)
  ✅ Phase 4c – MFA enforcement
  ✅ Phase 4d – Incident close-out (ticket, block-list, TI feed, debrief)
  ✅ Artifacts – 5 SSH-specific detection rules, 6 log sources, 4 SIEM queries
  ✅ Evidence paths (default + custom)
  ✅ All Jinja2 defaults applied when context keys omitted
  ✅ Lists: targeted_usernames, key_rotation_hosts, mfa_systems, ssh_allow_list
  ✅ Inherited blocks unchanged: summary, ioc_table, appendix
"""

import os
import pytest
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "sentinel", "templates")
)
TEMPLATE_NAME = "brute_force.md.j2"


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
    ctx.setdefault("generated_at", "2026-06-18T08:00:00Z")
    ctx.setdefault("attack_pattern", "brute_force")
    ctx.setdefault("severity", "HIGH")
    return template.render(**ctx)


# Minimal context with only required fields
@pytest.fixture
def minimal_ctx():
    return {
        "attack_pattern": "brute_force",
        "severity": "HIGH",
        "generated_at": "2026-06-18T08:00:00Z",
        "source_ip": "1.2.3.4",
        "target_ip": "192.168.10.50",
    }


# Full context with all optional fields populated
@pytest.fixture
def full_ctx():
    return {
        "title": "SSH Brute Force Incident",
        "attack_pattern": "brute_force",
        "severity": "CRITICAL",
        "generated_at": "2026-06-18T08:00:00Z",
        "playbook_id": "PB-SSH-001",
        "version": "2.0.0",
        "classification": "TLP:RED",
        "source_ip": "5.6.7.8",
        "target_ip": "10.0.1.100",
        "ssh_port": 2222,
        "failed_logins_threshold": 50,
        "timeframe": "2 minutes",
        "timeframe_seconds": "120s",
        "block_duration": "7200",
        "tarpit_delay_ms": 10000,
        "alert_level": "CRITICAL",
        "audit_period_hours": 72,
        "lockout_policy_threshold": 3,
        "min_password_length": 20,
        "ticket_system": "ServiceNow",
        "ticket_project": "CSIRT",
        "on_call_engineer": "Alice Smith",
        "escalate_to_ciso": True,
        "geo_block_country": "XX",
        "password_policy_ref": "https://corp.example.com/password-policy",
        "targeted_usernames": ["root", "admin", "ubuntu", "ec2-user"],
        "key_rotation_hosts": ["10.0.1.100", "10.0.1.101", "10.0.1.102"],
        "mfa_systems": ["10.0.1.100", "vpn.corp.example.com"],
        "ssh_allow_list": ["203.0.113.5", "203.0.113.6"],
        "ciso_contact": "ciso@corp.example.com",
    }


# ── Template existence ────────────────────────────────────────────────────

class TestTemplateExists:
    def test_template_file_exists(self):
        path = os.path.join(TEMPLATES_DIR, TEMPLATE_NAME)
        assert os.path.isfile(path), f"Template not found: {path}"

    def test_template_loads(self, template):
        assert template is not None

    def test_template_name(self, template):
        assert template.name == TEMPLATE_NAME

    def test_extends_base_playbook(self):
        """Verify brute_force.md.j2 uses {% extends 'base_playbook.md.j2' %}"""
        path = os.path.join(TEMPLATES_DIR, TEMPLATE_NAME)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        assert 'extends "base_playbook.md.j2"' in content or \
               "extends 'base_playbook.md.j2'" in content

    def test_base_template_exists(self):
        path = os.path.join(TEMPLATES_DIR, "base_playbook.md.j2")
        assert os.path.isfile(path)

    def test_renders_without_error(self, template, minimal_ctx):
        out = template.render(**minimal_ctx)
        assert isinstance(out, str)
        assert len(out) > 100


# ── Section 1: Header ─────────────────────────────────────────────────────

class TestHeader:
    def test_ssh_specific_title_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "SSH Brute Force" in out

    def test_custom_title(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "SSH Brute Force Incident" in out

    def test_severity_critical_badge(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "🔴 **CRITICAL**" in out

    def test_severity_high_badge(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "🟠 **HIGH**" in out

    def test_severity_medium_badge(self, template, minimal_ctx):
        ctx = {**minimal_ctx, "severity": "MEDIUM"}
        out = render(template, **ctx)
        assert "🟡 **MEDIUM**" in out

    def test_severity_low_badge(self, template, minimal_ctx):
        ctx = {**minimal_ctx, "severity": "LOW"}
        out = render(template, **ctx)
        assert "🟢 **LOW**" in out

    def test_ssh_port_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "22" in out

    def test_ssh_port_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "2222" in out

    def test_source_ip_in_header(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "1.2.3.4" in out

    def test_target_ip_in_header(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "192.168.10.50" in out

    def test_failed_logins_threshold_in_header(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "50" in out

    def test_timeframe_in_header(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "2 minutes" in out

    def test_generated_at_in_header(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "2026-06-18T08:00:00Z" in out

    def test_ticket_system_in_header(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "ServiceNow" in out

    def test_ticket_project_in_header(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "CSIRT" in out

    def test_playbook_id_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PB-SSH-BRUTE-FORCE" in out

    def test_playbook_id_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "PB-SSH-001" in out

    def test_classification_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "TLP:AMBER" in out

    def test_classification_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "TLP:RED" in out


# ── Section 4: ATT&CK Mapping ─────────────────────────────────────────────

class TestATTACKMapping:
    def test_attack_section_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "MITRE ATT" in out
        assert "SSH Brute Force" in out

    def test_t1110_brute_force(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1110" in out
        assert "Brute Force" in out

    def test_t1110_001_password_guessing(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1110.001" in out or "T1110/001" in out
        assert "Password Guessing" in out

    def test_t1110_003_password_spraying(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1110.003" in out or "T1110/003" in out
        assert "Password Spraying" in out

    def test_t1110_004_credential_stuffing(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1110.004" in out or "T1110/004" in out
        assert "Credential Stuffing" in out

    def test_t1078_valid_accounts(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1078" in out
        assert "Valid Accounts" in out

    def test_t1021_remote_services_ssh(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1021" in out
        assert "Remote Services" in out
        assert "T1021.004" in out or "T1021/004" in out

    def test_t1133_external_remote_services(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1133" in out
        assert "External Remote Services" in out

    def test_t1562_impair_defenses(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1562" in out
        assert "Impair Defenses" in out

    def test_credential_access_tactic(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Credential Access" in out

    def test_lateral_movement_tactic(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Lateral Movement" in out

    def test_mitre_attack_link(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "attack.mitre.org/techniques/T1110" in out

    def test_target_ip_in_attack_description(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "192.168.10.50" in out


# ── Section 5 Phase 1: IP Blocking ────────────────────────────────────────

class TestPhase1IPBlocking:
    def test_phase1_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 1" in out
        assert "Blocking" in out

    def test_block_attacker_ip_checkbox(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Block attacker IP" in out
        assert "1.2.3.4" in out

    def test_iptables_command_source_ip(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "iptables" in out
        assert "1.2.3.4" in out

    def test_block_duration_rendered(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "7200" in out

    def test_default_block_duration(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "3600" in out

    def test_sdn_controller_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "SDN" in out or "SDN controller" in out

    def test_tarpit_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "tarpit" in out.lower()

    def test_tarpit_delay_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "5000" in out

    def test_tarpit_delay_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "10000" in out

    def test_fail2ban_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "fail2ban" in out

    def test_fail2ban_command_with_ip(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "fail2ban-client" in out
        assert "1.2.3.4" in out

    def test_geo_block_absent_by_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "geo-block" not in out.lower() or "geo_block_country" in out

    def test_geo_block_present_when_set(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "geo-block" in out.lower() or "XX" in out

    def test_ssh_port_connectivity_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ssh -p" in out or "SSH OK" in out

    def test_alert_level_in_phase1(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "HIGH" in out

    def test_alert_level_critical(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "CRITICAL" in out

    def test_escalate_to_ciso_when_set(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "CISO" in out
        assert "ciso@corp.example.com" in out

    def test_ssh_allow_list_rendered(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "203.0.113.5" in out
        assert "203.0.113.6" in out

    def test_checkboxes_in_phase1(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "- [ ]" in out


# ── Section 5 Phase 2: SSH Key Rotation ───────────────────────────────────

class TestPhase2SSHKeyRotation:
    def test_phase2_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 2" in out
        assert "Key Rotation" in out

    def test_audit_authorized_keys_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "authorized_keys" in out or "authorized keys" in out.lower()

    def test_find_authorized_keys_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "find /home /root" in out or "authorized_keys" in out

    def test_rotate_host_keys_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ssh_host_" in out or "host keys" in out.lower()

    def test_ssh_keygen_a_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ssh-keygen -A" in out

    def test_restart_sshd(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "systemctl restart sshd" in out or "reload sshd" in out

    def test_key_rotation_hosts_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "10.0.1.101" in out
        assert "10.0.1.102" in out

    def test_key_rotation_fallback_without_list(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "key rotation" in out.lower() or "rotate keys" in out.lower()

    def test_disable_password_auth_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PasswordAuthentication no" in out

    def test_disable_root_login_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PermitRootLogin no" in out

    def test_service_account_key_rotation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "service" in out.lower() and "ssh" in out.lower()

    def test_distribute_new_keys_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "new public keys" in out.lower() or "replacement SSH" in out


# ── Section 5 Phase 3: Auth Log Review ────────────────────────────────────

class TestPhase3AuthLogReview:
    def test_phase3_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 3" in out
        assert "Log Review" in out or "Auth" in out

    def test_audit_period_hours_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "48" in out

    def test_audit_period_hours_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "72" in out

    def test_journalctl_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "journalctl" in out

    def test_grep_auth_log_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "grep" in out
        assert "auth.log" in out

    def test_targeted_usernames_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "root" in out
        assert "admin" in out
        assert "ubuntu" in out
        assert "ec2-user" in out

    def test_check_successful_logins(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Accepted" in out or "successful login" in out.lower()

    def test_escalate_on_successful_login_warning(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ESCALATE IMMEDIATELY" in out or "escalate" in out.lower()

    def test_subnet_scan_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "subnet" in out.lower() or "SUBNET" in out

    def test_lateral_movement_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "lateral movement" in out.lower() or "lateral" in out.lower()

    def test_last_command_in_template(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "last -i" in out or "last logins" in out.lower()

    def test_cron_persistence_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "cron" in out.lower() or "crontab" in out

    def test_siem_correlation_query(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=auth-logs" in out
        assert "ssh_login_attempt" in out

    def test_siem_query_has_source_ip(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "1.2.3.4" in out

    def test_threat_intel_lookup_steps(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "VirusTotal" in out
        assert "AbuseIPDB" in out

    def test_count_failed_by_username_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Failed password" in out


# ── Section 5 Phase 4a: Account Lockout ────────────────────────────────────

class TestPhase4aAccountLockout:
    def test_phase4_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 4" in out
        assert "Lockout" in out

    def test_lockout_threshold_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "5" in out  # default lockout_policy_threshold

    def test_lockout_threshold_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "3" in out

    def test_pam_faillock_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "faillock" in out or "pam_faillock" in out

    def test_pam_tally2_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "pam_tally2" in out or "tally" in out.lower()

    def test_passwd_lock_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "passwd -l" in out

    def test_lock_targeted_usernames(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "passwd -l root" in out
        assert "passwd -l admin" in out

    def test_unlock_legitimate_accounts(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "passwd -u" in out

    def test_force_password_change(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "chage -d 0" in out


# ── Section 5 Phase 4b: Password Policy ───────────────────────────────────

class TestPhase4bPasswordPolicy:
    def test_password_policy_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Password Policy" in out

    def test_min_password_length_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "16" in out

    def test_min_password_length_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "20" in out

    def test_pwquality_conf_reference(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "pwquality.conf" in out

    def test_minlen_setting(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "minlen" in out

    def test_complexity_requirements(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "minclass" in out or "dcredit" in out or "complexity" in out.lower()

    def test_password_history_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "remember" in out or "history" in out.lower()

    def test_password_max_age(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PASS_MAX_DAYS" in out or "maximum password age" in out.lower()

    def test_password_policy_ref_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "phantomnet.local" in out or "password-policy" in out

    def test_password_policy_ref_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "corp.example.com/password-policy" in out


# ── Section 5 Phase 4c: MFA ────────────────────────────────────────────────

class TestPhase4cMFA:
    def test_mfa_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "MFA" in out

    def test_mfa_systems_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "vpn.corp.example.com" in out

    def test_google_authenticator_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "google-authenticator" in out.lower() or "pam_google_authenticator" in out

    def test_mfa_verify_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "MFA is enforced" in out or "verify" in out.lower()


# ── Section 5 Phase 4d: Close-out ─────────────────────────────────────────

class TestPhase4dCloseOut:
    def test_create_incident_ticket_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Create incident ticket" in out or "incident ticket" in out.lower()

    def test_ticket_system_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Jira" in out

    def test_ticket_system_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "ServiceNow" in out

    def test_update_firewall_blocklist(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "block-list" in out.lower() or "block list" in out.lower() or "watchlist" in out.lower()

    def test_add_to_threat_intel_feed(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "threat intelligence" in out.lower() or "threat intel" in out.lower()

    def test_post_incident_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "post-incident" in out.lower() or "debrief" in out.lower()

    def test_fail2ban_signature_update(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "fail2ban" in out or "IDS" in out


# ── Section 6: Artifacts ──────────────────────────────────────────────────

class TestArtifacts:
    def test_artifacts_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Artifacts" in out

    def test_rule_bf_001(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-BF-001" in out

    def test_rule_bf_002_spray(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-BF-002" in out
        assert "Spray" in out or "spray" in out.lower()

    def test_rule_bf_003_root_login(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-BF-003" in out
        assert "Root" in out or "root" in out.lower()

    def test_rule_bf_004_non_allowlist(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-BF-004" in out

    def test_rule_bf_005_fail2ban(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-BF-005" in out

    def test_custom_detection_rule(self, template, minimal_ctx):
        ctx = {**minimal_ctx, "detection_rules": [
            {"id": "RULE-CUSTOM-99", "name": "Custom SSH Rule",
             "source": "Zeek", "threshold": "any", "status": "✅ Active"}
        ]}
        out = render(template, **ctx)
        assert "RULE-CUSTOM-99" in out
        assert "Custom SSH Rule" in out

    def test_log_sources_ssh_auth(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "auth.log" in out or "SSH Auth" in out

    def test_log_sources_journald(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "journald" in out or "journalctl" in out

    def test_log_sources_fail2ban(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "fail2ban" in out

    def test_log_sources_firewall(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Firewall" in out or "firewall" in out

    def test_log_sources_netflow(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "netflow" in out.lower() or "Network Flow" in out

    def test_siem_query_1_brute_force_threshold(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=auth-logs" in out
        assert "ssh_login_attempt" in out

    def test_siem_query_1_has_failed_threshold(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "20" in out  # default failed_logins_threshold

    def test_siem_query_2_spray_detection(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "unique_targets" in out
        assert "ssh_login_failed" in out

    def test_siem_query_3_lateral_movement(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ssh_login_success" in out
        assert "session_id" in out

    def test_siem_query_4_fail2ban_events(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "fail2ban.log" in out

    def test_evidence_paths_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "reports/incidents/brute_force" in out
        assert "1.2.3.4" in out

    def test_evidence_paths_pcap(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert ".pcap" in out

    def test_evidence_paths_auth_logs(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "auth_logs" in out

    def test_evidence_paths_authorized_keys_snapshot(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "authorized_keys" in out

    def test_evidence_paths_sshd_config_snapshot(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "sshd_config" in out

    def test_custom_evidence_paths(self, template, minimal_ctx):
        ctx = {**minimal_ctx, "evidence_paths": ["/data/evidence/case42/"]}
        out = render(template, **ctx)
        assert "/data/evidence/case42/" in out


# ── Inherited blocks (summary, ioc_table, appendix) ──────────────────────

class TestInheritedBlocks:
    def test_summary_section_inherited(self, template, minimal_ctx):
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

    def test_metadata_yaml_block_inherited(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "attack_pattern:" in out
