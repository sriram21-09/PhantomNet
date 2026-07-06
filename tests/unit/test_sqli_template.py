"""
tests/unit/test_sqli_template.py
----------------------------------
Unit tests for sentinel/templates/sqli_attempt.md.j2

Covers every deliverable:
  ✅ Template exists and extends base_playbook.md.j2
  ✅ Header – SQLi-specific fields (endpoint, DB engine, WAF vendor/mode, HTTP method)
  ✅ ATT&CK – All 8 techniques with correct IDs, tactics, and OWASP reference
  ✅ Phase 1 – Immediate triage (IP block, HTTP capture, DB session kill, maintenance mode)
  ✅ Phase 2 – WAF review (logs, prevention mode, custom rule, rate-limit, CSP headers)
  ✅ Phase 3 – Input validation audit (endpoint map, parameterised queries, ORM audit)
  ✅ Phase 4 – DB integrity (binlog review, affected tables, privilege check, restore, cred rotation)
  ✅ Artifacts – 7 detection rules, 7 log sources, 5 SIEM queries, evidence paths
  ✅ Inherited blocks (summary, ioc_table, appendix)
  ✅ All defaults applied when optional context keys omitted
  ✅ All lists: affected_tables, affected_endpoints, evidence_paths, detection_rules
"""

import os
import pytest
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "backend", "sentinel", "templates")
)
TEMPLATE_NAME = "sqli_attempt.md.j2"


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
    ctx.setdefault("attack_pattern", "sqli_attempt")
    ctx.setdefault("severity", "HIGH")
    return template.render(**ctx)


@pytest.fixture
def minimal_ctx():
    return {
        "attack_pattern": "sqli_attempt",
        "severity": "HIGH",
        "generated_at": "2026-06-22T12:00:00Z",
        "source_ip": "1.2.3.4",
        "target_ip": "10.0.0.50",
        "target_url": "/api/users",
        "db_host": "db.internal",
        "db_engine": "MySQL",
        "db_name": "app_db",
    }


@pytest.fixture
def full_ctx():
    return {
        "title": "SQLi Incident – Production API",
        "attack_pattern": "sqli_attempt",
        "severity": "CRITICAL",
        "generated_at": "2026-06-22T12:00:00Z",
        "playbook_id": "PB-SQLI-PROD-001",
        "version": "2.0.0",
        "classification": "TLP:RED",
        "source_ip": "5.5.5.5",
        "target_ip": "10.0.0.99",
        "target_url": "/api/v2/products",
        "db_host": "prod-db.internal",
        "db_engine": "PostgreSQL",
        "db_name": "prod_db",
        "waf_vendor": "ModSecurity",
        "waf_mode": "detection",
        "http_method": "POST",
        "response_code": 500,
        "alert_level": "CRITICAL",
        "block_duration": "7200",
        "audit_period_hours": 72,
        "app_framework": "Django",
        "orm_in_use": True,
        "escalate_to_ciso": True,
        "pen_test_required": True,
        "ticket_system": "ServiceNow",
        "ticket_project": "CSIRT",
        "dba_contact": "dba@corp.example.com",
        "payload_sample": "' OR 1=1; DROP TABLE users; --",
        "backup_path": "/backups/prod_db_20260622.dump",
        "db_app_user": "django_user",
        "ciso_contact": "ciso@corp.example.com",
        "affected_tables": ["users", "orders", "payment_info"],
        "affected_endpoints": ["/api/v2/products", "/api/v2/orders"],
        "evidence_paths": ["/data/sqli/case100/"],
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
    def test_sqli_icon_in_title(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "💉" in out or "SQL Injection" in out

    def test_custom_title(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "SQLi Incident – Production API" in out

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

    def test_http_method(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "POST" in out

    def test_http_method_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "GET" in out

    def test_target_url(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "/api/users" in out

    def test_target_ip_in_header(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "10.0.0.50" in out

    def test_db_host(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "db.internal" in out

    def test_db_engine(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "MySQL" in out

    def test_db_name(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "app_db" in out

    def test_waf_vendor_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "None / Unknown" in out or "WAF" in out

    def test_waf_vendor_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "ModSecurity" in out

    def test_waf_mode_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "detection" in out

    def test_source_ip(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "1.2.3.4" in out

    def test_playbook_id_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PB-SQLI-001" in out

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
        assert "MITRE ATT" in out and "SQL Injection" in out

    def test_t1190_exploit_public_app(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1190" in out
        assert "Exploit Public-Facing Application" in out

    def test_t1005_data_from_local_system(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1005" in out
        assert "Data from Local System" in out

    def test_t1552_unsecured_credentials(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1552" in out
        assert "Unsecured Credentials" in out

    def test_t1213_data_from_repositories(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1213" in out

    def test_t1565_data_manipulation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1565" in out
        assert "Data Manipulation" in out

    def test_t1110_brute_force(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1110" in out

    def test_t1078_valid_accounts(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1078" in out

    def test_t1059_scripting(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "T1059" in out

    def test_owasp_reference_link(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "owasp.org" in out

    def test_db_name_in_technique_desc(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "app_db" in out


# ── Phase 1: Immediate Triage ──────────────────────────────────────────────

class TestPhase1Triage:
    def test_phase1_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 1" in out and ("Triage" in out or "Block" in out)

    def test_block_attacker_ip(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Block attacker IP" in out
        assert "1.2.3.4" in out

    def test_iptables_drop_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "iptables -I INPUT" in out
        assert "1.2.3.4" in out

    def test_block_duration_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "3600" in out

    def test_block_duration_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "7200" in out

    def test_capture_http_request(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Capture" in out and ("HTTP" in out or "access" in out.lower())

    def test_grep_access_log(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "grep" in out and "access" in out.lower()

    def test_preserve_db_logs(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "error.log" in out or "db" in out.lower()

    def test_payload_sample_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "OR" in out or "payload" in out.lower()

    def test_payload_sample_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "DROP TABLE users" in out

    def test_kill_db_sessions(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "processlist" in out or "pg_stat_activity" in out or "session" in out.lower()

    def test_maintenance_mode_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "maintenance" in out.lower() or "503" in out

    def test_ciso_escalation_when_set(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "CISO" in out
        assert "ciso@corp.example.com" in out

    def test_soc_alert(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "alert" in out.lower() and "SOC" in out

    def test_checkboxes_present(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "- [ ]" in out


# ── Phase 2: WAF Review ───────────────────────────────────────────────────

class TestPhase2WAFReview:
    def test_phase2_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 2" in out and "WAF" in out

    def test_waf_log_review_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "WAF" in out and ("log" in out.lower() or "audit" in out.lower())

    def test_modsec_audit_log_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "modsec_audit.log" in out or "modsecurity" in out.lower()

    def test_owasp_crs_942_reference(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "942" in out or "OWASP CRS" in out

    def test_switch_to_prevention_mode(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "prevention" in out.lower() or "SecRuleEngine On" in out

    def test_modsec_secruleengine_command(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "SecRuleEngine" in out

    def test_custom_waf_rule_creation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "detectSQLi" in out or "custom_rules" in out

    def test_waf_replay_verification(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "403" in out or "Forbidden" in out

    def test_rate_limiting_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "rate" in out.lower() and ("limit" in out.lower() or "throttle" in out.lower())

    def test_csp_headers_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Content-Security-Policy" in out or "CSP" in out

    def test_cors_policy_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "CORS" in out


# ── Phase 3: Input Validation Audit ───────────────────────────────────────

class TestPhase3InputValidation:
    def test_phase3_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 3" in out and ("Input" in out or "Validation" in out)

    def test_affected_endpoints_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "/api/v2/products" in out
        assert "/api/v2/orders" in out

    def test_sqlmap_audit_fallback(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "sqlmap" in out

    def test_grep_raw_sql_concatenation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "SELECT" in out and ("grep" in out or "find" in out.lower())

    def test_orm_raw_query_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "raw" in out.lower() or "ORM" in out

    def test_orm_in_use_flag_rendered(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "True" in out or "orm_in_use" in out

    def test_parameterised_query_python_example(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "cursor.execute" in out or "parameterised" in out.lower() or "prepared" in out.lower()

    def test_parameterised_query_java_example(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "PreparedStatement" in out

    def test_parameterised_query_node_example(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "db.query" in out or "Node" in out

    def test_integer_type_validation(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "int()" in out or "parseInt" in out or "Integer" in out.lower()

    def test_stored_procedure_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "stored procedure" in out.lower()

    def test_error_response_hardening(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "500" in out or "error message" in out.lower()

    def test_vulnerable_vs_safe_code_shown(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "VULNERABLE" in out
        assert "SAFE" in out


# ── Phase 4: DB Integrity ─────────────────────────────────────────────────

class TestPhase4DBIntegrity:
    def test_phase4_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Phase 4" in out and ("Database" in out or "DB" in out or "Integrity" in out)

    def test_binlog_review_mysql(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "mysqlbinlog" in out or "BINARY LOGS" in out or "binary log" in out.lower()

    def test_pg_audit_log_query(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "postgresql" in out.lower() or "pg_audit" in out

    def test_mssql_fn_dblog(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "fn_dblog" in out or "MSSQL" in out

    def test_affected_tables_list(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "users" in out
        assert "orders" in out
        assert "payment_info" in out

    def test_affected_tables_fallback_query(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "performance_schema" in out or "events_statements" in out or "affected" in out.lower()

    def test_privilege_escalation_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "mysql.user" in out or "privilege" in out.lower() or "pg_user" in out

    def test_web_shell_scan(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "web shell" in out.lower() or "webshell" in out.lower() or "OUTFILE" in out

    def test_xp_cmdshell_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "xp_cmdshell" in out

    def test_data_exfiltration_assessment(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "exfiltrat" in out.lower() or "egress" in out.lower()

    def test_union_select_log_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "UNION" in out or "union" in out

    def test_restore_from_backup(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "backup" in out.lower() or "restore" in out.lower()

    def test_backup_path_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "/backups/" in out

    def test_backup_path_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "/backups/prod_db_20260622.dump" in out

    def test_rotate_db_credentials(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "ALTER USER" in out or "rotate" in out.lower()

    def test_least_privilege_check(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "least privilege" in out.lower() or "REVOKE" in out

    def test_revoke_file_privilege(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "REVOKE FILE" in out or "FILE" in out

    def test_db_query_auditing_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "general_log" in out or "audit" in out.lower()

    def test_incident_ticket_step(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "incident ticket" in out.lower() or "Create incident" in out

    def test_pentest_when_flag_set(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "penetration test" in out.lower() or "pentest" in out.lower()

    def test_post_incident_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "post-incident" in out.lower() or "debrief" in out.lower()


# ── Artifacts ─────────────────────────────────────────────────────────────

class TestArtifacts:
    def test_artifacts_heading(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Artifacts" in out

    def test_rule_sqli_001(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SQLI-001" in out

    def test_rule_sqli_002_post(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SQLI-002" in out

    def test_rule_sqli_003_error(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SQLI-003" in out

    def test_rule_sqli_004_union(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SQLI-004" in out

    def test_rule_sqli_005_blind(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SQLI-005" in out

    def test_rule_sqli_006_info_schema(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SQLI-006" in out

    def test_rule_sqli_007_db_error_spike(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "RULE-SQLI-007" in out

    def test_custom_detection_rule(self, template, minimal_ctx):
        ctx = {**minimal_ctx, "detection_rules": [
            {"id": "RULE-CUSTOM-99", "name": "Custom SQLi Rule",
             "source": "Zeek", "threshold": "any", "status": "✅ Active"}
        ]}
        out = render(template, **ctx)
        assert "RULE-CUSTOM-99" in out

    def test_log_source_waf(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "WAF" in out or "modsec" in out.lower()

    def test_log_source_db_error(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "DB Error" in out or "error.log" in out

    def test_log_source_db_slow_query(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "Slow Query" in out or "slow.log" in out

    def test_log_source_db_audit(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "DB Audit" in out or "db-audit" in out

    def test_siem_query_1_payload_detection(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "union.*select" in out or "UNION" in out

    def test_siem_query_2_db_error_spike(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=db-errors" in out

    def test_siem_query_3_blind_sqli(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "response_time" in out or "response_ms" in out

    def test_siem_query_4_union_select(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=waf-logs" in out

    def test_siem_query_5_post_compromise(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "index=db-audit" in out

    def test_evidence_paths_default(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "reports/incidents/sqli" in out
        assert "1.2.3.4" in out

    def test_evidence_paths_custom(self, template, full_ctx):
        out = render(template, **full_ctx)
        assert "/data/sqli/case100/" in out

    def test_evidence_binlog_path(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "binlog" in out

    def test_evidence_waf_audit_path(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "waf_audit" in out

    def test_evidence_source_code_review(self, template, minimal_ctx):
        out = render(template, **minimal_ctx)
        assert "source_code_review" in out


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
