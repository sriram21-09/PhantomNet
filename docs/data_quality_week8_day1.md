week: 8
day: 1
title: Data Quality Audit Report

overview:
  description: >
    This report documents the audit and validation of attack data collected by
    PhantomNet honeypots. The objective is to verify log integrity, schema
    consistency, feature accuracy, and attack simulation behavior before
    proceeding to the next integration phase.

log_sources_reviewed:
  - honeypot: http
    log_file: http_logs.jsonl
    status: reviewed
  - honeypot: ssh
    log_file: ssh_async.jsonl
    status: reviewed
  - honeypot: ftp
    log_file: ftp_logs.jsonl
    status: reviewed
  - honeypot: smtp
    log_file: smtp_logs.jsonl
    status: reviewed

manual_event_inspection:
  total_events_reviewed: 50
  observations:
    http:
      findings:
        - Realistic web attack behavior observed (admin page access, login attempts)
        - Presence of favicon and browser-generated noise
        - Legacy logs use inconsistent field names (src_ip vs source_ip)
        - Mixed timestamp formats across historical data
      assessment: usable_with_normalization

    ssh:
      findings:
        - Clear authentication attempts and outcomes
        - Command execution events captured accurately
        - IPv4 and IPv6 source addresses observed
      assessment: detection_ready

    smtp:
      findings:
        - High-fidelity protocol interaction (HELO, MAIL FROM, DATA, QUIT)
        - Email payload content captured
        - Proper severity levels assigned
      assessment: high_quality

    ftp:
      findings:
        - Multiple JSON objects concatenated into a single line
        - Malformed JSON records detected
      assessment: data_integrity_issue

attack_simulation:
  task: ssh_reconnaissance
  tool_used: nmap
  command_executed: "nmap -p 2222 localhost"
  results:
    port_status: open
    service_detected: ssh
  observations:
    - Basic TCP port scan did not generate SSH honeypot logs
    - SSH honeypot logs only protocol-level SSH interactions
  conclusion: >
    The absence of logs for TCP-only scans is expected behavior and aligns with
    real-world SSH honeypot designs.

data_quality_issues_identified:
  - issue: http_schema_inconsistency
    description: Legacy HTTP logs contain inconsistent field naming and timestamps
    severity: medium

  - issue: ftp_log_corruption
    description: FTP logs contain concatenated JSON entries causing invalid records
    severity: high

  - issue: ssh_scan_visibility
    description: TCP-level reconnaissance does not trigger SSH honeypot logging
    severity: low
    note: expected_behavior

readiness_assessment:
  overall_status: ready_with_conditions
  conditions:
    - Normalize legacy HTTP logs
    - Correct FTP log writing mechanism
  conclusion: >
    PhantomNet successfully captures realistic multi-protocol attack data.
    With minor corrective handling, the system is ready for next-phase detection
    and integration work.
