# Incident Response Playbook Framework

## Overview
PhantomNet's Incident Response Playbook system provides an automated way to respond to security threats. It uses a YAML-based execution engine to perform predefined actions when specific triggers are met.

## Core Concepts
- **Trigger**: A condition that initiates the playbook (e.g., "failed_logins > 20").
- **Actions**: Automated steps performed by the engine (e.g., "block_ip", "send_alert").
- **Decision Points**: Logical branching (if-then-else) to handle different scenarios.
- **Notifications**: Alerts sent to administrators via Slack or Email.
- **Documentation**: Automatic logging of all actions and outcomes.
- **Rollback**: Capability to revert actions if needed.

## Playbook Structure (YAML)
```yaml
name: "Brute Force Response"
description: "Handles brute force login attempts"
trigger:
  type: "event"
  condition: "failed_logins > 20"
  timeframe: "300s"

actions:
  - name: "block_ip"
    type: "firewall"
    params:
      ip: "${attacker_ip}"
      duration: "3600s"
    rollback: "unblock_ip"

  - name: "tarpit"
    type: "network"
    params:
      ip: "${attacker_ip}"
      delay: "5000ms"

  - name: "alert_admin"
    type: "notification"
    params:
      channel: "slack"
      message: "Brute force attack detected from ${attacker_ip}"

  - name: "query_threat_intel"
    type: "external_api"
    params:
      api: "virustotal"
      target: "${attacker_ip}"

  - name: "create_ticket"
    type: "ticketing"
    params:
      system: "jira"
      summary: "Incident: Brute Force Attack"
      description: "Detected ${failed_logins} failed logins from ${attacker_ip}"

decision_points:
  - condition: "${threat_score} > 7"
    then:
      - name: "isolate_host"
        type: "network"
        params:
          host: "${target_host}"
    else:
      - name: "log_incident"
        type: "logging"
        params:
          level: "INFO"
          message: "Moderate threat detected, monitoring continued."
```

## Supported Actions
| Action | Type | Description |
|--------|------|-------------|
| `block_ip` | `firewall` | Blocks an IP address via the firewall API. |
| `send_alert` | `notification` | Sends an alert via Email or Slack. |
| `deploy_honeypot` | `docker` | Dynamically deploys a new honeypot instance. |
| `query_threat_intel`| `external_api`| Queries external services (e.g., VT, AlienVault). |
| `create_ticket` | `ticketing` | Creates a ticket in Jira or ServiceNow. |
| `isolate_host` | `network` | Isolates a compromised host from the network. |

## Rollback Capability
Each action can define a `rollback` step. The engine tracks the state of execution and can execute rollback steps in reverse order if a critical failure occurs or if manually triggered.
