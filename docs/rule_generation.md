# Sentinel Rule Generation Documentation

## Overview
The PhantomNet Sentinel pipeline dynamically translates raw attacker traffic captured by honeypot instances into actionable, production-ready SIEM detection rules. The `rule_generator.py` module handles the transformation of MITRE ATT&CK mappings, incident payloads, and event clusters into standard **Snort** and **Sigma** rule formats. 

These rules are embedded into the generated Playbooks, enabling analysts to rapidly deploy network blocks and SIEM alerting logic.

---

## Snort Rule Generation

The system generates Snort rules compliant with Snort 2.9/3.0 syntax. These rules are designed to be deployed at the network perimeter (NIDS/IPS) to detect or block repeat activity.

### Rule Format
The baseline rule structure utilizes the following template:

```snort
alert {protocol} {src_ip} any -> $HOME_NET {dst_port} (msg:"{attack_desc}"; flow:to_server,established; threshold:type limit, track by_src, count 5, seconds 60; classtype:{classtype}; priority:{priority}; reference:url,attack.mitre.org/techniques/{technique_id}; sid:{sid}; rev:1;)
```

### Components
*   **Protocol**: Extracted from the `PacketLog` (TCP, UDP, ICMP).
*   **Network Addressing**: Triggers on traffic from the specific attacker `src_ip` aiming at any port traversing into the `$HOME_NET` specifically hitting the `dst_port` the attacker targeted.
*   **`msg`**: The attack description (`attack_desc`) dynamically generated from the campaign ID, source IP, target port, and MITRE Technique Name. Special characters (e.g., quotes, semicolons) are properly escaped.
*   **`flow`**: Hardcoded to `to_server,established` to ensure stateful tracking.
*   **`threshold`**: Hardcoded to `type limit, track by_src, count 5, seconds 60` to prevent alert flooding.
*   **`classtype`**: Mapped dynamically from the internal `attack_type` (e.g., `sqli_attempt` -> `web-application-attack`).
*   **`reference`**: Maps directly to the MITRE ATT&CK framework URL (`attack.mitre.org/techniques/{technique_id}`).
*   **`sid` (Snort ID)**: An auto-incrementing integer identifier.

### SID Auto-Increment Mechanism and Persistence
To prevent SID collisions across pipeline restarts and distributed generation:
1.  **Base SID**: Rule generation starts at SID `1000001`.
2.  **Persistence**: The current SID counter is stored on disk in `data/last_sid.txt`.
3.  **Thread Safety**: A `threading.Lock()` encapsulates the SID incrementer. When a rule is requested, the application locks the thread, assigns the current `_NEXT_SID`, increments the counter, flushes the new value to `last_sid.txt`, and releases the lock. 
4.  **Resilience**: If the file is corrupted or missing, the generator gracefully falls back to the Base SID of `1000001`.

---

## Sigma Rule Generation

The system generates YAML-formatted Sigma rules designed to be translated into queries for specific SIEM platforms (Splunk, Elastic, QRadar, etc.).

### Rule Format
```yaml
title: Campaign CAMP-123 Detection for Brute Force
status: experimental
logsource:
  category: network_traffic
  product: phantomnet
detection:
  selection:
    src_ip:
    - 192.168.1.100
    dst_port:
    - 2222
    protocol:
    - tcp
  condition: selection
level: high
tags:
- attack.t1110.001
- attack.credential_access
```

### Components
*   **`title`**: Descriptive title generated dynamically incorporating the Campaign ID and MITRE Technique name.
*   **`status`**: Defaulted to `experimental`.
*   **`logsource`**: Bound to `category: network_traffic` and `product: phantomnet` to allow SIEMs to filter appropriately.
*   **`detection`**: Automatically constructed `selection` block mapping to the observed `src_ip`, `dst_port`, and `protocol`.
*   **`level`**: Severity rating.
*   **`tags`**: Essential for SIEM categorization. Auto-injected to include both the specific technique ID (`attack.t1110.001`) and the parent MITRE tactic category (`attack.credential_access`).

---

## Internal Mapping Logic

### Attack Signature to Rule Content (`attack_desc`)
When the Signature Engine detects an attack (e.g., `SSH_AUTH_FAILURE`), the MITRE Mapper links it to a Technique Name (e.g., "Brute Force: Password Guessing").
The `attack_desc` mapped to the Snort `msg` field is dynamically structured via an f-string:
`Campaign {campaign_id} activity from {src_ip} targeting port {dst_port}: {technique_name}`

Example: `msg:"Campaign CAMP-001 activity from 192.168.1.50 targeting port 22: Brute Force: Password Guessing";`

### Severity to Priority Mapping
Sentinel leverages a centralized Severity architecture (CRITICAL, HIGH, MEDIUM, LOW) which must be translated into Snort's 1-4 Priority system and Sigma's level nomenclature.

| Sentinel Severity | Snort Priority | Sigma Level |
| :--- | :--- | :--- |
| **CRITICAL** | `1` | `critical` |
| **HIGH** | `2` | `high` |
| **MEDIUM** | `3` | `medium` |
| **LOW** | `4` | `low` |
| **INFO** | `4` | `low` |

---

## Example Rules for Primary Attack Patterns

### 1. SSH Brute Force
**Snort:**
```snort
alert tcp 192.168.10.50 any -> $HOME_NET 2222 (msg:"Campaign CAMP-001 activity from 192.168.10.50 targeting port 2222: Brute Force: Password Guessing"; flow:to_server,established; threshold:type limit, track by_src, count 5, seconds 60; classtype:attempted-admin; priority:2; reference:url,attack.mitre.org/techniques/T1110/001/; sid:1000001; rev:1;)
```
**Sigma:**
```yaml
title: Campaign CAMP-001 Detection for Brute Force: Password Guessing
status: experimental
logsource:
  category: network_traffic
  product: phantomnet
detection:
  selection:
    src_ip:
    - 192.168.10.50
    dst_port:
    - 2222
    protocol:
    - tcp
  condition: selection
level: high
tags:
- attack.t1110.001
- attack.credential_access
```

### 2. HTTP SQL Injection (SQLi)
**Snort:**
```snort
alert tcp 10.0.5.101 any -> $HOME_NET 8080 (msg:"Campaign CAMP-002 activity from 10.0.5.101 targeting port 8080: Exploit Public-Facing Application"; flow:to_server,established; threshold:type limit, track by_src, count 5, seconds 60; classtype:web-application-attack; priority:1; reference:url,attack.mitre.org/techniques/T1190/; sid:1000002; rev:1;)
```
**Sigma:**
```yaml
title: Campaign CAMP-002 Detection for Exploit Public-Facing Application
status: experimental
logsource:
  category: network_traffic
  product: phantomnet
detection:
  selection:
    src_ip:
    - 10.0.5.101
    dst_port:
    - 8080
    protocol:
    - tcp
  condition: selection
level: critical
tags:
- attack.t1190
- attack.initial_access
```

### 3. Network Port Scan
**Snort:**
```snort
alert tcp 172.16.20.200 any -> $HOME_NET 80 (msg:"Campaign CAMP-003 activity from 172.16.20.200 targeting port 80: Network Service Discovery"; flow:to_server,established; threshold:type limit, track by_src, count 5, seconds 60; classtype:attempted-recon; priority:4; reference:url,attack.mitre.org/techniques/T1046/; sid:1000003; rev:1;)
```
**Sigma:**
```yaml
title: Campaign CAMP-003 Detection for Network Service Discovery
status: experimental
logsource:
  category: network_traffic
  product: phantomnet
detection:
  selection:
    src_ip:
    - 172.16.20.200
    dst_port:
    - 21
    - 22
    - 80
    - 443
    protocol:
    - tcp
  condition: selection
level: low
tags:
- attack.t1046
- attack.discovery
```

### 4. FTP Data Exfiltration
**Snort:**
```snort
alert tcp 203.0.113.15 any -> $HOME_NET 21 (msg:"Campaign CAMP-004 activity from 203.0.113.15 targeting port 21: Exfiltration Over Unencrypted Non-C2 Protocol"; flow:to_server,established; threshold:type limit, track by_src, count 5, seconds 60; classtype:successful-admin; priority:1; reference:url,attack.mitre.org/techniques/T1048/003/; sid:1000004; rev:1;)
```
**Sigma:**
```yaml
title: Campaign CAMP-004 Detection for Exfiltration Over Unencrypted Non-C2 Protocol
status: experimental
logsource:
  category: network_traffic
  product: phantomnet
detection:
  selection:
    src_ip:
    - 203.0.113.15
    dst_port:
    - 21
    protocol:
    - tcp
  condition: selection
level: critical
tags:
- attack.t1048.003
- attack.exfiltration
```
