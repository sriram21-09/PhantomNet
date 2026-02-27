# Fully Automated Threat Response System

## Overview
The PhantomNet Automated Response System provides a proactive defense mechanism that automatically reacts to detected threats based on their severity and type. By integrating directly with the threat pipeline, it can neutralize attackers in real-time.

## Response Actions Matrix
The system follows a tiered response strategy:

| Threat Level | Actions | Description |
| :--- | :--- | :--- |
| **INFO** | LOG | Record the event for future analysis. |
| **WARNING** | LOG, ALERT | Notify security personnel via the Alert Manager. |
| **HIGH** | LOG, ALERT, BLOCK_IP | Neutralize the specific attacker by blocking their source IP. |
| **CRITICAL** | LOG, ALERT, BLOCK_IP, SCALE | Execute all actions plus deploy additional honeypot resources to absorb traffic. |

## Implementation Details

### IP Blocking
- **Linux**: Uses `iptables` to drop all incoming traffic from the malicious IP.
  - Command: `sudo iptables -A INPUT -s <IP> -j DROP`
- **Windows**: Uses `netsh advfirewall` to create a block rule.
  - Command: `netsh advfirewall firewall add rule name="PhantomNet_Block_<IP>" dir=in action=block remoteip=<IP>`

### Honeypot Scaling
When a `CRITICAL` threat is detected (e.g., a massive brute-force or multi-protocol attack), the system triggers horizontal scaling of the target honeypots to increase the attack surface and gather more intelligence.
- **Tool**: `docker-compose`
- **Action**: Increases the instance count of the relevant service to 2 (or more as configured).
- **Command**: `docker-compose up -d --scale <service>=2`

## Integration
The response system is integrated into the `AlertManager`. Whenever an alert is saved to the database, the `ResponseExecutor` is invoked to evaluate if additional defensive actions are required based on the alert level.

## Configuration
Policies can be adjusted in `backend/services/response_executor.py` via the `response_matrix` dictionary. Future versions will support dynamic policy loading from the database.
