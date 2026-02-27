# PhantomNet Attack Simulation Framework

**Date**: Week 9, Day 2
**Scope**: Validation of PhantomNet ML Detection Mechanisms via Mininet 3-Layer SD-N Topology

## 1. Executive Summary
An automated attack simulation framework (`simulation/attack_campaign.py`) was developed and executed to validate the detection algorithms of the PhantomNet Active Defense Platform. The script effectively simulates a multi-staged cyber attack including reconnaissance (scanning), exploitation (brute force), and persistence/payload delivery (APT).

## 2. Attack Simulation Methodology

The campaign utilizes the `h1` attacker node (IP `10.0.0.10`) targeting the honeypot DMZ node at the distribution layer of our 3-Layer topology.

### Stage 1: Reconnaissance (SYN/Connect Scan)
- **Target**: `10.0.2.31` (SSH), `10.0.2.30` (SMTP)
- **Action**: Sweeps ports 20-100 aggressively using multi-threading.
- **Expected Outcome**: Generates a massive volume of dropped packets or connection resets, triggering rate-limiting heuristics and high-frequency anomaly detection in the ML pipeline. 

### Stage 2: Initial Access (SSH Brute Force)
- **Target**: `10.0.2.31:2222`
- **Action**: Uses `paramiko` to attempt dictionary-based authentication using common weak credentials (`root`, `admin`, `ubuntu`, `guest`).
- **Expected Outcome**: Honeypot captures failed authentication attempts. Pattern recognition in ML should flag this series of events based on uniform temporal distribution and identical source IPs. 

### Stage 3: Data Exfiltration & APT Delivery (SMTP)
- **Target**: `10.0.2.30:2525`
- **Action**: Connects to the SMTP honeypot service and transmits an email containing the standard EICAR anti-virus test string along with simulated spam headers.
- **Expected Outcome**: Deep Packet Inspection (DPI) flags the known payload signature (EICAR) or NLP flags the anomalous email structure, marking the event with a massive `threat_score`. 

## 3. Validation Process
Unlike traditional attacks, this framework integrates an automated continuous validation loop:
1. Wait 10 seconds for Logstash parsing and ML endpoint scoring.
2. Query the main PhantomNet API: `GET http://10.0.3.40:8000/analyze-traffic`.
3. Evaluate the 50 most recent packet logs to ensure `ai_analysis.prediction` correctly evaluates to `"MALICIOUS"` and that the system appropriately scores the EICAR and SYN scan threats.

## 4. Run Instructions
To execute this framework in the PhantomNet environment:

```bash
# 1. Start the backend services (if not running)
docker compose up -d

# 2. Start the SD-N Topology (requires root)
sudo ./scripts/start_topology.sh

# 3. Inside the Mininet CLI, execute the attack script from the attacker node (h1)
mininet> h1 python3 simulation/attack_campaign.py
```

## 5. Next Steps
- Expand the simulation framework to include HTTP web application exploits (SQLi, XSS, Directory Traversal).
- Integrate automated metric generation to chart true-positive and false-positive rates of the ML model upon test execution.
