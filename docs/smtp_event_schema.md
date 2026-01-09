# PhantomNet – SMTP Event Schema

**Project:** PhantomNet  
**Phase:** Month 2 (SMTP Honeypot Introduction)  
**Status:** Specification Approved  
**Applies To:** SMTP Honeypot, Events Pipeline, SOC Dashboard

---

## 1. Purpose

This document defines the **canonical event schema** for all SMTP honeypot–generated events in PhantomNet.

The schema ensures:
- Consistent ingestion
- Accurate threat classification
- Reliable SOC visualization
- Future correlation with other honeypots (SSH, FTP, HTTP)

---

## 2. Event Source

| Attribute        | Value                         |
|------------------|-------------------------------|
| Source System    | SMTP Honeypot                 |
| Protocol         | SMTP                          |
| Transport        | TCP                           |
| Default Port     | 25                            |
| Additional Ports | 587, 465 (future monitoring) |
| Deployment       | Mininet / Real host           |

---

## 3. Event Lifecycle

```

SMTP Connection
↓
Command Sequence Captured
↓
Threat Scoring
↓
Event Normalization
↓
Stored as Security Event
↓
Visible in /api/events

````

---

## 4. Core Event Schema (Logical)

This is the **logical representation** of an SMTP event before storage.

```json
{
  "timestamp": "2026-01-05T14:22:11Z",
  "source_ip": "203.0.113.45",
  "destination_ip": "10.0.2.30",
  "protocol": "SMTP",
  "port": 25,
  "smtp_commands": [
    "HELO attacker.com",
    "MAIL FROM:<spam@evil.com>",
    "RCPT TO:<admin@target.com>"
  ],
  "payload_snippet": "Subject: Cheap meds",
  "honeypot_type": "SMTP",
  "threat_score": 72,
  "threat_level": "MALICIOUS",
  "classification_reason": "Spam relay behavior detected"
}
````

---

## 5. Field Definitions

### 5.1 Network Fields

| Field          | Type            | Required | Description         |
| -------------- | --------------- | -------- | ------------------- |
| timestamp      | ISO-8601 string | ✅        | Event creation time |
| source_ip      | string          | ✅        | Attacker IP         |
| destination_ip | string          | ✅        | Honeypot IP         |
| protocol       | string          | ✅        | Always SMTP         |
| port           | integer         | ✅        | Typically 25        |

---

### 5.2 SMTP-Specific Fields

| Field           | Type          | Required | Description           |
| --------------- | ------------- | -------- | --------------------- |
| smtp_commands   | array[string] | ✅        | Ordered SMTP commands |
| payload_snippet | string        | ❌        | Partial DATA content  |
| honeypot_type   | string        | ✅        | Always SMTP           |

---

### 5.3 Detection Fields

| Field                 | Type            | Required | Description                     |
| --------------------- | --------------- | -------- | ------------------------------- |
| threat_score          | integer (0–100) | ✅        | Numeric risk score              |
| threat_level          | string          | ✅        | BENIGN | SUSPICIOUS | MALICIOUS |
| classification_reason | string          | ✅        | Human-readable reason           |

---

## 6. Threat Level Mapping Rules

| Condition               | Threat Level |
| ----------------------- | ------------ |
| HELO only, no MAIL      | BENIGN       |
| MAIL FROM + RCPT TO     | SUSPICIOUS   |
| DATA command observed   | MALICIOUS    |
| Known spam patterns     | MALICIOUS    |
| High-frequency attempts | MALICIOUS    |

---

## 7. Database Mapping

### 7.1 packet_logs (Primary Storage)

| packet_logs Column | SMTP Field     |
| ------------------ | -------------- |
| timestamp          | timestamp      |
| src_ip             | source_ip      |
| dst_ip             | destination_ip |
| protocol           | "SMTP"         |
| length             | payload size   |
| is_malicious       | derived        |
| threat_score       | threat_score   |
| attack_type        | "SMTP"         |

---

### 7.2 events (Normalized Events)

| events Column | SMTP Field              |
| ------------- | ----------------------- |
| timestamp     | timestamp               |
| source_ip     | source_ip               |
| honeypot_type | "SMTP"                  |
| port          | port                    |
| raw_data      | smtp_commands + payload |
| threat_score  | threat_score            |

---

## 8. Example Events

### BENIGN

```json
{
  "source_ip": "198.51.100.10",
  "smtp_commands": ["HELO test.com"],
  "threat_level": "BENIGN"
}
```

### SUSPICIOUS

```json
{
  "smtp_commands": [
    "HELO evil.com",
    "MAIL FROM:<a@b.com>"
  ],
  "threat_level": "SUSPICIOUS"
}
```

### MALICIOUS

```json
{
  "smtp_commands": [
    "HELO spammer.com",
    "MAIL FROM:<spam@evil.com>",
    "RCPT TO:<admin@target.com>",
    "DATA"
  ],
  "threat_level": "MALICIOUS"
}
```

---

## 9. Explicit Non-Goals (Current Phase)

* Full email storage
* Attachment capture
* Malware detonation
* SMTP relay forwarding
* External mail delivery

---

## 10. Future Extensions

Planned additions:

* DKIM / SPF analysis
* Spam campaign correlation
* Attachment hash extraction
* Cross-honeypot attacker profiling

---

