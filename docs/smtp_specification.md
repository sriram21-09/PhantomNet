# 📧 PhantomNet — SMTP Honeypot Specification

**Project:** PhantomNet  
**Phase:** Month 2 (Weeks 5–8)  
**Component:** SMTP Honeypot  
**Status:** Specification Frozen  
**Last Updated:** 2026-01-05

---

## 1️⃣ Purpose & Scope

### Purpose
The SMTP honeypot is designed to:
- Attract and interact with malicious SMTP traffic
- Capture attacker intent at the **protocol level**
- Generate **high-signal security events**
- Feed events into PhantomNet’s existing backend pipeline

### Scope
- Semi-interactive SMTP deception service
- Observational only (no real mail delivery)
- Backend-integrated event generation

### Out of Scope
- Real mail delivery
- Open relay functionality
- Full RFC-complete SMTP implementation
- Authentication or encryption support

---

## 2️⃣ Interaction Level

### Selected Mode
**Semi-Interactive SMTP Honeypot**

### Rationale
- Encourages attacker engagement
- Low operational risk
- Simple to implement and verify
- Ideal for SOC-style detection workflows

---

## 3️⃣ Supported SMTP Commands

### Accepted Commands
The honeypot must accept and respond to the following commands:

| Command | Behavior |
|-------|---------|
| HELO / EHLO | Accept and log client identifier |
| MAIL FROM | Accept and log sender address |
| RCPT TO | Accept any recipient |
| DATA | Accept message payload |
| RSET | Reset fake session state |
| NOOP | Respond OK |
| QUIT | Cleanly close session |

### Unsupported / Restricted Commands

| Command | Behavior |
|--------|---------|
| AUTH | Respond with failure |
| STARTTLS | Reject |
| Unknown | Respond with `500` error |

**Rule:** The server must never crash, hang, or expose honeypot internals.

---

## 4️⃣ Server Banner & Responses

### SMTP Banner
220 mail.phantomnet.local ESMTP Postfix


### Deception Strategy
- Appear permissive
- Encourage session continuation
- Avoid revealing honeypot nature

### Example Session Flow


EHLO attacker.com → 250-mail.phantomnet.local
MAIL FROM:spam@x.com
 → 250 OK
RCPT TO:victim@y.com
 → 250 Accepted
DATA → 354 End data with <CR><LF>.<CR><LF>
<message body> → 250 Message queued
QUIT → 221 Bye


---

## 5️⃣ Suspicious & Malicious Behavior Indicators

### Suspicious Indicators
- Multiple `RCPT TO` commands
- Large DATA payloads
- Invalid sender or recipient domains
- Rapid command execution
- Repeated connections from same IP

### Malicious Indicators
- Open relay attempts
- Bulk recipient injection
- Spam-like payload content
- Known malicious IPs
- Scripted SMTP behavior patterns

---

## 6️⃣ Threat Scoring Inputs

The SMTP honeypot provides **signals**, not final verdicts.

### Scoring Inputs

| Signal | Weight |
|------|-------|
| Command frequency | Medium |
| DATA payload size | High |
| Recipient count | High |
| Payload content patterns | High |
| Source IP reputation | High |
| Session duration | Low |

### Output
- Numeric `threat_score`
- Mapped by backend to:
  - `BENIGN`
  - `SUSPICIOUS`
  - `MALICIOUS`

---

## 7️⃣ Logging Schema

### SMTP Session Log Fields
Each SMTP session must capture:

- `timestamp`
- `source_ip`
- `source_port`
- `helo_name`
- `mail_from`
- `rcpt_to` (list)
- `command_sequence`
- `data_size`
- `payload_hash`
- `session_duration`
- `threat_score`

Payloads must **never** be stored in raw form.

---

## 8️⃣ Event Generation Rules

### Event Creation Conditions
- At end of SMTP session  
**OR**
- When malicious threshold is crossed mid-session

### Event Mapping (PhantomNet)

| Field | Value |
|-----|------|
| timestamp | Event creation time |
| source_ip | Attacker IP |
| honeypot_type | `SMTP` |
| port | `25` |
| raw_data | Summarized SMTP session |
| threat_score | Calculated score |

**Rule:** One SMTP session produces **one event**.

---

## 9️⃣ Backend & Database Integration

### Integration Rules
- SMTP honeypot does **not** write directly to the database
- All persistence handled by existing backend services
- No schema duplication

### Data Flow


SMTP Honeypot → Backend API → events table


---

## 🔐 10️⃣ Security & Safety Constraints

Mandatory safety rules:

- No outbound email delivery
- No real relay behavior
- No file writes from payloads
- No shell or system execution
- Store payloads as hashes only

---

## 11️⃣ Success Criteria

This specification is considered **successfully implemented** when:

- SMTP behavior matches this document
- All listed commands handled correctly
- Logs match defined schema
- Events generated correctly
- Backend pipeline remains stable
- No regressions in Month 1 functionality

---

## 📌 Status

**Specification Status:** Final  
**Next Phase:** Mininet Topology Design (Phase 4)
