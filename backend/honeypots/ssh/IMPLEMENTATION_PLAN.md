# SSH Honeypot – Implementation Plan (Week 2 Day 1)

## Objective
Prepare a clear implementation plan for a functional SSH honeypot using AsyncSSH.

---

## 1. Review Existing SSH Honeypot

Current SSH honeypot:
- Listens on port 2222
- Accepts client connections
- Captures username and password attempts
- Logs activity in JSONL format
- Simulates a fake shell
- Handles broken connections

Limitations:
- Not a real SSH protocol implementation
- No real SSH key exchange
- Limited realism for attackers

---

## 2. SSH Library Choice

Chosen library: **AsyncSSH**

Reason:
- Implements real SSH protocol
- Handles malformed SSH packets safely
- Async and scalable
- Suitable for high-interaction honeypots
- Widely used in security research

---

## 3. Captured Data Fields

Each SSH interaction will capture:

### Connection Info
- timestamp
- source_ip
- source_port
- destination_port

### Authentication Data
- username
- password
- authentication_status (attempt / success / failure)

### Session Activity
- executed_command
- session_id
- command_timestamp

### Metadata
- honeypot_type = "ssh"
- ssh_protocol_version

---

## 4. Logging and Database Plan

Logging:
- JSON Lines format (.jsonl)
- Append-only logging
- One event per line

Log files:
- logs/ssh_async.jsonl
- logs/ssh_async_error.log

Database (planned):
- PostgreSQL
- Logs ingested using a separate ingestor script
- Honeypot will NOT directly connect to the database

Reason:
- Prevent honeypot crashes due to DB issues
- Cleaner architecture
- Easier scaling

---

## 5. Test Strategy

Manual Testing:
- Connect via ssh from localhost
- Try multiple usernames and passwords
- Verify logs are created

Error Testing:
- Abrupt client disconnect
- Invalid SSH clients
- Broken pipe errors

Verification:
- Honeypot continues running
- Errors logged safely
- No crashes

---

## Deliverable Checklist

- [x] SSH library selected (AsyncSSH)
- [x] Captured fields defined
- [x] Logging strategy finalized
- [x] Database ingestion planned
- [x] Test strategy documented
