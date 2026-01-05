# SMTP Protocol Reference (RFC 5321)

## 1. What is SMTP?
SMTP (Simple Mail Transfer Protocol) is used to send emails between mail servers.
It operates over TCP and follows a command-response model.

Default ports:
- 25   → Server-to-server mail transfer
- 587  → Mail submission (authenticated)
- 465  → SMTPS (encrypted, legacy)

---

## 2. SMTP Communication Flow

1. Client connects to SMTP server
2. Server responds with greeting (220)
3. Client identifies itself (HELO/EHLO)
4. Mail sender specified (MAIL FROM)
5. Recipient specified (RCPT TO)
6. Message body sent (DATA)
7. Session closed (QUIT)

---

## 3. SMTP Commands

| Command | Description |
|-------|-------------|
| HELO | Identify sending host |
| EHLO | Extended HELO (ESMTP) |
| MAIL FROM | Specify sender address |
| RCPT TO | Specify recipient |
| DATA | Begin email content |
| RSET | Reset session |
| VRFY | Verify mailbox (often disabled) |
| EXPN | Expand mailing list |
| NOOP | No operation |
| QUIT | Close session |

---

## 4. SMTP Response Codes

| Code | Meaning |
|----|--------|
| 220 | Service ready |
| 250 | Requested action completed |
| 354 | Start mail input |
| 421 | Service unavailable |
| 450 | Mailbox unavailable |
| 550 | Mailbox not found / access denied |
| 554 | Transaction failed |

---

## 5. SMTP Example Session

Client:
HELO attacker.com

Server:
250 Hello attacker.com

Client:
MAIL FROM:<attacker@evil.com>

Server:
250 OK

Client:
RCPT TO:<admin@target.com>

Server:
550 No such user

---

## 6. SMTP Honeypot Design Goals

- Capture spam attempts
- Capture phishing payloads
- Log sender, recipient, headers, body
- Do NOT relay real emails
- Prevent abuse

---

## 7. Planned SMTP Honeypot Architecture

- Python socket-based server
- Listen on configurable ports
- Fake SMTP banner
- Accept commands
- Log every step
- Reject delivery safely

---

## 8. Logging Format (JSON)

Example log:
```json
{
  "timestamp": "2026-01-05T10:15:30Z",
  "source_ip": "192.168.1.50",
  "honeypot_type": "smtp",
  "event": "mail_from",
  "data": {
    "from": "attacker@evil.com"
  },
  "level": "WARN"
}
