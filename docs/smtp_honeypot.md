
---

## 📘 4) SMTP Honeypot Documentation

### 📄 File: `docs/smtp_honeypot.md`

```md
# SMTP Honeypot – PhantomNet

### File location :- ' phantomnet/backend/honeypots/smtp/smtp_honeypot.py

## Purpose
The SMTP honeypot captures:
- Phishing attempts
- Spam campaigns
- Malicious email payloads

## Port
- Listens on configured SMTP port (e.g., 2525)

## Supported Commands
- HELO / EHLO
- MAIL FROM
- RCPT TO
- DATA
- QUIT

## Behavior
- Accepts all senders and recipients
- Captures full email body
- Does NOT relay emails

## Logged Fields
- timestamp
- honeypot_type: smtp
- source_ip
- helo_domain
- sender
- recipients
- email_content

## Example Attack
```bash
telnet localhost 2525
HELO evil.com
DATA
phishing content
.


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


Why This Matters :- 

Email is the #1 phishing vector.
SMTP honeypots are critical for SOC threat intelligence.