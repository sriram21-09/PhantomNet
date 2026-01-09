# SSH Honeypot Documentation

## File Location
backend/honeypots/ssh/async_ssh_honeypot.py

# SSH Honeypot – PhantomNet

## Purpose
The SSH honeypot simulates a real Linux SSH server to capture:
- Brute-force login attempts
- Credential guessing behavior
- Attacker command execution attempts

It is designed to **observe attackers**, not allow real system access.

## Port
- Listens on **port 2222**

## Technology Used
- asyncssh
- Python asyncio
- Central PhantomNet logger

## Behavior
- Accepts any username/password
- Always denies shell access
- Logs every authentication attempt
- Logs commands typed by attackers

## Logged Fields
- timestamp
- honeypot_type: ssh
- source_ip
- username
- password
- command (if any)
- event type (login_failed, command_attempt)

## Security Controls
- No real shell access
- No filesystem access
- Session auto-terminated

## Example Attack
```bash
ssh attacker@localhost -p 2222

Security Notes

No real OS access

No real filesystem access

Commands are simulated in memory

Why This Matters :- 

SSH brute-force attacks are one of the most common real-world attacks.
This honeypot helps SOC teams study attacker behavior safely.