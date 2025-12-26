# SSH Honeypot Documentation

## File Location
backend/honeypots/ssh/async_ssh_honeypot.py

---

## Purpose
The SSH honeypot simulates a real Linux SSH server to:
- Capture brute-force login attempts
- Monitor attacker shell activity
- Log commands without giving real system access

---

## Authentication Behaviour
- Password-based authentication
- Limited connections per IP
- Session timeout enforced

### Logged Events
- login_attempt (WARN)
- login_success (INFO)
- login_failed (ERROR)

---

## Shell Simulation
After successful login, attackers are dropped into a fake shell.

### Supported Commands
ls, pwd, cd, mkdir, touch, rm, cat  
whoami, uname -a, id  
exit, logout

Unsupported commands return:
bash: <command>: command not found


---

## Logging Example
```json
{
  "timestamp": "2025-01-01T10:22:11Z",
  "source_ip": "192.168.1.10",
  "honeypot_type": "ssh",
  "event": "command",
  "data": { "cmd": "ls" },
  "level": "INFO"
}

Security Notes

No real OS access

No real filesystem access

Commands are simulated in memory