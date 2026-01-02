# Honeypot Log Formats

## Common Fields
- timestamp (ISO 8601, UTC)
- source_ip
- honeypot_type
- event
- data
- level (INFO, WARN, ERROR)

## SSH Log Example
```json
{
  "timestamp": "2025-01-15T10:22:33+00:00",
  "source_ip": "127.0.0.1",
  "honeypot_type": "ssh",
  "event": "command",
  "data": { "cmd": "cat /etc/passwd" },
  "level": "WARN"
}

## HTTP Log Example

{
  "timestamp": "2025-01-15T10:25:01+00:00",
  "source_ip": "127.0.0.1",
  "honeypot_type": "http",
  "event": "login_attempt",
  "data": { "username": "admin' OR 1=1--" },
  "level": "WARN"
}


##FTP Log Example 

{
  "timestamp": "2025-01-15T10:30:12+00:00",
  "source_ip": "127.0.0.1",
  "honeypot_type": "ftp",
  "event": "command",
  "data": { "command": "LIST" },
  "level": "WARN"
}


