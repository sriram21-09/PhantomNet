# Honeypots PhantomNet Architecture

## Overview
PhantomNet is a multi-protocol honeypot platform designed to simulate
real-world attack surfaces and capture attacker behavior for analysis.

The system deploys SSH, HTTP, and FTP honeypots in isolated Docker containers,
with centralized logging for forensic and SOC-style investigation.

## Components

### SSH Honeypot
- Protocol: SSH (AsyncSSH)
- Port: 2222
- Simulates a Linux shell
- Captures login attempts, commands, and attacker intent

### HTTP Honeypot
- Protocol: HTTP
- Port: 8080
- Simulates admin login portals
- Captures form submissions, SQL injection attempts, and method abuse

### FTP Honeypot
- Protocol: FTP
- Port: 2121
- Simulates file access attempts
- Captures login failures, LIST, RETR, and enumeration attempts

### Logging Layer
- JSONL structured logs
- One log file per honeypot
- Timestamped with UTC timezone

### Containerization
- Docker & Docker Compose
- Each honeypot runs in isolation
- Shared volumes for logs

## Design Goals
- Safe attacker interaction
- No real system compromise
- High-fidelity logging
- SOC-friendly analysis
