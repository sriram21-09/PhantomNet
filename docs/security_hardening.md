# PhantomNet Security Hardening Guide

## Overview
This document outlines the security measures implemented in PhantomNet to protect against common vulnerabilities and ensure a robust security posture.

## 1. Container Security
### Non-Root Users
- **API Container**: Configured to run as a non-root user (`phantom`, uid=1000) to prevent privilege escalation attacks.
- **Frontend Container**: Switched to `nginxinc/nginx-unprivileged` to avoid running Nginx as root.

### Least Privilege
- **File Ownership**: Application files are owned by the non-root user.
- **Port Usage**: Containers listen on high ports (e.g., 8080) to avoid requiring root privileges to bind to standard ports.

## 2. Credential Management
### Environment Variables
- **SSH Honeypot**: Hardcoded database credentials have been removed. The service now reads `DB_NAME`, `DB_USER`, `DB_PASSWORD`, and `DB_HOST` from environment variables.
- **Docker Compose**: Credentials are passed to containers via the `environment` section in `docker-compose.yml`. In a production environment, these should be sourced from a `.env` file or a secret manager.

## 3. Logging & Monitoring
- **Structured Logging**: Replaced `print` statements with Python's `logging` module in `ssh_server.py` to ensure proper log levels and formats.
- **Sensitive Data**: Logs are reviewed to ensure no sensitive information (passwords, keys) is written to plain text logs, except for the deliberate capture of attacker credentials in the honeypot database.

## 4. Network Security
- **Isolation**: Database is only accessible to backend services and honeypots within the Docker network.
- **Firewall**: The application relies on Docker's internal network isolation. External access is limited to specific exposed ports.

## 5. Future Recommendations
- **Secret Management**: Implement a dedicated secret manager (e.g., HashiCorp Vault) for production.
- **HTTPS**: Enable TLS/SSL for all services.
- **Network Policies**: Implement strict network policies to further isolate honeypots from the core application.
- **Regular Scanning**: Integrate automated vulnerability scanning (e.g., Trivy, Grype) into the CI/CD pipeline.
