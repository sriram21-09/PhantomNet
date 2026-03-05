# Secrets Rotation Procedures

This document outlines the standard operating procedures (SOP) for rotating sensitive credentials within the PhantomNet platform.

## 1. Database Passwords (Monthly)
**Target**: `POSTGRES_PASSWORD`

### Procedure
1. **Generate New Password**: Generate a 32-character random string.
2. **Update Database**: Execute `ALTER USER postgres WITH PASSWORD 'new_password';` within the PostgreSQL container.
3. **Update Environment**:
    - Update the `.env` file in the production environment.
    - If using Docker Swarm, update the `db_password` secret: 
      `printf "new_password" | docker secret create db_password_v2 -`
4. **Redeploy**: Restart the `api` and `honeypot` services to pick up the new secret.
    - `docker-compose up -d --force-recreate api ssh_honeypot http_honeypot ftp_honeypot smtp_honeypot`
5. **Verify**: Check `api` health endpoint `/health` to ensure DB connectivity.

## 2. API Keys (Quarterly)
**Target**: `API_KEY` (Threat Intel, SIEM)

### Procedure
1. **Update External Providers**: Log in to provider consoles (e.g., AlienVault, VirusTotal) and generate new keys.
2. **Overlap Period**: Keep the old key active if the provider supports multiple keys to ensure zero downtime.
3. **Update Environment**: Update `API_KEY` in the production environment variables.
4. **Rotate**: Once all services are running with the new key, revoke the old key from the provider console.

## 3. JWT Signing Keys (Quarterly)
**Target**: `JWT_SECRET`

### Procedure
1. **Generate**: `openssl rand -base64 48`
2. **Deploy**: Update `JWT_SECRET` in environment.
3. **Impact**: All users will be logged out and must re-authenticate. Perform this during off-peak hours.

## 4. Encryption Keys (Bi-Anually)
**Target**: Data-at-rest encryption keys.

### Procedure
1. Follow the re-encryption utility documentation to cycle keys without data loss.
