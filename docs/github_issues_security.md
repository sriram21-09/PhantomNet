# GitHub Issues - Security Audit Week 10

## [Issue #101] [SECURITY] Update Vulnerable Frontend Dependencies (P1)
**Description**: `npm audit` identified high-severity vulnerabilities in development dependencies (`vite`, `storybook`, `nanoid`).
**Priority**: High
**Remediation**: Run `npm update` and verify compatibility with the current frontend-dev build.

## [Issue #102] [SECURITY] Implement Secure Vault for Log Signing Key (P2)
**Description**: The `LOG_SIGNING_KEY` is currently retrieved from environment variables with a hardcoded fallback in `logger.py`.
**Priority**: Medium
**Remediation**: Integrate with a secrets management service (e.g., HashiCorp Vault, AWS Secrets Manager) for dynamic key retrieval.

## [Issue #103] [SECURITY] Expand RBAC to Fine-Grained Permissions (P2)
**Description**: Current management API uses a single API Key for all administrative actions.
**Priority**: Medium
**Remediation**: Implement Role-Based Access Control (RBAC) with scopes (e.g., `nodes:read`, `policies:write`) to follow the principle of least privilege.

## [Issue #104] [SECURITY] Implement API Rate Limiting (P2)
**Description**: Management endpoints are vulnerable to brute force or DoS without explicit rate limiting.
**Priority**: Medium
**Remediation**: Add `slowapi` or similar FastAPI middleware to limit requests per IP/Key.
