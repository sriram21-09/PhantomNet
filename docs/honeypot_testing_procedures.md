
---

## 📘 5) Testing Procedures (VERY IMPORTANT)

### 📄 File: `docs/testing_procedures.md`

```md
# PhantomNet Testing Procedures

## SSH Testing
- Attempt multiple logins
- Verify connection closes
- Check logs for each attempt

## HTTP Testing
- Access /admin via GET
- Submit fake credentials via POST
- Test unsupported methods (PATCH, DELETE)

## FTP Testing
- Login with valid credentials
- Attempt LIST (expect abort)
- Attempt RETR (expect denial)

## SMTP Testing
- Send test email via telnet
- Confirm DATA is logged
- Ensure no email delivery occurs

## Validation Criteria
- No container crashes
- Logs generated for every action
- No real data exposure
