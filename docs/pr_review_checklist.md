# PhantomNet – Pull Request Review Checklist

**Project:** PhantomNet  
**Applies From:** Week 5 onward  
**Mandatory:** YES (No PR is merged without this)

---

## 1. PR Metadata (Required)

- [ ] PR title is clear and descriptive
- [ ] PR description explains *what* and *why*
- [ ] Related issue(s) linked
- [ ] Correct milestone assigned
- [ ] Labels applied (backend / frontend / infra / docs)

---

## 2. Scope Control

- [ ] Changes are limited to the stated objective
- [ ] No unrelated refactors included
- [ ] No experimental or debug code committed
- [ ] No commented-out code left behind

---

## 3. Backend Review Checklist

### API & Logic
- [ ] No breaking API changes without documentation update
- [ ] New endpoints added to `docs/api_spec.md`
- [ ] Backend is single source of truth
- [ ] No business logic moved to frontend

### Database
- [ ] Schema changes reviewed explicitly
- [ ] Migrations or ALTER statements documented
- [ ] Index impact considered
- [ ] No data loss risk introduced

### Stability
- [ ] Server starts without errors
- [ ] Background services (sniffer, schedulers) unaffected
- [ ] Graceful shutdown confirmed

---

## 4. Frontend Review Checklist

- [ ] No mock data used
- [ ] All data fetched from backend APIs
- [ ] No threat recalculation on frontend
- [ ] Filters map exactly to backend fields
- [ ] No console errors or warnings
- [ ] Empty/error states handled cleanly

---

## 5. Security & Defensive Posture

- [ ] No hardcoded credentials or secrets
- [ ] No localhost blocking logic broken
- [ ] Firewall / honeypot logic reviewed carefully
- [ ] Input validation present where applicable

---

## 6. SMTP / Honeypot-Specific (If Applicable)

- [ ] Event schema followed (`smtp_event_schema.md`)
- [ ] Threat scoring logic documented
- [ ] No external mail forwarding
- [ ] Payload handling is safe (no execution)

---

## 7. Documentation

- [ ] README updated if behavior changes
- [ ] Architecture docs updated if needed
- [ ] New configs or env vars documented
- [ ] Diagrams updated (if topology changes)

---

## 8. Testing & Verification

- [ ] Manual testing performed
- [ ] Relevant API endpoints tested
- [ ] Logs reviewed for errors
- [ ] CI passes (if applicable)

---

## 9. Reviewer Sign-off

- [ ] Code readability approved
- [ ] Design decisions understood
- [ ] No hidden side effects
- [ ] Ready for merge

**Reviewer Name:**  
**Date:**  

---

## Merge Rule

> ❌ **PRs without this checklist completed must not be merged.**

This is a hard rule for PhantomNet.
