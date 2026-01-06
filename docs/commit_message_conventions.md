# PhantomNet – Commit Message Conventions

**Project:** PhantomNet  
**Effective From:** Week 5  
**Status:** Mandatory  
**Applies To:** All contributors, all branches

---

## 1. Why This Matters

Commit messages are part of PhantomNet’s **security posture**.

Clear commits allow:
- Fast incident debugging
- Reliable rollbacks
- Clean audits
- Accurate changelogs
- Strong engineering discipline

Poor commits are treated as **process violations**.

---

## 2. Mandatory Commit Format

```

<type>: <short, clear description>

```

### ✅ Valid Examples

```

feat: add SMTP honeypot event ingestion
fix: resolve traffic_stats column mismatch
docs: add SMTP event schema documentation
refactor: simplify stats aggregation logic
chore: update gitignore for venv files

```

### ❌ Invalid Examples

```

update
fix stuff
changes made
final commit
working now

```

---

## 3. Allowed Commit Types

| Type     | Usage                                   |
|----------|------------------------------------------|
| feat     | New feature or capability                |
| fix      | Bug fix                                  |
| docs     | Documentation only                       |
| refactor | Code change with no behavior change      |
| chore    | Tooling, config, housekeeping            |
| test     | Adding or modifying tests                |
| infra    | Infrastructure / Mininet / Docker        |
| security | Security-related changes                 |

---

## 4. Scope Rules (Strict)

- One logical change per commit
- Do **not** mix unrelated changes
- Large features must be split into multiple commits
- Docs-only changes must use `docs:` only

---

## 5. Message Style Rules

- Use present tense (“add”, not “added”)
- No emojis
- No trailing punctuation
- No ticket IDs unless required by milestone
- Maximum 72 characters recommended

---

## 6. Examples by Area

### Backend

```

fix: prevent duplicate event generation
feat: add SMTP honeypot listener
refactor: simplify packet classification logic

```

### Frontend

```

fix: align events page with backend schema
feat: add pagination to events table
docs: update frontend setup instructions

```

### Infrastructure / Mininet

```

infra: add 5-node PhantomNet mininet topology
infra: stabilize ovs switch startup

```

### Documentation

```

docs: update api specification
docs: add PR review checklist

```

---

## 7. Enforcement Rules

- PRs with invalid commit messages **must be rejected**
- Squash merges must preserve the commit type
- Maintainers may request rebase for cleanup
- CI may enforce commit linting in later phases

---

## 8. Future Enhancements

Planned:
- Commit lint automation
- Changelog generation from commit history
- Release notes automation

---

## Rule Statement

> ❌ **Any commit not following this convention is considered non-compliant.**

This rule is non-negotiable for PhantomNet.
```
