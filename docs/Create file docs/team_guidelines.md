# PhantomNet Team Guidelines

## Branch Strategy

- `main` → Stable only (reviewed, tested, ready to demo)
- `develop` → Integration branch for features that passed basic tests
- `feature/<name>` → All new work (one feature or fix per branch)

Examples:

- `feature/ssh-honeypot-handler`
- `feature/http-log-ingestor`
- `feature/dashboard-events-table`

---

## Commit Messages

**Format:**

`type: short description`

Where `type` is one of:

- `feat` → new feature
- `fix` → bug fix
- `docs` → documentation only
- `refactor` → code change without new feature
- `chore` → tooling, config, or minor cleanup
- `test` → adding or updating tests

**Examples:**

- `feat: add ssh honeypot handler`
- `fix: correct log ingestion bug`
- `docs: update setup instructions`
- `refactor: simplify event parsing logic`
- `test: add unit tests for /logs endpoint`

---

## Pull Requests

- One feature or logical change per PR  
- PR must be **small and focused** (easier to review)  
- Must pass CI (GitHub Actions) before review  
- Must be reviewed by **Team Lead** (or delegate) before merge  
- PR description should include:
  - What was changed
  - How it was tested
  - Any screenshots (for frontend)

---

## Coding Standards

- **Python:**
  - Follow PEP8 style
  - Use type hints where reasonable
  - Keep functions short and focused
- **React:**
  - Functional components only
  - Use hooks (`useState`, `useEffect`, etc.)
  - Keep components small and reusable
- **Security:**
  - No secrets (passwords, tokens, keys) in repo
  - Use `.env` files locally (never commit them)
- **General:**
  - Meaningful variable and function names
  - Add docstrings/comments for non-obvious logic

---

## Communication

- Daily standup (10 minutes) on Discord:
  - What you did yesterday
  - What you will do today
  - Any blockers
- Blockers must be reported **immediately** in the team channel  
- Use GitHub Issues for:
  - Bugs
  - Feature requests
  - Technical debt
- Major decisions (architecture, tech changes) should be written in:
  - `docs/` (design notes) or
  - GitHub Wiki page
