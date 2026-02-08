# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in haveibeenclawned (the audit script or the web UI), please report it responsibly.

**Email:** wadim.grasza@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

You should receive a response within 48 hours. Please do not open a public issue for security vulnerabilities.

## Scope

- `audit.sh` — the shell-based security audit script
- The haveibeenclawned.com web application (Next.js)
- The `/api/submit` and `/api/stats` endpoints

## Out of Scope

- The OpenClaw agents being audited (report those to their respective maintainers)
- Typosquatting domains (we own them, they redirect to the canonical domain)
