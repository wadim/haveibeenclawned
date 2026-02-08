# Have I Been Clawned?

Open source security audit for OpenClaw agents. 72 checks, OWASP-mapped, runs in 60 seconds.

## Quick Start

```bash
curl -sSL https://haveibeenclawned.com/audit.sh | bash
```

Or download first, review, then run:

```bash
curl -sSL https://haveibeenclawned.com/audit.sh -o audit.sh
cat audit.sh   # review it
bash audit.sh
```

## What It Checks

72 security checks across 9 categories:

| Category | What it covers |
|----------|---------------|
| **Identity** | Personal email as agent identity, default credentials |
| **Secrets** | Plaintext API keys, secrets in sessions, secrets in git history |
| **Network** | Gateway exposure, authentication, firewall, services on 0.0.0.0 |
| **Sandbox** | Docker privileged mode, seccomp/AppArmor, running as root |
| **Supply Chain** | Malicious skills, MCP vulnerabilities, npm scripts, malware IOC |
| **Config** | File permissions, log redaction, debug mode, cloud sync |
| **MCP** | Tool description poisoning, credential hygiene, definition pinning |
| **Persistence** | Memory poisoning, writable cron/bashrc/launchd paths |
| **Observability** | Telemetry endpoint security, debug endpoint exposure |

Every check is mapped to OWASP ASI, CVE, and CWE references where applicable.

## Scoring

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Hardened |
| B | 75-89 | Good |
| C | 60-74 | Needs Work |
| D | 40-59 | Exposed |
| F | 0-39 | Critical |

Skipped checks are excluded from scoring. WARN counts as half credit.

## Options

```bash
bash audit.sh                          # Full audit, human-readable
bash audit.sh --json                   # JSON output only
bash audit.sh --dry-run                # List checks without running
bash audit.sh --scan-sessions          # Include session transcript scan
bash audit.sh --submit                 # Opt in to anonymous community stats
bash audit.sh --skip=network,secrets   # Skip specific categories
bash audit.sh --categories             # List available categories
```

## Agent Skill

Drop `SKILL.md` into your agent's skills directory. Then ask your agent:

> "Run the security audit script from haveibeenclawned.com"

The agent will download and run the audit, interpret results, and show you a shareable report link.

## Shareable Reports

Results encode into a URL — no backend needed. Share your report:

```
https://haveibeenclawned.com/report?d=<base64url-encoded-results>
```

The report page renders your score, grade, and per-check results.

## How It Works

Everything runs locally. The script:

1. Reads OpenClaw config files (never modifies them)
2. Checks file permissions, container settings, network config
3. Probes for real vulnerabilities (gateway exposure, metadata service, open ports)
4. Scores each check as PASS, FAIL, WARN, or SKIP
5. Calculates a weighted hardening score

No data is sent anywhere unless you explicitly pass `--submit`.

## Contributing

Add checks, update threat intel, improve fix commands.

### Check format

Each check in `audit.sh` follows this pattern:

```bash
check_XX() {
  local cat="category"
  if should_skip "$cat"; then record -1 "Skipped (--skip=$cat)"; return; fi
  # ... detection logic ...
  record 1 "PASS reason"   # pass
  record 0 "FAIL reason"   # fail
  record 2 "WARN reason"   # warn
  record -1 "SKIP reason"  # not applicable
}
```

### How to contribute

1. Fork this repo
2. Add your check to `audit.sh`
3. Update check count, scoring weights, and labels
4. Open a PR with a reference (CVE, blog post, research paper) and real-world impact

## Credits

IOC data (C2 IPs, malicious domains, publishers, AMOS stealer patterns, file hashes) sourced from [openclaw-security-monitor](https://github.com/adibirzu/openclaw-security-monitor) by Adi Birzu (MIT license).

## License

MIT
