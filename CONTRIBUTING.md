# Contributing

Security is a moving target. New attack surfaces, new CVEs, new misconfigurations — we need the community to keep this tool sharp.

## What we're looking for

- **New checks** — found a misconfiguration or attack vector that isn't covered? Add it.
- **Better detection** — a check that's too noisy or misses real issues? Improve it.
- **Fix commands** — every finding needs a concrete remediation. If you have a better one, PR it.
- **Threat intel** — new C2 IPs, malicious domains, IOC patterns, known-bad publishers.
- **False positive reports** — if a check fires incorrectly in your environment, tell us.

## Single source of truth

All check metadata lives in **`data/checks.json`**. This is the canonical definition for every check — ID, title, severity, points, category, references, description, steps, and fix.

The other files consume or mirror this data:

| File | Role |
|------|------|
| `data/checks.json` | **Canonical source** — edit this first |
| `lib/haveibeenclawned.ts` | Imports JSON, derives `CHECKS` array |
| `components/agent-instructions.tsx` | Imports JSON, renders CheckCards |
| `audit.sh` | Standalone — parallel arrays must match JSON |
| `SKILL.md` | Hand-written — IDs and titles must match JSON |

## Adding a new check

### 1. Pick the next CLAW number

CLAW-XX is a **stable identifier** — like CVE numbers. New checks always get the next sequential number. Never renumber existing checks.

```
Current: CLAW-01 through CLAW-72
Next:    CLAW-73
```

The CLAW number does **not** determine display order. Severity does.

### 2. Add the check to `data/checks.json`

Append a new object at the end of the array:

```json
{
  "id": "CLAW-73",
  "title": "Your Check Title",
  "severity": "CRITICAL",
  "points": 15,
  "category": "network",
  "owasp": "ASI-XX",
  "cwe": "CWE-XXX",
  "description": "What this check detects and why it matters.",
  "steps": ["Step 1", "Step 2", "Step 3"],
  "fix": "exact remediation command"
}
```

The website and TypeScript consumers pick up new checks automatically from the JSON.

### 3. Write the check function in `audit.sh`

Follow this pattern:

```bash
check_73() {
  local cat="category"
  if should_skip "$cat"; then record -1 "Skipped (--skip=$cat)"; return; fi

  # Detection logic — verify, don't just detect.
  record 1 "Not vulnerable — reason"    # PASS
  record 0 "FAIL — what's wrong"        # FAIL
  record 2 "WARN — partial issue"       # WARN
  record -1 "Not applicable — reason"   # SKIP
}
```

### 4. Update the audit.sh parallel arrays

Three arrays must stay in sync with `data/checks.json`:

```bash
CHECK_POINTS=(... 15)                    # Must match JSON points
CHECK_LABELS=(... "Your Check Title")    # Must match JSON title exactly
CHECK_CATEGORIES=(... category)          # Must match JSON category
```

Update the array length validation and run loop:

```bash
if (( ${#CHECK_POINTS[@]} != 73 || ...)); then
```

```bash
for i in $(seq 1 73); do
```

### 5. Validate

```bash
npm run validate-checks
```

This compares `audit.sh` arrays and `SKILL.md` against `data/checks.json` and reports any mismatches.

### 6. Update counts

Search for `72` across the codebase and update to `73`:

- `audit.sh` — array validation, run loop, header text
- `components/install-steps.tsx` — "72 checks run locally"
- `app/page.tsx` — "72 checks across 9 categories"
- `SKILL.md` — check count in intro
- `README.md` — check count in description

## Severity guidelines

| Severity | Points | When to use |
|----------|--------|-------------|
| CRITICAL (15) | Direct path to compromise | RCE, credential exposure, unauthenticated access, full system control |
| HIGH (10) | Significant risk | Privilege escalation, information disclosure, supply chain risk |
| MEDIUM (5) | Hardening gap | Missing defense-in-depth, config best practices, observability gaps |

## Check quality bar

- **Verified findings** — actually test for the vulnerability, don't just check a config value exists
- **Concrete fix** — include the exact command to remediate
- **Reference** — link a CVE, CWE, OWASP ASI category, blog post, or research paper
- **Real-world impact** — explain why this matters with a plausible attack scenario
- **No false positives on default installs** — SKIP if the check doesn't apply

## Testing your check

```bash
# Validate JSON ↔ audit.sh consistency
npm run validate-checks

# Run the full audit
bash audit.sh

# JSON output for machine parsing
bash audit.sh --json

# Dry run to verify labels
bash audit.sh --dry-run
```

Verify your check produces the correct result in both a vulnerable and hardened environment.

## PR checklist

- [ ] Check added to `data/checks.json` with all fields
- [ ] Check function follows `check_XX()` pattern in `audit.sh`
- [ ] `CHECK_POINTS`, `CHECK_LABELS`, `CHECK_CATEGORIES` updated in `audit.sh`
- [ ] Array length validation and run loop updated
- [ ] `npm run validate-checks` passes with 0 errors
- [ ] All "72" references updated to new count
- [ ] Check has a concrete fix command
- [ ] Check has OWASP/CVE/CWE reference
- [ ] PR description includes reference (CVE, blog post, research paper) and real-world impact
- [ ] `bash audit.sh --dry-run` passes without errors

## Other contributions

Not everything is a new check:

- **Website** — `app/page.tsx`, `components/` (Next.js + Tailwind)
- **Threat intel** — IOC arrays at the top of `audit.sh`
- **Documentation** — `README.md`, `SKILL.md`
- **Bug fixes** — open an issue or PR

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
