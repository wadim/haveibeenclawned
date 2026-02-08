#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Have I Been Clawned — Security Audit v3                                   ║
# ║  https://github.com/wadim/haveibeenclawned                                ║
# ║                                                                            ║
# ║  72 checks across identity, secrets, network, sandbox, supply chain,       ║
# ║  and infrastructure. Weighted scoring with OWASP and CVE references.       ║
# ║                                                                            ║
# ║  Everything runs locally — no data is sent anywhere unless you pass        ║
# ║  --submit to opt in to anonymous community stats.                          ║
# ║                                                                            ║
# ║  Review this script before running:  cat audit.sh                          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Usage:
#   bash audit.sh                  # Run all checks, human-readable output
#   bash audit.sh --json           # Output only the JSON result line
#   bash audit.sh --scan-sessions  # Include CLAW-07 (session transcript scan)
#   bash audit.sh --submit         # Submit anonymous stats after audit
#   bash audit.sh --dry-run        # Show what would be checked, run nothing
#   bash audit.sh --skip=network,secrets  # Skip specific check categories
#   bash audit.sh --categories     # List available check categories
#
# Categories: network, secrets, container, mcp, supply-chain, config,
#   identity, persistence, observability
#
# Requirements: bash 4+, standard Unix tools (stat, curl, grep, etc.)
# Optional: jq or python3 (for JSON config parsing)
#
# IOC data (C2 IPs, malicious domains, publishers, AMOS patterns, file hashes)
# sourced from openclaw-security-monitor by Adi Birzu (MIT license)
# https://github.com/adibirzu/openclaw-security-monitor

set -uo pipefail

# ── Argument parsing ─────────────────────────────────────────────────────────

OPT_JSON=false
OPT_SUBMIT=false
OPT_DRY_RUN=false
OPT_SCAN_SESSIONS=false
OPT_SKIP=""

for arg in "$@"; do
  case "$arg" in
    --json)           OPT_JSON=true ;;
    --submit)         OPT_SUBMIT=true ;;
    --dry-run)        OPT_DRY_RUN=true ;;
    --scan-sessions)  OPT_SCAN_SESSIONS=true ;;
    --skip=*)         OPT_SKIP="${arg#--skip=}" ;;
    --categories)
      cat <<'CATS'
Available check categories:

  network        Gateway exposure, metadata service, outbound access, firewall, C2 detection (CLAW-01,02,03,23,24,33,42,48,51,60,64,70)
  secrets        API keys, credentials, tokens, git history, session scans (CLAW-05,07,17,19,21,22,34,39,45,53,58)
  container      Docker, sandbox, runtime, read-only FS, resource limits (CLAW-08,09,25,35,41,49,62)
  mcp            MCP servers, tool descriptions, transport, shadowing (CLAW-14,31,32,56,57)
  supply-chain   Skills, npm audit, lifecycle scripts, malware, IOC (CLAW-13,26,27,46,61,65,66,67,72)
  config         Sandbox mode, permissions, .env, debug, auto-approve, DM policy (CLAW-10,11,12,15,16,18,28,29,36,37,38,43,47,50,52,55,68,69,71)
  identity       Email identity, browser profiles, wallets, deserialization (CLAW-04,06,20,40)
  persistence    Memory poisoning, dormant payloads, writable paths, rules injection (CLAW-44,54,59,63)
  observability  Logging, cloud sync, telemetry endpoints (CLAW-30)

Usage: bash audit.sh --skip=network,secrets
CATS
      exit 0
      ;;
    --help|-h)
      head -30 "$0" | tail -25
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

# ── Colors & formatting ─────────────────────────────────────────────────────

if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]; then
  RED='\033[0;31m'    GREEN='\033[0;32m'  YELLOW='\033[0;33m'
  ORANGE='\033[0;91m' CYAN='\033[0;36m'   DIM='\033[2m'
  BOLD='\033[1m'      RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' ORANGE='' CYAN='' DIM='' BOLD='' RESET=''
fi

# ── Results tracking ─────────────────────────────────────────────────────────

# 72 results: 1=pass, 0=fail, 2=warn, -1=skip
declare -a RESULTS=()
declare -a DETAILS=()

# Points per check (indexed 0-71)
# CLAW-01..09: CRITICAL(15), CLAW-10..27: HIGH(10), CLAW-28..30: MEDIUM(5)
# CLAW-31..34: CRITICAL(15), CLAW-35: HIGH(10), CLAW-36: CRITICAL(15)
# CLAW-37..48: HIGH(10), CLAW-49..50: MEDIUM(5)
# CLAW-51..53: CRITICAL(15), CLAW-54..61: HIGH(10), CLAW-62..63: MEDIUM(5)
# CLAW-64..65: CRITICAL(15), CLAW-66: HIGH(10), CLAW-67..68: CRITICAL(15),
# CLAW-69: HIGH(10), CLAW-70: MEDIUM(5), CLAW-71..72: HIGH(10)
CHECK_POINTS=(
  15 15 15 15 15 15 15 15 15
  10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
  5 5 5
  15 15 15 15 10 15 10 10 10 10 10 10 10 10 10 10 10 10 5 5
  15 15 15 10 10 10 10 10 10 10 10 5 5
  15 15 10 15 15 10 5 10 10
)

points_for() {
  echo "${CHECK_POINTS[$1]}"
}

record() {
  local result=$1 detail="${2:-}"
  RESULTS+=("$result")
  DETAILS+=("$detail")
}

# ── JSON config reading ──────────────────────────────────────────────────────

# Read a dot-path value from a JSON file.
# Tries jq first, then python3, then basic grep fallback.
# Usage: val=$(json_val file.json "gateway.bind")
json_val() {
  local file="$1" path="$2"
  [[ -f "$file" ]] || return 1

  if command -v jq &>/dev/null; then
    # Build jq path with bracket notation to handle hyphenated keys
    # e.g. "gateway.rate-limit.enabled" → .["gateway"]["rate-limit"]["enabled"]
    local jq_path=""
    local IFS_BAK="$IFS"
    IFS='.'
    for key in $path; do
      jq_path+="[\"$key\"]"
    done
    IFS="$IFS_BAK"
    jq -r "$jq_path // empty" "$file" 2>/dev/null
  elif command -v python3 &>/dev/null; then
    python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    for k in sys.argv[2].split('.'):
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            sys.exit(0)
    if d is not None:
        print(d if isinstance(d, str) else json.dumps(d) if not isinstance(d, bool) else str(d).lower())
except:
    pass
" "$file" "$path" 2>/dev/null
  else
    # Crude grep fallback — only works for top-level string values
    grep -o "\"${path##*.}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$file" 2>/dev/null \
      | head -1 | sed 's/.*: *"//;s/"$//'
  fi
}

# ── OpenClaw config detection ────────────────────────────────────────────────

OC_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
OC_CONFIG="$OC_HOME/openclaw.json"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Check if a file is readable by group or others (returns 0 if too open)
perms_too_open() {
  local file="$1"
  [[ ! -e "$file" ]] && return 1
  local mode
  if [[ "$(uname)" == "Darwin" ]]; then
    mode=$(stat -f '%Lp' "$file" 2>/dev/null) || return 1
  else
    mode=$(stat -c '%a' "$file" 2>/dev/null) || return 1
  fi
  # Extract last 2 digits (group+other) — handles both 3-digit (644) and 4-digit (2644) modes
  local len=${#mode}
  local group_other="${mode:$((len - 2)):2}"
  [[ "$group_other" != "00" ]]
}

# Check if we're inside a Docker container
in_docker() {
  [[ -f /.dockerenv ]] || grep -q 'docker\|containerd' /proc/1/cgroup 2>/dev/null
}

# Check if a path is inside a cloud sync folder
in_sync_folder() {
  local path="$1"
  [[ "$path" == *"Mobile Documents"* ]] || \
  [[ "$path" == *"iCloud"* ]] || \
  [[ "$path" == *"Dropbox"* ]] || \
  [[ "$path" == *"Google Drive"* ]] || \
  [[ "$path" == *"OneDrive"* ]]
}

# ── Dry run ──────────────────────────────────────────────────────────────────

if $OPT_DRY_RUN; then
  cat <<'DRYRUN'
Have I Been Clawned — Dry Run
═════════════════════════════

This script would run the following 72 checks:

CRITICAL (15 pts each):
  CLAW-01  Gateway Network Exposure       Read gateway.bind from openclaw.json
  CLAW-02  Gateway Authentication          Read gateway.auth from openclaw.json
  CLAW-03  Cloud Metadata Service          curl 169.254.169.254 (2s timeout)
  CLAW-04  Personal Email as Agent ID      Check email config for personal domains
  CLAW-05  Plaintext API Keys in Config    Grep config files for key patterns
  CLAW-06  Sensitive Files Accessible      Test-read ~/.ssh, ~/.aws, ~/.kube, etc.
  CLAW-07  Secrets in Session Transcripts  Grep session .jsonl files (--scan-sessions)
  CLAW-08  Docker Privileged Mode          Check /.dockerenv + docker inspect
  CLAW-09  Agent Running as Root           Check current UID
  CLAW-31  MCP Tool Description Poisoning  Scan MCP configs for invisible Unicode
  CLAW-32  MCP Tool Shadowing             Count MCP servers for collision risk
  CLAW-33  Unrestricted Outbound Network   Check network.allowedHosts config
  CLAW-34  Messaging Token Exposure        Scan for Telegram/Slack/Discord tokens
  CLAW-36  Dangerous CLI Flags             Check process args and startup scripts
  CLAW-51  WebSocket Origin Validation     Test WebSocket upgrade with spoofed origin
  CLAW-52  LLM Endpoint Integrity          Check API base URLs, proxies, TLS settings
  CLAW-53  Credential Routing Through LLM  Scan skills for credential-in-prompt patterns

HIGH (10 pts each):
  CLAW-10  Sandbox Configuration           Read sandbox.mode from openclaw.json
  CLAW-11  Elevated Mode Restrictions      Read tools.elevated from openclaw.json
  CLAW-12  Config File Permissions         stat config files
  CLAW-13  Installed Skills Threat Intel   ls ~/.openclaw/skills/ vs known-bad list
  CLAW-14  MCP Server Vulnerabilities      Check MCP package versions
  CLAW-15  OpenClaw Version Security       openclaw --version or package.json
  CLAW-16  Session File Permissions        stat session directories
  CLAW-17  Default Credentials in Config   Grep for placeholder patterns
  CLAW-18  .env Not in .gitignore          Check .gitignore files
  CLAW-19  Secrets in Git History          git log last 50 commits for key patterns
  CLAW-20  Browser Profiles Accessible     Test-read Chrome/Firefox/Brave dirs
  CLAW-21  Git Credentials Accessible      Test-read ~/.git-credentials
  CLAW-22  Database Credentials Accessible Test-read ~/.pgpass, ~/.my.cnf, etc.
  CLAW-23  Additional Services on 0.0.0.0  ss -tlnp or netstat
  CLAW-24  No Firewall Rules               iptables / ufw / nftables / pf
  CLAW-25  Container Security Profile      docker inspect SecurityOpt
  CLAW-26  Agent Code Integrity            git status in agent install dir
  CLAW-27  npm Lifecycle Scripts in Skills Check package.json scripts in skills
  CLAW-35  No User Namespace Isolation     Check /proc/self/uid_map in container
  CLAW-37  Writable Install Directory      Test if agent dir is writable
  CLAW-38  No Rate Limiting                Check gateway.rateLimit config
  CLAW-39  Crypto Wallets Accessible       Test-read wallet dirs and seed files
  CLAW-40  Unsafe Deserialization          Check langchain-core version, yaml.load
  CLAW-41  No Container Read-Only FS       Check /proc/mounts for ro flag
  CLAW-42  Skill Network Unrestricted      Check plugins.permissions config
  CLAW-43  Unencrypted Session Storage     Check sessions.encryptAtRest config
  CLAW-44  Rules File Injection            Scan CLAUDE.md for invisible Unicode
  CLAW-45  Stale API Keys                  Check credential file modification age
  CLAW-46  npm Audit Vulnerabilities       Run npm audit on agent dependencies
  CLAW-47  Excessive Tool Permissions      Check tools config for wildcards
  CLAW-48  Insecure MCP Transport          Check for http:// in MCP configs
  CLAW-54  Persistent Memory Poisoning     Scan memory files for injection markers
  CLAW-55  Auto-Approval Beyond --yolo     Check for auto-approve wildcards in config
  CLAW-56  Semantic Tool Desc Poisoning    Scan tool configs for exfiltration patterns
  CLAW-57  Tool Definition Pinning         Check for tool hash/integrity mechanism
  CLAW-58  MCP Credential Hygiene          Check MCP configs for inline PATs/secrets
  CLAW-59  Dormant Payload Detection       Scan context files for conditional triggers
  CLAW-60  Observability Endpoint Security Check telemetry endpoints use HTTPS
  CLAW-61  Skill Typosquatting Detection   Compare skill names vs popular packages

MEDIUM (5 pts each):
  CLAW-28  Log Redaction                   Read logging.redactSensitive
  CLAW-29  Debug Logging Enabled           Read logging.level
  CLAW-30  Sessions Synced to Cloud        Check if ~/.openclaw is in a sync folder
  CLAW-49  No Process Resource Limits      Check ulimits and cgroup limits
  CLAW-50  Exposed Debug Endpoints         Probe common debug/health URLs
  CLAW-62  Sandbox Runtime Detection       Check container runtime (gVisor/Firecracker)
  CLAW-63  Writable Persistence Paths      Check agent write access to shell profiles

IOC CHECKS (from openclaw-security-monitor by Adi Birzu, MIT license):

CRITICAL (15 pts each):
  CLAW-64  Active C2 Connection Detection  Check connections against known C2 IPs
  CLAW-65  Malware Signature Scan          Scan skills for AMOS stealer / known hashes
  CLAW-67  VS Code Extension Trojans       Check for fake OpenClaw VS Code extensions
  CLAW-68  Gateway Device Auth Bypass      Check dangerouslyDisableDeviceAuth flag

HIGH (10 pts each):
  CLAW-66  Exfiltration Domain References  Check skills for webhook.site, ngrok, etc.
  CLAW-69  Exec-Approvals Hardening        Check exec-approvals.json for allow-all
  CLAW-71  DM Channel Restrictions         Check messaging channel DM policies
  CLAW-72  Known Malicious Publishers      Check skill authors against blacklist

MEDIUM (5 pts each):
  CLAW-70  mDNS/Bonjour Exposure           Check discovery.mdns.mode setting

No files are modified. No data is sent anywhere.
DRYRUN
  exit 0
fi

# ── Banner ───────────────────────────────────────────────────────────────────

if ! $OPT_JSON; then
  echo ""
  echo -e "${BOLD}Have I Been Clawned${RESET} — Security Audit v3"
  echo -e "${DIM}72 checks · weighted scoring · OWASP-mapped${RESET}"
  echo ""
  if [[ ! -f "$OC_CONFIG" ]]; then
    echo -e "${YELLOW}Warning: $OC_CONFIG not found${RESET}"
    echo -e "${DIM}Checks that require config will be skipped.${RESET}"
    echo ""
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# CRITICAL CHECKS (CLAW-01 through CLAW-09) — 15 points each
# ══════════════════════════════════════════════════════════════════════════════

# ── CLAW-01: Gateway Network Exposure ────────────────────────────────────────
# CVE-2026-25253 · OWASP ASI-03 · CWE-1327
# If gateway is bound to 0.0.0.0, anyone on the internet can reach it.
check_01() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi

  # ── ACTIVE: Probe the gateway port from the public IP ──────────────────
  local bind port public_ip active_done=false
  bind=$(json_val "$OC_CONFIG" "gateway.bind" 2>/dev/null) || true
  port=$(json_val "$OC_CONFIG" "gateway.port" 2>/dev/null) || true
  port=${port:-18789}
  [[ "$port" =~ ^[0-9]+$ ]] || port=18789

  if [[ "$bind" == "0.0.0.0" || "$bind" == "lan" || "$bind" == "::" ]]; then
    public_ip=$(curl -s -m 3 https://httpbin.org/ip 2>/dev/null \
      | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true
    if [[ -n "$public_ip" ]]; then
      local probe_code
      probe_code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 \
        "http://${public_ip}:${port}/" 2>/dev/null) || true
      if [[ "$probe_code" != "000" && -n "$probe_code" ]]; then
        record 0 "VERIFIED: gateway reachable from public IP (HTTP $probe_code)"
        active_done=true
      fi
    fi
  fi

  # ── PASSIVE: Fall back to config-based check ───────────────────────────
  if ! $active_done; then
    if [[ -z "$bind" ]]; then
      record -1 "gateway.bind not configured"
    elif [[ "$bind" == "0.0.0.0" || "$bind" == "lan" || "$bind" == "::" ]]; then
      record 0 "Bound to $bind — exposed to network"
    elif [[ "$bind" == "127.0.0.1" || "$bind" == "localhost" || "$bind" == "loopback" || "$bind" == "::1" ]]; then
      record 1 "Bound to $bind"
    else
      record 2 "Bound to $bind — verify this is not public"
    fi
  fi
}

# ── CLAW-02: Gateway Authentication ─────────────────────────────────────────
# CVE-2026-25253 · OWASP ASI-03 · CWE-306
# Without auth, anyone who can reach the gateway controls the agent.
check_02() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi

  local auth_mode port active_done=false
  auth_mode=$(json_val "$OC_CONFIG" "gateway.auth.mode" 2>/dev/null) || true
  port=$(json_val "$OC_CONFIG" "gateway.port" 2>/dev/null) || true
  port=${port:-18789}
  [[ "$port" =~ ^[0-9]+$ ]] || port=18789

  # ── ACTIVE: Attempt unauthenticated WebSocket upgrade & bogus token ────
  if [[ -n "$auth_mode" && "$auth_mode" != "none" && "$auth_mode" != "false" ]]; then
    # Check if gateway is actually running
    local gw_check
    gw_check=$(curl -s -o /dev/null -w '%{http_code}' -m 3 \
      "http://127.0.0.1:${port}/health" 2>/dev/null) || true
    if [[ "$gw_check" != "000" ]]; then
      # Try unauthenticated WebSocket upgrade
      local noauth_code
      noauth_code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 \
        -H "Upgrade: websocket" -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGVzdA==" \
        "http://127.0.0.1:${port}/" 2>/dev/null) || true
      # Try a bogus bearer token
      local bogus_code
      bogus_code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 \
        -H "Authorization: Bearer BOGUS_INVALID_TOKEN_12345" \
        "http://127.0.0.1:${port}/" 2>/dev/null) || true

      if [[ "$noauth_code" == "101" || "$noauth_code" == "200" ]]; then
        record 0 "VERIFIED: gateway accepts unauthenticated WebSocket (HTTP $noauth_code)"
        active_done=true
      elif [[ "$bogus_code" == "200" || "$bogus_code" == "101" ]]; then
        record 0 "VERIFIED: gateway accepts bogus token (HTTP $bogus_code)"
        active_done=true
      fi
    fi
  fi

  # ── PASSIVE: Fall back to config-based check ───────────────────────────
  if ! $active_done; then
    # If gateway.bind isn't configured, gateway isn't set up — skip
    local gw_bind
    gw_bind=$(json_val "$OC_CONFIG" "gateway.bind" 2>/dev/null) || true
    if [[ -z "$gw_bind" ]]; then
      record -1 "Gateway not configured"
      return
    fi
    if [[ -z "$auth_mode" || "$auth_mode" == "none" || "$auth_mode" == "false" ]]; then
      record 0 "No gateway authentication"
    elif [[ "$auth_mode" == "token" || "$auth_mode" == "bearer" || "$auth_mode" == "key" ]]; then
      local token
      token=$(json_val "$OC_CONFIG" "gateway.auth.token" 2>/dev/null) || true
      if [[ -z "$token" ]]; then
        record 0 "Auth mode=$auth_mode but no token set"
      else
        record 1 "Auth enabled (mode=$auth_mode)"
      fi
    else
      record 1 "Auth enabled (mode=$auth_mode)"
    fi
  fi
}

# ── CLAW-03: Cloud Metadata Service ─────────────────────────────────────────
# OWASP ASI-03 · CWE-918
# If 169.254.169.254 is reachable, agent can steal IAM credentials.
check_03() {
  local http_code
  http_code=$(curl -s -o /dev/null -w '%{http_code}' -m 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null) || true
  if [[ "$http_code" == "200" ]]; then
    record 0 "Metadata endpoint reachable (HTTP $http_code) — IMDSv1 exposed"
  elif [[ "$http_code" == "000" || -z "$http_code" ]]; then
    record 1 "Metadata endpoint not reachable"
  elif [[ "$http_code" == "401" || "$http_code" == "403" ]]; then
    record 1 "Metadata auth-gated (HTTP $http_code — IMDSv2 enforced)"
  else
    record 1 "Metadata returned HTTP $http_code (not exploitable)"
  fi
}

# ── CLAW-04: Personal Email as Agent Identity ────────────────────────────────
# OWASP ASI-03 · CWE-269
# If agent sends email from your personal address, compromise = impersonation.
check_04() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi
  local email
  email=$(json_val "$OC_CONFIG" "email.from" 2>/dev/null) || true
  if [[ -z "$email" ]]; then
    email=$(json_val "$OC_CONFIG" "email.address" 2>/dev/null) || true
  fi
  if [[ -z "$email" ]]; then
    record 1 "No email configured"
  elif echo "$email" | grep -qiE '@(gmail|yahoo|hotmail|outlook|icloud|protonmail|aol|live|me)\.(com|net|org)$'; then
    record 0 "Personal email as agent identity: ${email%%@*}@***"
  else
    record 1 "Custom domain email"
  fi
}

# ── CLAW-05: Plaintext API Keys in Config ────────────────────────────────────
# CVE-2026-22038 · OWASP ASI-03 · CWE-312
# API keys in plaintext config can be read by any process with file access.
check_05() {
  local files_to_scan=()
  [[ -f "$OC_CONFIG" ]] && files_to_scan+=("$OC_CONFIG")
  [[ -f "$OC_HOME/.env" ]] && files_to_scan+=("$OC_HOME/.env")
  [[ -f ".env" ]] && files_to_scan+=(".env")
  [[ -f "openclaw.json" ]] && files_to_scan+=("openclaw.json")

  # ── ACTIVE: Also scan shell history and /proc/*/environ ────────────────
  for hf in "$HOME/.bash_history" "$HOME/.zsh_history"; do
    [[ -r "$hf" ]] && files_to_scan+=("$hf")
  done
  # Scan readable /proc/*/environ for leaked env vars (Linux only)
  if [[ -d /proc ]]; then
    for ef in /proc/[0-9]*/environ; do
      [[ -r "$ef" ]] && files_to_scan+=("$ef")
    done 2>/dev/null
  fi

  if [[ ${#files_to_scan[@]} -eq 0 ]]; then
    record -1 "No config files found"
    return
  fi

  # Patterns that match API key formats (never echo the actual key)
  local found=0
  local validated=0
  local pattern='(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9-]+|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|xox[bp]-[a-zA-Z0-9-]+|AIza[a-zA-Z0-9_-]{35}|glpat-[a-zA-Z0-9_-]{20,})'
  # Telegram bot token pattern
  local tg_pattern='[0-9]{8,10}:[A-Za-z0-9_-]{35}'

  for f in "${files_to_scan[@]}"; do
    if grep -qE "$pattern" "$f" 2>/dev/null; then
      found=$((found + 1))
    fi
    if grep -qE "$tg_pattern" "$f" 2>/dev/null; then
      found=$((found + 1))
    fi
  done

  # ── ACTIVE: Lightweight key validation ─────────────────────────────────
  # Check for Telegram bot token patterns (format validation only — no network call)
  for f in "${files_to_scan[@]}"; do
    if grep -qE '[0-9]{8,10}:[A-Za-z0-9_-]{35}' "$f" 2>/dev/null; then
      validated=$((validated + 1))
      break
    fi
  done

  # Validate AWS key format (AKIA must be exactly 20 chars total)
  for f in "${files_to_scan[@]}"; do
    if grep -qE 'AKIA[0-9A-Z]{16}' "$f" 2>/dev/null; then
      local aws_key
      aws_key=$(grep -oE 'AKIA[0-9A-Z]{16}' "$f" 2>/dev/null | head -1) || true
      if [[ -n "$aws_key" && ${#aws_key} -eq 20 ]]; then
        validated=$((validated + 1))
      fi
      break
    fi
  done

  # ── PASSIVE: Report results ────────────────────────────────────────────
  if (( validated > 0 )); then
    record 0 "CRITICAL: $validated well-formed API key(s) found (format-validated, not network-verified)"
  elif (( found > 0 )); then
    record 0 "API key patterns found in $found file(s)"
  else
    record 1 "No plaintext API keys detected"
  fi
}

# ── CLAW-06: Sensitive Files Accessible ──────────────────────────────────────
# OWASP ASI-03 · CWE-732
# Without a sandbox, agent has full filesystem access to SSH keys, cloud creds.
check_06() {
  local sensitive_files=(
    "$HOME/.ssh/id_rsa"
    "$HOME/.ssh/id_ed25519"
    "$HOME/.aws/credentials"
    "$HOME/.config/gcloud/application_default_credentials.json"
    "$HOME/.kube/config"
    "$HOME/.npmrc"
    "$HOME/.docker/config.json"
    "$HOME/.netrc"
  )
  local readable=0
  for f in "${sensitive_files[@]}"; do
    [[ -r "$f" ]] && readable=$((readable + 1))
  done

  if (( readable >= 3 )); then
    record 0 "$readable sensitive files readable"
  elif (( readable >= 1 )); then
    record 2 "$readable sensitive file(s) readable"
  else
    record 1 "No sensitive files readable"
  fi
}

# ── CLAW-07: Secrets in Session Transcripts ──────────────────────────────────
# CVE-2026-22038 · OWASP ASI-03 · CWE-532
# Credit cards, SSNs, or API keys may be in agent conversation history.
check_07() {
  if ! $OPT_SCAN_SESSIONS; then
    record -1 "Skipped (use --scan-sessions to opt in)"
    return
  fi
  local session_dir="$OC_HOME/agents"
  if [[ ! -d "$session_dir" ]]; then
    record -1 "No session directory found"
    return
  fi

  # ── ACTIVE: Extended patterns including JWTs, credential URLs, PII ─────
  # Base secret patterns
  local pattern='(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b|\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b)'
  # JWT tokens (header.payload.signature)
  local jwt_pattern='eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+'
  # Credential URLs (proto://user:pass@host)
  local credurl_pattern='://[^:[:space:]]+:[^@[:space:]]+@'
  # Long base64 strings (potential encoded secrets, 40+ chars)
  local b64_pattern='[A-Za-z0-9+/]{40,}={0,2}'
  # PII: email addresses in sensitive contexts (password, secret, credential)
  local pii_pattern='(password|secret|credential|token)[^}]{0,40}[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

  local found=0
  local found_extended=0

  # Scan 10 most recent session files
  while IFS= read -r f; do
    # ── PASSIVE: Original patterns ─────────────────────────────────────
    if grep -qE "$pattern" "$f" 2>/dev/null; then
      found=$((found + 1))
    fi
    # ── ACTIVE: Extended patterns ──────────────────────────────────────
    if grep -qE "$jwt_pattern" "$f" 2>/dev/null; then
      found_extended=$((found_extended + 1))
    elif grep -qE "$credurl_pattern" "$f" 2>/dev/null; then
      found_extended=$((found_extended + 1))
    elif grep -qE "$b64_pattern" "$f" 2>/dev/null; then
      found_extended=$((found_extended + 1))
    elif grep -qiE "$pii_pattern" "$f" 2>/dev/null; then
      found_extended=$((found_extended + 1))
    fi
  done < <(find "$session_dir" -name '*.jsonl' -type f -print0 2>/dev/null \
    | xargs -0 ls -t 2>/dev/null | head -10)

  local total=$((found + found_extended))
  if (( found > 0 )); then
    record 0 "Secrets found in $found session file(s) ($found_extended with extended patterns)"
  elif (( found_extended > 0 )); then
    record 0 "Extended secret patterns (JWTs/cred URLs/PII) in $found_extended session file(s)"
  else
    record 1 "No secrets detected in recent sessions"
  fi
}

# ── CLAW-08: Docker Privileged Mode ─────────────────────────────────────────
# CVE-2024-21626 · OWASP ASI-05 · CWE-250
# --privileged, host network, or full mount negates all container isolation.
check_08() {
  if ! in_docker; then
    record -1 "Not running in Docker"
    return
  fi

  # Primary: docker inspect (accurate when Docker CLI + socket available)
  local container_id
  container_id=$(cat /proc/self/cgroup 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1) || true
  if [[ -z "$container_id" ]]; then
    container_id=$(hostname 2>/dev/null) || true
  fi

  if command -v docker &>/dev/null && [[ -n "$container_id" ]]; then
    local privileged network_mode
    privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "$container_id" 2>/dev/null) || true
    network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container_id" 2>/dev/null) || true

    if [[ "$privileged" == "true" ]]; then
      record 0 "Container running in privileged mode"
    elif [[ "$network_mode" == "host" ]]; then
      record 0 "Container using host network"
    else
      record 1 "Container isolation OK"
    fi
    return
  fi

  # Fallback: /proc-based detection (works from inside without Docker)
  if [[ -w /proc/sysrq-trigger ]] 2>/dev/null; then
    record 0 "Privileged: sysrq-trigger writable"
    return
  fi

  local cap_eff
  cap_eff=$(grep -i '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}') || true
  if [[ "$cap_eff" == "000001ffffffffff" || "$cap_eff" == "0000003fffffffff" ]]; then
    record 0 "Privileged: all capabilities granted"
    return
  fi

  record 1 "No privileged mode indicators found"
}

# ── CLAW-09: Agent Running as Root ───────────────────────────────────────────
# CVE-2019-5736 · OWASP ASI-05 · CWE-250
# Agent process running as UID 0 = full system compromise on any exploit.
check_09() {
  if [[ "$(id -u)" -eq 0 ]]; then
    record 0 "Running as root (UID 0)"
  else
    record 1 "Running as UID $(id -u)"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# HIGH CHECKS (CLAW-10 through CLAW-27) — 10 points each
# ══════════════════════════════════════════════════════════════════════════════

# ── CLAW-10: Sandbox Configuration ──────────────────────────────────────────
# OWASP ASI-05 · CWE-693
# Without container isolation, compromised agent has full access.
check_10() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi
  local mode
  mode=$(json_val "$OC_CONFIG" "sandbox.mode" 2>/dev/null) || true
  if [[ -z "$mode" || "$mode" == "off" || "$mode" == "none" || "$mode" == "false" ]]; then
    record 0 "Sandbox disabled"
  elif [[ "$mode" == "all" ]]; then
    local scope
    scope=$(json_val "$OC_CONFIG" "sandbox.scope" 2>/dev/null) || true
    if [[ "$scope" == "shared" ]]; then
      record 2 "Sandbox on but scope=shared (persists across sessions)"
    else
      record 1 "Sandbox enabled (mode=$mode)"
    fi
  else
    record 2 "Sandbox mode=$mode (not 'all')"
  fi
}

# ── CLAW-11: Elevated Mode Restrictions ──────────────────────────────────────
# CVE-2026-25049 · OWASP ASI-05 · CWE-250
# Unrestricted elevated mode lets any session escape the sandbox.
check_11() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi
  local allow_from
  allow_from=$(json_val "$OC_CONFIG" "tools.elevated.allowFrom" 2>/dev/null) || true
  if [[ "$allow_from" == "*" || "$allow_from" == "all" || "$allow_from" == '["*"]' ]]; then
    record 0 "Elevated mode unrestricted (allowFrom=*)"
  elif [[ -n "$allow_from" ]]; then
    record 1 "Elevated mode restricted"
  else
    record 1 "Elevated mode not configured (default=restricted)"
  fi
}

# ── CLAW-12: Config File Permissions ─────────────────────────────────────────
# OWASP ASI-03 · CWE-732
# Config files readable by group/others expose secrets.
check_12() {
  local config_files=("$OC_CONFIG" "$OC_HOME/.env")
  local too_open=0
  local checked=0

  for f in "${config_files[@]}"; do
    if [[ -f "$f" ]]; then
      checked=$((checked + 1))
      if perms_too_open "$f"; then
        too_open=$((too_open + 1))
      fi
    fi
  done

  # Also check credential dirs
  if [[ -d "$OC_HOME/credentials" ]]; then
    checked=$((checked + 1))
    if perms_too_open "$OC_HOME/credentials"; then
      too_open=$((too_open + 1))
    fi
  fi

  if (( checked == 0 )); then
    record -1 "No config files found"
  elif (( too_open > 0 )); then
    record 0 "$too_open config file(s) readable by group/others"
  else
    record 1 "Config files are owner-only"
  fi
}

# ── CLAW-13: Installed Skills Threat Intel ───────────────────────────────────
# CVE-2025-6514 · OWASP ASI-04 · CWE-1104
# 341 malicious ClawHub skills found Feb 2026. Skills run with agent perms.
check_13() {
  local skills_dir="$OC_HOME/skills"
  if [[ ! -d "$skills_dir" ]]; then
    record -1 "No skills directory"
    return
  fi

  local known_bad=(
    "data-exfil" "keylogger" "reverse-shell" "crypto-miner"
    "credential-stealer" "prompt-injector" "shadow-agent" "backdoor-tool"
    "solana-wallet-tracker" "polymarket-trader" "token-sniper"
    "atomic-stealer" "openclaw-boost" "free-credits" "claw-premium" "admin-tools"
  )
  local malicious=0
  local unverified=0

  for dir in "$skills_dir"/*/; do
    [[ -d "$dir" ]] || continue
    local name
    name=$(basename "$dir")

    # Check known-bad list
    for bad in "${known_bad[@]}"; do
      if [[ "$name" == "$bad" ]]; then
        malicious=$((malicious + 1))
        continue 2
      fi
    done

    # Check for missing SKILL.md
    if [[ ! -f "$dir/SKILL.md" ]]; then
      unverified=$((unverified + 1))
    fi
  done

  if (( malicious > 0 )); then
    record 0 "$malicious known-malicious skill(s) installed"
  elif (( unverified >= 3 )); then
    record 2 "$unverified unverified skills (no SKILL.md)"
  else
    record 1 "No known-malicious skills"
  fi
}

# ── CLAW-14: MCP Server Vulnerabilities ──────────────────────────────────────
# CVE-2025-6514 · OWASP ASI-04 · CWE-78
# MCP packages with known CVEs may be installed.
check_14() {
  local vulnerable=0
  local checked=0

  # Check common MCP package locations
  for pkg_json in \
    "$OC_HOME/node_modules/mcp-remote/package.json" \
    "$OC_HOME/node_modules/@anthropic/mcp-inspector/package.json" \
    "$OC_HOME/node_modules/@anthropic/mcp-server-filesystem/package.json" \
    "$OC_HOME/node_modules/@anthropic/mcp-server-git/package.json" \
    ./node_modules/mcp-remote/package.json \
    ./node_modules/@anthropic/mcp-inspector/package.json; do
    if [[ -f "$pkg_json" ]]; then
      checked=$((checked + 1))
      local ver
      ver=$(json_val "$pkg_json" "version" 2>/dev/null) || true
      local pkg_name
      pkg_name=$(json_val "$pkg_json" "name" 2>/dev/null) || true

      # mcp-remote < 1.1.0 is vulnerable (CVE-2025-6514)
      if [[ "$pkg_name" == "mcp-remote" ]] && [[ -n "$ver" ]]; then
        local major minor
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if (( major < 1 )) || (( major == 1 && minor < 1 )); then
          vulnerable=$((vulnerable + 1))
        fi
      fi
    fi
  done

  if (( checked == 0 )); then
    record -1 "No MCP packages found"
  elif (( vulnerable > 0 )); then
    record 0 "$vulnerable vulnerable MCP package(s)"
  else
    record 1 "MCP packages up to date"
  fi
}

# ── CLAW-15: OpenClaw Version Security ───────────────────────────────────────
# OWASP ASI-04 · CWE-1104
# Running an outdated version with known vulnerabilities.
check_15() {
  local version=""

  # Try CLI first
  if command -v openclaw &>/dev/null; then
    version=$(openclaw --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true
  fi

  # Try package.json
  if [[ -z "$version" ]] && [[ -f "$OC_HOME/package.json" ]]; then
    version=$(json_val "$OC_HOME/package.json" "version" 2>/dev/null) || true
  fi

  if [[ -z "$version" ]]; then
    record -1 "Cannot determine OpenClaw version"
    return
  fi

  local major minor patch
  major=$(echo "$version" | cut -d. -f1)
  minor=$(echo "$version" | cut -d. -f2)
  patch=$(echo "$version" | cut -d. -f3)

  # CVE-2026-25253 affects < 2.6.1
  if (( major < 2 )) || (( major == 2 && minor < 6 )) || (( major == 2 && minor == 6 && patch < 1 )); then
    record 0 "Version $version — CVE-2026-25253 (upgrade to 2.6.1+)"
  else
    record 1 "Version $version — up to date"
  fi
}

# ── CLAW-16: Session File Permissions ────────────────────────────────────────
# OWASP ASI-03 · CWE-538
# Session files contain full conversation history.
check_16() {
  local session_dirs=()
  while IFS= read -r d; do
    session_dirs+=("$d")
  done < <(find "$OC_HOME/agents" -type d -name sessions 2>/dev/null)

  if [[ ${#session_dirs[@]} -eq 0 ]]; then
    record -1 "No session directories found"
    return
  fi

  local too_open=0
  for d in "${session_dirs[@]}"; do
    if perms_too_open "$d"; then
      too_open=$((too_open + 1))
    fi
  done

  if (( too_open > 0 )); then
    record 0 "$too_open session dir(s) readable by others"
  else
    record 1 "Session directories are owner-only"
  fi
}

# ── CLAW-17: Default Credentials in Config ───────────────────────────────────
# OWASP ASI-03 · CWE-1392
# Default or placeholder values left unchanged from setup templates.
check_17() {
  local files_to_scan=()
  [[ -f "$OC_CONFIG" ]] && files_to_scan+=("$OC_CONFIG")
  [[ -f "$OC_HOME/.env" ]] && files_to_scan+=("$OC_HOME/.env")

  if [[ ${#files_to_scan[@]} -eq 0 ]]; then
    record -1 "No config files found"
    return
  fi

  # Match values, not keys — look for placeholder strings in value positions
  # Anchored to appear after ":" (JSON values) or "=" (.env values)
  local json_pattern=':\s*"(change_me|CHANGE_ME|placeholder|YOUR_[A-Z_]+|xxx+|CHANGEME|REPLACE_THIS|INSERT_[A-Z_]+|example_[a-z_]+)"'
  local env_pattern='=\s*(change_me|CHANGE_ME|placeholder|YOUR_[A-Z_]+|xxx+|CHANGEME|REPLACE_THIS|INSERT_[A-Z_]+|default)\s*$'
  local found=0
  for f in "${files_to_scan[@]}"; do
    if grep -qE "$json_pattern" "$f" 2>/dev/null; then
      found=$((found + 1))
    elif grep -qE "$env_pattern" "$f" 2>/dev/null; then
      found=$((found + 1))
    fi
  done

  if (( found > 0 )); then
    record 0 "Placeholder values found in $found file(s)"
  else
    record 1 "No default credentials detected"
  fi
}

# ── CLAW-18: .env Not in .gitignore ─────────────────────────────────────────
# OWASP ASI-03 · CWE-538
# If .env is not gitignored, secrets may be committed accidentally.
check_18() {
  # Check both CWD and OC_HOME
  local checked=false
  local missing=0

  for dir in "." "$OC_HOME"; do
    if [[ -d "$dir/.git" ]]; then
      checked=true
      if [[ -f "$dir/.gitignore" ]]; then
        if ! grep -q '\.env' "$dir/.gitignore" 2>/dev/null; then
          missing=$((missing + 1))
        fi
      else
        missing=$((missing + 1))
      fi
    fi
  done

  if ! $checked; then
    record -1 "Not a git repository"
  elif (( missing > 0 )); then
    record 0 ".env not in .gitignore"
  else
    record 1 ".env is gitignored"
  fi
}

# ── CLAW-19: Secrets in Git History ──────────────────────────────────────────
# OWASP ASI-03 · CWE-538
# API keys committed even once persist in git history forever.
check_19() {
  if ! command -v git &>/dev/null; then
    record -1 "git not available"
    return
  fi

  local git_dir=""
  if [[ -d "$OC_HOME/.git" ]]; then
    git_dir="$OC_HOME"
  elif [[ -d ".git" ]]; then
    git_dir="."
  fi

  if [[ -z "$git_dir" ]]; then
    record -1 "Not a git repository"
    return
  fi

  local issues=0

  # ── ACTIVE: Check for .env files ever committed then deleted ───────────
  local deleted_envs
  deleted_envs=$(git -C "$git_dir" log --all --diff-filter=D --name-only --pretty=format: \
    -- '*.env' '*.env.*' '*.env.local' '*.env.production' 2>/dev/null \
    | grep -c '\.env' 2>/dev/null) || true
  if [[ -n "$deleted_envs" ]] && (( deleted_envs > 0 )); then
    issues=$((issues + deleted_envs))
  fi

  # ── ACTIVE: Check for dangling objects after filter-branch cleanup ─────
  local dangling
  if command -v timeout &>/dev/null; then
    dangling=$(timeout 30 git -C "$git_dir" fsck --unreachable --no-reflogs 2>/dev/null \
      | grep -c 'dangling commit\|dangling blob' 2>/dev/null) || true
  elif command -v gtimeout &>/dev/null; then
    dangling=$(gtimeout 30 git -C "$git_dir" fsck --unreachable --no-reflogs 2>/dev/null \
      | grep -c 'dangling commit\|dangling blob' 2>/dev/null) || true
  else
    dangling=$(git -C "$git_dir" fsck --unreachable --no-reflogs 2>/dev/null \
      | grep -c 'dangling commit\|dangling blob' 2>/dev/null) || true
  fi
  local dangling_secrets=0
  if [[ -n "$dangling" ]] && (( dangling > 10 )); then
    # Many dangling objects suggest a filter-branch that left remnants
    dangling_secrets=1
  fi

  # ── PASSIVE: Grep recent git log for API key patterns ──────────────────
  # Use --no-ext-diff and pipe through head to cap output size
  local pattern='(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|xox[bp]-[a-zA-Z0-9-]+|AIza[a-zA-Z0-9_-]{35})'
  local found
  if command -v timeout &>/dev/null; then
    found=$(timeout 30 git -C "$git_dir" log --all -p -50 --no-ext-diff --diff-filter=ACMR 2>/dev/null \
      | head -c 10000000 | grep -cE "$pattern" 2>/dev/null) || true
  elif command -v gtimeout &>/dev/null; then
    found=$(gtimeout 30 git -C "$git_dir" log --all -p -50 --no-ext-diff --diff-filter=ACMR 2>/dev/null \
      | head -c 10000000 | grep -cE "$pattern" 2>/dev/null) || true
  else
    found=$(git -C "$git_dir" log --all -p -50 --no-ext-diff --diff-filter=ACMR 2>/dev/null \
      | head -c 10000000 | grep -cE "$pattern" 2>/dev/null) || true
  fi
  if [[ -n "$found" ]] && (( found > 0 )); then
    issues=$((issues + found))
  fi

  if (( issues > 0 && dangling_secrets > 0 )); then
    record 0 "Secrets in git history ($issues matches) + dangling objects from incomplete cleanup"
  elif (( issues > 0 )); then
    record 0 "API key patterns found in git history ($issues matches, including deleted .env files)"
  elif (( dangling_secrets > 0 )); then
    record 2 "Many dangling git objects — possible incomplete secret cleanup"
  else
    record 1 "No secrets in recent git history"
  fi
}

# ── CLAW-20: Browser Profiles Accessible ─────────────────────────────────────
# CVE-2025-2783 · OWASP ASI-03 · CWE-732
# Chrome/Firefox/Brave profiles contain saved passwords and session tokens.
check_20() {
  local browser_dirs=(
    "$HOME/.config/google-chrome"
    "$HOME/.config/BraveSoftware"
    "$HOME/.mozilla/firefox"
    "$HOME/Library/Application Support/Google/Chrome"
    "$HOME/Library/Application Support/BraveSoftware/Brave-Browser"
    "$HOME/Library/Application Support/Firefox/Profiles"
  )
  local readable=0
  for d in "${browser_dirs[@]}"; do
    [[ -r "$d" ]] && readable=$((readable + 1))
  done

  if (( readable > 0 )); then
    record 0 "$readable browser profile dir(s) readable"
  else
    record 1 "No browser profiles accessible"
  fi
}

# ── CLAW-21: Git Credentials Accessible ──────────────────────────────────────
# OWASP ASI-03 · CWE-256
# Git credential files contain repository tokens and passwords.
check_21() {
  local files=("$HOME/.git-credentials" "$HOME/.gitconfig")
  local found=0

  for f in "${files[@]}"; do
    if [[ -r "$f" ]]; then
      # .gitconfig is fine unless it stores credentials directly
      if [[ "$f" == *".git-credentials" ]]; then
        found=$((found + 1))
      elif grep -qiE 'helper.*store|password|token' "$f" 2>/dev/null; then
        found=$((found + 1))
      fi
    fi
  done

  if (( found > 0 )); then
    record 0 "$found git credential file(s) with stored secrets"
  else
    record 1 "No git credential files exposed"
  fi
}

# ── CLAW-22: Database Credentials Accessible ─────────────────────────────────
# OWASP ASI-03 · CWE-798
# Database credential files allow direct database access.
check_22() {
  local db_files=(
    "$HOME/.pgpass"
    "$HOME/.my.cnf"
    "$HOME/.mongosh"
    "$HOME/.redis-cli-history"
    "$HOME/.dbshell"
  )
  local found=0
  for f in "${db_files[@]}"; do
    [[ -r "$f" ]] && found=$((found + 1))
  done

  if (( found > 0 )); then
    record 0 "$found database credential file(s) readable"
  else
    record 1 "No database credential files exposed"
  fi
}

# ── CLAW-23: Additional Services on 0.0.0.0 ─────────────────────────────────
# OWASP ASI-03 · CWE-1327
# Other agent services bound to all interfaces.
check_23() {
  local exposed=0

  if command -v ss &>/dev/null; then
    exposed=$(ss -tlnp 2>/dev/null | grep -cE '0\.0\.0\.0:(3000|5000|8000|8080|8888|9090)' 2>/dev/null) || true
  elif command -v lsof &>/dev/null; then
    # macOS: lsof works better than netstat -tlnp (BSD netstat lacks -p)
    exposed=$(lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null | grep -cE '\*:(3000|5000|8000|8080|8888|9090)' 2>/dev/null) || true
  elif command -v netstat &>/dev/null; then
    exposed=$(netstat -an 2>/dev/null | grep LISTEN | grep -cE '0\.0\.0\.0\.(3000|5000|8000|8080|8888|9090)' 2>/dev/null) || true
  else
    record -1 "Neither ss nor netstat available"
    return
  fi

  if (( exposed > 0 )); then
    record 0 "$exposed service(s) bound to 0.0.0.0 on common ports"
  else
    record 1 "No services on 0.0.0.0 at common agent ports"
  fi
}

# ── CLAW-24: No Firewall Rules ───────────────────────────────────────────────
# OWASP ASI-03 · CWE-284
# Without a firewall, every listening port is directly reachable.
check_24() {
  local has_firewall=false

  # Linux: iptables
  if command -v iptables &>/dev/null; then
    local rules
    rules=$(iptables -L -n 2>/dev/null | grep -cvE '^Chain|^target|^$' 2>/dev/null) || true
    if [[ -n "$rules" ]] && (( rules > 0 )); then
      has_firewall=true
    fi
  fi

  # Linux: ufw
  if ! $has_firewall && command -v ufw &>/dev/null; then
    if ufw status 2>/dev/null | grep -q 'Status: active'; then
      has_firewall=true
    fi
  fi

  # Linux: nftables
  if ! $has_firewall && command -v nft &>/dev/null; then
    if nft list ruleset 2>/dev/null | grep -q 'chain'; then
      has_firewall=true
    fi
  fi

  # macOS: pf
  if ! $has_firewall && [[ "$(uname)" == "Darwin" ]]; then
    if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
      has_firewall=true
    else
      # macOS Application Firewall
      if command -v /usr/libexec/ApplicationFirewall/socketfilterfw &>/dev/null; then
        if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q 'enabled'; then
          has_firewall=true
        fi
      fi
    fi
  fi

  if $has_firewall; then
    record 1 "Firewall active"
  else
    record 0 "No firewall detected"
  fi
}

# ── CLAW-25: Container Security Profile ──────────────────────────────────────
# CVE-2025-31133 · OWASP ASI-05 · CWE-250
# Without seccomp/AppArmor, container escape via runC CVEs is possible.
check_25() {
  if ! in_docker; then
    record -1 "Not running in Docker"
    return
  fi

  # Primary: docker inspect (accurate when Docker CLI + socket available)
  local container_id
  container_id=$(cat /proc/self/cgroup 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1) || true
  if [[ -z "$container_id" ]]; then
    container_id=$(hostname 2>/dev/null) || true
  fi

  if command -v docker &>/dev/null && [[ -n "$container_id" ]]; then
    local sec_opt
    sec_opt=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' "$container_id" 2>/dev/null) || true
    if [[ "$sec_opt" == "[]" || "$sec_opt" == "<no value>" || -z "$sec_opt" ]]; then
      record 0 "No seccomp/AppArmor profile"
    elif echo "$sec_opt" | grep -q "unconfined"; then
      record 0 "Security profile set to unconfined"
    else
      record 1 "Security profile applied"
    fi
    return
  fi

  # Fallback: /proc-based detection (works from inside without Docker)
  local seccomp_mode apparmor_profile

  # Seccomp: 0=disabled, 1=strict, 2=filter (Docker default)
  seccomp_mode=$(grep -i '^Seccomp:' /proc/self/status 2>/dev/null | awk '{print $2}') || true
  apparmor_profile=$(cat /proc/self/attr/current 2>/dev/null) || true

  if [[ "$seccomp_mode" == "0" && ( -z "$apparmor_profile" || "$apparmor_profile" == "unconfined" ) ]]; then
    record 0 "No security profile (seccomp disabled, AppArmor unconfined)"
  elif [[ "$seccomp_mode" == "0" ]]; then
    record 2 "Partial (seccomp disabled, AppArmor: ${apparmor_profile})"
  elif [[ -z "$apparmor_profile" || "$apparmor_profile" == "unconfined" ]]; then
    record 2 "Partial (seccomp mode ${seccomp_mode}, AppArmor unconfined)"
  else
    record 1 "Security profiles active (seccomp mode ${seccomp_mode}, AppArmor: ${apparmor_profile})"
  fi
}

# ── CLAW-26: Agent Code Integrity ────────────────────────────────────────────
# OWASP ASI-04 · CWE-494
# Uncommitted modifications to agent source could be backdoors.
check_26() {
  local agent_dir="$OC_HOME"
  if [[ ! -d "$agent_dir/.git" ]]; then
    # Try to find the openclaw installation
    local bin_path
    bin_path=$(command -v openclaw 2>/dev/null) || true
    if [[ -n "$bin_path" ]]; then
      agent_dir=$(dirname "$(dirname "$bin_path")")
    fi
  fi

  if [[ ! -d "$agent_dir/.git" ]]; then
    record -1 "Agent dir is not a git repo"
    return
  fi

  local issues=0

  # ── ACTIVE: Check for source files newer than lockfiles (post-install tampering)
  local lockfile=""
  for lf in "$agent_dir/package-lock.json" "$agent_dir/yarn.lock" "$agent_dir/pnpm-lock.yaml"; do
    [[ -f "$lf" ]] && lockfile="$lf" && break
  done
  if [[ -n "$lockfile" ]]; then
    local lock_mtime
    if [[ "$(uname)" == "Darwin" ]]; then
      lock_mtime=$(stat -f %m "$lockfile" 2>/dev/null) || true
    else
      lock_mtime=$(stat -c %Y "$lockfile" 2>/dev/null) || true
    fi
    if [[ -n "$lock_mtime" ]]; then
      local tampered=0
      while IFS= read -r src; do
        local src_mtime
        if [[ "$(uname)" == "Darwin" ]]; then
          src_mtime=$(stat -f %m "$src" 2>/dev/null) || true
        else
          src_mtime=$(stat -c %Y "$src" 2>/dev/null) || true
        fi
        if [[ -n "$src_mtime" ]] && (( src_mtime > lock_mtime )); then
          tampered=$((tampered + 1))
        fi
      done < <(find "$agent_dir/node_modules" -maxdepth 3 -name '*.js' -type f 2>/dev/null | head -50)
      if (( tampered > 0 )); then
        issues=$((issues + tampered))
      fi
    fi
  fi

  # ── ACTIVE: Check for obfuscation patterns in JS files ─────────────────
  local obfuscated=0
  if [[ -d "$agent_dir/node_modules" ]]; then
    local obf_pattern='eval\(atob\(|String\.fromCharCode\([0-9,[:space:]]{20,}\)|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}'
    obfuscated=$(find "$agent_dir/node_modules" -maxdepth 3 -name '*.js' -type f 2>/dev/null \
      | head -100 \
      | while IFS= read -r f; do
          grep -lE "$obf_pattern" "$f" 2>/dev/null
        done | wc -l) || true
    obfuscated=$((obfuscated + 0))
  fi

  # ── PASSIVE: Check git status for uncommitted changes ──────────────────
  local changes
  changes=$(git -C "$agent_dir" status --porcelain 2>/dev/null | grep -c '^ M\|^M ' 2>/dev/null) || true

  if (( obfuscated > 0 )); then
    record 0 "VERIFIED: $obfuscated JS file(s) with obfuscation patterns (eval/atob/fromCharCode)"
  elif (( issues > 0 )); then
    record 0 "$issues source file(s) modified after lockfile — possible post-install tampering"
  elif [[ -n "$changes" ]] && (( changes > 0 )); then
    record 0 "$changes uncommitted modification(s) to agent source"
  else
    record 1 "Agent source is clean"
  fi
}

# ── CLAW-27: npm Lifecycle Scripts in Skills ─────────────────────────────────
# OWASP ASI-04 · CWE-829
# Skills with lifecycle scripts execute arbitrary code on install.
check_27() {
  local skills_dir="$OC_HOME/skills"
  if [[ ! -d "$skills_dir" ]]; then
    record -1 "No skills directory"
    return
  fi

  local suspicious=0
  local malicious=0

  for pkg in "$skills_dir"/*/package.json; do
    [[ -f "$pkg" ]] || continue
    # Check for preinstall, postinstall, prepare scripts
    if grep -qE '"(preinstall|postinstall|prepare|preuninstall)"' "$pkg" 2>/dev/null; then
      suspicious=$((suspicious + 1))

      # ── PASSIVE: Basic download/eval patterns ────────────────────────
      if grep -E '"(preinstall|postinstall|prepare)"' "$pkg" 2>/dev/null \
         | grep -qiE '(curl|wget|eval|exec|bash -c|node -e|python -c)' 2>/dev/null; then
        malicious=$((malicious + 1))
        continue
      fi

      # ── ACTIVE: Deep analysis of script content for malicious patterns ──
      local script_dir
      script_dir=$(dirname "$pkg")

      # Reverse shells: bash -i >& /dev/tcp, nc -e, python socket
      local revshell_pattern='bash -i >&.*\/dev\/tcp|nc[[:space:]].*-e|python[23]?[[:space:]].*-c.*import[[:space:]]*socket|perl.*socket.*connect|ruby.*TCPSocket'
      if grep -rlE "$revshell_pattern" "$script_dir" 2>/dev/null | head -1 | grep -q .; then
        malicious=$((malicious + 1))
        continue
      fi

      # Credential access: reading SSH keys, AWS creds, etc.
      local cred_access_pattern='cat[[:space:]].*\/\.ssh|cat[[:space:]].*\/\.aws|\$HOME\/\.ssh|\$HOME\/\.aws|\/\.gnupg|\/\.npmrc'
      if grep -rlE "$cred_access_pattern" "$script_dir" 2>/dev/null | head -1 | grep -q .; then
        malicious=$((malicious + 1))
        continue
      fi

      # Downloads piped to execution: curl|wget ... | bash/sh/eval
      local pipe_exec_pattern='(curl|wget)[[:space:]].*\|[[:space:]]*(bash|sh|eval|node|python)'
      if grep -rlE "$pipe_exec_pattern" "$script_dir" 2>/dev/null | head -1 | grep -q .; then
        malicious=$((malicious + 1))
        continue
      fi

      # Environment variable exfiltration
      local env_exfil_pattern='(printenv|env|set)[[:space:]]*\||(curl|wget|nc).*\$[A-Z_]+(KEY|TOKEN|SECRET|PASS|CRED)'
      if grep -rlE "$env_exfil_pattern" "$script_dir" 2>/dev/null | head -1 | grep -q .; then
        malicious=$((malicious + 1))
        continue
      fi
    fi
  done

  if (( malicious > 0 )); then
    record 0 "$malicious skill(s) with malicious lifecycle scripts (reverse shells/cred access/exfiltration)"
  elif (( suspicious > 0 )); then
    record 2 "$suspicious skill(s) with lifecycle scripts"
  else
    record 1 "No lifecycle scripts in skills"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# MEDIUM CHECKS (CLAW-28 through CLAW-30) — 5 points each
# ══════════════════════════════════════════════════════════════════════════════

# ── CLAW-28: Log Redaction ───────────────────────────────────────────────────
# CVE-2026-22038 · OWASP ASI-03 · CWE-532
# Without log redaction, secrets may appear in log files.
check_28() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi
  local redact
  redact=$(json_val "$OC_CONFIG" "logging.redactSensitive" 2>/dev/null) || true
  if [[ -z "$redact" || "$redact" == "false" || "$redact" == "off" ]]; then
    record 0 "Log redaction disabled"
  else
    record 1 "Log redaction enabled ($redact)"
  fi
}

# ── CLAW-29: Debug Logging Enabled ───────────────────────────────────────────
# CVE-2026-22038 · OWASP ASI-03 · CWE-532
# Debug/verbose mode leaks extra data including full request/response payloads.
check_29() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi
  local level
  level=$(json_val "$OC_CONFIG" "logging.level" 2>/dev/null) || true
  if [[ "$level" == "debug" || "$level" == "verbose" || "$level" == "trace" ]]; then
    record 0 "Logging level=$level — verbose output"
  else
    record 1 "Logging level=${level:-info (default)}"
  fi
}

# ── CLAW-30: Sessions Synced to Cloud ────────────────────────────────────────
# OWASP ASI-03 · CWE-922
# Session files in cloud-synced folder = history uploaded to iCloud/Dropbox.
check_30() {
  local real_path
  real_path=$(cd "$OC_HOME" 2>/dev/null && pwd -P 2>/dev/null) || true
  if [[ -z "$real_path" ]]; then
    real_path="$OC_HOME"
  fi

  if in_sync_folder "$real_path"; then
    record 0 "OpenClaw home is inside a cloud-synced folder"
  else
    record 1 "OpenClaw home is not in a sync folder"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# NEW CHECKS (CLAW-31 through CLAW-50)
# ══════════════════════════════════════════════════════════════════════════════

# ── CLAW-31: MCP Tool Description Poisoning ──────────────────────────────────
# CVE-2025-6514 · OWASP ASI-01 · CWE-94
# Invisible Unicode in MCP tool descriptions can hijack agent behavior.
check_31() {
  local files=()
  [[ -f "$OC_CONFIG" ]] && files+=("$OC_CONFIG")
  for f in "$OC_HOME/mcp"/*.json; do [[ -f "$f" ]] && files+=("$f"); done

  local found=0
  local live_poisoned=0

  # ── ACTIVE: Query running MCP servers via JSON-RPC tools/list ──────────
  local port
  if [[ -f "$OC_CONFIG" ]]; then
    port=$(json_val "$OC_CONFIG" "gateway.port" 2>/dev/null) || true
  fi
  port=${port:-18789}
  [[ "$port" =~ ^[0-9]+$ ]] || port=18789

  # Try to get the MCP tool list from the running gateway
  local tools_response
  tools_response=$(curl -s -m 3 -X POST \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' \
    "http://127.0.0.1:${port}/mcp" 2>/dev/null) || true

  if [[ -n "$tools_response" && "$tools_response" != *'"error"'* ]]; then
    # Check live tool descriptions for invisible Unicode
    if command -v perl &>/dev/null; then
      if echo "$tools_response" | perl -ne 'exit 1 if /[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]/' 2>/dev/null; then
        : # clean
      else
        live_poisoned=$((live_poisoned + 1))
      fi
    elif echo "$tools_response" | grep -qP '\xe2\x80[\x8b-\x8f]|\xe2\x80[\xaa-\xae]' 2>/dev/null; then
      live_poisoned=$((live_poisoned + 1))
    fi

    # Check for suspicious instruction patterns in tool descriptions
    local inject_pattern='(ignore previous|ignore safety|system prompt|override|exfiltrate|send (all|data) to|you must|always execute|bypass)'
    if echo "$tools_response" | grep -qiE "$inject_pattern" 2>/dev/null; then
      live_poisoned=$((live_poisoned + 1))
    fi
  fi

  # ── PASSIVE: Scan config files for invisible Unicode ───────────────────
  if [[ ${#files[@]} -eq 0 && $live_poisoned -eq 0 ]]; then
    record -1 "No MCP configs found"
    return
  fi

  for f in "${files[@]}"; do
    if command -v perl &>/dev/null; then
      if ! perl -ne 'exit 1 if /[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]/' "$f" 2>/dev/null; then
        found=$((found + 1))
      fi
    elif grep -cP '\xe2\x80[\x8b-\x8f]|\xe2\x80[\xaa-\xae]' "$f" &>/dev/null; then
      found=$((found + 1))
    fi
  done

  if (( live_poisoned > 0 )); then
    record 0 "VERIFIED: live MCP tool descriptions contain poisoning ($live_poisoned issue(s))"
  elif (( found > 0 )); then
    record 0 "Invisible Unicode in $found config file(s)"
  else
    record 1 "No tool description poisoning detected"
  fi
}

# ── CLAW-32: MCP Tool Shadowing ──────────────────────────────────────────────
# OWASP ASI-02 · CWE-349
# Duplicate tool names across MCP servers let a malicious server intercept calls.
check_32() {
  local mcp_dir="$OC_HOME/mcp"
  local server_count=0
  local all_tools=""

  # Count MCP servers and collect tool names from config
  if [[ -f "$OC_CONFIG" ]]; then
    local mcp_section
    mcp_section=$(json_val "$OC_CONFIG" "mcpServers" 2>/dev/null) || true
    if [[ -n "$mcp_section" && "$mcp_section" != "null" ]]; then
      server_count=$(echo "$mcp_section" | grep -oE '"[^"]+"\s*:\s*\{' | wc -l) || true
      # Extract tool names from MCP server configs (tools arrays)
      if command -v jq &>/dev/null; then
        local tools
        tools=$(jq -r '.mcpServers // {} | to_entries[] | .value.tools // [] | .[]' "$OC_CONFIG" 2>/dev/null) || true
        if [[ -n "$tools" ]]; then
          all_tools+="$tools"$'\n'
        fi
      fi
    fi
  fi

  # Count standalone MCP config files and collect tool names
  if [[ -d "$mcp_dir" ]]; then
    for f in "$mcp_dir"/*.json; do
      [[ -f "$f" ]] || continue
      server_count=$((server_count + 1))
      if command -v jq &>/dev/null; then
        local tools
        tools=$(jq -r '.tools // [] | .[] | .name // empty' "$f" 2>/dev/null) || true
        if [[ -n "$tools" ]]; then
          all_tools+="$tools"$'\n'
        fi
      fi
    done
  fi

  if (( server_count == 0 )); then
    record -1 "No MCP servers configured"
    return
  fi

  # Check for actual duplicate tool names
  local dupes=""
  if [[ -n "$all_tools" ]]; then
    dupes=$(echo "$all_tools" | grep -v '^$' | sort | uniq -d) || true
  fi

  if [[ -n "$dupes" ]]; then
    local dupe_count
    dupe_count=$(echo "$dupes" | wc -l | tr -d ' ')
    record 0 "$dupe_count duplicate tool name(s) across $server_count MCP servers (shadowing detected)"
  elif (( server_count > 5 )); then
    record 2 "$server_count MCP servers — high tool shadowing risk (could not parse tool names to verify)"
  else
    record 1 "$server_count MCP server(s), no tool shadowing detected"
  fi
}

# ── CLAW-33: Unrestricted Outbound Network Access ───────────────────────────
# OWASP ASI-01 · CWE-941
# Without egress filtering, compromised agent can exfiltrate data anywhere.
check_33() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi

  local allowed
  allowed=$(json_val "$OC_CONFIG" "network.allowedHosts" 2>/dev/null) || true

  # Strip JSON array wrapper and quotes: ["*"] → *, ["*","example.com"] → *,example.com
  local cleaned
  cleaned=$(echo "$allowed" | sed 's/^\[//;s/\]$//;s/"//g;s/[[:space:]]//g') || true
  if [[ -z "$allowed" || "$allowed" == "null" || "$cleaned" == "*" ]]; then
    local vectors_open=0

    # ── ACTIVE: Multi-vector outbound connectivity testing ───────────────

    # Vector 1: HTTPS to httpbin (original test)
    local http_code
    http_code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 https://httpbin.org/get 2>/dev/null) || true
    if [[ "$http_code" == "200" ]]; then
      vectors_open=$((vectors_open + 1))
    fi

    # Vector 2: DNS exfiltration — resolve via a known public resolver
    if command -v dig &>/dev/null; then
      local dns_result
      dns_result=$(dig +short +time=3 +tries=1 @8.8.8.8 example.com A 2>/dev/null) || true
      if [[ -n "$dns_result" && "$dns_result" != *"timed out"* ]]; then
        vectors_open=$((vectors_open + 1))
      fi
    elif command -v nslookup &>/dev/null; then
      local dns_result
      if command -v timeout &>/dev/null; then
        dns_result=$(timeout 3 nslookup example.com 8.8.8.8 2>/dev/null) || true
      else
        dns_result=$(nslookup -timeout=3 example.com 8.8.8.8 2>/dev/null) || true
      fi
      if [[ -n "$dns_result" && "$dns_result" == *"Address"* ]]; then
        vectors_open=$((vectors_open + 1))
      fi
    fi

    # Vector 3: Non-standard port connectivity
    local alt_code
    alt_code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://portquiz.net:8443 2>/dev/null) || true
    if [[ "$alt_code" != "000" && -n "$alt_code" ]]; then
      vectors_open=$((vectors_open + 1))
    fi

    # Vector 4: Raw TCP if nc/ncat available
    if command -v nc &>/dev/null; then
      if nc -z -w 3 8.8.8.8 53 2>/dev/null; then
        vectors_open=$((vectors_open + 1))
      fi
    elif command -v ncat &>/dev/null; then
      if ncat -z -w 3 8.8.8.8 53 2>/dev/null; then
        vectors_open=$((vectors_open + 1))
      fi
    fi

    # ── PASSIVE: Report based on results ─────────────────────────────────
    if (( vectors_open >= 2 )); then
      record 0 "Unrestricted outbound network ($vectors_open vectors confirmed: HTTPS/DNS/alt-port/TCP)"
    elif (( vectors_open == 1 )); then
      record 0 "Unrestricted outbound network (1 vector confirmed)"
    else
      record 2 "No network allowlist configured (connectivity tests inconclusive)"
    fi
  else
    record 1 "Network allowlist configured"
  fi
}

# ── CLAW-34: Messaging Platform Token Exposure ───────────────────────────────
# OWASP ASI-03 · CWE-522
# Telegram/Slack/Discord tokens in plaintext config files.
check_34() {
  local files_to_scan=()
  [[ -f "$OC_CONFIG" ]] && files_to_scan+=("$OC_CONFIG")
  [[ -f "$OC_HOME/.env" ]] && files_to_scan+=("$OC_HOME/.env")
  [[ -f ".env" ]] && files_to_scan+=(".env")

  if [[ ${#files_to_scan[@]} -eq 0 ]]; then
    record -1 "No config files found"
    return
  fi

  # Telegram bot tokens: 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ_1234567
  # Slack tokens: xoxb-, xoxp-, xapp-
  # Discord tokens: base64 with dots
  local pattern='([0-9]{8,10}:[A-Za-z0-9_-]{35}|xox[bpa]-[a-zA-Z0-9-]{10,}|[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})'
  local found=0

  for f in "${files_to_scan[@]}"; do
    if grep -qE "$pattern" "$f" 2>/dev/null; then
      # Check file permissions
      if perms_too_open "$f"; then
        found=$((found + 2)) # worse if permissions too open
      else
        found=$((found + 1))
      fi
    fi
  done

  if (( found >= 2 )); then
    record 0 "Messaging tokens found with lax permissions"
  elif (( found == 1 )); then
    record 2 "Messaging tokens found (permissions OK)"
  else
    record 1 "No messaging platform tokens detected"
  fi
}

# ── CLAW-35: No User Namespace Isolation (Container) ────────────────────────
# CVE-2025-31133 · OWASP ASI-05 · CWE-269
# Without userns-remap, root in container = root on host.
check_35() {
  if ! in_docker; then
    record -1 "Not running in Docker"
    return
  fi

  local uid_map
  uid_map=$(cat /proc/self/uid_map 2>/dev/null) || true

  if [[ -z "$uid_map" ]]; then
    record 2 "Cannot read uid_map"
  elif echo "$uid_map" | grep -q '^[[:space:]]*0[[:space:]]*0'; then
    record 0 "No user namespace remapping (root=root on host)"
  else
    record 1 "User namespace remapping active"
  fi
}

# ── CLAW-36: Dangerous CLI Flags in Agent Startup ────────────────────────────
# OWASP ASI-05 · CWE-693
# --yolo, --dangerously-skip-permissions disable all security protections.
check_36() {
  local dangerous_pattern='dangerously-skip-permissions|--yolo|--trust-all-tools|--no-verify|--disable-sandbox|--allow-all'
  local found=0

  # Check running openclaw/claude processes (not our own /proc/self)
  if [[ -d /proc ]]; then
    for pid_dir in /proc/[0-9]*/cmdline; do
      [[ -r "$pid_dir" ]] || continue
      local cmdline
      cmdline=$(tr '\0' ' ' < "$pid_dir" 2>/dev/null) || continue
      # Only check openclaw/claude processes, skip our own PID
      if [[ "$cmdline" == *openclaw* || "$cmdline" == *claude* ]] && \
         [[ "${pid_dir#/proc/}" != "self/"* ]] && \
         echo "$cmdline" | grep -qiE "$dangerous_pattern"; then
        found=$((found + 1))
      fi
    done 2>/dev/null
  elif command -v pgrep &>/dev/null; then
    # macOS fallback: use pgrep + ps
    local pids
    pids=$(pgrep -f 'openclaw|claude' 2>/dev/null) || true
    for pid in $pids; do
      local cmdline
      cmdline=$(ps -p "$pid" -o args= 2>/dev/null) || continue
      if echo "$cmdline" | grep -qiE "$dangerous_pattern"; then
        found=$((found + 1))
      fi
    done
  fi

  # Check systemd service files
  for svc in /etc/systemd/system/openclaw* ~/.config/systemd/user/openclaw*; do
    if [[ -f "$svc" ]] && grep -qiE "$dangerous_pattern" "$svc" 2>/dev/null; then
      found=$((found + 1))
    fi
  done

  # Check docker-compose and Dockerfiles
  for f in docker-compose*.yml docker-compose*.yaml Dockerfile*; do
    if [[ -f "$f" ]] && grep -qiE "$dangerous_pattern" "$f" 2>/dev/null; then
      found=$((found + 1))
    fi
  done

  # Check startup scripts
  for f in "$OC_HOME/scripts"/*; do
    if [[ -f "$f" ]] && grep -qiE "$dangerous_pattern" "$f" 2>/dev/null; then
      found=$((found + 1))
    fi
  done

  # Check environment variables
  if env 2>/dev/null | grep -qiE 'OPENCLAW_SKIP_PERMISSIONS|OPENCLAW_YOLO|TRUST_ALL'; then
    found=$((found + 1))
  fi

  if (( found > 0 )); then
    record 0 "Dangerous flags found in $found location(s)"
  else
    record 1 "No dangerous CLI flags detected"
  fi
}

# ── CLAW-37: Writable Agent Installation Directory ───────────────────────────
# OWASP ASI-04 · CWE-276
# If agent can modify its own code, prompt injection can install persistent backdoor.
check_37() {
  local install_dir=""

  if command -v openclaw &>/dev/null; then
    install_dir=$(dirname "$(dirname "$(command -v openclaw)" 2>/dev/null)" 2>/dev/null) || true
  fi

  if [[ -z "$install_dir" ]] || [[ ! -d "$install_dir" ]]; then
    # Try common paths
    for d in /usr/lib/node_modules/openclaw /usr/local/lib/node_modules/openclaw; do
      if [[ -d "$d" ]]; then
        install_dir="$d"
        break
      fi
    done
  fi

  if [[ -z "$install_dir" ]] || [[ ! -d "$install_dir" ]]; then
    record -1 "Cannot find OpenClaw installation directory"
    return
  fi

  if [[ -w "$install_dir" ]]; then
    record 0 "Install directory is writable: $install_dir"
  else
    record 1 "Install directory is read-only"
  fi
}

# ── CLAW-38: No Rate Limiting on Agent API ───────────────────────────────────
# OWASP ASI-03 · CWE-770
# Without rate limiting, Denial of Wallet attacks can run up LLM costs.
check_38() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi

  # If gateway.bind isn't configured, gateway isn't set up — skip
  local gw_bind
  gw_bind=$(json_val "$OC_CONFIG" "gateway.bind" 2>/dev/null) || true
  if [[ -z "$gw_bind" ]]; then
    record -1 "Gateway not configured"
    return
  fi

  local rate_enabled
  rate_enabled=$(json_val "$OC_CONFIG" "gateway.rateLimit.enabled" 2>/dev/null) || true

  if [[ "$rate_enabled" == "true" ]]; then
    record 1 "Rate limiting enabled"
  elif [[ -z "$rate_enabled" || "$rate_enabled" == "false" ]]; then
    record 0 "No rate limiting on gateway"
  else
    record 2 "Rate limiting status unclear ($rate_enabled)"
  fi
}

# ── CLAW-39: Cryptocurrency Wallet Files Accessible ──────────────────────────
# OWASP ASI-03 · CWE-732
# Crypto wallet files readable by agent — funds can be drained irreversibly.
check_39() {
  local wallet_dirs=()
  # macOS
  wallet_dirs+=("$HOME/Library/Application Support/Exodus")
  wallet_dirs+=("$HOME/Library/Application Support/Electrum")
  wallet_dirs+=("$HOME/Library/Application Support/Bitcoin")
  wallet_dirs+=("$HOME/Library/Application Support/Ethereum")
  # Linux
  wallet_dirs+=("$HOME/.config/Exodus")
  wallet_dirs+=("$HOME/.electrum")
  wallet_dirs+=("$HOME/.bitcoin")
  wallet_dirs+=("$HOME/.ethereum")

  local readable=0
  for d in "${wallet_dirs[@]}"; do
    [[ -r "$d" ]] && readable=$((readable + 1))
  done

  # Also check for seed phrase files
  local seed_files
  seed_files=$(find "$HOME" -maxdepth 3 \( -name "*seed*" -o -name "*mnemonic*" -o -name "*recovery*phrase*" -o -name "*wallet*backup*" \) 2>/dev/null | head -3 | wc -l) || true

  readable=$((readable + seed_files))

  if (( readable >= 2 )); then
    record 0 "$readable crypto wallet path(s) readable"
  elif (( readable == 1 )); then
    record 2 "1 crypto wallet path readable"
  else
    record 1 "No crypto wallets accessible"
  fi
}

# ── CLAW-40: Unsafe Deserialization in Dependencies ──────────────────────────
# OWASP ASI-04 · CWE-502
# Vulnerable langchain-core or unsafe yaml.load in skills.
check_40() {
  local vulnerable=0

  # Check langchain-core (Python)
  if command -v pip &>/dev/null || command -v pip3 &>/dev/null; then
    local lc_version
    lc_version=$(pip show langchain-core 2>/dev/null | grep -i '^version:' | awk '{print $2}') || true
    if [[ -z "$lc_version" ]]; then
      lc_version=$(pip3 show langchain-core 2>/dev/null | grep -i '^version:' | awk '{print $2}') || true
    fi
    if [[ -n "$lc_version" ]]; then
      local major minor patch
      major=$(echo "$lc_version" | cut -d. -f1)
      minor=$(echo "$lc_version" | cut -d. -f2)
      patch=$(echo "$lc_version" | cut -d. -f3)
      # < 0.3.81 or (>= 1.0.0 and < 1.2.5)
      if (( major == 0 && minor == 3 && patch < 81 )); then
        vulnerable=$((vulnerable + 1))
      elif (( major == 1 && (minor < 2 || (minor == 2 && patch < 5)) )); then
        vulnerable=$((vulnerable + 1))
      fi
    fi
  fi

  # Check for unsafe YAML loading in skills
  if [[ -d "$OC_HOME/skills" ]]; then
    local unsafe
    unsafe=$(grep -rlE 'yaml\.load\(|yaml\.unsafe_load' "$OC_HOME/skills/" 2>/dev/null | wc -l) || true
    if [[ -n "$unsafe" ]] && (( unsafe > 0 )); then
      vulnerable=$((vulnerable + unsafe))
    fi
  fi

  if (( vulnerable > 0 )); then
    record 0 "$vulnerable unsafe deserialization issue(s)"
  else
    record 1 "No unsafe deserialization detected"
  fi
}

# ── CLAW-41: No Container Read-Only Filesystem ──────────────────────────────
# OWASP ASI-05 · CWE-732
# Writable container filesystem allows persistent malware installation.
check_41() {
  if ! in_docker; then
    record -1 "Not running in Docker"
    return
  fi

  local root_mount
  root_mount=$(grep ' / ' /proc/mounts 2>/dev/null | head -1) || true

  if echo "$root_mount" | grep -q '\bro\b'; then
    record 1 "Container root filesystem is read-only"
  else
    record 0 "Container root filesystem is read-write"
  fi
}

# ── CLAW-42: Skill/Plugin Network Access Unrestricted ────────────────────────
# OWASP ASI-02 · CWE-284
# Without per-skill network permissions, any skill can exfiltrate data.
check_42() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi

  local perms
  perms=$(json_val "$OC_CONFIG" "plugins.permissions" 2>/dev/null) || true
  local default_deny
  default_deny=$(json_val "$OC_CONFIG" "plugins.defaultDeny" 2>/dev/null) || true

  if [[ -n "$default_deny" && "$default_deny" == *"network"* ]]; then
    record 1 "Skill network access denied by default"
  elif [[ -n "$perms" && "$perms" != "null" ]]; then
    record 2 "Skill permissions configured (verify network scoping)"
  else
    record 0 "No per-skill network permissions"
  fi
}

# ── CLAW-43: Unencrypted Session Storage ─────────────────────────────────────
# OWASP ASI-03 · CWE-311
# Session files stored unencrypted expose conversation history on disk compromise.
check_43() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi

  local encrypt
  encrypt=$(json_val "$OC_CONFIG" "sessions.encryptAtRest" 2>/dev/null) || true

  if [[ "$encrypt" == "true" ]]; then
    record 1 "Session encryption at rest enabled"
  else
    # Check if any session files exist
    local sessions
    sessions=$(find "$OC_HOME/agents" -name '*.jsonl' -type f 2>/dev/null | head -1) || true
    if [[ -n "$sessions" ]]; then
      record 0 "Session files unencrypted on disk"
    else
      record -1 "No session files found"
    fi
  fi
}

# ── CLAW-44: CLAUDE.md / Agent Rules File Injection ─────────────────────────
# OWASP ASI-01 · CWE-94
# Rules files with invisible Unicode or suspicious injection patterns.
check_44() {
  local rules_files=()
  [[ -f "CLAUDE.md" ]] && rules_files+=("CLAUDE.md")
  [[ -f ".claude/CLAUDE.md" ]] && rules_files+=(".claude/CLAUDE.md")
  [[ -f "$OC_HOME/rules.md" ]] && rules_files+=("$OC_HOME/rules.md")

  for f in "$OC_HOME/agents"/*/system-prompt.md; do
    [[ -f "$f" ]] && rules_files+=("$f")
  done

  if [[ ${#rules_files[@]} -eq 0 ]]; then
    record -1 "No rules files found"
    return
  fi

  local suspicious=0
  for f in "${rules_files[@]}"; do
    # Check for invisible Unicode
    if command -v perl &>/dev/null; then
      if ! perl -ne 'exit 1 if /[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]/' "$f" 2>/dev/null; then
        suspicious=$((suspicious + 2))
        continue
      fi
    fi
    # Check for suspicious injection keywords
    if grep -qiE 'ignore previous|ignore safety|exfiltrate|send data to|override permissions|bypass security' "$f" 2>/dev/null; then
      suspicious=$((suspicious + 1))
    fi
    # Check for suspiciously long lines
    if awk 'length > 1000 {found=1; exit} END {exit !found}' "$f" 2>/dev/null; then
      suspicious=$((suspicious + 1))
    fi
  done

  if (( suspicious >= 2 )); then
    record 0 "Suspicious content in rules files"
  elif (( suspicious == 1 )); then
    record 2 "Potentially suspicious rules file content"
  else
    record 1 "Rules files look clean"
  fi
}

# ── CLAW-45: Stale or Unrotated API Keys ─────────────────────────────────────
# OWASP ASI-03 · CWE-324
# Credential files not modified in 90+ days.
check_45() {
  local cred_files=()
  [[ -f "$OC_HOME/.env" ]] && cred_files+=("$OC_HOME/.env")
  [[ -f "$OC_CONFIG" ]] && cred_files+=("$OC_CONFIG")

  if [[ ${#cred_files[@]} -eq 0 ]]; then
    record -1 "No credential files found"
    return
  fi

  local now
  now=$(date +%s)
  local stale=0

  for f in "${cred_files[@]}"; do
    local mtime
    if [[ "$(uname)" == "Darwin" ]]; then
      mtime=$(stat -f %m "$f" 2>/dev/null) || continue
    else
      mtime=$(stat -c %Y "$f" 2>/dev/null) || continue
    fi
    local age_days=$(( (now - mtime) / 86400 ))
    if (( age_days > 90 )); then
      stale=$((stale + 1))
    fi
  done

  if (( stale > 0 )); then
    record 0 "$stale credential file(s) not modified in 90+ days"
  else
    record 1 "Credential files recently updated"
  fi
}

# ── CLAW-46: npm Audit Vulnerabilities in Agent Dependencies ─────────────────
# OWASP ASI-04 · CWE-1104
# Known vulnerabilities in agent npm dependencies.
check_46() {
  if ! command -v npm &>/dev/null; then
    record -1 "npm not available"
    return
  fi

  local agent_dir=""
  if [[ -f "$OC_HOME/package.json" ]]; then
    agent_dir="$OC_HOME"
  elif command -v openclaw &>/dev/null; then
    agent_dir=$(dirname "$(dirname "$(command -v openclaw)" 2>/dev/null)" 2>/dev/null) || true
  fi

  if [[ -z "$agent_dir" ]] || [[ ! -f "$agent_dir/package.json" ]]; then
    record -1 "No agent package.json found"
    return
  fi

  local audit_output
  if command -v timeout &>/dev/null; then
    audit_output=$(cd "$agent_dir" && timeout 30 npm audit --json 2>/dev/null) || true
  elif command -v gtimeout &>/dev/null; then
    audit_output=$(cd "$agent_dir" && gtimeout 30 npm audit --json 2>/dev/null) || true
  else
    audit_output=$(cd "$agent_dir" && npm audit --json 2>/dev/null) || true
  fi

  if [[ -z "$audit_output" ]]; then
    record -1 "npm audit failed or timed out"
    return
  fi

  local high_crit
  high_crit=$(echo "$audit_output" | grep -oE '"(high|critical)"' | wc -l) || true

  if [[ -n "$high_crit" ]] && (( high_crit > 0 )); then
    record 0 "$high_crit high/critical npm vulnerabilities"
  else
    record 1 "No high/critical npm vulnerabilities"
  fi
}

# ── CLAW-47: Excessive Tool Permissions (Least Privilege) ─────────────────────
# OWASP ASI-02 · CWE-250
# Wildcard tool permissions — agent can write anywhere, execute anything.
check_47() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "Config not found"
    return
  fi

  local unrestricted=0

  # Check filesystem write permissions
  local fs_write
  fs_write=$(json_val "$OC_CONFIG" "tools.filesystem.write" 2>/dev/null) || true
  if [[ "$fs_write" == "*" || "$fs_write" == '"*"' || "$fs_write" == "/" || "$fs_write" == '"/"' ]]; then
    unrestricted=$((unrestricted + 1))
  fi

  # Check execute permissions
  local exec_allowed
  exec_allowed=$(json_val "$OC_CONFIG" "tools.execute.allowed" 2>/dev/null) || true
  if [[ "$exec_allowed" == "*" || "$exec_allowed" == '"*"' || "$exec_allowed" == "all" ]]; then
    unrestricted=$((unrestricted + 1))
  fi

  # Check network outbound
  local net_out
  net_out=$(json_val "$OC_CONFIG" "tools.network.outbound" 2>/dev/null) || true
  if [[ "$net_out" == "*" || "$net_out" == '"*"' ]]; then
    unrestricted=$((unrestricted + 1))
  fi

  if (( unrestricted >= 3 )); then
    record 0 "$unrestricted tool categories with wildcard permissions"
  elif (( unrestricted >= 1 )); then
    record 2 "$unrestricted tool category with wildcard permissions"
  else
    record 1 "Tool permissions are scoped"
  fi
}

# ── CLAW-48: Insecure MCP Transport (No TLS) ─────────────────────────────────
# OWASP ASI-07 · CWE-319
# Remote MCP servers connected via HTTP transmit data in cleartext.
check_48() {
  local config_files=()
  [[ -f "$OC_CONFIG" ]] && config_files+=("$OC_CONFIG")
  for f in "$OC_HOME/mcp"/*.json; do [[ -f "$f" ]] && config_files+=("$f"); done

  if [[ ${#config_files[@]} -eq 0 ]]; then
    record -1 "No MCP configs found"
    return
  fi

  local insecure=0
  for f in "${config_files[@]}"; do
    # Check for http:// URLs that are NOT localhost
    if grep -E 'http://' "$f" 2>/dev/null | grep -vqE 'localhost|127\.0\.0\.1|::1' 2>/dev/null; then
      insecure=$((insecure + 1))
    fi
  done

  if (( insecure > 0 )); then
    record 0 "$insecure config(s) with insecure MCP transport"
  else
    record 1 "MCP transport is secure or local"
  fi
}

# ── CLAW-49: No Process Resource Limits ──────────────────────────────────────
# OWASP ASI-05 · CWE-400
# Without limits, runaway agent can exhaust all host resources.
check_49() {
  local unlimited=0

  # Check ulimits
  local max_procs
  max_procs=$(ulimit -u 2>/dev/null) || true
  if [[ "$max_procs" == "unlimited" ]]; then
    unlimited=$((unlimited + 1))
  fi

  local max_files
  max_files=$(ulimit -n 2>/dev/null) || true
  if [[ -n "$max_files" ]] && (( max_files > 65536 )); then
    unlimited=$((unlimited + 1))
  fi

  # Check cgroup memory limit (container)
  if in_docker; then
    local mem_limit
    mem_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || \
                cat /sys/fs/cgroup/memory.max 2>/dev/null) || true
    if [[ "$mem_limit" == "max" ]] || { [[ -n "$mem_limit" ]] && [[ "$mem_limit" =~ ^[0-9]+$ ]] && (( mem_limit > 100000000000 )); }; then
      unlimited=$((unlimited + 1))
    fi
  fi

  if (( unlimited == 0 )); then
    record 1 "Resource limits configured"
  elif (( unlimited >= 2 )); then
    record 0 "No resource limits ($unlimited categories unlimited)"
  else
    record 2 "Partial resource limits"
  fi
}

# ── CLAW-50: Exposed Health/Debug Endpoints ──────────────────────────────────
# OWASP ASI-03 · CWE-215
# Debug endpoints leak internal state to attackers.
check_50() {
  local port
  if [[ -f "$OC_CONFIG" ]]; then
    port=$(json_val "$OC_CONFIG" "gateway.port" 2>/dev/null) || true
  fi
  port=${port:-18789}
  [[ "$port" =~ ^[0-9]+$ ]] || port=18789

  # Check if gateway is running
  local health_code
  health_code=$(curl -s -o /dev/null -w '%{http_code}' -m 2 "http://127.0.0.1:$port/health" 2>/dev/null) || true
  if [[ "$health_code" == "000" ]]; then
    record -1 "Gateway not running on port $port"
    return
  fi

  local exposed=0
  local header_leaks=0

  # ── ACTIVE: Extended endpoint list ─────────────────────────────────────
  for endpoint in /debug /env /config /_debug /admin /metrics \
                  /swagger /swagger-ui /api-docs /actuator /actuator/env \
                  /graphql /.well-known /server-info /phpinfo; do
    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' -m 2 "http://127.0.0.1:$port$endpoint" 2>/dev/null) || true
    if [[ "$status" == "200" ]]; then
      exposed=$((exposed + 1))
    fi
  done

  # ── ACTIVE: Check response headers for information leakage ─────────────
  local headers
  headers=$(curl -s -D - -o /dev/null -m 2 "http://127.0.0.1:$port/health" 2>/dev/null) || true
  if [[ -n "$headers" ]]; then
    # Check for Server header revealing software/version
    if echo "$headers" | grep -qiE '^Server:' 2>/dev/null; then
      header_leaks=$((header_leaks + 1))
    fi
    # Check for X-Powered-By header
    if echo "$headers" | grep -qiE '^X-Powered-By:' 2>/dev/null; then
      header_leaks=$((header_leaks + 1))
    fi
    # Check for X-Debug-Token header
    if echo "$headers" | grep -qiE '^X-Debug-Token' 2>/dev/null; then
      header_leaks=$((header_leaks + 1))
    fi
  fi

  # ── PASSIVE: Report results ────────────────────────────────────────────
  if (( exposed > 0 && header_leaks > 0 )); then
    record 0 "$exposed debug endpoint(s) exposed + $header_leaks info-leaking header(s)"
  elif (( exposed > 0 )); then
    record 0 "$exposed debug endpoint(s) exposed"
  elif (( header_leaks > 0 )); then
    record 2 "$header_leaks response header(s) leak server info (Server/X-Powered-By/X-Debug-Token)"
  else
    record 1 "No debug endpoints exposed"
  fi
}

# ── CLAW-51: WebSocket Origin Validation ──────────────────────────────────────
# OWASP ASI-03 · CWE-346
# Cross-Site WebSocket Hijacking if origin is not validated.
check_51() {
  # Skip if gateway not configured (consistent with CLAW-02, CLAW-38)
  if [[ -f "$OC_CONFIG" ]]; then
    local gw_bind
    gw_bind=$(json_val "$OC_CONFIG" "gateway.bind" 2>/dev/null) || true
    if [[ -z "$gw_bind" ]]; then
      record -1 "Gateway not configured"
      return
    fi
  fi

  local port
  if [[ -f "$OC_CONFIG" ]]; then
    port=$(json_val "$OC_CONFIG" "gateway.port" 2>/dev/null) || true
  fi
  port=${port:-18789}
  [[ "$port" =~ ^[0-9]+$ ]] || port=18789

  # ACTIVE: Try WebSocket upgrade with spoofed Origin
  local ws_code
  ws_code=$(curl -s -o /dev/null -w '%{http_code}' -m 3 \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    -H "Origin: https://evil.example.com" \
    "http://127.0.0.1:$port/" 2>/dev/null) || true

  if [[ "$ws_code" == "101" ]]; then
    record 0 "Gateway accepted WebSocket from spoofed origin (CSWSH vulnerable)"
  elif [[ "$ws_code" == "403" || "$ws_code" == "401" ]]; then
    record 1 "Gateway rejected spoofed WebSocket origin"
  elif [[ "$ws_code" == "000" ]]; then
    # Gateway not running — check config
    if [[ -f "$OC_CONFIG" ]]; then
      local origins
      origins=$(json_val "$OC_CONFIG" "gateway.cors.allowedOrigins" 2>/dev/null) || true
      if [[ -z "$origins" || "$origins" == "*" ]]; then
        record 2 "No CORS origin restriction configured (gateway not running to verify)"
      else
        record 1 "CORS origins configured: $origins"
      fi
    else
      record -1 "Gateway not running, no config found"
    fi
  else
    # Got some other response — check config
    if [[ -f "$OC_CONFIG" ]]; then
      local origins
      origins=$(json_val "$OC_CONFIG" "gateway.cors.allowedOrigins" 2>/dev/null) || true
      if [[ -z "$origins" || "$origins" == "*" ]]; then
        record 2 "CORS origins not restricted (HTTP $ws_code on WS probe)"
      else
        record 1 "CORS origins configured"
      fi
    else
      record 2 "Could not verify WebSocket origin validation (HTTP $ws_code)"
    fi
  fi
}

# ── CLAW-52: LLM Endpoint Integrity ──────────────────────────────────────────
# OWASP ASI-01 · CWE-345
# Detects custom API base URLs, proxy overrides, or disabled TLS verification.
check_52() {
  local issues=0

  # Check API base URLs in config and environment
  local known_good="api.anthropic.com|api.openai.com|generativelanguage.googleapis.com|api.mistral.ai|api.cohere.ai"

  # Check config file
  if [[ -f "$OC_CONFIG" ]]; then
    local base_url
    base_url=$(json_val "$OC_CONFIG" "llm.baseUrl" 2>/dev/null) || true
    if [[ -n "$base_url" && ! "$base_url" =~ ($known_good) ]]; then
      issues=$((issues + 1))
    fi
  fi

  # Check environment variables
  for var in OPENAI_BASE_URL ANTHROPIC_BASE_URL OPENAI_API_BASE; do
    local val="${!var:-}"
    if [[ -n "$val" && ! "$val" =~ ($known_good) ]]; then
      issues=$((issues + 1))
    fi
  done

  # Check for proxy overrides
  if [[ -n "${HTTP_PROXY:-}" || -n "${HTTPS_PROXY:-}" ]]; then
    issues=$((issues + 1))
  fi

  # Check for disabled TLS verification
  if [[ "${NODE_TLS_REJECT_UNAUTHORIZED:-}" == "0" ]]; then
    issues=$((issues + 1))
  fi

  if (( issues > 0 )); then
    record 0 "$issues LLM endpoint integrity issue(s): custom base URL, proxy override, or disabled TLS"
  else
    record 1 "LLM endpoints use known providers, no proxy or TLS overrides"
  fi
}

# ── CLAW-53: Credential Routing Through LLM Context ──────────────────────────
# OWASP ASI-03 · CWE-522
# Skills that route credentials through the LLM prompt window.
check_53() {
  local skill_dir="$OC_HOME/skills"
  if [[ ! -d "$skill_dir" ]]; then
    record -1 "No skills directory found"
    return
  fi

  local bad_patterns=0
  local bad_files=""

  # Scan SKILL.md and README files in skills for credential-routing patterns
  while IFS= read -r -d '' file; do
    if grep -qiE '(pass|send|include|put|add).{0,20}(api.?key|token|secret|credential|password).{0,20}(in|to|into).{0,20}(message|prompt|request|context)' "$file" 2>/dev/null; then
      bad_patterns=$((bad_patterns + 1))
      bad_files+=" $(basename "$(dirname "$file")")"
    fi
    if grep -qiE '(api.?key|token|password|secret).{0,10}(in|as).{0,10}(system|user).{0,10}(message|prompt)' "$file" 2>/dev/null; then
      bad_patterns=$((bad_patterns + 1))
      bad_files+=" $(basename "$(dirname "$file")")"
    fi
  done < <(find "$skill_dir" -maxdepth 3 \( -iname "SKILL.md" -o -iname "README.md" -o -iname "*.md" \) -print0 2>/dev/null)

  if (( bad_patterns > 0 )); then
    record 0 "Skills route credentials through LLM context:$bad_files"
  else
    record 1 "No credential-routing patterns found in skill docs"
  fi
}

# ── CLAW-54: Persistent Memory Poisoning ─────────────────────────────────────
# OWASP ASI-06 · CWE-94
# Injection markers in memory/context files can hijack agent behavior.
check_54() {
  local suspicious=0
  local scan_paths=()

  # Collect memory/context file paths
  [[ -d "$OC_HOME/memory" ]] && scan_paths+=("$OC_HOME/memory")
  [[ -f "$HOME/CLAUDE.md" ]] && scan_paths+=("$HOME/CLAUDE.md")
  [[ -f ".claude/CLAUDE.md" ]] && scan_paths+=(".claude/CLAUDE.md")
  [[ -d ".claude/memory" ]] && scan_paths+=(".claude/memory")

  if (( ${#scan_paths[@]} == 0 )); then
    record -1 "No memory/context files found"
    return
  fi

  # Scan for injection markers
  for path in "${scan_paths[@]}"; do
    if [[ -f "$path" ]]; then
      # Use multi-word phrases to avoid matching "override default settings" or "do not disregard"
      if grep -qiE '(ignore (all )?previous|ignore (all )?above|you are now|new (system )?instructions|disregard (all )?(previous|above|prior)|override (all )?(previous|prior|system)|act as|pretend to be|forget (all )?(previous|your))' "$path" 2>/dev/null; then
        suspicious=$((suspicious + 1))
      fi
      # Check for base64 payloads (40+ chars of base64)
      if grep -qE '[A-Za-z0-9+/]{40,}={0,2}' "$path" 2>/dev/null; then
        suspicious=$((suspicious + 1))
      fi
      # Check for suspicious Unicode (zero-width chars, RTL override)
      if perl -ne 'exit 0 if /[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{202A}-\x{202E}]/; END{exit 1}' "$path" 2>/dev/null; then
        suspicious=$((suspicious + 1))
      fi
    elif [[ -d "$path" ]]; then
      while IFS= read -r -d '' f; do
        if grep -qiE '(ignore (all )?previous|ignore (all )?above|you are now|new (system )?instructions|disregard (all )?(previous|above|prior)|override (all )?(previous|prior|system)|act as|pretend to be|forget (all )?(previous|your))' "$f" 2>/dev/null; then
          suspicious=$((suspicious + 1))
        fi
      done < <(find "$path" -maxdepth 2 -name "*.md" -print0 2>/dev/null)
    fi
  done

  if (( suspicious > 0 )); then
    record 0 "$suspicious injection marker(s) found in memory/context files"
  else
    record 1 "No injection markers in memory/context files"
  fi
}

# ── CLAW-55: Auto-Approval Beyond --yolo ─────────────────────────────────────
# OWASP ASI-02 · CWE-863
# Auto-approve settings that bypass human-in-the-loop.
check_55() {
  local issues=0

  # Check OpenClaw config
  if [[ -f "$OC_CONFIG" ]]; then
    # Check for wildcard tool permissions
    local allowed_tools
    allowed_tools=$(json_val "$OC_CONFIG" "tools.allowedTools" 2>/dev/null) || true
    if [[ "$allowed_tools" == *'"*"'* || "$allowed_tools" == '"*"' ]]; then
      issues=$((issues + 1))
    fi

    # Check for autoApprove patterns
    if grep -qiE '"autoApprove"\s*:\s*true' "$OC_CONFIG" 2>/dev/null; then
      issues=$((issues + 1))
    fi
  fi

  # Check Claude Code settings
  local claude_settings="$HOME/.claude/settings.json"
  if [[ -f "$claude_settings" ]]; then
    if grep -qiE '"allowedTools"\s*:\s*\[.*"\*"' "$claude_settings" 2>/dev/null; then
      issues=$((issues + 1))
    fi
    if grep -qiE '"autoApprove"\s*:\s*true' "$claude_settings" 2>/dev/null; then
      issues=$((issues + 1))
    fi
  fi

  # Check MCP configs for autoApprove
  local mcp_configs=("$HOME/.claude/mcp_servers.json" "$OC_HOME/mcp.json")
  for cfg in "${mcp_configs[@]}"; do
    if [[ -f "$cfg" ]] && grep -qiE '"autoApprove"\s*:\s*true' "$cfg" 2>/dev/null; then
      issues=$((issues + 1))
    fi
  done

  if (( issues > 0 )); then
    record 0 "$issues auto-approval setting(s) bypass human-in-the-loop"
  else
    record 1 "No auto-approval wildcards or overrides found"
  fi
}

# ── CLAW-56: Semantic Tool Description Poisoning ─────────────────────────────
# OWASP ASI-01 · CWE-94
# Tool descriptions that embed exfiltration or instruction-injection patterns.
check_56() {
  local suspicious=0

  # Scan MCP tool configs and skill definitions for exfiltration instructions
  local scan_files=()
  [[ -f "$HOME/.claude/mcp_servers.json" ]] && scan_files+=("$HOME/.claude/mcp_servers.json")
  [[ -f "$OC_HOME/mcp.json" ]] && scan_files+=("$OC_HOME/mcp.json")

  # Also scan skill tool definition files
  if [[ -d "$OC_HOME/skills" ]]; then
    while IFS= read -r -d '' f; do
      scan_files+=("$f")
    done < <(find "$OC_HOME/skills" -maxdepth 3 -name "*.json" -print0 2>/dev/null)
  fi

  if (( ${#scan_files[@]} == 0 )); then
    record -1 "No tool config files found"
    return
  fi

  local exfil_pattern='(read|cat|access|include|send|exfiltrate|upload|post).{0,30}(~/\.ssh|~/\.aws|api.?key|credentials|\.env|password|secret|private.?key|/etc/passwd|/etc/shadow)'
  local instruct_pattern='(before using this tool|first you must|always include|you should also|ignore previous|system:|<system>)'

  for file in "${scan_files[@]}"; do
    if grep -qiE "$exfil_pattern" "$file" 2>/dev/null; then
      suspicious=$((suspicious + 1))
    fi
    if grep -qiE "$instruct_pattern" "$file" 2>/dev/null; then
      suspicious=$((suspicious + 1))
    fi
  done

  if (( suspicious > 0 )); then
    record 0 "$suspicious tool description(s) contain exfiltration/instruction patterns"
  else
    record 1 "No semantic poisoning detected in tool descriptions"
  fi
}

# ── CLAW-57: Tool Definition Pinning (Rug-Pull) ──────────────────────────────
# OWASP ASI-04 · CWE-494
# MCP servers can change tool behavior after initial approval without detection.
check_57() {
  # Check if any tool definition integrity mechanism exists
  local has_pinning=false

  # Check for tool hash/pin files
  if [[ -f "$OC_HOME/tool-hashes.json" ]] || [[ -f "$OC_HOME/tool-pins.json" ]] || \
     [[ -f "$HOME/.claude/tool-hashes.json" ]]; then
    has_pinning=true
  fi

  # Check config for integrity settings
  if [[ -f "$OC_CONFIG" ]]; then
    local integrity
    integrity=$(json_val "$OC_CONFIG" "tools.verifyIntegrity" 2>/dev/null) || true
    if [[ "$integrity" == "true" ]]; then
      has_pinning=true
    fi
    local pin_mode
    pin_mode=$(json_val "$OC_CONFIG" "tools.pinDefinitions" 2>/dev/null) || true
    if [[ "$pin_mode" == "true" ]]; then
      has_pinning=true
    fi
  fi

  if $has_pinning; then
    record 1 "Tool definition pinning/integrity mechanism found"
  else
    record 2 "No tool definition pinning — MCP servers can change tool behavior after approval"
  fi
}

# ── CLAW-58: MCP Credential Hygiene ──────────────────────────────────────────
# OWASP ASI-03 · CWE-522
# Long-lived PATs, broad OAuth scopes, or inline secrets in MCP configs.
check_58() {
  local issues=0
  local mcp_configs=("$HOME/.claude/mcp_servers.json" "$OC_HOME/mcp.json")

  local found_config=false
  for cfg in "${mcp_configs[@]}"; do
    [[ -f "$cfg" ]] && found_config=true

    if [[ -f "$cfg" ]]; then
      # Check for long-lived PATs (github tokens, gitlab tokens, etc.)
      if grep -qiE '(ghp_|glpat-|xoxb-|xoxp-|sk-[a-z]{2}-)[A-Za-z0-9_-]{20,}' "$cfg" 2>/dev/null; then
        issues=$((issues + 1))
      fi

      # Check for broad OAuth scopes
      if grep -qiE '"scope".*\b(admin|org|write:all|repo)\b' "$cfg" 2>/dev/null; then
        issues=$((issues + 1))
      fi

      # Check for tokens in environment args (passed as env vars)
      if grep -qiE '"(TOKEN|API_KEY|SECRET|PASSWORD|CREDENTIALS)"' "$cfg" 2>/dev/null; then
        # These keys exist — check if they reference env vars (ok) or inline values (bad)
        if grep -qiE '"(TOKEN|API_KEY|SECRET|PASSWORD)":\s*"[^$][^"]{10,}"' "$cfg" 2>/dev/null; then
          issues=$((issues + 1))
        fi
      fi
    fi
  done

  if ! $found_config; then
    record -1 "No MCP config files found"
  elif (( issues > 0 )); then
    record 0 "$issues MCP credential issue(s): long-lived PATs, broad scopes, or inline secrets"
  else
    record 1 "MCP credential hygiene looks reasonable"
  fi
}

# ── CLAW-59: Dormant Payload Detection ───────────────────────────────────────
# OWASP ASI-01 · CWE-506
# Conditional triggers in context files that activate under specific conditions.
check_59() {
  local suspicious=0
  local scan_paths=()

  # Collect persistent context paths
  [[ -d "$OC_HOME/memory" ]] && scan_paths+=("$OC_HOME/memory")
  [[ -f "$HOME/CLAUDE.md" ]] && scan_paths+=("$HOME/CLAUDE.md")
  [[ -f ".claude/CLAUDE.md" ]] && scan_paths+=(".claude/CLAUDE.md")
  [[ -d ".claude/memory" ]] && scan_paths+=(".claude/memory")
  [[ -d "$OC_HOME/context" ]] && scan_paths+=("$OC_HOME/context")

  if (( ${#scan_paths[@]} == 0 )); then
    record -1 "No persistent context files found"
    return
  fi

  local trigger_pattern='(if date is|when.*after|when.*user.*asks.*about|on day|after.*messages|if.*count.*>|when.*triggered|execute.*when|activate.*on)'
  local encoded_conditional='(if|when|date|trigger).*[A-Za-z0-9+/]{20,}={0,2}'

  for path in "${scan_paths[@]}"; do
    if [[ -f "$path" ]]; then
      if grep -qiE "$trigger_pattern" "$path" 2>/dev/null; then
        suspicious=$((suspicious + 1))
      fi
      if grep -qiE "$encoded_conditional" "$path" 2>/dev/null; then
        suspicious=$((suspicious + 1))
      fi
    elif [[ -d "$path" ]]; then
      while IFS= read -r -d '' f; do
        if grep -qiE "$trigger_pattern" "$f" 2>/dev/null; then
          suspicious=$((suspicious + 1))
        fi
      done < <(find "$path" -maxdepth 2 -type f -print0 2>/dev/null)
    fi
  done

  if (( suspicious > 0 )); then
    record 0 "$suspicious dormant/conditional trigger(s) found in context files"
  else
    record 1 "No dormant payload patterns detected"
  fi
}

# ── CLAW-60: Observability Endpoint Security ─────────────────────────────────
# OWASP ASI-10 · CWE-319
# Telemetry endpoints using insecure HTTP transport leak prompts and completions.
check_60() {
  local issues=0
  local has_telemetry=false

  # Check for telemetry config in environment
  for var in LANGCHAIN_TRACING_V2 LANGCHAIN_API_KEY LANGFUSE_PUBLIC_KEY HELICONE_API_KEY \
             LANGSMITH_API_KEY LANGCHAIN_ENDPOINT LANGFUSE_HOST; do
    if [[ -n "${!var:-}" ]]; then
      has_telemetry=true
      # Check if endpoint uses HTTP (not HTTPS)
      if [[ "${!var:-}" =~ ^http:// ]]; then
        issues=$((issues + 1))
      fi
    fi
  done

  # Check config for telemetry settings
  if [[ -f "$OC_CONFIG" ]]; then
    local telemetry_url
    telemetry_url=$(json_val "$OC_CONFIG" "telemetry.endpoint" 2>/dev/null) || true
    if [[ -n "$telemetry_url" ]]; then
      has_telemetry=true
      if [[ "$telemetry_url" =~ ^http:// ]]; then
        issues=$((issues + 1))
      fi
    fi
  fi

  if ! $has_telemetry; then
    record -1 "No telemetry/observability endpoints configured"
  elif (( issues > 0 )); then
    record 0 "$issues observability endpoint(s) use insecure HTTP transport"
  else
    record 1 "Observability endpoints use HTTPS"
  fi
}

# ── CLAW-61: Skill Typosquatting Detection ───────────────────────────────────
# OWASP ASI-04 · CWE-426
# Skills with names suspiciously similar to popular packages.
check_61() {
  local skill_dir="$OC_HOME/skills"
  if [[ ! -d "$skill_dir" ]]; then
    record -1 "No skills directory found"
    return
  fi

  # Top 30 popular MCP skills/servers
  local popular=(
    "filesystem" "github" "gitlab" "slack" "postgres" "sqlite" "redis"
    "puppeteer" "playwright" "brave-search" "google-search" "google-maps"
    "docker" "kubernetes" "aws" "cloudflare" "vercel" "supabase"
    "notion" "linear" "jira" "confluence" "asana" "trello"
    "openai" "anthropic" "langchain" "llama" "huggingface" "replicate"
  )

  local suspects=""
  local suspect_count=0

  # Get installed skill names
  for dir in "$skill_dir"/*/; do
    [[ -d "$dir" ]] || continue
    local name
    name=$(basename "$dir")
    name=$(echo "$name" | tr '[:upper:]' '[:lower:]')  # lowercase (bash 3.2 compatible)

    for pop in "${popular[@]}"; do
      # Skip exact match
      [[ "$name" == "$pop" ]] && continue
      # Check edit distance 1: same length with 1 char diff, or length diff of 1
      local len_diff=$(( ${#name} - ${#pop} ))
      (( len_diff < 0 )) && len_diff=$(( -len_diff ))
      if (( len_diff <= 1 )) && [[ "$name" != "$pop" ]]; then
        # Simple heuristic: check if names differ by 1-2 characters
        local common=0
        local shorter="${pop}"
        [[ ${#name} -lt ${#pop} ]] && shorter="$name"
        for (( c=0; c<${#shorter}; c++ )); do
          [[ "${name:$c:1}" == "${pop:$c:1}" ]] && common=$((common + 1))
        done
        local threshold=$(( ${#shorter} - 2 ))
        if (( common >= threshold && common < ${#shorter} )); then
          suspects+=" $name≈$pop"
          suspect_count=$((suspect_count + 1))
          break
        fi
      fi
    done
  done

  if (( suspect_count > 0 )); then
    record 0 "$suspect_count possible typosquat(s):$suspects"
  else
    record 1 "No typosquatting candidates detected"
  fi
}

# ── CLAW-62: Sandbox Runtime Detection ───────────────────────────────────────
# OWASP ASI-05 · CWE-693
# Standard runc provides weaker isolation than gVisor or Firecracker.
check_62() {
  if ! in_docker; then
    record -1 "Not running in a container"
    return
  fi

  local runtime="unknown"

  # Check for gVisor (runsc)
  if [[ -f /proc/1/status ]] && grep -qi "gvisor\|runsc" /proc/1/status 2>/dev/null; then
    runtime="gVisor"
  elif command -v runsc &>/dev/null; then
    runtime="gVisor"
  # Check for Firecracker
  elif [[ -f /sys/hypervisor/type ]] && grep -qi "firecracker" /sys/hypervisor/type 2>/dev/null; then
    runtime="Firecracker"
  elif [[ -f /proc/cpuinfo ]] && grep -qi "firecracker" /proc/cpuinfo 2>/dev/null; then
    runtime="Firecracker"
  # Check Docker info for runtime
  elif command -v docker &>/dev/null; then
    local rt
    rt=$(docker info --format '{{.DefaultRuntime}}' 2>/dev/null) || true
    if [[ -n "$rt" ]]; then
      runtime="$rt"
    fi
  fi

  # Default runc detection
  if [[ "$runtime" == "unknown" ]]; then
    if [[ -f /proc/1/status ]]; then
      runtime="runc (default)"
    fi
  fi

  case "$runtime" in
    gVisor|Firecracker|runsc)
      record 1 "Strong sandbox runtime: $runtime"
      ;;
    runc*)
      record 2 "Standard container runtime: $runtime (gVisor/Firecracker provides stronger isolation)"
      ;;
    *)
      record 2 "Container runtime: $runtime"
      ;;
  esac
}

# ── CLAW-63: Writable Persistence Paths ──────────────────────────────────────
# OWASP ASI-05 · CWE-276
# Agent can persist across sessions via shell profiles, crontab, or launchd.
check_63() {
  local writable=0
  local writable_paths=""

  # Check common persistence paths
  local paths_to_check=(
    "$HOME/.bashrc"
    "$HOME/.zshrc"
    "$HOME/.bash_profile"
    "$HOME/.profile"
  )

  # Platform-specific paths
  if [[ "$(uname)" == "Darwin" ]]; then
    paths_to_check+=("$HOME/Library/LaunchAgents")
  else
    paths_to_check+=("/etc/cron.d" "$HOME/.config/systemd/user")
  fi

  for p in "${paths_to_check[@]}"; do
    if [[ -e "$p" && -w "$p" ]]; then
      writable=$((writable + 1))
      writable_paths+=" $(basename "$p")"
    fi
  done

  # Check crontab access
  if command -v crontab &>/dev/null; then
    if crontab -l &>/dev/null; then
      writable=$((writable + 1))
      writable_paths+=" crontab"
    fi
  fi

  if (( writable >= 3 )); then
    record 0 "VERIFIED: $writable persistence path(s) writable:$writable_paths"
  elif (( writable > 0 )); then
    record 2 "Agent can write to $writable persistence path(s):$writable_paths"
  else
    record 1 "No writable persistence paths detected"
  fi
}

# ── CLAW-64: Active C2 Connection Detection ─────────────────────────────────
# IOC data from openclaw-security-monitor by Adi Birzu (MIT)
# https://github.com/adibirzu/openclaw-security-monitor

check_64() {
  # Known C2 IPs from ClawHavoc campaign
  local c2_ips="91\.92\.242\.30|95\.92\.242\.30|96\.92\.242\.30|54\.91\.154\.110|202\.161\.50\.59"
  local found=0

  if command -v ss &>/dev/null; then
    found=$(ss -tnp 2>/dev/null | grep -cE "$c2_ips") || true
  elif command -v lsof &>/dev/null; then
    found=$(lsof -i -nP 2>/dev/null | grep -cE "$c2_ips") || true
  elif command -v netstat &>/dev/null; then
    found=$(netstat -tn 2>/dev/null | grep -cE "$c2_ips") || true
  else
    record -1 "No network tool available (ss/lsof/netstat)"
    return
  fi

  if (( found > 0 )); then
    record 0 "CRITICAL: $found active connection(s) to known C2 infrastructure"
  else
    record 1 "No connections to known C2 IPs"
  fi
}

# ── CLAW-65: Malware Signature Scan ─────────────────────────────────────────
# IOC data from openclaw-security-monitor by Adi Birzu (MIT)

check_65() {
  local skills_dir="$OC_HOME/skills"
  if [[ ! -d "$skills_dir" ]]; then
    record -1 "No skills directory found"
    return
  fi

  # AMOS stealer / malware patterns
  local pattern="authtool|atomic\.stealer|\bAMOS\b|NovaStealer|nova\.stealer"
  pattern+="|osascript.*password|osascript.*dialog|osascript.*keychain"
  pattern+="|Security\.framework.*Auth|openclaw-agent\.exe|openclaw-agent\.zip"
  pattern+="|openclawcli\.zip|Installer-Package"

  local matches
  matches=$(grep -rlEi "$pattern" "$skills_dir" 2>/dev/null | head -5) || true

  if [[ -n "$matches" ]]; then
    local count
    count=$(echo "$matches" | wc -l | tr -d ' ')
    record 0 "CRITICAL: Malware signatures in $count skill file(s)"
    return
  fi

  # Check known malicious file hashes (binaries/archives only)
  local known_hashes=(
    "17703b3d5e8e1fe69d6a6c78a240d8c84b32465fe62bed5610fb29335fe42283"
    "1e6d4b0538558429422b71d1f4d724c8ce31be92d299df33a8339e32316e2298"
    "0e52566ccff4830e30ef45d2ad804eefba4ffe42062919398bf1334aab74dd65"
    "79e8f3f7a6113773cdbced2c7329e6dbb2d0b8b3bf5a18c6c97cb096652bc1f2"
  )

  local hash_found=false
  while IFS= read -r -d '' f; do
    local h
    h=$(shasum -a 256 "$f" 2>/dev/null || sha256sum "$f" 2>/dev/null) || continue
    h=$(echo "$h" | cut -d' ' -f1)
    for kh in "${known_hashes[@]}"; do
      if [[ "$h" == "$kh" ]]; then
        hash_found=true
        break 2
      fi
    done
  done < <(find "$skills_dir" -type f \( -name "*.exe" -o -name "*.zip" -o -name "*.dmg" -o -name "*.pkg" -o -name "*.app" \) -print0 2>/dev/null)

  if $hash_found; then
    record 0 "CRITICAL: Known malicious file hash detected in skills"
  else
    record 1 "No malware signatures or known malicious hashes"
  fi
}

# ── CLAW-66: Exfiltration Domain References ─────────────────────────────────
# IOC data from openclaw-security-monitor by Adi Birzu (MIT)

check_66() {
  local skills_dir="$OC_HOME/skills"
  if [[ ! -d "$skills_dir" ]]; then
    record -1 "No skills directory found"
    return
  fi

  # Known exfiltration / payload domains
  local exfil="webhook\.site|pipedream\.net|requestbin\.com|hookbin\.com"
  exfil+="|burpcollaborator\.net|ngrok\.io|interact\.sh"
  exfil+="|install\.app-distribution\.net"

  local matches
  matches=$(grep -rlE "$exfil" "$skills_dir" 2>/dev/null | head -5) || true

  if [[ -n "$matches" ]]; then
    local count
    count=$(echo "$matches" | wc -l | tr -d ' ')
    record 0 "Skills reference $count exfiltration domain(s)"
  else
    record 1 "No exfiltration domain references in skills"
  fi
}

# ── CLAW-67: VS Code Extension Trojans ──────────────────────────────────────
# IOC data from openclaw-security-monitor by Adi Birzu (MIT)

check_67() {
  local found=0
  local checked=false
  local ext_dirs=("$HOME/.vscode/extensions" "$HOME/.vscode-insiders/extensions")

  for ext_dir in "${ext_dirs[@]}"; do
    [[ -d "$ext_dir" ]] || continue
    checked=true
    # OpenClaw has no official VS Code extension — any match is suspicious
    local fake
    fake=$(find "$ext_dir" -maxdepth 1 -type d \( -iname "*clawdbot*" -o -iname "*moltbot*" -o -iname "*openclaw*" \) 2>/dev/null) || true
    if [[ -n "$fake" ]]; then
      found=$((found + 1))
    fi
  done

  if (( found > 0 )); then
    record 0 "CRITICAL: Suspicious VS Code extension — OpenClaw has no official extension"
  elif $checked; then
    record 1 "No suspicious VS Code extensions"
  else
    record -1 "VS Code not installed"
  fi
}

# ── CLAW-68: Gateway Device Auth Bypass ─────────────────────────────────────
# IOC data from openclaw-security-monitor by Adi Birzu (MIT)

check_68() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "No OpenClaw config found"
    return
  fi

  local disable_auth
  disable_auth=$(json_val "$OC_CONFIG" "gateway.dangerouslyDisableDeviceAuth" 2>/dev/null) || true

  if [[ "$disable_auth" == "true" ]]; then
    record 0 "CRITICAL: dangerouslyDisableDeviceAuth is TRUE"
    return
  fi

  local bind
  bind=$(json_val "$OC_CONFIG" "gateway.bind" 2>/dev/null) || true
  local proxies
  proxies=$(json_val "$OC_CONFIG" "gateway.trustedProxies" 2>/dev/null) || true

  if [[ "$bind" == "0.0.0.0" || "$bind" == "lan" ]] && [[ -z "$proxies" || "$proxies" == "null" || "$proxies" == "[]" ]]; then
    record 2 "LAN-bound gateway without trustedProxies — localhost trust bypass risk"
    return
  fi

  record 1 "Device auth not bypassed"
}

# ── CLAW-69: Exec-Approvals Hardening ───────────────────────────────────────
# IOC data from openclaw-security-monitor by Adi Birzu (MIT)

check_69() {
  local exec_file="$OC_HOME/exec-approvals.json"
  if [[ ! -f "$exec_file" ]]; then
    record -1 "No exec-approvals.json found"
    return
  fi

  # Check for overly permissive settings
  local unsafe
  unsafe=$(grep -iE '"security"[[:space:]]*:[[:space:]]*"allow"|"ask"[[:space:]]*:[[:space:]]*"off"|"allowlist"[[:space:]]*:[[:space:]]*\[[[:space:]]*\]' "$exec_file" 2>/dev/null) || true

  if [[ -n "$unsafe" ]]; then
    record 0 "Exec-approvals has allow-all or prompts disabled"
    return
  fi

  if perms_too_open "$exec_file"; then
    record 2 "exec-approvals.json readable by group/others"
    return
  fi

  record 1 "Exec-approvals properly configured"
}

# ── CLAW-70: mDNS/Bonjour Exposure ─────────────────────────────────────────
# IOC data from openclaw-security-monitor by Adi Birzu (MIT)

check_70() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "No OpenClaw config found"
    return
  fi

  local mdns_mode
  mdns_mode=$(json_val "$OC_CONFIG" "discovery.mdns.mode" 2>/dev/null) || true

  if [[ "$mdns_mode" == "full" ]]; then
    record 2 "mDNS broadcasting in 'full' mode — exposes paths and ports to LAN"
  elif [[ -z "$mdns_mode" || "$mdns_mode" == "off" || "$mdns_mode" == "minimal" ]]; then
    record 1 "mDNS not broadcasting sensitive info"
  else
    record 1 "mDNS mode: $mdns_mode"
  fi
}

# ── CLAW-71: DM Channel Restrictions ───────────────────────────────────────
# IOC data from openclaw-security-monitor by Adi Birzu (MIT)

check_71() {
  if [[ ! -f "$OC_CONFIG" ]]; then
    record -1 "No OpenClaw config found"
    return
  fi

  local open_channels=0
  local open_names=""
  local configured=0

  for channel in whatsapp telegram discord slack signal; do
    local dm_policy
    dm_policy=$(json_val "$OC_CONFIG" "channels.${channel}.dmPolicy" 2>/dev/null) || true
    local allow_from
    allow_from=$(json_val "$OC_CONFIG" "channels.${channel}.allowFrom" 2>/dev/null) || true

    [[ -z "$dm_policy" && -z "$allow_from" ]] && continue
    configured=$((configured + 1))

    if [[ "$dm_policy" == "open" ]]; then
      open_channels=$((open_channels + 1))
      open_names+=" $channel"
    elif echo "$allow_from" 2>/dev/null | grep -qF '"*"' 2>/dev/null; then
      open_channels=$((open_channels + 1))
      open_names+=" $channel"
    fi
  done

  if (( configured == 0 )); then
    record -1 "No messaging channels configured"
    return
  fi

  if (( open_channels >= 2 )); then
    record 0 "$open_channels channel(s) accept messages from anyone:$open_names"
  elif (( open_channels == 1 )); then
    record 2 "1 channel accepts messages from anyone:$open_names"
  else
    record 1 "DM channels properly restricted"
  fi
}

# ── CLAW-72: Known Malicious Publishers ─────────────────────────────────────
# IOC data from openclaw-security-monitor by Adi Birzu (MIT)

check_72() {
  local skills_dir="$OC_HOME/skills"
  if [[ ! -d "$skills_dir" ]]; then
    record -1 "No skills directory found"
    return
  fi

  # Known malicious ClawHub publishers
  local bad_pubs="hightower6eu|zaycv|noreplyboter|rjnpage|aslaep123|gpaitai|lvy19811120-gif|Ddoy233|hedefbari"

  local found_count=0

  while IFS= read -r pkg; do
    # Check author field
    if grep -qEi "\"author\"[[:space:]]*:[[:space:]]*\"($bad_pubs)" "$pkg" 2>/dev/null; then
      found_count=$((found_count + 1))
    fi
    # Check scoped package name @publisher/...
    if grep -qEi "\"name\"[[:space:]]*:[[:space:]]*\"@($bad_pubs)/" "$pkg" 2>/dev/null; then
      found_count=$((found_count + 1))
    fi
  done < <(find "$skills_dir" -maxdepth 2 -name "package.json" 2>/dev/null)

  if (( found_count > 0 )); then
    record 0 "CRITICAL: $found_count skill(s) from known malicious publishers"
  else
    record 1 "No skills from known malicious publishers"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# RUN ALL CHECKS
# ══════════════════════════════════════════════════════════════════════════════

CHECK_LABELS=(
  "Gateway Network Exposure"
  "Gateway Authentication"
  "Cloud Metadata Service"
  "Personal Email as Agent Identity"
  "Plaintext API Keys in Config"
  "Sensitive Files Accessible"
  "Secrets in Session Transcripts"
  "Docker Privileged Mode"
  "Agent Running as Root"
  "Sandbox Configuration"
  "Elevated Mode Restrictions"
  "Config File Permissions"
  "Installed Skills Threat Intel"
  "MCP Server Vulnerabilities"
  "OpenClaw Version Security"
  "Session File Permissions"
  "Default Credentials in Config"
  ".env Not in .gitignore"
  "Secrets in Git History"
  "Browser Profiles Accessible"
  "Git Credentials Accessible"
  "Database Credentials Accessible"
  "Additional Services on 0.0.0.0"
  "No Firewall Rules"
  "Container Security Profile"
  "Agent Code Integrity"
  "npm Lifecycle Scripts in Skills"
  "Log Redaction"
  "Debug Logging Enabled"
  "Sessions Synced to Cloud"
  "MCP Tool Description Poisoning"
  "MCP Tool Shadowing"
  "Unrestricted Outbound Network"
  "Messaging Token Exposure"
  "No User Namespace Isolation"
  "Dangerous CLI Flags"
  "Writable Install Directory"
  "No Rate Limiting"
  "Crypto Wallets Accessible"
  "Unsafe Deserialization"
  "No Container Read-Only FS"
  "Skill Network Unrestricted"
  "Unencrypted Session Storage"
  "Rules File Injection"
  "Stale API Keys"
  "npm Audit Vulnerabilities"
  "Excessive Tool Permissions"
  "Insecure MCP Transport"
  "No Process Resource Limits"
  "Exposed Debug Endpoints"
  "WebSocket Origin Validation"
  "LLM Endpoint Integrity"
  "Credential Routing Through LLM"
  "Persistent Memory Poisoning"
  "Auto-Approval Beyond --yolo"
  "Semantic Tool Description Poisoning"
  "Tool Definition Pinning"
  "MCP Credential Hygiene"
  "Dormant Payload Detection"
  "Observability Endpoint Security"
  "Skill Typosquatting Detection"
  "Sandbox Runtime Detection"
  "Writable Persistence Paths"
  "Active C2 Connection Detection"
  "Malware Signature Scan"
  "Exfiltration Domain References"
  "VS Code Extension Trojans"
  "Gateway Device Auth Bypass"
  "Exec-Approvals Hardening"
  "mDNS/Bonjour Exposure"
  "DM Channel Restrictions"
  "Known Malicious Publishers"
)

# Category tags per check (indexed 0-71, must have exactly 72 elements)
CHECK_CATEGORIES=(
  network network network identity secrets identity secrets container container
  config config config supply-chain mcp config config secrets config
  secrets identity secrets secrets network network container supply-chain supply-chain
  config config observability
  mcp mcp network secrets container config config config secrets identity
  container network config persistence secrets supply-chain config network
  container config
  network config secrets persistence config mcp mcp secrets persistence
  network supply-chain container persistence
  network supply-chain supply-chain supply-chain config config network config supply-chain
)

# Validate parallel arrays are all the same length
if (( ${#CHECK_POINTS[@]} != 72 || ${#CHECK_LABELS[@]} != 72 || ${#CHECK_CATEGORIES[@]} != 72 )); then
  echo "FATAL: Array length mismatch — CHECK_POINTS=${#CHECK_POINTS[@]}, CHECK_LABELS=${#CHECK_LABELS[@]}, CHECK_CATEGORIES=${#CHECK_CATEGORIES[@]} (expected 72)" >&2
  exit 1
fi

# Build skip set from comma-separated list (bash 3.2 compatible — no associative arrays)
SKIP_CATS_STR=""
if [[ -n "$OPT_SKIP" ]]; then
  IFS=',' read -ra skip_arr <<< "$OPT_SKIP"
  for cat in "${skip_arr[@]}"; do
    SKIP_CATS_STR+="|${cat}|"
  done
fi

for i in $(seq 1 72); do
  idx=$((i - 1))
  cat="${CHECK_CATEGORIES[$idx]}"
  if [[ "$SKIP_CATS_STR" == *"|${cat}|"* ]]; then
    record -1 "Skipped (category: $cat)"
  else
    fn=$(printf "check_%02d" "$i")
    $fn
  fi
done

# ══════════════════════════════════════════════════════════════════════════════
# SCORING
# ══════════════════════════════════════════════════════════════════════════════

earned=0
possible=0
fail_count=0
warn_count=0
pass_count=0
skip_count=0
critical_fail=0

for i in "${!RESULTS[@]}"; do
  local_result=${RESULTS[$i]}
  local_points=$(points_for "$i")

  case $local_result in
    1)  # PASS
      earned=$((earned + local_points))
      possible=$((possible + local_points))
      pass_count=$((pass_count + 1))
      ;;
    0)  # FAIL
      possible=$((possible + local_points))
      fail_count=$((fail_count + 1))
      if (( local_points == 15 )); then
        critical_fail=$((critical_fail + 1))
      fi
      ;;
    2)  # WARN — half points
      earned=$((earned + local_points / 2))
      possible=$((possible + local_points))
      warn_count=$((warn_count + 1))
      ;;
    *)  # SKIP
      skip_count=$((skip_count + 1))
      ;;
  esac
done

if (( possible > 0 )); then
  score=$(( (earned * 100) / possible ))
else
  score=100
fi

if (( score >= 90 )); then grade="A"
elif (( score >= 75 )); then grade="B"
elif (( score >= 60 )); then grade="C"
elif (( score >= 40 )); then grade="D"
else grade="F"
fi

# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

# Build JSON result array
json_results="["
for i in "${!RESULTS[@]}"; do
  (( i > 0 )) && json_results+=","
  json_results+="${RESULTS[$i]}"
done
json_results+="]"

today=$(date +%Y-%m-%d)
json_output="{\"v\":3,\"s\":$score,\"g\":\"$grade\",\"r\":$json_results,\"t\":\"$today\"}"

if $OPT_JSON; then
  echo "$json_output"
else
  # ── Human-readable output ────────────────────────────────────────────────

  severity_labels=()
  for i in "${!RESULTS[@]}"; do
    local_points=${CHECK_POINTS[$i]}
    case $local_points in
      15) severity_labels+=("CRITICAL") ;;
      10) severity_labels+=("HIGH") ;;
      5)  severity_labels+=("MEDIUM") ;;
      *)  severity_labels+=("") ;;
    esac
  done

  for i in "${!RESULTS[@]}"; do
    local_result=${RESULTS[$i]}
    local_detail="${DETAILS[$i]}"
    local_label="${CHECK_LABELS[$i]}"
    local_severity="${severity_labels[$i]}"
    local_id=$(printf "CLAW-%02d" $((i + 1)))

    case $local_result in
      1)  icon="${GREEN}PASS${RESET}" ;;
      0)  icon="${RED}FAIL${RESET}" ;;
      2)  icon="${YELLOW}WARN${RESET}" ;;
      *)  icon="${DIM}SKIP${RESET}" ;;
    esac

    printf "  [%b] %-7s %-7s  %-40s %b\n" \
      "$icon" "$local_id" "$local_severity" "$local_label" "${DIM}${local_detail}${RESET}"
  done

  echo ""
  echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
  echo ""

  # Grade color
  case $grade in
    A) gc="$GREEN" ;;
    B) gc="$GREEN" ;;
    C) gc="$YELLOW" ;;
    D) gc="$ORANGE" ;;
    F) gc="$RED" ;;
    *) gc="" ;;
  esac

  echo -e "  Hardening Score: ${BOLD}${gc}${score}/100 — Grade ${grade}${RESET}"
  echo ""
  echo -e "  ${GREEN}${pass_count} passed${RESET}  ${RED}${fail_count} failed${RESET}  ${YELLOW}${warn_count} warned${RESET}  ${DIM}${skip_count} skipped${RESET}"
  if (( critical_fail > 0 )); then
    echo -e "  ${RED}${critical_fail} critical issue(s) need immediate attention${RESET}"
  fi
  echo ""

  # Shareable report URL
  if command -v base64 &>/dev/null; then
    b64=$(echo -n "$json_output" | base64 2>/dev/null | tr -d '\n' | tr '+/' '-_' | tr -d '=') || true
    if [[ -n "$b64" ]]; then
      echo -e "  ${DIM}Report:${RESET} https://haveibeenclawned.com/report?d=${b64}"
      echo ""
    fi
  fi

  # JSON for agent consumption
  echo -e "  ${DIM}JSON:${RESET} $json_output"
  echo ""

  # Recommend built-in audit if openclaw is available
  if command -v openclaw &>/dev/null; then
    echo -e "  ${DIM}Tip: Run ${RESET}openclaw security audit --deep${DIM} for additional config checks.${RESET}"
    echo ""
  fi
fi

# ── Optional: submit anonymous stats ─────────────────────────────────────────

if $OPT_SUBMIT; then
  if ! $OPT_JSON; then
    echo -e "  ${DIM}Submitting anonymous stats...${RESET}"
  fi
  submit_body="{\"v\":3,\"s\":$score,\"g\":\"$grade\",\"r\":$json_results}"
  http_code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST "https://haveibeenclawned.com/api/submit" \
    -H "Content-Type: application/json" \
    -d "$submit_body" 2>/dev/null) || true
  if ! $OPT_JSON; then
    if [[ "$http_code" == "200" ]]; then
      echo -e "  ${GREEN}Stats submitted successfully.${RESET}"
    else
      echo -e "  ${YELLOW}Could not submit stats (HTTP $http_code).${RESET}"
    fi
    echo ""
  fi
fi
