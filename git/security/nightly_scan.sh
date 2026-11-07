#!/usr/bin/env bash
# Nightly security scan — full scans on active projects; activity-only check on stale ones.
# Installed in crontab: 13 2 * * * bash ~/.config/git/security/nightly_scan.sh
#
# Active projects: full Bandit + Semgrep + SBOM/Grype + npm audit every night.
# Stale projects: skipped unless they have commits since the last scan run,
#                 in which case a macOS notification prompts you to trigger a manual scan.
#
# To activate a stale project: add its directory name to ACTIVE_PROJECTS below.
# To suppress stale-project notifications: add name to STALE_QUIET below.
set -euo pipefail

LOG_DIR="$HOME/.local/logs"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/security-scan.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
TOTAL_FAILURES=0

log()   { echo "$1" | tee -a "$LOG"; }
pass()  { log "[PASS] $1"; }
fail()  { log "[FAIL] $1"; TOTAL_FAILURES=$((TOTAL_FAILURES+1)); }
warn()  { log "[WARN] $1"; }
header(){ log ""; log "=== $1 ==="; }

log ""
log "╔══════════════════════════════════════════════════╗"
log "║  Nightly Security Scan — $TIMESTAMP  ║"
log "╚══════════════════════════════════════════════════╝"

# ─── Active projects — full scan every night ──────────────────────────────────
# Add a project's directory name here to include it in the nightly full scan.
ACTIVE_PROJECTS=(
    "trading-intelligence"
    "forex-trade"
    "pokemon-tracker"
    "market-data-platform"
)

# ─── Auto-discover all project repos ─────────────────────────────────────────
SEARCH_ROOTS="${SECURITY_SCAN_ROOTS:-$HOME/source/Claude-code}"

ACTIVE_REPOS=()
STALE_REPOS=()
while IFS= read -r gitdir; do
    repo="$(dirname "$gitdir")"
    name="$(basename "$repo")"
    # Include if it has Python or npm dependencies
    if [ -f "$repo/requirements.txt" ] || [ -f "$repo/backend/requirements.txt" ] || \
       [ -f "$repo/app/requirements.txt" ] || [ -f "$repo/package.json" ] || \
       [ -f "$repo/frontend/package.json" ] || [ -f "$repo/interface/web/frontend/package.json" ]; then
        # Bucket into active vs stale
        is_active=0
        for ap in "${ACTIVE_PROJECTS[@]}"; do
            [ "$name" = "$ap" ] && is_active=1 && break
        done
        if [ "$is_active" -eq 1 ]; then
            ACTIVE_REPOS+=("$repo")
        else
            STALE_REPOS+=("$repo")
        fi
    fi
done < <(find $SEARCH_ROOTS -maxdepth 3 -name ".git" -type d 2>/dev/null | sort)

if [ ${#ACTIVE_REPOS[@]} -eq 0 ]; then
    log "No active projects found under $SEARCH_ROOTS — check ACTIVE_PROJECTS list"
    exit 1
fi

log "Active (full scan): ${#ACTIVE_REPOS[@]}"
for r in "${ACTIVE_REPOS[@]}"; do log "  · $(basename "$r")"; done
if [ ${#STALE_REPOS[@]} -gt 0 ]; then
    log "Stale (activity-watch only): ${#STALE_REPOS[@]}"
    for r in "${STALE_REPOS[@]}"; do log "  · $(basename "$r")"; done
fi

# ─── Helper: run full scan on a single repo ───────────────────────────────────
scan_repo() {
    local REPO="$1"
    local PROJECT="$(basename "$REPO")"
    header "$PROJECT"

    # Detect requirements file
    local REQ_FILE=""
    for f in "$REPO/requirements.txt" "$REPO/backend/requirements.txt" \
              "$REPO/app/requirements.txt" "$REPO/src/requirements.txt"; do
        [ -f "$f" ] && REQ_FILE="$f" && break
    done

    # Detect frontend
    local FRONTEND=""
    for d in "$REPO/frontend" "$REPO/interface/web/frontend" \
              "$REPO/client" "$REPO/web" "$REPO/ui"; do
        [ -f "$d/package.json" ] && FRONTEND="$d" && break
    done

    # Build Bandit exclude list
    local BANDIT_EXCLUDE="$REPO/dist,$REPO/build,$REPO/.sbom"
    for venv in "$REPO/.venv" "$REPO/venv" "$REPO/backend/.venv" "$REPO/backend/venv"; do
        [ -d "$venv" ] && BANDIT_EXCLUDE="$BANDIT_EXCLUDE,$venv"
    done
    for nd in "$REPO/node_modules" "$REPO/frontend/node_modules" \
              "$REPO/interface/web/frontend/node_modules"; do
        [ -d "$nd" ] && BANDIT_EXCLUDE="$BANDIT_EXCLUDE,$nd"
    done

    local SBOM_DIR="$REPO/.sbom"
    mkdir -p "$SBOM_DIR"

    # 1. Bandit
    if [ -n "$REQ_FILE" ] && command -v bandit &>/dev/null; then
        local BANDIT_OUT
        BANDIT_OUT=$(bandit -r "$REPO" --exclude "$BANDIT_EXCLUDE" -ll -q 2>&1 || true)
        local COUNT
        COUNT=$(echo "$BANDIT_OUT" | grep -c ">> Issue:" || true)
        if [ "$COUNT" -gt 0 ]; then
            fail "[$PROJECT] Bandit: $COUNT issue(s)"
            echo "$BANDIT_OUT" | grep -A2 ">> Issue:" | head -30 >> "$LOG"
        else
            pass "[$PROJECT] Bandit: clean"
        fi
    else
        warn "[$PROJECT] Bandit: skipped (no requirements.txt or bandit not installed)"
    fi

    # 2. Semgrep
    if command -v semgrep &>/dev/null; then
        local SEMGREP_EXIT=0
        semgrep --config=auto --error "$REPO" \
            --exclude .venv --exclude venv \
            --exclude backend/.venv --exclude backend/venv \
            --exclude node_modules --exclude dist --exclude build \
            --quiet >> "$LOG" 2>&1 || SEMGREP_EXIT=$?
        if [ "$SEMGREP_EXIT" -ne 0 ]; then
            fail "[$PROJECT] Semgrep: findings detected"
        else
            pass "[$PROJECT] Semgrep: clean"
        fi
    else
        warn "[$PROJECT] Semgrep: not installed"
    fi

    # 3. SBOM + Grype
    if command -v cyclonedx-py &>/dev/null && command -v grype &>/dev/null; then
        if [ -n "$REQ_FILE" ]; then
            cyclonedx-py requirements --of JSON \
                -o "$SBOM_DIR/python-sbom.json" "$REQ_FILE" 2>/dev/null || true

            if [ -f "$SBOM_DIR/python-sbom.json" ]; then
                local GRYPE_OUT
                GRYPE_OUT=$(grype "sbom:$SBOM_DIR/python-sbom.json" --output table 2>&1 || true)
                local HIGH
                HIGH=$(echo "$GRYPE_OUT" | grep -cE "High|Critical" || true)
                if [ "$HIGH" -gt 0 ]; then
                    fail "[$PROJECT] Grype Python: $HIGH HIGH/CRITICAL CVE(s)"
                    echo "$GRYPE_OUT" | grep -E "High|Critical" >> "$LOG"
                else
                    pass "[$PROJECT] Grype Python: clean"
                fi
            fi
        fi

        if [ -n "$FRONTEND" ] && [ -f "$FRONTEND/package.json" ]; then
            if (cd "$FRONTEND" && npm sbom --sbom-format cyclonedx \
                --package-lock-only > "$SBOM_DIR/npm-sbom.json" 2>/dev/null); then
                local GRYPE_NPM
                GRYPE_NPM=$(grype "sbom:$SBOM_DIR/npm-sbom.json" --output table 2>&1 || true)
                local NPM_HIGH
                NPM_HIGH=$(echo "$GRYPE_NPM" | grep -cE "High|Critical" || true)
                if [ "$NPM_HIGH" -gt 0 ]; then
                    fail "[$PROJECT] Grype npm: $NPM_HIGH CVE(s)"
                    echo "$GRYPE_NPM" | grep -E "High|Critical" >> "$LOG"
                else
                    pass "[$PROJECT] Grype npm: clean"
                fi
            fi
        fi
    else
        warn "[$PROJECT] SBOM scan: cyclonedx-py or grype not installed"
    fi

    # 4. npm audit
    if [ -n "$FRONTEND" ] && [ -f "$FRONTEND/package.json" ]; then
        local NPM_EXIT=0
        (cd "$FRONTEND" && npm audit --audit-level=high >> "$LOG" 2>&1) || NPM_EXIT=$?
        if [ "$NPM_EXIT" -ne 0 ]; then
            fail "[$PROJECT] npm audit: high/critical vulnerabilities"
        else
            pass "[$PROJECT] npm audit: clean"
        fi
    fi
}

# ─── Full scan: active projects ───────────────────────────────────────────────
for REPO in "${ACTIVE_REPOS[@]}"; do
    scan_repo "$REPO"
done

# ─── Activity watch: stale projects ──────────────────────────────────────────
# If a stale project has commits since the last scan run, notify the user.
# No scan is run — just a prompt to trigger one manually when ready.
STALE_CHANGED=()
for REPO in "${STALE_REPOS[@]}"; do
    PROJECT="$(basename "$REPO")"
    # Commits in the last 24 h (matches nightly cadence)
    RECENT=$(git -C "$REPO" log --oneline --since="24 hours ago" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$RECENT" -gt 0 ]; then
        STALE_CHANGED+=("$PROJECT ($RECENT commit(s))")
        log "[STALE-CHANGED] $PROJECT: $RECENT new commit(s) — security scan not yet run"
    fi
done

# ─── Summary ──────────────────────────────────────────────────────────────────
log ""
log "════════════════════════════════════════════════════"
if [ "$TOTAL_FAILURES" -eq 0 ]; then
    log "[OK] All active projects clean — $TIMESTAMP"
else
    log "[ALERT] $TOTAL_FAILURES check(s) failed — see $LOG"
    osascript -e "display notification \"$TOTAL_FAILURES issue(s) in active projects — check ~/.local/logs/security-scan.log\" with title \"Nightly Security Scan\" sound name \"Basso\"" 2>/dev/null || true
fi

if [ ${#STALE_CHANGED[@]} -gt 0 ]; then
    STALE_LIST=$(printf "%s, " "${STALE_CHANGED[@]}" | sed 's/, $//')
    log "[INFO] Stale projects with recent commits: $STALE_LIST"
    osascript -e "display notification \"${STALE_LIST} — want to run a security scan? Open Claude Code and ask.\" with title \"Stale Project Activity\" sound name \"Blow\"" 2>/dev/null || true
fi
