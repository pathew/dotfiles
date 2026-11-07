# dotfiles

Machine config and DevSecOps tooling.

## Contents

| File | Purpose |
|------|---------|
| `git/hooks/pre-push` | Universal security gate — blocks pushes with Bandit/Semgrep/Grype findings |
| `git/security/nightly_scan.sh` | Nightly scan across all active projects (cron at 2:13am) |

## Install

```bash
git clone https://github.com/patrickhew/dotfiles.git ~/dotfiles
cd ~/dotfiles && bash install.sh
```

Then one-time per machine:

```bash
git config --global core.hooksPath ~/.config/git/hooks
chmod +x ~/.config/git/hooks/pre-push
# Add to crontab:
# 13 2 * * * bash ~/.config/git/security/nightly_scan.sh
```

## Active projects (nightly full scan)

Configured in `git/security/nightly_scan.sh` → `ACTIVE_PROJECTS` array:

- trading-intelligence
- forex-trade
- pokemon-tracker
- market-data-platform

Stale projects are auto-discovered and watched for activity. A macOS notification fires if commits appear.
