#!/usr/bin/env bash
# Installs dotfiles by symlinking them into place.
# Safe to re-run — existing symlinks are skipped.
set -euo pipefail

DOTFILES="$(cd "$(dirname "$0")" && pwd)"

symlink() {
    local src="$1" dst="$2"
    mkdir -p "$(dirname "$dst")"
    if [ -L "$dst" ] && [ "$(readlink "$dst")" = "$src" ]; then
        echo "  already linked: $dst"
    elif [ -e "$dst" ] && [ ! -L "$dst" ]; then
        echo "  SKIP (real file exists): $dst — back it up and re-run if you want to link it"
    else
        ln -sf "$src" "$dst"
        echo "  linked: $dst → $src"
    fi
}

echo "Installing git security hooks..."
symlink "$DOTFILES/git/hooks/pre-push"           "$HOME/.config/git/hooks/pre-push"
symlink "$DOTFILES/git/security/nightly_scan.sh" "$HOME/.config/git/security/nightly_scan.sh"

echo ""
echo "One-time setup (run once per machine):"
echo "  git config --global core.hooksPath ~/.config/git/hooks"
echo "  chmod +x ~/.config/git/hooks/pre-push"
echo "  crontab -e   # add: 13 2 * * * bash ~/.config/git/security/nightly_scan.sh"
