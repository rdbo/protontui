#!/bin/sh
# Puts Proton's local_agent_rs where Cargo.toml expects it (../python-proton-vpn-local-agent/local_agent_rs),
# at the commit protontui is tested with. It comes without a license, so it isn't vendored in this repo; and
# Cargo can't take it as a git dependency, because that repo has submodules in Proton's private GitLab. The
# GitHub archive has no submodules. Cargo needs the source even for `--no-default-features` builds (which
# don't link it).
#
#   sh scripts/fetch-local-agent.sh [DEST]   # DEST defaults to ../python-proton-vpn-local-agent
set -eu

REV=74ec6f4f093805d766f11f9ef522bf1120591058
HERE=$(cd "$(dirname "$0")/.." && pwd)
DEST=${1:-$HERE/../python-proton-vpn-local-agent}

if [ -f "$DEST/local_agent_rs/Cargo.toml" ]; then
    echo "local_agent_rs is already in $DEST"
    exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://github.com/ProtonVPN/local-agent-rs/archive/$REV.tar.gz" | tar -xz -C "$tmp"
mkdir -p "$DEST"
mv "$tmp/local-agent-rs-$REV/local_agent_rs" "$DEST/local_agent_rs"
echo "local_agent_rs ($REV) is in $DEST"
