#!/usr/bin/env bash
# =============================================================================
# cleanup.sh — Destroy all Detection Home Lab VMs and free resources
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; RESET='\033[0m'

warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
info()  { echo -e "${GREEN}[INFO]${RESET}  $*"; }

echo ""
warn "This will DESTROY all Detection Home Lab VMs and delete their disk images."
warn "All data on the VMs will be permanently lost."
echo ""
read -r -p "Are you sure? Type 'yes' to continue: " CONFIRM
echo ""

if [[ "$CONFIRM" != "yes" ]]; then
  info "Cleanup cancelled."
  exit 0
fi

info "Destroying all VMs..."
vagrant destroy -f

info "Removing VirtualBox host-only adapter (if exists)..."
VBoxManage hostonlyif remove vboxnet0 2>/dev/null || true

info "Removing SSH known_hosts entries for lab IPs..."
ssh-keygen -R 192.168.56.10 2>/dev/null || true
ssh-keygen -R 192.168.56.20 2>/dev/null || true
ssh-keygen -R 192.168.56.30 2>/dev/null || true

info "Cleanup complete. Run ./scripts/setup.sh to rebuild the lab."
