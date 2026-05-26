#!/usr/bin/env bash
# =============================================================================
# setup.sh — One-shot Detection Home Lab Setup
# Run from the project root on your Windows host (Git Bash / WSL2 / PowerShell)
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'

info()  { echo -e "${GREEN}[SETUP]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║          Detection Home Lab — Setup Script              ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Pre-flight checks ─────────────────────────────────────────────────────────
info "Checking prerequisites..."
command -v vagrant    &>/dev/null || error "Vagrant not found. Install from https://vagrantup.com"
command -v VBoxManage &>/dev/null || warn  "VBoxManage not found. Install VirtualBox from https://virtualbox.org"

VAGRANT_VERSION=$(vagrant --version)
info "Found: ${VAGRANT_VERSION}"

# ── Vault setup ───────────────────────────────────────────────────────────────
VAULT_FILE="ansible/group_vars/vault.yml"
if [[ ! -f "$VAULT_FILE" ]]; then
  warn "Vault file not found. Creating from example with DEFAULT passwords."
  warn "Change passwords in ${VAULT_FILE} before running in any real environment!"
  cp "ansible/group_vars/vault.yml.example" "$VAULT_FILE"
fi

# ── Start VMs ─────────────────────────────────────────────────────────────────
info "Starting VMs with vagrant up..."
info "This will take 15–30 minutes on first run (downloads box + installs Wazuh)."
info ""
info "VM resource allocation:"
info "  wazuh-server : 8 GB RAM, 4 vCPUs"
info "  agent-node   : 2 GB RAM, 2 vCPUs"
info "  attacker     : 1 GB RAM, 1 vCPU"
info ""

vagrant up

# ── Post-setup info ───────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}  ✓ Detection Home Lab is UP${RESET}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${RESET}"
echo ""
info "Wazuh Dashboard : https://192.168.56.10"
info "Username        : admin"
info "Password        : Run: vagrant ssh wazuh-server -- cat /tmp/wazuh-passwords.txt"
echo ""
info "Run attack simulation:"
info "  vagrant ssh agent-node -- sudo bash /vagrant/attack/simulate_attack.sh"
echo ""
info "SSH into VMs:"
info "  vagrant ssh wazuh-server"
info "  vagrant ssh agent-node"
info "  vagrant ssh attacker"
