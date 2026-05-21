#!/usr/bin/env bash
# =============================================================================
# simulate_attack.sh — MITRE ATT&CK Simulation Orchestrator
# Detection Home Lab | github.com/YOUR_USERNAME/detection-homelab
#
# PURPOSE:
#   Runs all 5 MITRE ATT&CK technique simulations in sequence on the agent-node.
#   Each technique generates telemetry captured by Sysmon4Linux → Wazuh.
#
# USAGE (from agent-node VM):
#   sudo bash /vagrant/attack/simulate_attack.sh [--technique T1053]
#
# USAGE (from attacker VM via SSH):
#   ssh vagrant@192.168.56.20 "sudo bash /vagrant/attack/simulate_attack.sh"
#
# WARNING:
#   FOR EDUCATIONAL USE IN ISOLATED LAB ENVIRONMENTS ONLY.
#   These scripts simulate attacker TTPs. Never run on production systems.
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TECHNIQUES_DIR="${SCRIPT_DIR}/techniques"
LOG_FILE="/var/log/attack_simulation.log"
SLEEP_BETWEEN=5  # seconds between techniques (allow Sysmon to capture events)

# ── Logging ───────────────────────────────────────────────────────────────────
log() { echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')]${RESET} $*" | tee -a "$LOG_FILE"; }
info() { echo -e "${GREEN}[INFO]${RESET} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*" | tee -a "$LOG_FILE"; }
attack() { echo -e "${RED}${BOLD}[ATT&CK]${RESET} $*" | tee -a "$LOG_FILE"; }

# ── Guard ─────────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[ERROR]${RESET} This script must be run as root (sudo)."
  exit 1
fi

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat <<'EOF'
  ╔══════════════════════════════════════════════════════════════╗
  ║          DETECTION HOME LAB — ATT&CK SIMULATOR              ║
  ║  FOR EDUCATIONAL USE IN ISOLATED LAB ENVIRONMENTS ONLY      ║
  ╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${RESET}"

log "=== Attack Simulation Started ==="
log "Agent node: $(hostname) | $(date)"
log "Sysmon status: $(systemctl is-active sysmon 2>/dev/null || echo 'not running')"
log "Wazuh agent: $(systemctl is-active wazuh-agent 2>/dev/null || echo 'not running')"

# ── Technique runner ─────────────────────────────────────────────────────────
run_technique() {
  local id="$1"
  local name="$2"
  local script="$3"

  echo ""
  echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
  attack "Technique: ${id} — ${name}"
  echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"

  if [[ -f "${TECHNIQUES_DIR}/${script}" ]]; then
    bash "${TECHNIQUES_DIR}/${script}"
    info "✓ ${id} simulation complete"
  else
    warn "Script not found: ${TECHNIQUES_DIR}/${script}"
  fi

  log "Waiting ${SLEEP_BETWEEN}s for Sysmon to capture events..."
  sleep "$SLEEP_BETWEEN"
}

# ── Parse optional --technique flag ──────────────────────────────────────────
FILTER="${1:-all}"

# ── Run techniques ────────────────────────────────────────────────────────────
[[ "$FILTER" == "all" || "$FILTER" == "T1053" ]] && \
  run_technique "T1053.003" "Scheduled Task/Job: Cron" "T1053_scheduled_task.sh"

[[ "$FILTER" == "all" || "$FILTER" == "T1059" ]] && \
  run_technique "T1059.004" "Command and Scripting Interpreter: Unix Shell" "T1059_command_script.sh"

[[ "$FILTER" == "all" || "$FILTER" == "T1055" ]] && \
  run_technique "T1055" "Process Injection" "T1055_process_inject.sh"

[[ "$FILTER" == "all" || "$FILTER" == "T1136" ]] && \
  run_technique "T1136.001" "Create Account: Local Account" "T1136_create_account.sh"

[[ "$FILTER" == "all" || "$FILTER" == "T1070" ]] && \
  run_technique "T1070.003" "Indicator Removal: Clear Linux Logs" "T1070_log_clear.sh"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
log "=== Simulation Complete ==="
info "Check Wazuh Dashboard: https://192.168.56.10"
info "Filter alerts by: agent.name: agent-node"
info "Local simulation log: ${LOG_FILE}"
