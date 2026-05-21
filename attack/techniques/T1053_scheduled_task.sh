#!/usr/bin/env bash
# =============================================================================
# T1053_scheduled_task.sh — Scheduled Task/Job: Cron (T1053.003)
# MITRE ATT&CK: https://attack.mitre.org/techniques/T1053/003/
#
# SIMULATION:
#   Injects a cron job that would execute a simulated payload.
#   Uses both `crontab` (detected by Sysmon EventID 1 on image match)
#   and direct cron.d file write (detected by Sysmon EventID 11 on FileCreate).
#
# EXPECTED DETECTIONS:
#   - Wazuh Rule 100001 (level 10): crontab invoked
#   - Wazuh Rule 100002 (level 12): file written to /etc/cron.d
#   - FIM alert: /etc/cron.d modification
# =============================================================================

set -euo pipefail

PAYLOAD_COMMENT="# DetectionLab ATT&CK Simulation T1053.003"
CRON_FILE="/etc/cron.d/detection-lab-sim"
BACKDOOR_USER="vagrant"

echo "[T1053.003] Simulating cron-based persistence..."

# ── Step 1: Invoke crontab (generates Sysmon EventID 1 with image=crontab) ──
echo "[T1053.003] Step 1: Listing crontab for user ${BACKDOOR_USER} (triggers Sysmon EventID 1)"
crontab -l -u "$BACKDOOR_USER" 2>/dev/null || true

# ── Step 2: Write malicious cron job via crontab -e equivalent ────────────────
echo "[T1053.003] Step 2: Adding cron entry via crontab (triggers Sysmon EventID 1 + image=crontab)"
(crontab -l -u "$BACKDOOR_USER" 2>/dev/null; \
  echo "${PAYLOAD_COMMENT}"; \
  echo "# Simulated payload — NOT real malware") | \
  crontab -u "$BACKDOOR_USER" - 2>/dev/null || true

# ── Step 3: Write directly to /etc/cron.d (triggers Sysmon EventID 11) ────────
echo "[T1053.003] Step 3: Writing to /etc/cron.d/ (triggers Sysmon EventID 11 - FileCreate)"
cat > "$CRON_FILE" <<EOF
${PAYLOAD_COMMENT}
# Simulated attacker cron persistence entry
# In a real attack, this would execute a reverse shell or download a payload
# * * * * * root /tmp/.implant 2>/dev/null
SIMULATION_ONLY="true"
EOF

echo "[T1053.003] ✓ Cron entry written to ${CRON_FILE}"

# ── Cleanup (remove simulation artifacts) ─────────────────────────────────────
sleep 2
echo "[T1053.003] Cleanup: removing simulation cron file"
rm -f "$CRON_FILE"

# Remove the simulation entry from crontab
crontab -l -u "$BACKDOOR_USER" 2>/dev/null | \
  grep -v "$PAYLOAD_COMMENT" | \
  grep -v "SIMULATION_ONLY" | \
  crontab -u "$BACKDOOR_USER" - 2>/dev/null || true

echo "[T1053.003] Simulation complete. Check Wazuh for rules 100001 / 100002."
