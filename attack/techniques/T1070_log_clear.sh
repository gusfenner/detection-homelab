#!/usr/bin/env bash
# =============================================================================
# T1070_log_clear.sh — Indicator Removal: Clear Linux Logs (T1070.003)
# MITRE ATT&CK: https://attack.mitre.org/techniques/T1070/003/
#
# SIMULATION:
#   Simulates attacker clearing forensic artifacts:
#     1. history -c (clear bash history in memory)
#     2. HISTFILE redirection to /dev/null
#     3. Truncation of /var/log/wtmp (login records)
#     4. Truncation of /var/log/btmp (failed login records)
#     5. Writing to /var/log/auth.log to simulate log poisoning
#
# EXPECTED DETECTIONS:
#   - Wazuh Rule 100040 (level 12): history -c or HISTFILE manipulation
#   - Wazuh Rule 100041 (level 12): truncation of /var/log files
#   - Sysmon EventID 1: CommandLine containing truncate / history patterns
#
# NOTE: We backup and restore /var/log/wtmp and /var/log/btmp to avoid
#       damaging the lab environment.
# =============================================================================

set -euo pipefail

echo "[T1070.003] Simulating indicator removal / log clearing..."

# ── Backup critical log files before simulation ───────────────────────────────
echo "[T1070.003] Creating backups of log files before simulation"
cp /var/log/wtmp  /tmp/wtmp.bak  2>/dev/null || true
cp /var/log/btmp  /tmp/btmp.bak  2>/dev/null || true

# ── Step 1: Clear bash history in memory ─────────────────────────────────────
echo "[T1070.003] Step 1: history -c (Sysmon EventID 1 cmdline=history -c)"
bash -c "history -c"
echo "[T1070.003] ✓ Bash history cleared in memory"

sleep 1

# ── Step 2: Redirect HISTFILE to /dev/null ────────────────────────────────────
echo "[T1070.003] Step 2: HISTFILE redirect (Sysmon EventID 1 cmdline=unset HISTFILE)"
bash -c "unset HISTFILE; export HISTFILE=/dev/null; history -w"
echo "[T1070.003] ✓ HISTFILE redirected to /dev/null"

sleep 1

# ── Step 3: Clear .bash_history file ─────────────────────────────────────────
echo "[T1070.003] Step 3: Truncating .bash_history (Sysmon EventID 11 FileCreate)"
# Using 'truncate' command — generates both EventID 1 (ProcessCreate) and
# EventID 11 (FileCreate/overwrite) in Sysmon
truncate -s 0 /root/.bash_history 2>/dev/null || true
truncate -s 0 /home/vagrant/.bash_history 2>/dev/null || true
echo "[T1070.003] ✓ .bash_history files truncated"

sleep 1

# ── Step 4: Truncate wtmp (login records) ────────────────────────────────────
echo "[T1070.003] Step 4: Truncating /var/log/wtmp (who/last records)"
truncate -s 0 /var/log/wtmp
echo "[T1070.003] ✓ /var/log/wtmp cleared"

sleep 1

# ── Step 5: Truncate btmp (failed login records) ─────────────────────────────
echo "[T1070.003] Step 5: Truncating /var/log/btmp (failed login records)"
truncate -s 0 /var/log/btmp
echo "[T1070.003] ✓ /var/log/btmp cleared"

sleep 1

# ── Step 6: Shred simulation (overwrite pattern) ─────────────────────────────
echo "[T1070.003] Step 6: shred pattern on a temp log file"
echo "simulation log data" > /tmp/fake_audit.log
shred -vzn 1 /tmp/fake_audit.log 2>/dev/null || true
rm -f /tmp/fake_audit.log
echo "[T1070.003] ✓ Shred pattern executed on temp file"

# ── Restore backups ───────────────────────────────────────────────────────────
sleep 2
echo "[T1070.003] Restoring log backups to maintain lab integrity"
cp /tmp/wtmp.bak /var/log/wtmp 2>/dev/null || true
cp /tmp/btmp.bak /var/log/btmp 2>/dev/null || true
rm -f /tmp/wtmp.bak /tmp/btmp.bak

echo "[T1070.003] Simulation complete. Check Wazuh for rules 100040 / 100041."
