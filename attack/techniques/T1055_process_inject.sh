#!/usr/bin/env bash
# =============================================================================
# T1055_process_inject.sh — Process Injection (T1055)
# MITRE ATT&CK: https://attack.mitre.org/techniques/T1055/
#
# SIMULATION:
#   Simulates process injection techniques on Linux:
#     1. /proc/PID/mem write attempt (caught by kernel, generates syscall telemetry)
#     2. ptrace attach attempt (triggers Sysmon EventID 10 ProcessAccess)
#     3. LD_PRELOAD injection pattern (file creation in /tmp + env var)
#
# EXPECTED DETECTIONS:
#   - Wazuh Rule 100020 (level 15): CreateRemoteThread (EventID 8)
#   - Wazuh Rule 100021 (level 12): /proc/PID/mem or ptrace reference
#   - Sysmon EventID 10: ProcessAccess to foreign PID
#
# NOTE: Actual memory writes are blocked by kernel (PTRACE_TRACEME / Yama).
#       The simulation generates the syscall patterns without injecting code.
# =============================================================================

set -euo pipefail

echo "[T1055] Simulating process injection techniques..."

# ── Step 1: /proc/PID/mem write simulation ────────────────────────────────────
echo "[T1055] Step 1: /proc/PID/mem read/write attempt"

# Get PID of an innocuous background process
TARGET_PROC=$(pgrep -x "bash" | head -1 || pgrep -x "sleep" | head -1 || echo "1")
echo "[T1055]   Target PID: ${TARGET_PROC} ($(cat /proc/${TARGET_PROC}/comm 2>/dev/null || echo 'unknown'))"

# Attempt to open /proc/PID/mem for reading (triggers Sysmon EventID 10 / syscall audit)
python3 - <<PYEOF
import os, sys

pid = int("${TARGET_PROC}")
mem_path = f"/proc/{pid}/mem"
maps_path = f"/proc/{pid}/maps"

print(f"[T1055]   Attempting to open {mem_path} (will fail safely — generates telemetry)")
try:
    with open(maps_path, "r") as mf:
        first_region = mf.readline().strip()
    print(f"[T1055]   First memory region: {first_region}")
    # This open() call generates the syscall event captured by Sysmon
    fd = os.open(mem_path, os.O_RDONLY)
    os.close(fd)
    print("[T1055]   /proc/mem opened (unexpected — ptrace restrictions may be off)")
except PermissionError:
    print("[T1055]   ✓ Access denied (Yama LSM active) — but syscall telemetry was generated")
except Exception as e:
    print(f"[T1055]   Expected failure: {e}")
PYEOF

sleep 1

# ── Step 2: ptrace attach attempt ────────────────────────────────────────────
echo "[T1055] Step 2: ptrace ATTACH attempt (Sysmon EventID 10 ProcessAccess)"
python3 - <<PYEOF
import ctypes, sys, os

# PTRACE_ATTACH = 16
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

pid = int("${TARGET_PROC}")
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

print(f"[T1055]   Attempting ptrace(PTRACE_ATTACH, {pid}) — generates ProcessAccess telemetry")
result = libc.ptrace(PTRACE_ATTACH, pid, None, None)
if result == -1:
    errno = ctypes.get_errno()
    print(f"[T1055]   ✓ ptrace blocked (errno {errno}) — telemetry generated")
else:
    print(f"[T1055]   ptrace attached (detaching now)")
    libc.ptrace(PTRACE_DETACH, pid, None, None)
PYEOF

sleep 1

# ── Step 3: LD_PRELOAD injection pattern ─────────────────────────────────────
echo "[T1055] Step 3: LD_PRELOAD shared library injection pattern"

# Create a dummy .so file in /tmp (Sysmon EventID 11 FileCreate in /tmp)
cat > /tmp/sim_inject.c <<'CEOF'
/* Simulation: LD_PRELOAD injection stub — not functional, for telemetry only */
#include <stdio.h>
void __attribute__((constructor)) sim_init(void) {
    /* A real implant would hook system calls here */
}
CEOF

gcc -shared -fPIC -o /tmp/sim_inject.so /tmp/sim_inject.c 2>/dev/null || \
  echo "[T1055]   gcc not available, skipping .so compilation (file creation telemetry still fires)"

echo "[T1055]   Simulating: LD_PRELOAD=/tmp/sim_inject.so id"
LD_PRELOAD=/tmp/sim_inject.so id 2>/dev/null || true

# Cleanup
rm -f /tmp/sim_inject.c /tmp/sim_inject.so
echo "[T1055] Simulation complete. Check Wazuh for rules 100020 / 100021."
