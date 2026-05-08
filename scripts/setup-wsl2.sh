#!/usr/bin/env bash
# setup-wsl2.sh — Apply RuntimeGuard WSL2 kernel parameter recommendations
#
# Run from inside WSL2 with:
#   sudo bash scripts/setup-wsl2.sh
#
# This script:
#   1. Applies recommended sysctl values immediately (survives until wsl --shutdown)
#   2. Writes /etc/sysctl.d/99-wsl2-memory.conf for persistence across restarts
#   3. Prints the recommended .wslconfig content for the Windows host
#
# Root required for steps 1 and 2 only.  Step 3 is informational.
set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
info() { echo -e "        $*"; }

# ── Detect WSL2 ────────────────────────────────────────────────────────────
if ! grep -qi "microsoft" /proc/version 2>/dev/null; then
    warn "Not running in WSL2.  Kernel param tuning is still safe on plain Linux."
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "  RuntimeGuard — WSL2 Kernel Parameter Setup"
echo "═══════════════════════════════════════════════════════════════════"

# ── Step 1: Live sysctl application ───────────────────────────────────────
echo ""
echo "── Step 1: Applying sysctl values live ─────────────────────────────"

apply_param() {
    local param=$1 value=$2 reason=$3
    local current
    current=$(sysctl -n "$param" 2>/dev/null || echo "unknown")
    if [ "$current" = "$value" ]; then
        ok "$param = $value (already set)"
    else
        if sysctl -w "$param=$value" >/dev/null 2>&1; then
            ok "$param: $current → $value"
        else
            warn "$param: could not set (need root).  Manual: sudo sysctl -w $param=$value"
        fi
    fi
    info "  Reason: $reason"
}

# Determine recommended min_free_kbytes: ~2% of MemTotal, clamped [128 MB, 1 GB]
MEM_TOTAL_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
REC_MIN_FREE=$(python3 -c "print(max(131072, min(1048576, $MEM_TOTAL_KB // 50)))" 2>/dev/null || echo "409600")

apply_param "vm.swappiness" "10" \
    "Reduce aggressiveness of swap usage; keep active data in RAM"
apply_param "vm.min_free_kbytes" "$REC_MIN_FREE" \
    "Reserve ~2% of RAM as kernel floor; prevents OOM kill storms"
apply_param "vm.dirty_ratio" "10" \
    "Cap dirty pages at 10% of RAM; prevents large writeback stalls"
apply_param "vm.dirty_background_ratio" "5" \
    "Start background writeback at 5%; spreads I/O evenly"
apply_param "vm.overcommit_memory" "0" \
    "Heuristic overcommit; refuses obviously excessive allocations early"
apply_param "vm.vfs_cache_pressure" "50" \
    "Keep dentry/inode cache longer; fewer repeated dir reads during tests"

# ── Step 2: Persist via sysctl.d ──────────────────────────────────────────
echo ""
echo "── Step 2: Writing /etc/sysctl.d/99-wsl2-memory.conf ───────────────"

CONF_PATH="/etc/sysctl.d/99-wsl2-memory.conf"
cat > "$CONF_PATH" <<EOF
# WSL2 memory pressure optimisations — managed by RuntimeGuard setup-wsl2.sh
# Regenerate with: sudo bash runtime-guard/scripts/setup-wsl2.sh
vm.swappiness = 10
vm.min_free_kbytes = ${REC_MIN_FREE}
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.overcommit_memory = 0
vm.vfs_cache_pressure = 50
EOF

if sysctl -p "$CONF_PATH" >/dev/null 2>&1; then
    ok "Wrote and applied $CONF_PATH"
else
    warn "Wrote $CONF_PATH but sysctl -p failed — values already applied live above"
fi

# ── Step 3: .wslconfig recommendation ─────────────────────────────────────
echo ""
echo "── Step 3: .wslconfig for Windows host ─────────────────────────────"
echo ""
warn ".wslconfig NOT FOUND on this system (or not readable from WSL)."
echo ""
info "CRITICAL: Without .wslconfig, WSL2 has NO memory ceiling and can"
info "consume ALL Windows host RAM + pagefile → Windows stall → WSL crash."
echo ""

MEM_TOTAL_GB=$(( MEM_TOTAL_KB / 1024 / 1024 ))
REC_MEM_GB=$(python3 -c "print(max(8, int($MEM_TOTAL_GB * 0.65)))" 2>/dev/null || echo "12")
REC_SWAP_GB=$(python3 -c "print(max(4, $REC_MEM_GB // 2))" 2>/dev/null || echo "6")
REC_PROCS=$(python3 -c "import os; print(max(2, (os.cpu_count() or 4) // 2))" 2>/dev/null || echo "4")

info "Copy the following to %UserProfile%\\.wslconfig on WINDOWS:"
echo ""
cat <<WSLCFG
[wsl2]
# Hard memory ceiling — prevents WSL2 from consuming all host RAM
memory=${REC_MEM_GB}GB

# WSL2 swap (backed by Windows pagefile)
swap=${REC_SWAP_GB}GB

# Limit vCPUs to avoid starving the Windows host
processors=${REC_PROCS}

# Return unused pages to Windows more aggressively
pageReporting=true

localhostForwarding=true
nestedVirtualization=false
WSLCFG

echo ""
info "Then in PowerShell:  wsl --shutdown"
info "Then restart WSL to apply the new limits."

echo ""
echo "═══════════════════════════════════════════════════════════════════"
ok "setup-wsl2.sh complete."
echo "═══════════════════════════════════════════════════════════════════"
