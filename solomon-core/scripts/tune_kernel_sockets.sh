#!/usr/bin/env bash
# ==============================================================================
# Project Solomon: OS Kernel Network & Socket Saturation Tuning Profile
# Target: Ultra-High-Throughput Post-Quantum Proxy (>500,000 tx/sec)
# ==============================================================================

set -euo pipefail

echo "[*] Applying Project Solomon High-Throughput Linux Kernel Tuning..."

# 1. Ephemeral Port Range Expansion (Avoid port exhaustion under heavy connection churning)
sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# 2. TIME_WAIT Connection Reuse (Immediately recycle closed sockets)
sysctl -w net.ipv4.tcp_tw_reuse=1

# 3. Connection Backlog Expansion (Prevent SYN dropouts during massive burst ingress)
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sysctl -w net.core.netdev_max_backlog=65535

# 4. TCP Socket Buffer Tuning (Autotuning max buffer sizes for gigabit/10G links)
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

# 5. Fast FIN/TIME_WAIT Timeout (Reclaim lingering sockets within 15s)
sysctl -w net.ipv4.tcp_fin_timeout=15

# 6. File Descriptor Limits (Support 2M concurrent descriptors)
sysctl -w fs.file-max=2097152

# Set user-level descriptor limits
ulimit -n 1048576 || true

echo "[+] Kernel network socket parameters successfully tuned."
