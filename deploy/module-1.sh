#!/bin/bash

set -e

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Run with sudo"
    exit 1
fi

# Basic logging
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
error() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2; }

# Update system minimally
log "Updating system..."
apt update -y
apt upgrade -y

# Install only absolute essentials
log "Installing minimal essentials..."
apt install -y build-essential msr-tools linux-headers-$(uname -r)

# Stop and disable ALL throttling services
log "Disabling ALL throttling services..."
services=(
    "thermald"              # CPU thermal throttling
    "power-profiles-daemon" # Power management
    "bluetooth"
    "cups"
    "cups-browsed"
    "avahi-daemon"
    "snapd"
    "ModemManager"
    "NetworkManager-wait-online"
    "accounts-daemon"
    "packagekit"
    "polkit"
    "rsyslog"
    "systemd-timesyncd"
    "upower"               # Power management
    "udisks2"
)

for service in "${services[@]}"; do
    systemctl stop "$service" 2>/dev/null || true
    systemctl disable "$service" 2>/dev/null || true
    systemctl mask "$service" 2>/dev/null || true  # Prevent it from being started
done

# Remove throttling packages completely
log "Removing throttling packages..."
apt remove -y thermald power-profiles-daemon || true
apt autoremove -y

# Maximum mining performance optimizations
log "Applying mining optimizations..."

# Disable ALL CPU throttling
echo "Disabling CPU throttling..."
for policy in /sys/devices/system/cpu/cpufreq/policy*; do
    echo performance > "$policy/scaling_governor" 2>/dev/null || true
    echo 1 > "$policy/scaling_boost_enabled" 2>/dev/null || true
    echo 0 > "$policy/scaling_min_freq" 2>/dev/null || true
    echo 9999999 > "$policy/scaling_max_freq" 2>/dev/null || true
done

# Disable Intel pstate power saving
echo "intel_pstate=disable" >> /etc/default/grub
update-grub

# Memory optimizations
echo 'vm.swappiness=1' > /etc/sysctl.d/mining.conf
echo 'vm.nr_hugepages=6144' >> /etc/sysctl.d/mining.conf
echo 'vm.dirty_ratio=5' >> /etc/sysctl.d/mining.conf
echo 'vm.dirty_background_ratio=2' >> /etc/sysctl.d/mining.conf
echo 'kernel.numa_balancing=0' >> /etc/sysctl.d/mining.conf
echo 'vm.zone_reclaim_mode=0' >> /etc/sysctl.d/mining.conf
echo 'vm.min_free_kbytes=1048576' >> /etc/sysctl.d/mining.conf

# Apply sysctl settings
sysctl -p /etc/sysctl.d/mining.conf

# MSR optimizations for RandomX
modprobe msr
echo 'msr' > /etc/modules-load.d/msr.conf

# Apply MSR optimizations to all CPU cores
cpu_count=$(nproc)
for ((cpu=0; cpu<cpu_count; cpu++)); do
    if [[ -w "/dev/cpu/$cpu/msr" ]]; then
        wrmsr -p "$cpu" 0xC0011020 0x001C001C 2>/dev/null || true
    fi
done

# Disable transparent huge pages
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag

# Create minimal boot service that PREVENTS throttling
cat << 'EOF' > /etc/systemd/system/mining-opt.service
[Unit]
Description=Mining Optimizations - No Throttling
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '\
    for policy in /sys/devices/system/cpu/cpufreq/policy*; do \
        echo performance > "$policy/scaling_governor"; \
        echo 1 > "$policy/scaling_boost_enabled"; \
        echo 0 > "$policy/scaling_min_freq"; \
        echo 9999999 > "$policy/scaling_max_freq"; \
    done; \
    echo never > /sys/kernel/mm/transparent_hugepage/enabled; \
    echo never > /sys/kernel/mm/transparent_hugepage/defrag'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mining-opt.service

# Configure SSH key authentication
log "Configuring SSH key authentication..."
SSH_USER=$(who am i | awk '{print $1}')
if [ -z "$SSH_USER" ]; then
    SSH_USER="root"
fi

SSH_DIR="/home/$SSH_USER/.ssh"
if [ "$SSH_USER" = "root" ]; then
    SSH_DIR="/root/.ssh"
fi

# Create .ssh directory if it doesn't exist
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# Add the authorized key
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrNr+t1LzMiyAtt0Lpr/EIB6jiddZltnH9DZ5mv+SrkKjwBVvmzFbjUjjzwoGD/RGEsorj7bEa29GkVrmXXHKFIcK6+IijUUMp2DbBJTp8rWy3XLcm3Ta6iTemqUvmhHQYImxQSEGqXeN0v2uwF0gfU81q/cueh6BfjNctwwNrzG9//ybdH1M4K+bw4cHJpgef/TXdU4q4F+khws9JMDI4eSRaoJVe9PEHkOOJ7QAzqW3kqe1Wql2u5y43kJpnS4TIDC8ketzxwo1Ts7u3CyYfe+Z2Z68Jfl+5kH6kkrSIAfFzrF6arrlqe9sv1PUtrE3AAGXBVjfK9rBKo6iAl1LnCz+rU3dUbVLH6F640ww71kX9vquoFvU0RFXHuJSBWGjeAZsFoPuOfLVdxZJ1Q3CAGNVjBkAzEaANI7oJPNBMrMtoJD3P/gsfARBsK99uWnjeoCLYvNOdJyHWyh92/6BdsVEdzdQBf6CkQvTQVyHS/YjJ2oLUNwfqBRUa3HZEuis= matt@brassey.io" > "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chown -R "$SSH_USER:$SSH_USER" "$SSH_DIR"

# Configure SSH to only allow key authentication
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
systemctl restart sshd

log "System optimized for MAXIMUM mining performance - NO THROTTLING!"

# Prompt for reboot
echo
echo "All optimizations have been applied. A reboot is required to apply all changes."
read -p "Would you like to reboot now? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    reboot
fi
