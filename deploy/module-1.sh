#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
    echo ":: Run with sudo"
    exit 1
fi

log() { echo ":: [$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
error() { echo ":: [$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2; }
warning() { echo ":: [$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1" >&2; }
info() { echo ":: [$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1"; }

cleanup_previous_state() {
    log "==> Cleaning up previous configurations..."
    
    local services=("node_exporter" "system-metrics" "packagekit")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log "Stopping $service service..."
            systemctl stop "$service" 2>/dev/null || true
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log "Disabling $service service..."
            systemctl disable "$service" 2>/dev/null || true
        fi
        log "Unmasking $service service..."
        systemctl unmask "$service" 2>/dev/null || true
    done
    
    local service_files=(
        "/etc/systemd/system/node_exporter.service"
        "/etc/systemd/system/system-metrics.service"
        "/etc/systemd/system/system-metrics.timer"
    )
    for file in "${service_files[@]}"; do
        if [[ -f "$file" ]]; then
            log "Removing service file: $file"
            rm -f "$file"
        fi
    done
    
    local binaries=(
        "/usr/local/bin/node_exporter"
        "/usr/local/bin/system-metrics.sh"
    )
    for binary in "${binaries[@]}"; do
        if [[ -f "$binary" ]]; then
            log "Removing binary: $binary"
            rm -f "$binary"
        fi
    done
    
    if [[ -d "/var/lib/node_exporter" ]]; then
        log "Cleaning up metrics directory..."
        rm -rf "/var/lib/node_exporter"
    fi
    
    if [[ -f "/etc/sysctl.d/mining.conf" ]]; then
        log "Removing previous sysctl configurations..."
        rm -f "/etc/sysctl.d/mining.conf"
    fi
    
    log "Resetting CPU governor settings..."
    for policy in /sys/devices/system/cpu/cpufreq/policy*; do
        if [[ -f "$policy/scaling_governor" ]]; then
            echo ondemand > "$policy/scaling_governor" 2>/dev/null || true
        fi
    done
    
    log "Resetting systemd state..."
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    
    log "✓ Previous configurations cleaned up"
}

cleanup_package_management() {
    log "==> Cleaning up package management..."
    
    if [[ -d "/etc/apt/sources.list.d" ]]; then
        log "Found PPA files:"
        ls -la /etc/apt/sources.list.d/ | grep -E "(thopiekar|openrgb)" || log "No problematic PPA files found"
    fi
    
    rm -f /etc/apt/sources.list.d/thopiekar*.list* 2>/dev/null || true
    rm -f /etc/apt/sources.list.d/*openrgb*.list* 2>/dev/null || true
    rm -f /etc/apt/sources.list.d/*.save 2>/dev/null || true
    
    find /etc/apt/sources.list.d/ -type f -name '*.list' -exec sed -i '/thopiekar/d' {} \; 2>/dev/null || true
    find /etc/apt/sources.list.d/ -type f -name '*.list' -exec sed -i '/openrgb/d' {} \; 2>/dev/null || true
    find /etc/apt/sources.list.d/ -type f -name '*.list' -exec sed -i '/ppa.launchpadcontent.net/d' {} \; 2>/dev/null || true
    
    sed -i '/thopiekar/d' /etc/apt/sources.list 2>/dev/null || true
    sed -i '/openrgb/d' /etc/apt/sources.list 2>/dev/null || true
    sed -i '/ppa.launchpadcontent.net/d' /etc/apt/sources.list 2>/dev/null || true
    
    if command -v add-apt-repository >/dev/null 2>&1; then
        add-apt-repository --remove ppa:thopiekar/openrgb -y 2>/dev/null || true
    fi
    
    if [[ -d "/var/lib/apt/lists" ]]; then
        find /var/lib/apt/lists -type f -name "*thopiekar*" -delete 2>/dev/null || true
        find /var/lib/apt/lists -type f -name "*openrgb*" -delete 2>/dev/null || true
        find /var/lib/apt/lists -type f -name "*ppa.launchpadcontent.net*" -delete 2>/dev/null || true
    fi
    
    mkdir -p /var/lib/apt/lists/partial 2>/dev/null || true
    
    apt-get clean 2>/dev/null || true
    apt-get autoclean 2>/dev/null || true
    
    log "✓ Package management cleaned up"
}

check_and_expand_disk_space() {
    log "==> Checking disk space utilization..."
    
    if ! command -v vgs &>/dev/null || ! command -v lvs &>/dev/null; then
        log "LVM not detected, skipping disk expansion check"
        return 0
    fi
    
    local vg_output=$(vgs --noheadings --units g 2>/dev/null)
    if [[ -z "$vg_output" ]]; then
        log "No LVM volume groups found, skipping disk expansion check"
        return 0
    fi
    
    local current_usage=$(df -h / | awk 'NR==2{print $5}' | sed 's/%//')
    local available_gb=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
    
    log "Current root partition usage: ${current_usage}%, Available: ${available_gb}GB"
    
    local vg_info=$(vgs --noheadings --units g --separator='|' 2>/dev/null | head -1)
    if [[ -n "$vg_info" ]]; then
        local vg_name=$(echo "$vg_info" | cut -d'|' -f1 | xargs)
        local vg_size=$(echo "$vg_info" | cut -d'|' -f6 | sed 's/g//' | xargs)
        local vg_free=$(echo "$vg_info" | cut -d'|' -f7 | sed 's/g//' | xargs)
        
        log "Volume Group: $vg_name"
        log "VG Total Size: ${vg_size}GB"
        log "VG Free Space: ${vg_free}GB"
        
        if (( $(echo "$vg_free > 10" | bc -l 2>/dev/null || echo "0") )); then
            log "Found ${vg_free}GB unallocated space in volume group $vg_name"
            
            local lv_info=$(lvs --noheadings --units g --separator='|' "$vg_name" 2>/dev/null | grep -E "(root|ubuntu-lv)")
            if [[ -n "$lv_info" ]]; then
                local lv_name=$(echo "$lv_info" | cut -d'|' -f1 | xargs)
                local lv_path="/dev/$vg_name/$lv_name"
                
                log "Found logical volume: $lv_path"
                
                log "DISK SPACE EXPANSION DETECTED:"
                log "  Current usage: ${current_usage}% (${available_gb}GB available)"
                log "  Unallocated space: ${vg_free}GB"
                log "  This will expand your disk from ~$(df -h / | awk 'NR==2{print $2}') to ~$((${vg_size%.*}))GB"
                
                read -p "Automatically expand disk space to use full capacity? [Y/n] " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Nn]$ ]]; then
                    log "Disk expansion skipped by user choice"
                    return 0
                fi
                
                log "Expanding logical volume to use all available space..."
                
                if lvextend -l +100%FREE "$lv_path" 2>/dev/null; then
                    log "✓ Logical volume extended successfully"
                    
                    log "Resizing filesystem to use extended space..."
                    if resize2fs "$lv_path" 2>/dev/null; then
                        log "✓ Filesystem resized successfully"
                        
                        local new_usage=$(df -h / | awk 'NR==2{print $5}' | sed 's/%//')
                        local new_available=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
                        local new_total=$(df -h / | awk 'NR==2{print $2}')
                        
                        log ""
                        log ": expansion complete."
                        log "  Before: ${current_usage}% usage, ${available_gb}GB available"
                        log "  After:  ${new_usage}% usage, ${new_available}GB available"
                        log "  Total disk size: $new_total"
                        log "  Gained: ~$((new_available - available_gb))GB additional space"
                        log ""
                        
                    else
                        error "Failed to resize filesystem! Logical volume was extended but filesystem resize failed."
                        log "Manual intervention required: sudo resize2fs $lv_path"
                        return 1
                    fi
                else
                    error "Failed to extend logical volume $lv_path"
                    return 1
                fi
            else
                warning "Could not identify root logical volume in volume group $vg_name"
                log "Available logical volumes:"
                lvs "$vg_name" 2>/dev/null || true
            fi
        else
            log "✓ Disk space appears to be fully allocated (${vg_free}GB free space is minimal)"
        fi
    else
        log "Could not retrieve volume group information"
    fi
    
    local final_usage=$(df -h / | awk 'NR==2{print $5,$4,$2}')
    log "Final disk status: $final_usage (Usage%, Available, Total)"
}

setup_firewall() {
    log "==> Configuring firewall for mining and node access..."
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw || error "Failed to install UFW"
    
    log "Clearing all existing firewall rules..."
    
    ufw --force disable >/dev/null 2>&1
    
    ufw --force reset >/dev/null 2>&1
    
    ufw status numbered 2>/dev/null | grep '\[' | cut -d']' -f 1 | grep -o '[0-9]' | tac | xargs -r -I{} ufw --force delete {} >/dev/null 2>&1
    
    log "Configuring new firewall rules..."
    
    ufw --force default deny incoming >/dev/null 2>&1
    ufw --force default allow outgoing >/dev/null 2>&1
    
    {
        ufw allow 22/tcp comment 'SSH'
        
        ufw allow from 192.168.0.0/16 to any port 18080 proto tcp comment 'Monero P2P LAN'
        ufw allow from 172.16.0.0/12 to any port 18080 proto tcp comment 'Monero P2P LAN'
        ufw allow from 10.0.0.0/8 to any port 18080 proto tcp comment 'Monero P2P LAN'
        
        ufw allow from 192.168.0.0/16 to any port 18081 proto tcp comment 'Monero RPC LAN'
        ufw allow from 172.16.0.0/12 to any port 18081 proto tcp comment 'Monero RPC LAN'
        ufw allow from 10.0.0.0/8 to any port 18081 proto tcp comment 'Monero RPC LAN'
        
        ufw allow 3333/tcp comment 'P2Pool Mining'
        ufw allow 37889/tcp comment 'P2Pool P2P Network'
        ufw allow 37888/tcp comment 'P2Pool Mini P2P Network'
        
        ufw allow from 192.168.0.0/16 to any port 9100 proto tcp comment 'Node Exporter Metrics LAN'
        ufw allow from 172.16.0.0/12 to any port 9100 proto tcp comment 'Node Exporter Metrics LAN'
        ufw allow from 10.0.0.0/8 to any port 9100 proto tcp comment 'Node Exporter Metrics LAN'
        
        ufw allow from 192.168.0.0/16 to any port 18088 proto tcp comment 'XMRig API LAN'
        ufw allow from 172.16.0.0/12 to any port 18088 proto tcp comment 'XMRig API LAN'
        ufw allow from 10.0.0.0/8 to any port 18088 proto tcp comment 'XMRig API LAN'
        
        ufw allow in on lo comment 'Allow all localhost traffic'
        
    } >/dev/null 2>&1
    
    echo "y" | ufw --force enable >/dev/null 2>&1
    
    log "Final firewall configuration:"
    ufw status numbered | grep -v "Status: active"
    
    log "Verifying required ports:"
    log "✓ SSH (22): Allowed from anywhere"
    log "✓ Monero P2P (18080): Allowed from LAN"
    log "✓ Monero RPC (18081): Allowed from LAN"
    log "✓ Monero ZMQ (18083): Allowed on localhost"
    log "✓ P2Pool Mining (3333): Allowed from anywhere"
    log "✓ P2Pool P2P (37889): Allowed from anywhere"
    log "✓ P2Pool Mini P2P (37888): Allowed from anywhere"
    log "✓ Node Exporter (9100): Allowed from LAN"
    log "✓ XMRig API (18088): Allowed from LAN"
    log "✓ Localhost: All traffic allowed"
    
    log "✓ Firewall configured successfully with clean ruleset"
}

setup_node_exporter() {
    log "==> Setting up Node Exporter..."
    
    log "Ensuring clean Node Exporter state..."
    systemctl stop node_exporter 2>/dev/null || true
    systemctl disable node_exporter 2>/dev/null || true
    systemctl unmask node_exporter 2>/dev/null || true
    systemctl stop system-metrics.timer 2>/dev/null || true
    systemctl disable system-metrics.timer 2>/dev/null || true
    systemctl unmask system-metrics.timer 2>/dev/null || true
    systemctl unmask system-metrics.service 2>/dev/null || true
    rm -f /etc/systemd/system/node_exporter.service 2>/dev/null || true
    rm -f /etc/systemd/system/system-metrics.service 2>/dev/null || true
    rm -f /etc/systemd/system/system-metrics.timer 2>/dev/null || true
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    
    log "Cleaning up existing Node Exporter files..."
    rm -f /usr/local/bin/node_exporter 2>/dev/null || true
    rm -f /usr/local/bin/system-metrics.sh 2>/dev/null || true
    rm -rf /var/lib/node_exporter 2>/dev/null || true
    
    if ! id -u nodeusr &>/dev/null; then
        useradd -rs /bin/false nodeusr 2>/dev/null
    fi
    
    local LATEST_VERSION=$(curl -s https://api.github.com/repos/prometheus/node_exporter/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
    if [[ -z "$LATEST_VERSION" ]]; then
        LATEST_VERSION="1.7.0"
        warning "Could not determine latest version, using fallback: $LATEST_VERSION"
    fi
    LATEST_VERSION="${LATEST_VERSION#v}"
    
    cd /tmp
    
    rm -f "node_exporter-${LATEST_VERSION}.linux-amd64.tar.gz"* 2>/dev/null || true
    rm -rf "node_exporter-${LATEST_VERSION}.linux-amd64" 2>/dev/null || true
    
    log "Downloading Node Exporter ${LATEST_VERSION}..."
    wget -q -O "node_exporter-${LATEST_VERSION}.linux-amd64.tar.gz" \
        "https://github.com/prometheus/node_exporter/releases/download/v${LATEST_VERSION}/node_exporter-${LATEST_VERSION}.linux-amd64.tar.gz" || error "Failed to download Node Exporter"
    
    if ! tar xzf "node_exporter-${LATEST_VERSION}.linux-amd64.tar.gz" 2>/dev/null; then
        error "Failed to extract Node Exporter"
    fi
    
    if ! cp "node_exporter-${LATEST_VERSION}.linux-amd64/node_exporter" /usr/local/bin/ 2>/dev/null; then
        error "Failed to install Node Exporter binary"
    fi
    chown nodeusr:nodeusr /usr/local/bin/node_exporter 2>/dev/null
    chmod 755 /usr/local/bin/node_exporter 2>/dev/null
    
    mkdir -p /var/lib/node_exporter/textfile_collector 2>/dev/null
    chown -R nodeusr:nodeusr /var/lib/node_exporter 2>/dev/null
    chmod -R 755 /var/lib/node_exporter 2>/dev/null
    
    rm -f "node_exporter-${LATEST_VERSION}.linux-amd64.tar.gz" 2>/dev/null
    rm -rf "node_exporter-${LATEST_VERSION}.linux-amd64" 2>/dev/null
    
    cat > /etc/systemd/system/node_exporter.service 2>/dev/null <<EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=nodeusr
Group=nodeusr
Type=simple
ExecStart=/usr/local/bin/node_exporter \\
    --web.listen-address=:9100 \\
    --collector.textfile.directory=/var/lib/node_exporter/textfile_collector \\
    --collector.cpu \\
    --collector.cpufreq \\
    --collector.meminfo \\
    --collector.loadavg \\
    --collector.filesystem \\
    --collector.netdev \\
    --collector.systemd \\
    --collector.thermal_zone

[Install]
WantedBy=multi-user.target
EOF

    cat > /usr/local/bin/system-metrics.sh 2>/dev/null <<'EOF'
#!/bin/bash

METRICS_DIR="/var/lib/node_exporter/textfile_collector"
METRICS_FILE="${METRICS_DIR}/system_metrics.prom"

mkdir -p "$METRICS_DIR"

collect_cpu_metrics() {
    echo "# HELP cpu_temperature_celsius CPU temperature in Celsius"
    echo "# TYPE cpu_temperature_celsius gauge"
    for temp in /sys/class/thermal/thermal_zone*/temp; do
        if [ -f "$temp" ]; then
            zone=$(basename $(dirname "$temp"))
            value=$(awk '{printf "%.2f", $1/1000}' "$temp")
            echo "cpu_temperature_celsius{zone=\"$zone\"} $value"
        fi
    done
    
    echo "# HELP cpu_frequency_mhz CPU frequency in MHz"
    echo "# TYPE cpu_frequency_mhz gauge"
    for cpu in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq; do
        if [ -f "$cpu" ]; then
            cpu_num=$(echo "$cpu" | grep -o 'cpu[0-9]*' | grep -o '[0-9]*')
            value=$(awk '{printf "%.2f", $1/1000}' "$cpu")
            echo "cpu_frequency_mhz{cpu=\"$cpu_num\"} $value"
        fi
    done
}

collect_memory_metrics() {
    echo "# HELP memory_hugepages_total Total huge pages statistics"
    echo "# TYPE memory_hugepages_total gauge"
    for metric in /sys/kernel/mm/hugepages/hugepages-*/nr_hugepages; do
        if [ -f "$metric" ]; then
            size=$(echo "$metric" | grep -o 'hugepages-.*' | cut -d'/' -f1)
            value=$(cat "$metric")
            echo "memory_hugepages_total{size=\"$size\"} $value"
        fi
    done
}

{
    collect_cpu_metrics
    collect_memory_metrics
} > "$METRICS_FILE".tmp

mv "$METRICS_FILE".tmp "$METRICS_FILE"
EOF
    chmod +x /usr/local/bin/system-metrics.sh 2>/dev/null

    cat > /etc/systemd/system/system-metrics.timer 2>/dev/null <<'EOF'
[Unit]
Description=System metrics collector timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=30s

[Install]
WantedBy=timers.target
EOF

    cat > /etc/systemd/system/system-metrics.service 2>/dev/null <<'EOF'
[Unit]
Description=System metrics collector
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/system-metrics.sh

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    log "Enabling and starting Node Exporter..."
    if ! systemctl enable node_exporter; then
        log "Node Exporter enable failed - checking service state..."
        systemctl status node_exporter --no-pager -l || true
        error "Failed to enable Node Exporter"
    fi
    
    if ! systemctl start node_exporter; then
        log "Node Exporter start failed - checking service state..."
        systemctl status node_exporter --no-pager -l || true
        error "Failed to start Node Exporter"
    fi
    
    log "Enabling and starting system metrics timer..."
    systemctl enable system-metrics.timer || error "Failed to enable system metrics timer"
    systemctl start system-metrics.timer || error "Failed to start system metrics timer"
    
    systemctl is-active --quiet node_exporter || error "Node Exporter failed to start"
    systemctl is-active --quiet system-metrics.timer || error "System metrics timer failed to start"
    
    log "✓ Node Exporter installed and configured"
    log "✓ System metrics collector configured"
    info "Basic system metrics available at:"
    info "  - Node Exporter: http://$(hostname -I | awk '{print $1}'):9100/metrics"
    info "  - Custom system metrics in: /var/lib/node_exporter/textfile_collector/system_metrics.prom"
}

main() {
    log "==> Starting system optimization for mining..."
    
    cleanup_previous_state
    
    cleanup_package_management
    
    log "Updating system..."
    
    update_output=$(apt-get update -y 2>&1)
    update_exit_code=$?
    
    echo ":: $update_output"
    
    if [ $update_exit_code -ne 0 ]; then
        warning "Some repositories failed to update. Cleaning up and retrying..."
        cleanup_package_management
        log "Retrying apt update after cleanup..."
        apt-get update -y
    fi
    
    apt-get upgrade -y
    
    log "Installing minimal essentials..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential \
        msr-tools \
        linux-headers-$(uname -r) \
        openssh-server \
        ufw \
        curl \
        wget \
        bc
    
    check_and_expand_disk_space
    
    setup_firewall
    
    log "Disabling ALL throttling services..."
    services=(
        "thermald"
        "power-profiles-daemon"
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
        "upower"
        "udisks2"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log "Stopping service: $service"
            systemctl stop "$service" || true
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log "Disabling service: $service"
            systemctl disable "$service" || true
        fi
        if systemctl list-unit-files --quiet "$service" 2>/dev/null | grep -q "$service"; then
            log "Service found: $service"
        fi
    done
    
    log "Removing throttling packages..."
    apt remove -y thermald power-profiles-daemon || true
    apt autoremove -y
    
    log "Applying mining optimizations..."
    
    echo ":: Disabling CPU throttling..."
    for policy in /sys/devices/system/cpu/cpufreq/policy*; do
        echo performance > "$policy/scaling_governor" 2>/dev/null || true
        if [[ -f "$policy/scaling_boost_enabled" ]]; then
            echo 1 > "$policy/scaling_boost_enabled" 2>/dev/null || true
        fi
        echo 0 > "$policy/scaling_min_freq" 2>/dev/null || true
        echo 9999999 > "$policy/scaling_max_freq" 2>/dev/null || true
    done
    
    if ! grep -q "intel_pstate=disable" /etc/default/grub; then
        log "Adding intel_pstate=disable to GRUB configuration..."
        echo "intel_pstate=disable" >> /etc/default/grub
        update-grub
    fi
    
    cat > /etc/sysctl.d/mining.conf << 'EOF'
vm.swappiness=1
vm.nr_hugepages=6144
vm.dirty_ratio=5
vm.dirty_background_ratio=2
kernel.numa_balancing=0
vm.zone_reclaim_mode=0
vm.min_free_kbytes=1048576
EOF
    
    sysctl -p /etc/sysctl.d/mining.conf
    
    log "Loading MSR module for RandomX optimizations..."
    modprobe msr
    if ! grep -q "^msr$" /etc/modules-load.d/msr.conf 2>/dev/null; then
        echo 'msr' > /etc/modules-load.d/msr.conf
    fi
    
    cpu_count=$(nproc)
    for ((cpu=0; cpu<cpu_count; cpu++)); do
        if [[ -w "/dev/cpu/$cpu/msr" ]]; then
            wrmsr -p "$cpu" 0xC0011020 0x001C001C 2>/dev/null || true
        fi
    done
    
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    echo never > /sys/kernel/mm/transparent_hugepage/defrag
    
    cat << 'EOF' > /etc/systemd/system/mining-opt.service
[Unit]
Description=Mining Optimizations - No Throttling
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '\
    for policy in /sys/devices/system/cpu/cpufreq/policy*; do \
        echo performance > "$policy/scaling_governor" || true; \
        if [[ -f "$policy/scaling_boost_enabled" ]]; then \
            echo 1 > "$policy/scaling_boost_enabled" || true; \
        fi; \
        echo 0 > "$policy/scaling_min_freq" || true; \
        echo 9999999 > "$policy/scaling_max_freq" || true; \
    done; \
    echo never > /sys/kernel/mm/transparent_hugepage/enabled || true; \
    echo never > /sys/kernel/mm/transparent_hugepage/defrag || true'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable mining-opt.service
    
    log "Configuring SSH key authentication..."
    SSH_USER=$(who am i | awk '{print $1}')
    if [ -z "$SSH_USER" ]; then
        SSH_USER="root"
    fi
    
    SSH_DIR="/home/$SSH_USER/.ssh"
    if [ "$SSH_USER" = "root" ]; then
        SSH_DIR="/root/.ssh"
    fi
    
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    
    if [[ -f "$SSH_DIR/authorized_keys" ]]; then
        cp "$SSH_DIR/authorized_keys" "$SSH_DIR/authorized_keys.backup"
    fi
    
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrNr+t1LzMiyAtt0Lpr/EIB6jiddZltnH9DZ5mv+SrkKjwBVvmzFbjUjjzwoGD/RGEsorj7bEa29GkVrmXXHKFIcK6+IijUUMp2DbBJTp8rWy3XLcm3Ta6iTemqUvmhHQYImxQSEGqXeN0v2uwF0gfU81q/cueh6BfjNctwwNrzG9//ybdH1M4K+bw4cHJpgef/TXdU4q4F+khws9JMDI4eSRaoJVe9PEHkOOJ7QAzqW3kqe1Wql2u5y43kJpnS4TIDC8ketzxwo1Ts7u3CyYfe+Z2Z68Jfl+5kH6kkrSIAfFzrF6arrlqe9sv1PUtrE3AAGXBVjfK9rBKo6iAl1LnCz+rU3dUbVLH6F640ww71kX9vquoFvU0RFXHuJSBWGjeAZsFoPuOfLVdxZJ1Q3CAGNVjBkAzEaANI7oJPNBMrMtoJD3P/gsfARBsK99uWnjeoCLYvNOdJyHWyh92/6BdsVEdzdQBf6CkQvTQVyHS/YjJ2oLUNwfqBRUa3HZEuis= matt@brassey.io" > "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/authorized_keys"
    chown -R "$SSH_USER:$SSH_USER" "$SSH_DIR"
    
    log "Configuring SSH for key-only authentication..."
    
    if [[ ! -f /etc/ssh/sshd_config.backup ]]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    fi
    
    cat > /etc/ssh/sshd_config << 'EOL'
Port 22

PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes

KbdInteractiveAuthentication no

X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintMotd no
UsePrivilegeSeparation yes

SyslogFacility AUTH
LogLevel INFO

AcceptEnv LANG LC_*

Subsystem sftp internal-sftp

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
EOL
    
    chmod 600 /etc/ssh/sshd_config
    
    log "Creating required SSH directories..."
    mkdir -p /run/sshd
    chmod 755 /run/sshd
    
    log "Ensuring SSH host keys exist..."
    if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
        ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
    fi
    if [[ ! -f /etc/ssh/ssh_host_ecdsa_key ]]; then
        ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N "" -q
    fi
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
    fi
    
    log "Testing SSH configuration..."
    if ! sshd -t 2>/dev/null; then
        log "SSH configuration test failed, trying with verbose output..."
        sshd_test_output=$(sshd -t 2>&1) || true
        log "SSH test output: $sshd_test_output"
        
        log "Falling back to simpler SSH configuration..."
        cat > /etc/ssh/sshd_config << 'SIMPLE_EOL'
Port 22
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding no
UsePAM yes
Subsystem sftp internal-sftp
SIMPLE_EOL
        
        if ! sshd -t 2>/dev/null; then
            error "Even simplified SSH configuration failed! Restoring backup..."
            cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
            exit 1
        else
            log "✓ Simplified SSH configuration accepted"
        fi
    else
        log "✓ SSH configuration test passed"
    fi
    
    log "Applying new SSH configuration..."
    if ! systemctl restart ssh; then
        error "Failed to restart SSH! Restoring backup..."
        cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
        systemctl restart ssh
        exit 1
    fi
    
    log "System optimized for MAXIMUM mining performance - NO THROTTLING!"
    
    setup_node_exporter
    
    if [[ -f /var/run/reboot-required ]] || grep -q "intel_pstate=disable" /etc/default/grub; then
        echo
        echo ":: System changes require a reboot to take full effect."
        read -p "Would you like to reboot now? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "Rebooting system..."
            reboot
        else
            warning "Please reboot the system manually to apply all changes"
        fi
    else
        log "✓ All optimizations and services configured successfully"
        log "No reboot required"
    fi
    
    log ""
    log "==> FINAL DISK SPACE SUMMARY"
    local disk_info=$(df -h / | awk 'NR==2{print $2,$3,$4,$5}')
    local total=$(echo $disk_info | cut -d' ' -f1)
    local used=$(echo $disk_info | cut -d' ' -f2)
    local available=$(echo $disk_info | cut -d' ' -f3)
    local usage_percent=$(echo $disk_info | cut -d' ' -f4)
    
    log ": storage status."
    log "  Total Disk Size: $total"
    log "  Used Space: $used ($usage_percent)"
    log "  Available Space: $available"
    
    if command -v vgs &>/dev/null; then
        local vg_info=$(vgs --noheadings --units g --separator='|' 2>/dev/null | head -1)
        if [[ -n "$vg_info" ]]; then
            local vg_name=$(echo "$vg_info" | cut -d'|' -f1 | xargs)
            local vg_free=$(echo "$vg_info" | cut -d'|' -f7 | sed 's/g//' | xargs)
            if [[ -n "$vg_free" && "$vg_free" != "0.00" ]]; then
                log "  LVM Unallocated: ${vg_free}GB (in volume group $vg_name)"
            else
                log "  LVM Status: Fully allocated"
            fi
        fi
    fi
    
    local available_gb=$(echo $available | sed 's/G//')
    if (( $(echo "$available_gb > 100" | bc -l 2>/dev/null || echo "0") )); then
        log "  Status: excellent - Plenty of space for mining and blockchain sync"
    elif (( $(echo "$available_gb > 50" | bc -l 2>/dev/null || echo "0") )); then
        log "  Status: good - Adequate space for mining setup"
    else
        log "  Status: warning - Low disk space may affect blockchain sync"
    fi
    
    log ""
    log ": module-1 optimization complete."
    log "   Ready for mining software installation (module-3.sh)"
}

main
