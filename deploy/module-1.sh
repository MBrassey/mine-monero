#!/bin/bash

# Module 1: System Preparation
# Configures static IP, SSH access, and hardware optimizations
# Requires reboot for full optimization activation

set -e

# ================================
# CONFIGURATION VARIABLES
# ================================
STATIC_IP="10.10.10.2" # UPDATE
GATEWAY="10.10.10.1"
SUBNET_MASK="255.255.255.0"
CIDR_NOTATION="24"
DNS_SERVERS="8.8.8.8,8.8.4.4"

# Engineer SSH Public Key
ENGINEER_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrNr+t1LzMiyAtt0Lpr/EIB6jiddZltnH9DZ5mv+SrkKjwBVvmzFbjUjjzwoGD/RGEsorj7bEa29GkVrmXXHKFIcK6+IijUUMp2DbBJTp8rWy3XLcm3Ta6iTemqUvmhHQYImxQSEGqXeN0v2uwF0gfU81q/cueh6BfjNctwwNrzG9//ybdH1M4K+bw4cHJpgef/TXdU4q4F+khws9JMDI4eSRaoJVe9PEHkOOJ7QAzqW3kqe1Wql2u5y43kJpnS4TIDC8ketzxwo1Ts7u3CyYfe+Z2Z68Jfl+5kH6kkrSIAfFzrF6arrlqe9sv1PUtrE3AAGXBVjfK9rBKo6iAl1LnCz+rU3dUbVLH6F640ww71kX9vquoFvU0RFXHuJSBWGjeAZsFoPuOfLVdxZJ1Q3CAGNVjBkAzEaANI7oJPNBMrMtoJD3P/gsfARBsK99uWnjeoCLYvNOdJyHWyh92/6BdsVEdzdQBf6CkQvTQVyHS/YjJ2oLUNwfqBRUa3HZEuis= matt@brassey.io"

# Global Variables
PRIMARY_INTERFACE=""
CURRENT_IP=""
ORIGINAL_GATEWAY=""

# ================================
# LOGGING FUNCTIONS
# ================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

success() {
    echo -e "${CYAN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}"
}

section() {
    echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] === $1 ===${NC}"
}

# Prompt for user confirmation
confirm() {
    local message="$1"
    local default="${2:-n}"
    
    if [[ "$default" == "y" ]]; then
        local prompt="[Y/n]"
    else
        local prompt="[y/N]"
    fi
    
    while true; do
        read -p "$message $prompt: " choice
        case "${choice:-$default}" in
            [Yy]* ) return 0 ;;
            [Nn]* ) return 1 ;;
            * ) echo "Please answer yes or no." ;;
        esac
    done
}

# ================================
# VERIFICATION FUNCTIONS
# ================================

verify_root_access() {
    section "Verifying Root Access"
    
    # Check if running as sudo
    if [[ $EUID -eq 0 ]]; then
       error "Script should not be run as root directly. Run with sudo from regular user account."
       exit 1
    fi

    # Verify sudo access
    if ! sudo -n true 2>/dev/null; then
        error "Script requires sudo access. Ensure user has sudo privileges."
        exit 1
    fi
    
    success "Root access verified"
}

detect_network_interface() {
    section "Detecting Network Interface"
    
    info "Scanning for active network interfaces..."
    
    # Get all available network interfaces
    local interfaces=($(ip link show | grep -E '^[0-9]+:' | grep -v 'lo:' | awk -F: '{print $2}' | tr -d ' '))
    
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        error "No network interfaces found"
        exit 1
    fi
    
    info "Available interfaces: ${interfaces[*]}"
    
    # Try to detect primary interface with default route
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        warning "No default route found. Detecting active interface..."
        
        # Try to find interface with IP address
        for iface in "${interfaces[@]}"; do
            if ip addr show "$iface" | grep -q "inet "; then
                PRIMARY_INTERFACE="$iface"
                break
            fi
        done
    fi
    
    if [[ -z "$PRIMARY_INTERFACE" ]]; then
        warning "Could not auto-detect primary network interface"
        info "Available interfaces: ${interfaces[*]}"
        echo "Please select an interface:"
        select interface in "${interfaces[@]}"; do
            if [[ -n "$interface" ]]; then
                PRIMARY_INTERFACE="$interface"
                break
            else
                echo "Invalid selection. Please try again."
            fi
        done
        
        if [[ -z "$PRIMARY_INTERFACE" ]]; then
            error "No interface selected"
            exit 1
        fi
    fi
    
    # Verify interface exists and is up
    if ! ip link show "$PRIMARY_INTERFACE" &>/dev/null; then
        error "Interface $PRIMARY_INTERFACE does not exist"
        exit 1
    fi
    
    # Get current network configuration
    CURRENT_IP=$(ip addr show "$PRIMARY_INTERFACE" | grep "inet " | awk '{print $2}' | cut -d'/' -f1 | head -n1)
    ORIGINAL_GATEWAY=$(ip route | grep default | awk '{print $3}' | head -n1)
    
    success "Primary interface detected: $PRIMARY_INTERFACE"
    info "Current IP: ${CURRENT_IP:-'No IP assigned'}"
    info "Current Gateway: ${ORIGINAL_GATEWAY:-'No gateway'}"
    
    # Show interface details
    info "Interface details:"
    ip addr show "$PRIMARY_INTERFACE" | head -5
    
    if ! confirm "Continue with interface $PRIMARY_INTERFACE?" "y"; then
        error "User canceled interface selection"
        exit 1
    fi
}

verify_network_configuration() {
    section "Verifying Network Configuration"
    
    info "Target static IP: $STATIC_IP/$CIDR_NOTATION"
    info "Target gateway: $GATEWAY"
    info "DNS servers: $DNS_SERVERS"
    
    # Validate IP format
    if ! [[ $STATIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        error "Invalid IP address format: $STATIC_IP"
        exit 1
    fi
    
    if ! [[ $GATEWAY =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        error "Invalid gateway address format: $GATEWAY"
        exit 1
    fi
    
    # Check if IP is in same subnet as gateway
    local static_network=$(echo $STATIC_IP | cut -d. -f1-3)
    local gateway_network=$(echo $GATEWAY | cut -d. -f1-3)
    
    if [[ "$static_network" != "$gateway_network" ]]; then
        warning "Static IP and gateway appear to be in different subnets"
        if ! confirm "Continue anyway?"; then
            exit 1
        fi
    fi
    
    success "Network configuration validated"
    
    if ! confirm "Proceed with network configuration?" "y"; then
        error "User canceled network configuration"
        exit 1
    fi
}

# ================================
# INSTALLATION FUNCTIONS
# ================================

update_system_packages() {
    section "Updating System Packages"
    
    info "Updating package lists..."
    if ! sudo apt update -y; then
        error "Failed to update package lists"
        exit 1
    fi
    
    info "Upgrading installed packages..."
    if ! sudo apt upgrade -y; then
        error "Failed to upgrade packages"
        exit 1
    fi
    
    success "System packages updated successfully"
}

install_essential_tools() {
    section "Installing Essential Tools"
    
    local essential_packages=(
        "openssh-server"
        "bpytop"
        "net-tools"
        "jq"
        "curl"
        "wget"
        "git"
        "htop"
        "iotop"
        "iftop"
        "lm-sensors"
        "ethtool"
        "tcpdump"
        "rsync"
        "tree"
        "unzip"
        "vim"
        "dmidecode"
        "build-essential"
        "cmake"
        "python3-pip"
    )
    
    info "Installing ${#essential_packages[@]} essential packages..."
    
    for package in "${essential_packages[@]}"; do
        info "Installing $package..."
        if ! sudo apt install -y "$package"; then
            warning "Failed to install $package, continuing..."
        else
            success "$package installed successfully"
        fi
    done
    
    success "Essential tools installation completed"
}

configure_static_network() {
    section "Configuring Static Network"
    
    info "Backing up existing netplan configuration..."
    sudo mkdir -p /etc/netplan/backup
    sudo cp /etc/netplan/*.yaml /etc/netplan/backup/ 2>/dev/null || true
    
    info "Creating static IP configuration for interface: $PRIMARY_INTERFACE"
    
    # Create new netplan configuration
    cat << EOF | sudo tee /etc/netplan/01-static-config.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ${PRIMARY_INTERFACE}:
      dhcp4: false
      addresses:
        - ${STATIC_IP}/${CIDR_NOTATION}
      gateway4: ${GATEWAY}
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
      optional: true
EOF

    success "Static network configuration created"
    
    # Validate netplan configuration
    info "Validating netplan configuration..."
    if ! sudo netplan generate; then
        error "Netplan configuration validation failed"
        exit 1
    fi
    
    success "Netplan configuration validated"
    
    if confirm "Apply network configuration now? (This may temporarily disconnect the session)" "y"; then
        info "Applying network configuration..."
        if sudo netplan apply; then
            success "Network configuration applied"
            sleep 3  # Allow time for network to stabilize
        else
            error "Failed to apply network configuration"
            exit 1
        fi
    fi
}

verify_network_connectivity() {
    section "Verifying Network Connectivity"
    
    # Get current IP after configuration
    local new_ip=$(hostname -I | awk '{print $1}')
    info "Current IP address: $new_ip"
    
    # Verify static IP was actually applied
    if [[ "$new_ip" == "$STATIC_IP" ]]; then
        success "Static IP correctly applied: $STATIC_IP"
    else
        error "Static IP not applied correctly. Expected: $STATIC_IP, Got: $new_ip"
        info "This may require reboot or manual network restart"
        if confirm "Continue anyway? (May need manual network restart)" "n"; then
            warning "Continuing with potentially incorrect network configuration"
        else
            exit 1
        fi
    fi
    
    # Test local connectivity
    info "Testing local connectivity..."
    if ping -c 2 "$GATEWAY" >/dev/null 2>&1; then
        success "Gateway ($GATEWAY) is reachable"
    else
        error "Gateway ($GATEWAY) is not reachable - network configuration failed"
        exit 1
    fi
    
    # Test internet connectivity
    info "Testing internet connectivity..."
    if ping -c 3 8.8.8.8 >/dev/null 2>&1; then
        success "Internet connectivity verified"
    else
        error "Internet connectivity test failed"
        exit 1
    fi
    
    # Test DNS resolution
    info "Testing DNS resolution..."
    if nslookup google.com >/dev/null 2>&1; then
        success "DNS resolution working"
    else
        warning "DNS resolution test failed - continuing with backup DNS"
    fi
    
    # Additional network verification
    info "Verifying network route configuration..."
    local default_route=$(ip route | grep default | awk '{print $3}' | head -n1)
    if [[ "$default_route" == "$GATEWAY" ]]; then
        success "Default route correctly configured to: $GATEWAY"
    else
        warning "Default route mismatch. Expected: $GATEWAY, Got: $default_route"
    fi
    
    # Test network interface configuration
    info "Verifying interface configuration..."
    local interface_ip=$(ip addr show "$PRIMARY_INTERFACE" | grep "inet " | awk '{print $2}' | cut -d'/' -f1 | head -n1)
    if [[ "$interface_ip" == "$STATIC_IP" ]]; then
        success "Interface $PRIMARY_INTERFACE correctly configured with $STATIC_IP"
    else
        warning "Interface IP mismatch. Expected: $STATIC_IP, Got: $interface_ip"
    fi
}

configure_ssh_access() {
    section "Configuring SSH Access"
    
    info "Enabling and starting SSH service..."
    sudo systemctl enable ssh
    sudo systemctl start ssh
    
    # Create .ssh directory for current user
    info "Setting up SSH directory and permissions..."
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    
    # Add engineer public key to authorized_keys
    info "Adding engineer public key to authorized_keys..."
    echo "${ENGINEER_PUBLIC_KEY}" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    
    # Configure SSH for security and performance
    info "Configuring SSH security settings..."
    sudo tee /etc/ssh/sshd_config.d/mining-rig.conf << EOF
# Mining Rig SSH Configuration
Port 22
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication yes
MaxAuthTries 3
ClientAliveInterval 60
ClientAliveCountMax 10
X11Forwarding no
AllowUsers ${USER}

# Security hardening
Protocol 2
MaxSessions 3
LoginGraceTime 60
TCPKeepAlive yes
Compression delayed
UseDNS no

# Brute force protection
MaxStartups 3:30:10
AuthenticationMethods publickey,password
EOF

    # Install and configure fail2ban for SSH protection
    info "Installing SSH brute-force protection..."
    sudo apt install -y fail2ban
    
    sudo tee /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

    info "Restarting SSH and fail2ban services..."
    sudo systemctl restart ssh
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    
    # Verify SSH is running
    if systemctl is-active --quiet ssh; then
        success "SSH service is active and configured"
    else
        error "SSH service is not active"
        exit 1
    fi
    
    # Verify fail2ban is running
    if systemctl is-active --quiet fail2ban; then
        success "Fail2ban SSH protection active"
    else
        warning "Fail2ban service is not active"
    fi
    
    # Test SSH key authentication
    info "Testing SSH key authentication..."
    if ssh-keygen -l -f ~/.ssh/authorized_keys >/dev/null 2>&1; then
        success "SSH public key properly installed"
        local key_info=$(ssh-keygen -l -f ~/.ssh/authorized_keys | head -1)
        info "Key info: $key_info"
    else
        warning "SSH key validation failed - manual verification recommended"
    fi
}

configure_firewall() {
    section "Configuring Firewall"
    
    info "Enabling UFW firewall..."
    sudo ufw --force enable
    
    info "Allowing SSH access..."
    sudo ufw allow ssh
    
    info "Allowing access from mining network (10.10.10.0/24)..."
    sudo ufw allow from 10.10.10.0/24
    
    info "Opening metrics and monitoring ports..."
    sudo ufw allow 9100/tcp comment "XMRig Exporter"
    sudo ufw allow 9101/tcp comment "Node Exporter"
    sudo ufw allow 18088/tcp comment "XMRig API"
    
    success "Firewall configured successfully"
}

optimize_system() {
    section "Optimizing System for Mining"
    
    # Disable unnecessary services for mining rig
    local services_to_disable=(
        "bluetooth"
        "cups"
        "cups-browsed"
        "avahi-daemon"
        "snapd"
        "ModemManager"
        "NetworkManager-wait-online"
    )
    
    info "Disabling unnecessary services..."
    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" 2>/dev/null | grep -q enabled; then
            sudo systemctl disable "$service" 2>/dev/null || true
            success "Disabled service: $service"
        else
            info "Service $service already disabled or not present"
        fi
    done
    
    # Configure system for performance
    info "Applying system performance optimizations..."
    echo 'vm.swappiness=1' | sudo tee -a /etc/sysctl.conf
    echo 'net.core.default_qdisc=fq' | sudo tee -a /etc/sysctl.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' | sudo tee -a /etc/sysctl.conf
    
    success "System optimizations applied"
}

create_system_utilities() {
    section "Creating System Utilities"
    
    info "Creating system information script..."
    cat << 'EOF' | sudo tee /usr/local/bin/system-info
#!/bin/bash
echo "=== Mining Rig System Information ==="
echo "Hostname: $(hostname)"
echo "IP Address: $(hostname -I | awk '{print $1}')"
echo "Uptime: $(uptime -p)"
echo "CPU: $(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)"
echo "Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
echo "Disk Usage: $(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')"
echo "Temperature: $(sensors 2>/dev/null | grep -E 'Core|Tctl' | head -1 || echo 'Not available')"
echo "Network Interface: $(ip route | grep default | awk '{print $5}' | head -n1)"
echo "SSH Status: $(systemctl is-active ssh)"
echo "=== Ready for Module 2 Installation ==="
EOF

    sudo chmod +x /usr/local/bin/system-info
    
    success "System utilities created"
}

configure_huge_pages() {
    section "Configuring Memory Optimization (Huge Pages)"
    
    info "Configuring huge pages for optimal mining performance..."
    
    # Configure 2MB huge pages for RandomX (32 threads + extra)
    echo 'vm.nr_hugepages=6144' | sudo tee -a /etc/sysctl.conf
    
    # Enable 1GB huge pages for maximum RandomX performance
    echo 4 | sudo tee /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages 2>/dev/null || true
    
    # Add 1GB huge pages to GRUB configuration
    if ! grep -q "hugetlb_1gb" /etc/default/grub 2>/dev/null; then
        echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT hugetlb_1gb=4"' | sudo tee -a /etc/default/grub
        sudo update-grub
        info "GRUB updated with 1GB huge pages configuration"
    fi
    
    # Disable transparent huge pages for consistent performance
    echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
    echo never | sudo tee /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true
    
    # Add transparent huge page disabling to systemd
    cat << 'EOF' | sudo tee /etc/systemd/system/disable-thp.service > /dev/null
[Unit]
Description=Disable Transparent Huge Pages for Mining
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled'
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/defrag'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable disable-thp.service
    
    # Additional memory optimizations for mining
    cat << 'EOF' | sudo tee -a /etc/sysctl.conf

# Memory optimizations for RandomX mining
vm.dirty_ratio=5
vm.dirty_background_ratio=2
kernel.numa_balancing=0
vm.zone_reclaim_mode=0
vm.vfs_cache_pressure=50
vm.min_free_kbytes=1048576

# Network optimizations for mining
net.core.rmem_default=262144
net.core.rmem_max=16777216
net.core.wmem_default=262144
net.core.wmem_max=16777216

# CPU performance optimizations
kernel.sched_migration_cost_ns=5000000
kernel.sched_autogroup_enabled=0
kernel.randomize_va_space=0

# Memory allocation optimizations
vm.overcommit_memory=1
vm.overcommit_ratio=100
EOF

    success "Huge pages and memory optimizations configured"
    warning "1GB huge pages require reboot to take effect"
}

apply_cpu_optimizations() {
    section "Applying CPU and System Optimizations"
    
    # Install MSR tools for CPU optimizations
    info "Installing CPU optimization tools..."
    sudo apt install -y msr-tools cpufrequtils linux-tools-common linux-tools-generic || {
        warning "Some CPU optimization tools may not be available"
    }
    
    # Enable MSR module for RandomX optimizations
    sudo modprobe msr 2>/dev/null || true
    echo 'msr' | sudo tee -a /etc/modules-load.d/msr.conf
    
    # Advanced MSR optimizations for RandomX mining (with safety checks)
    apply_msr_optimizations() {
        local msr_success=false
        
        # Check if MSR module is loaded and accessible
        if [[ ! -c /dev/cpu/0/msr ]]; then
            info "Loading MSR module..."
            sudo modprobe msr 2>/dev/null || {
                warning "MSR module cannot be loaded - BIOS may have MSR access disabled"
                return 1
            }
        fi
        
        # Verify MSR tools are available
        if ! command -v wrmsr &> /dev/null; then
            warning "wrmsr tool not available - MSR optimizations skipped"
            return 1
        fi
        
        # Test MSR access with safe read-only operation first
        if sudo rdmsr -p 0 0x1A &>/dev/null; then
            info "MSR access confirmed - applying Ryzen optimizations..."
            
            # Apply MSR optimizations with proper error handling
            local cpu_count=$(nproc)
            local success_count=0
            
            for ((cpu=0; cpu<cpu_count; cpu++)); do
                if [[ -w "/dev/cpu/$cpu/msr" ]]; then
                    # MSR 0xC0011020 - LS-CFG register optimizations (conservative values)
                    if sudo wrmsr -p "$cpu" 0xC0011020 0x001C001C 2>/dev/null; then
                        ((success_count++))
                    fi
                fi
            done
            
            if [[ "$success_count" -gt 0 ]]; then
                success "MSR optimizations applied successfully to $success_count cores"
                msr_success=true
            else
                warning "MSR write operations failed - using fallback optimizations"
            fi
        else
            warning "MSR access denied - BIOS may have MSR access disabled"
            warning "Enable MSR access in BIOS for optimal performance"
        fi
        
        return $([[ "$msr_success" == "true" ]] && echo 0 || echo 1)
    }
    
    if apply_msr_optimizations; then
        success "MSR optimizations applied for enhanced RandomX performance"
    else
        info "MSR optimizations unavailable - using CPU governor optimizations instead"
        # Fallback: more aggressive CPU governor settings
        echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor &>/dev/null || true
        echo '1' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_boost &>/dev/null || true
    fi
    
    # Create persistent CPU optimization service
    info "Creating persistent CPU optimizations..."
    cat << 'EOF' | sudo tee /usr/local/bin/mining-optimization.sh > /dev/null
#!/bin/bash
# Mining Hardware Optimizations - Applied at Boot

# Set performance governor for all CPUs
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || true

# Disable CPU idle states for consistent performance
for i in /sys/devices/system/cpu/cpu*/cpuidle/state*/disable; do
    [ -f "$i" ] && echo 1 > "$i" 2>/dev/null || true
done

# Disable NUMA balancing for mining workload
echo 0 > /proc/sys/kernel/numa_balancing 2>/dev/null || true

# Memory performance optimizations
echo 1 > /proc/sys/vm/compact_memory 2>/dev/null || true

# Disable transparent huge pages
echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true

# Set I/O scheduler to performance for all storage devices
for disk in /sys/block/sd* /sys/block/nvme* /sys/block/mmcblk*; do
    [ -d "$disk" ] && echo mq-deadline > "$disk/queue/scheduler" 2>/dev/null || true
done

# IRQ affinity optimization - reserve cores 0-1 for system
for irq in /proc/irq/*/; do
    if [[ -f "${irq}/smp_affinity" ]]; then
        local irq_num=$(basename "$irq")
        if [[ "$irq_num" =~ ^[0-9]+$ ]]; then
            echo "3" > "${irq}/smp_affinity" 2>/dev/null || true
        fi
    fi
done

# Initialize sensors
sensors -s 2>/dev/null || true
EOF
    
    chmod +x /usr/local/bin/mining-optimization.sh
    
    # Create systemd service for boot-time optimizations
    cat << 'EOF' | sudo tee /etc/systemd/system/mining-optimization.service > /dev/null
[Unit]
Description=Mining Hardware Optimizations
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mining-optimization.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable mining-optimization.service
    
    success "CPU and system optimizations configured for boot"
}

setup_thermal_monitoring() {
    section "Setting up Thermal Monitoring"
    
    # Install thermal monitoring tools
    info "Installing thermal monitoring tools..."
    sudo apt install -y lm-sensors fancontrol pwmconfig || true
    
    # Detect sensors
    sudo sensors-detect --auto 2>/dev/null || true
    
    # Create thermal monitoring script (simplified for system preparation)
    info "Creating thermal monitoring service..."
    sudo tee /usr/local/bin/thermal-monitor.sh > /dev/null << 'EOF'
#!/bin/bash
# System thermal monitoring

TEMP_THRESHOLD=85  # Celsius
LOG_FILE="/var/log/thermal-monitor.log"

log_thermal() {
    echo "$(date): $1" >> "$LOG_FILE"
}

optimize_for_temperature() {
    local temp=$1
    
    if [[ "$temp" -gt 90 ]]; then
        # Critical temperature - reduce performance
        log_thermal "Critical temp ${temp}°C - reducing performance"
        echo powersave > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || true
    elif [[ "$temp" -gt 85 ]]; then
        # High temperature - moderate reduction
        log_thermal "High temp ${temp}°C - reducing optimizations"
        echo schedutil > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || true
    elif [[ "$temp" -lt 75 ]]; then
        # Good temperature - enable maximum performance
        log_thermal "Good temp ${temp}°C - enabling maximum performance"
        echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || true
    fi
}

# Main monitoring loop
while true; do
    # Get CPU temperature
    CPU_TEMP=$(sensors 2>/dev/null | grep -i "Tctl\|Package" | grep -oP '\+\K[0-9]+' | head -1)
    
    if [[ -n "$CPU_TEMP" ]]; then
        echo "$(date): CPU temperature: ${CPU_TEMP}°C" >> "$LOG_FILE"
        optimize_for_temperature "$CPU_TEMP"
    fi
    
    sleep 60
done
EOF
    
    chmod +x /usr/local/bin/thermal-monitor.sh
    
    # Create thermal monitoring service
    sudo tee /etc/systemd/system/thermal-monitor.service > /dev/null << 'EOF'
[Unit]
Description=System Thermal Monitoring
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/bin/thermal-monitor.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable thermal-monitor.service
    
    success "Thermal monitoring configured"
}

prepare_for_module2() {
    section "Preparing for Module-2 Execution"
    
    # Create mining user directories
    info "Creating mining directories..."
    mkdir -p ~/mining-setup
    mkdir -p ~/mining-logs
    
    # Set execute permissions for module-2.sh if it exists
    if [[ -f "module-3.sh" ]]; then
        chmod +x module-3.sh
        success "Module-3.sh permissions set"
    else
        info "Module-3.sh not found in current directory"
    fi
    
    # Apply immediate sysctl settings (non-reboot ones)
    info "Applying immediate system optimizations..."
    sudo sysctl -p
    
    success "System prepared for Module-3 execution"
}

prompt_reboot() {
    section "System Reboot Required"
    
    info "The following optimizations require system reboot to take effect:"
    info "  - 1GB huge pages for maximum RandomX performance"
    info "  - CPU performance optimizations"
    info "  - Memory bandwidth optimizations"
    info "  - MSR (CPU register) access for mining"
    info "  - Persistent performance governor settings"
    echo ""
    warning "Without reboot: ~95% mining performance"
    success "After reboot: 100% mining performance"
    echo ""
    
    if confirm "Reboot now to enable all optimizations? (Recommended)" "y"; then
        info "System will reboot in 10 seconds..."
        info "After reboot:"
        info "  1. SSH back into system: ssh ${USER}@${STATIC_IP}"
        info "  2. Remove video card (if not done already)"
        info "  3. Run module-3.sh for mining software installation"
        echo ""
        sleep 10
        sudo reboot
    else
        echo ""
        warning "Reboot postponed - remember to reboot before running module-3.sh"
        info "To reboot later: sudo reboot"
        info "After reboot, verify optimizations:"
        info "  - 1GB huge pages: cat /proc/meminfo | grep -i hugepages"
        info "  - CPU governor: cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
        info "  - MSR access: ls -la /dev/cpu/*/msr"
        echo ""
        info "Then proceed with module-3.sh installation"
    fi
}

# ================================
# MAIN EXECUTION FUNCTION
# ================================

main() {
    section "Module 1: System Preparation Script"
    info "Configuring mining rig with static IP: ${STATIC_IP}"
    info "Target gateway: ${GATEWAY}"
    info "Engineer SSH key will be installed for remote access"
    
    if ! confirm "Begin Module 1 system preparation?" "y"; then
        error "User canceled installation"
        exit 1
    fi
    
    # Execute all modules in sequence with verification
    verify_root_access
    detect_network_interface
    verify_network_configuration
    update_system_packages
    install_essential_tools
    configure_static_network
    verify_network_connectivity
    configure_ssh_access
    configure_firewall
    optimize_system
    configure_huge_pages
    apply_cpu_optimizations
    setup_thermal_monitoring
    create_system_utilities
    prepare_for_module2
    
    # Final system information and next steps
    section "Module 1 Configuration Complete"
    success "Static IP configured: ${STATIC_IP}"
    success "Gateway configured: ${GATEWAY}"
    success "SSH access enabled for user: ${USER}"
    success "Engineer public key added to authorized_keys"
    success "Essential tools installed: bpytop, netstat, jq, and others"
    success "System optimizations applied"
    success "Huge pages and CPU optimizations configured"
    success "Mining performance optimizations ready"
    
    # Show system info
    echo ""
    /usr/local/bin/system-info
    
    # Prompt for reboot (includes all next steps)
    prompt_reboot
}

# ================================
# SCRIPT EXECUTION
# ================================

# Trap to handle script interruption
trap 'echo -e "\n${RED}Script interrupted by user${NC}"; exit 1' INT

# Execute main function
main "$@"
