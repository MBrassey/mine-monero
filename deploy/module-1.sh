#!/bin/bash

# Module 1: System Preparation
# Configures SSH access and hardware optimizations
# Requires reboot for full optimization activation

# Exit on any error
set -e

# Trap errors and print the line number where they occurred
trap 'echo "Error on line $LINENO"' ERR

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run with sudo"
    exit 1
fi

# Check if running directly as root (not via sudo)
if [ -z "$SUDO_USER" ]; then
    echo "This script must be run with sudo, not as root directly"
    exit 1
fi

# ================================
# CONFIGURATION VARIABLES
# ================================

# Engineer SSH Public Key
ENGINEER_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrNr+t1LzMiyAtt0Lpr/EIB6jiddZltnH9DZ5mv+SrkKjwBVvmzFbjUjjzwoGD/RGEsorj7bEa29GkVrmXXHKFIcK6+IijUUMp2DbBJTp8rWy3XLcm3Ta6iTemqUvmhHQYImxQSEGqXeN0v2uwF0gfU81q/cueh6BfjNctwwNrzG9//ybdH1M4K+bw4cHJpgef/TXdU4q4F+khws9JMDI4eSRaoJVe9PEHkOOJ7QAzqW3kqe1Wql2u5y43kJpnS4TIDC8ketzxwo1Ts7u3CyYfe+Z2Z68Jfl+5kH6kkrSIAfFzrF6arrlqe9sv1PUtrE3AAGXBVjfK9rBKo6iAl1LnCz+rU3dUbVLH6F640ww71kX9vquoFvU0RFXHuJSBWGjeAZsFoPuOfLVdxZJ1Q3CAGNVjBkAzEaANI7oJPNBMrMtoJD3P/gsfARBsK99uWnjeoCLYvNOdJyHWyh92/6BdsVEdzdQBf6CkQvTQVyHS/YjJ2oLUNwfqBRUa3HZEuis= matt@brassey.io"

# Global Variables
PRIMARY_INTERFACE=""

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
# VALIDATION FUNCTIONS
# ================================

verify_root_access() {
    section "Verifying Root Access"
    
    # Check if we have sudo privileges
    if ! sudo -n true 2>/dev/null; then
        error "Script requires sudo access. Ensure user has sudo privileges."
        exit 1
    fi
    
    # Verify correct username
    if [[ "$SUDO_USER" != "ubuntu" ]]; then
        error "Script must be run as user 'ubuntu'. Current user: $SUDO_USER"
        exit 1
    fi
    
    success "Root access and user verification completed"
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
    
    success "Primary interface detected: $PRIMARY_INTERFACE"
    
    # Show interface details
    info "Interface details:"
    ip addr show "$PRIMARY_INTERFACE" | head -5
    
    if ! confirm "Continue with interface $PRIMARY_INTERFACE?" "y"; then
        error "User canceled interface selection"
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
    
    # Install base packages first
    local base_packages=(
        "software-properties-common"
        "apt-transport-https"
        "ca-certificates"
        "gnupg"
        "sudo"
        "ufw"
        "iproute2"
        "systemd"
        "curl"               # Required for network checks
        "iputils-ping"       # Required for network checks
        "netcat-openbsd"    # Required for port checks
        "net-tools"         # Required for network tools
        "openssh-server"    # Required for SSH
        "fail2ban"          # Required for SSH security
    )
    
    info "Installing base packages..."
    # Ensure apt is available and updated
    if ! command -v apt >/dev/null 2>&1; then
        error "apt package manager not found. This script requires Ubuntu."
        exit 1
    fi
    
    # Update package lists first
    info "Updating package lists..."
    if ! sudo apt update; then
        error "Failed to update package lists"
        exit 1
    fi
    
    # Install base packages
    info "Installing base packages..."
    if ! sudo DEBIAN_FRONTEND=noninteractive apt install -y "${base_packages[@]}"; then
        error "Failed to install base packages"
        exit 1
    fi
    success "Base packages installed successfully"
    
    # Verify critical networking tools
    local critical_network_tools=("curl" "ping" "nc" "netstat" "ssh")
    local missing_tools=()
    
    for tool in "${critical_network_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Critical networking tools missing after installation: ${missing_tools[*]}"
        exit 1
    fi
    success "Critical networking tools verified"
    
    # Define essential packages in order of importance
    local essential_packages=(
        # Core build tools
        "build-essential"
        "cmake"
        "git"
        
        # System utilities
        "vim"
        "jq"
        "wget"
        
        # Monitoring tools
        "htop"
        "bpytop"
        "iotop"
        "iftop"
        "lm-sensors"
        
        # Network tools
        "ethtool"
        "tcpdump"
        
        # Additional utilities
        "rsync"
        "tree"
        "unzip"
        "dmidecode"
        "python3-pip"
        "linux-headers-$(uname -r)"
        "pciutils"
        "acpi"
        "bc"
        "kmod"
    )
    
    info "Installing ${#essential_packages[@]} essential packages..."
    
    # Install all packages at once
    if ! sudo DEBIAN_FRONTEND=noninteractive apt install -y "${essential_packages[@]}"; then
        warning "Some non-critical packages may have failed to install. Continuing..."
    fi
    
    # Verify critical tools are installed
    local critical_tools=("gcc" "make" "git")
    local missing_tools=()
    
    for tool in "${critical_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Critical build tools missing after installation: ${missing_tools[*]}"
        exit 1
    fi
    
    success "Essential tools installation completed"
}

configure_ssh_access() {
    section "Configuring SSH Access"
    
    info "Ensuring netcat-openbsd is installed..."
    sudo apt install -y netcat-openbsd || {
        error "Failed to install netcat-openbsd"
        exit 1
    }
    
    info "Enabling and starting SSH service..."
    sudo systemctl enable ssh
    sudo systemctl start ssh
    
    # Create .ssh directory for current user
    info "Setting up SSH directory and permissions..."
    sudo -u "$SUDO_USER" mkdir -p "/home/$SUDO_USER/.ssh"
    sudo chown "$SUDO_USER:$SUDO_USER" "/home/$SUDO_USER/.ssh"
    sudo chmod 700 "/home/$SUDO_USER/.ssh"
    
    # Add engineer public key to authorized_keys
    info "Adding engineer public key to authorized_keys..."
    echo "${ENGINEER_PUBLIC_KEY}" | sudo -u "$SUDO_USER" tee "/home/$SUDO_USER/.ssh/authorized_keys" > /dev/null
    sudo chown "$SUDO_USER:$SUDO_USER" "/home/$SUDO_USER/.ssh/authorized_keys"
    sudo chmod 600 "/home/$SUDO_USER/.ssh/authorized_keys"
    
    # Configure SSH for security and performance
    info "Configuring SSH security settings..."
    sudo tee /etc/ssh/sshd_config.d/mining-rig.conf << EOF
# Mining Rig SSH Configuration
Port 22
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM no
MaxAuthTries 3
ClientAliveInterval 60
ClientAliveCountMax 10
X11Forwarding no
AllowUsers ${SUDO_USER}

# Security hardening
Protocol 2
MaxSessions 3
LoginGraceTime 60
TCPKeepAlive yes
Compression delayed
UseDNS no

# Brute force protection
MaxStartups 3:30:10
AuthenticationMethods publickey
EOF

    # Ensure main sshd_config has strict settings
    sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*UsePAM.*/UsePAM no/' /etc/ssh/sshd_config

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
    if ssh-keygen -l -f "/home/$SUDO_USER/.ssh/authorized_keys" >/dev/null 2>&1; then
        success "SSH public key properly installed"
        local key_info=$(ssh-keygen -l -f "/home/$SUDO_USER/.ssh/authorized_keys" | head -1)
        info "Key info: $key_info"
    else
        error "SSH key validation failed"
        exit 1
    fi
    
    # Get current IP address
    local ip_addr=$(ip addr show "$PRIMARY_INTERFACE" | grep -oP 'inet \K[\d.]+')
    if [[ -z "$ip_addr" ]]; then
        error "Could not determine IP address"
        exit 1
    fi
    
    # Display SSH connection information
    info "===== SSH CONNECTION INFORMATION ====="
    info "IP Address: $ip_addr"
    info "Username: $SUDO_USER"
    info "SSH Command: ssh -i ~/.ssh/id_rsa $SUDO_USER@$ip_addr"
    info "=================================="
}

verify_ssh_config() {
    local config_errors=0
    
    info "Performing final SSH configuration verification..."
    
    # Check SSH service status
    if ! systemctl is-active --quiet ssh; then
        error "SSH service is not running"
        ((config_errors++))
    fi
    
    # Check SSH configuration syntax
    if ! sudo sshd -t; then
        error "SSH configuration has syntax errors"
        ((config_errors++))
    fi
    
    # Check authorized_keys file
    if [[ ! -f ~/.ssh/authorized_keys ]]; then
        error "authorized_keys file is missing"
        ((config_errors++))
    elif [[ $(stat -c %a ~/.ssh/authorized_keys) != "600" ]]; then
        error "authorized_keys has incorrect permissions"
        ((config_errors++))
    fi
    
    # Check .ssh directory permissions
    if [[ $(stat -c %a ~/.ssh) != "700" ]]; then
        error ".ssh directory has incorrect permissions"
        ((config_errors++))
    fi
    
    # Check if public key is properly installed
    if ! grep -q "ssh-rsa" ~/.ssh/authorized_keys; then
        error "No SSH public key found in authorized_keys"
        ((config_errors++))
    fi
    
    # Get IP address for connection test
    local ip_addr=$(ip addr show "$PRIMARY_INTERFACE" | grep -oP 'inet \K[\d.]+')
    if [[ -z "$ip_addr" ]]; then
        error "Could not determine IP address"
        ((config_errors++))
    fi
    
    if [[ $config_errors -eq 0 ]]; then
        success "SSH configuration verification completed successfully"
        info "System is ready for headless operation"
        info "===== HEADLESS CONNECTION INFORMATION ====="
        info "IP Address: $ip_addr"
        info "Username: $USER"
        info "SSH Command: ssh $USER@$ip_addr"
        info "Verify you can connect before proceeding!"
        info "=========================================="
    else
        error "SSH configuration verification failed with $config_errors errors"
        error "Please fix the issues before proceeding"
        exit 1
    fi
}

configure_firewall() {
    section "Configuring Firewall"
    
    info "Step 1/8: Checking UFW installation..."
    if ! command -v ufw >/dev/null 2>&1; then
        warning "UFW not found - installing now..."
        if ! sudo apt install -y ufw; then
            error "Failed to install UFW package"
            error "Command failed: sudo apt install -y ufw"
            exit 1
        fi
        success "UFW installed successfully"
    else
        success "UFW is already installed"
    fi
    
    info "Step 2/8: Ensuring UFW service is enabled..."
    if ! systemctl is-enabled --quiet ufw; then
        info "  • Enabling UFW service..."
        if ! sudo systemctl enable ufw; then
            error "Failed to enable UFW service"
            exit 1
        fi
        success "UFW service enabled"
    else
        success "UFW service already enabled"
    fi
    
    info "Step 3/8: Starting UFW service..."
    if ! systemctl is-active --quiet ufw; then
        info "  • Starting UFW service..."
        if ! sudo systemctl start ufw; then
            error "Failed to start UFW service"
            exit 1
        fi
        success "UFW service started"
    else
        success "UFW service already running"
    fi
    
    info "Step 4/8: Enabling UFW..."
    if ! sudo ufw --force enable; then
        error "Failed to enable UFW"
        error "Command failed: sudo ufw --force enable"
        exit 1
    fi
    success "UFW enabled successfully"
    
    info "Step 5/8: Resetting UFW to clean state..."
    if ! sudo ufw --force reset; then
        error "Failed to reset UFW"
        error "Command failed: sudo ufw --force reset"
        exit 1
    fi
    success "UFW reset successfully"
    
    # Re-enable after reset
    if ! sudo ufw --force enable; then
        error "Failed to re-enable UFW after reset"
        exit 1
    fi
    success "UFW re-enabled after reset"
    
    info "Step 6/8: Setting default policies..."
    info "  • Setting default deny incoming..."
    if ! sudo ufw default deny incoming; then
        error "Failed to set default incoming policy"
        exit 1
    fi
    success "Default incoming policy set to deny"
    
    info "  • Setting default allow outgoing..."
    if ! sudo ufw default allow outgoing; then
        error "Failed to set default outgoing policy"
        exit 1
    fi
    success "Default outgoing policy set to allow"
    
    # Force UFW to reload policies
    info "  • Reloading UFW..."
    if ! sudo ufw reload; then
        error "Failed to reload UFW"
        exit 1
    fi
    sleep 2
    
    # Verify default policies were set
    info "  • Verifying policies..."
    local verbose_status=$(sudo ufw status verbose)
    
    # Check incoming policy
    if ! echo "$verbose_status" | grep -q "deny (incoming)"; then
        error "Failed to set default incoming policy"
        error "Current UFW status:"
        echo "$verbose_status"
        exit 1
    fi
    success "Default incoming policy verified"
    
    # Check outgoing policy
    if ! echo "$verbose_status" | grep -q "allow (outgoing)"; then
        error "Failed to set default outgoing policy"
        error "Current UFW status:"
        echo "$verbose_status"
        exit 1
    fi
    success "Default outgoing policy verified"
    
    success "Default policies configured and verified"
    
    info "Step 7/8: Configuring firewall rules..."
    
    # Array of rules to add
    declare -A firewall_rules=(
        ["SSH Access"]="allow ssh"
        ["P2Pool Stratum"]="allow 3333/tcp"
        ["P2Pool P2P"]="allow 37889/tcp"
        ["P2Pool Mini P2P"]="allow 37888/tcp"
        ["Monero P2P"]="allow 18080/tcp"
        ["Monero RPC"]="allow 18081/tcp"
        ["XMRig API"]="allow 18088/tcp"
        ["XMRig Exporter"]="allow 9100/tcp"
        ["Node Exporter"]="allow 9101/tcp"
        ["Mining Network"]="allow from 192.168.1.0/24"
    )
    
    # Add each rule and log the result
    for desc in "${!firewall_rules[@]}"; do
        rule="${firewall_rules[$desc]}"
        info "  • Adding rule: $desc"
        if ! sudo ufw $rule comment "$desc"; then
            error "    ✗ Failed to add rule: $desc"
            error "    Command failed: sudo ufw $rule"
            exit 1
        fi
        success "    ✓ Rule added: $desc"
    done
    
    info "Step 8/8: Final verification..."
    if ! sudo ufw status | grep -q "Status: active"; then
        error "UFW is not active after configuration"
        error "Current UFW status:"
        sudo ufw status verbose
        error "Current UFW service status:"
        sudo systemctl status ufw
        exit 1
    fi
    
    success "Firewall enabled and configured successfully"
    info "Current UFW status:"
    sudo ufw status numbered
    
    # Verify final configuration
    verify_firewall_config
}

verify_firewall_config() {
    section "Verifying Firewall Configuration"
    local config_errors=0
    
    info "Running comprehensive firewall checks..."
    
    info "1. Basic UFW checks..."
    # Check if UFW is installed
    if ! command -v ufw >/dev/null 2>&1; then
        error "✗ UFW is not installed"
        ((config_errors++))
        return 1
    else
        success "✓ UFW is installed"
    fi
    
    # Check if UFW service is enabled
    if systemctl is-enabled --quiet ufw; then
        success "✓ UFW service is enabled"
    else
        error "✗ UFW service is not enabled"
        ((config_errors++))
    fi
    
    # Check if UFW service is running
    if systemctl is-active --quiet ufw; then
        success "✓ UFW service is running"
    else
        error "✗ UFW service is not running"
        ((config_errors++))
    fi
    
    # Check if UFW is active
    if sudo ufw status | grep -q "Status: active"; then
        success "✓ UFW is active"
    else
        error "✗ UFW is not active"
        ((config_errors++))
    fi
    
    info "2. Checking required ports..."
    # Define required ports and their descriptions
    declare -A required_ports=(
        ["22"]="SSH"
        ["3333"]="P2Pool Stratum"
        ["37889"]="P2Pool P2P"
        ["37888"]="P2Pool Mini P2P"
        ["18080"]="Monero P2P"
        ["18081"]="Monero RPC"
        ["18088"]="XMRig API"
        ["9100"]="XMRig Exporter"
        ["9101"]="Node Exporter"
    )
    
    # Check each required port
    local ufw_status=$(sudo ufw status numbered)
    for port in "${!required_ports[@]}"; do
        if echo "$ufw_status" | grep -q "$port/tcp.*ALLOW"; then
            success "✓ Port $port (${required_ports[$port]}) is open"
        else
            error "✗ Port $port (${required_ports[$port]}) is not open"
            ((config_errors++))
        fi
    done
    
    info "3. Checking policies..."
    # Verify default policies using verbose status
    local verbose_status=$(sudo ufw status verbose)
    
    # Check incoming policy
    if echo "$verbose_status" | grep -q "deny (incoming)"; then
        success "✓ Default incoming policy is set to deny"
    else
        error "✗ Default incoming policy is not set to deny"
        ((config_errors++))
    fi
    
    # Check outgoing policy
    if echo "$verbose_status" | grep -q "allow (outgoing)"; then
        success "✓ Default outgoing policy is set to allow"
    else
        error "✗ Default outgoing policy is not set to allow"
        ((config_errors++))
    fi
    
    info "4. Checking mining network access..."
    # Verify mining network access
    if echo "$ufw_status" | grep -q "ALLOW.*192.168.1.0/24"; then
        success "✓ Mining network (192.168.1.0/24) access is configured"
    else
        error "✗ Mining network (192.168.1.0/24) access is not configured"
        ((config_errors++))
    fi
    
    info "5. Testing outbound connectivity..."
    local test_hosts=(
        "api.github.com"
        "pool.supportxmr.com"
        "github.com"
        "raw.githubusercontent.com"
    )
    
    for host in "${test_hosts[@]}"; do
        if nc -zw2 "$host" 443 2>/dev/null; then
            success "✓ Can connect to $host:443"
        else
            error "✗ Cannot connect to $host:443"
            ((config_errors++))
        fi
    done
    
    # Final status report
    if [[ $config_errors -eq 0 ]]; then
        success "Firewall verification completed successfully"
        info "=== Firewall Configuration Summary ==="
        sudo ufw status numbered
        info "===================================="
    else
        error "Firewall verification failed with $config_errors errors"
        error "Please review the errors above and fix the configuration"
        exit 1
    fi
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

configure_headless_boot() {
    section "Configuring Headless Boot"
    
    info "Configuring GRUB for headless operation..."
    
    # Backup original GRUB config
    if [[ -f /etc/default/grub ]]; then
        sudo cp /etc/default/grub /etc/default/grub.backup
    fi
    
    # Configure GRUB for true headless operation (no video card required)
    sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="nomodeset video=efifb:off console=tty1 console=ttyS0,115200n8"/' /etc/default/grub
    sudo sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="nomodeset video=efifb:off console=tty1 console=ttyS0,115200n8"/' /etc/default/grub
    
    # Ensure GRUB doesn't wait for video
    sudo sed -i 's/^GRUB_TERMINAL=.*/GRUB_TERMINAL=console/' /etc/default/grub
    sudo sed -i 's/^#GRUB_TERMINAL=.*/GRUB_TERMINAL=console/' /etc/default/grub
    
    # Update GRUB
    sudo update-grub
    
    # Create udev rule to handle simpledrm module
    info "Creating udev rule to handle simpledrm module..."
    cat << 'EOF' | sudo tee /etc/udev/rules.d/71-disable-simpledrm.rules
# Disable simpledrm framebuffer to prevent boot issues
ACTION=="add", SUBSYSTEM=="module", KERNEL=="simpledrm", RUN+="/bin/rm -f /dev/dri/card0"
EOF

    # Reload udev rules
    sudo udevadm control --reload-rules
    
    # Enable serial console
    sudo systemctl enable serial-getty@ttyS0.service
    
    # Set multi-user target (non-graphical)
    sudo systemctl set-default multi-user.target
    
    # Disable any services that might wait for display
    sudo systemctl mask display-manager.service || true
    
    success "True headless operation configured (no video card required)"
    info "System will boot without video card after reboot"
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
        info "  1. SSH back into system"
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

verify_headless_readiness() {
    section "Verifying Headless Operation Readiness"
    
    local ready=true
    local errors=0
    
    # Check SSH service
    info "1. Checking SSH service..."
    if systemctl is-active --quiet ssh; then
        success "✓ SSH service is active"
    else
        error "✗ SSH service is not running"
        ready=false
        ((errors++))
    fi
    
    # Check network connectivity
    info "2. Checking network connectivity..."
    if curl -s --head --max-time 5 google.com >/dev/null 2>&1; then
        success "✓ Internet connectivity verified"
    else
        # Try another site in case google.com is blocked
        if curl -s --head --max-time 5 cloudflare.com >/dev/null 2>&1; then
            success "✓ Internet connectivity verified"
        else
            error "✗ No internet connectivity"
            ready=false
            ((errors++))
        fi
    fi
    
    # Check firewall status
    info "3. Checking firewall status..."
    if sudo ufw status | grep -q "Status: active"; then
        success "✓ Firewall is active"
        
        # Check SSH port specifically
        if sudo ufw status | grep -q "22/tcp.*ALLOW"; then
            success "✓ SSH port 22 is allowed through firewall"
        else
            error "✗ SSH port 22 is not allowed through firewall"
            ready=false
            ((errors++))
        fi
    else
        error "✗ Firewall is not active"
        ready=false
        ((errors++))
    fi
    
    # Get IP address
    local ip_addr=$(ip addr show "$PRIMARY_INTERFACE" | grep -oP 'inet \K[\d.]+')
    if [[ -z "$ip_addr" ]]; then
        error "✗ Could not determine IP address"
        ready=false
        ((errors++))
    fi
    
    # Check SSH key setup
    info "4. Checking SSH key configuration..."
    if [[ -f "/home/$SUDO_USER/.ssh/authorized_keys" ]]; then
        if ssh-keygen -l -f "/home/$SUDO_USER/.ssh/authorized_keys" >/dev/null 2>&1; then
            success "✓ SSH public key is properly installed"
        else
            error "✗ SSH public key validation failed"
            ready=false
            ((errors++))
        fi
    else
        error "✗ SSH authorized_keys file not found"
        ready=false
        ((errors++))
    fi
    
    if $ready; then
        success "System is ready for headless operation"
        info "===== FINAL CONNECTION INFORMATION ====="
        info "IP Address: $ip_addr"
        info "Username: $SUDO_USER"
        info "SSH Command: ssh $SUDO_USER@$ip_addr"
        info "======================================="
        info "IMPORTANT: Before proceeding:"
        info "1. Open a new terminal"
        info "2. Test SSH connection: ssh $SUDO_USER@$ip_addr"
        info "3. Verify you can connect successfully"
        info "4. Only then proceed with system reboot"
        
        if ! confirm "Have you verified SSH connection works from another terminal?" "n"; then
            error "Please verify SSH connection before proceeding"
            exit 1
        fi
    else
        error "System is not ready for headless operation"
        error "Found $errors issues that need to be fixed"
        error "Please review the errors above and fix the configuration"
        exit 1
    fi
}

# ================================
# MAIN EXECUTION FUNCTION
# ================================

main() {
    # Print welcome message
    section "Starting Module 1: System Preparation"
    info "This module will:"
    info "• Update system packages"
    info "• Install essential tools"
    info "• Configure SSH access"
    info "• Set up firewall"
    info "• Apply system optimizations"
    info "• Configure memory settings"
    info "• Apply CPU optimizations"
    info "• Configure headless boot"
    
    # Execute all functions in sequence
    verify_root_access
    detect_network_interface
    update_system_packages
    install_essential_tools
    configure_ssh_access
    configure_firewall
    optimize_system
    create_system_utilities
    configure_huge_pages
    apply_cpu_optimizations
    setup_thermal_monitoring
    configure_headless_boot
    
    # Final verification before reboot
    verify_headless_readiness
    
    success "Module 1 installation completed successfully"
    
    section "Preparing for Headless Operation"
    info "IMPORTANT: System will now halt for video card removal"
    info "1. System will shut down completely (all lights off)"
    info "2. Remove the video card from the system"
    info "3. Power the system back on"
    info "4. Wait 2-3 minutes for full boot"
    info "5. Connect via SSH: ssh $SUDO_USER@$ip_addr"
    info "6. Then proceed with Module 2 installation"
    
    if confirm "Ready to halt system for video card removal?" "n"; then
        local ip_addr=$(ip addr show "$PRIMARY_INTERFACE" | grep -oP 'inet \K[\d.]+')
        echo ""
        echo "!!! REMOVING VIDEO CARD PROCEDURE !!!"
        echo "1. Wait for system to completely shut down"
        echo "2. Remove power cable"
        echo "3. Remove video card"
        echo "4. Reconnect power cable"
        echo "5. Power on system"
        echo "6. Wait 2-3 minutes"
        echo "7. SSH from another machine: ssh -i ~/.ssh/id_rsa $SUDO_USER@$ip_addr"
        echo ""
        warning "System halting in 10 seconds..."
        sleep 10
        sudo halt
    else
        warning "System will remain powered on with video card"
        warning "You will need to manually halt and remove video card later"
        warning "Use 'sudo halt' when ready to proceed with video card removal"
    fi
}

# ================================
# SCRIPT EXECUTION
# ================================

# Trap to handle script interruption
trap 'echo -e "\n${RED}Script interrupted by user${NC}"; exit 1' INT

# Execute main function
main "$@"
