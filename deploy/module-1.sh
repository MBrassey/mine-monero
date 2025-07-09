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

configure_headless_operation() {
    section "Configuring Headless Operation"
    
    # Configure GRUB for headless operation
    info "Configuring GRUB for headless operation..."
    sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="nomodeset console=tty1 console=ttyS0,115200n8"/' /etc/default/grub
    sudo sed -i 's/GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="console=tty1 console=ttyS0,115200n8"/' /etc/default/grub
    sudo update-grub

    # Enable and configure serial console
    info "Enabling serial console..."
    sudo systemctl enable serial-getty@ttyS0.service
    sudo systemctl start serial-getty@ttyS0.service

    # Configure systemd to not wait for a display manager
    info "Configuring systemd for headless boot..."
    sudo systemctl set-default multi-user.target
    
    success "Headless operation configured successfully"
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

# ================================
# MAIN EXECUTION
# ================================

main() {
    verify_root_access
    detect_network_interface
    update_system_packages
    install_essential_tools
    configure_ssh_access
    configure_headless_operation
    verify_ssh_config
    
    success "Module 1 completed successfully"
    info "Please reboot the system to apply all changes"
    info "After reboot, verify SSH access before removing the display"
}

main "$@"
