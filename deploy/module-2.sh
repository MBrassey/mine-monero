#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

confirm() {
    local prompt="$1"
    local default="${2:-y}"
    local response

    if [[ "$default" == "y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    while true; do
        read -p "$prompt" response
        response=${response:-$default}
        case "$response" in
            [yY]|[yY][eE][sS]) return 0 ;;
            [nN]|[nN][oO]) return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

check_system() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot determine OS version"
    fi

    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        error "This script is designed for Ubuntu only"
    fi

    if [[ "$VERSION_ID" != "24.04" ]]; then
        warning "This script is optimized for Ubuntu 24.04. Current version: $VERSION_ID"
        if ! confirm "Continue anyway?" "n"; then
            error "Installation cancelled"
        fi
    fi
}

verify_network() {
    log "Verifying network connectivity..."
    
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        error "No internet connectivity. Please check your network connection."
    fi
    
    if ! curl -s --max-time 10 https://github.com >/dev/null; then
        error "Cannot reach GitHub. Please check your internet connection."
    fi
    
    log "Network connectivity verified"
}

check_config() {
    local config_file="$SCRIPT_DIR/config.json"
    
    log "Checking configuration file..."
    
    if [[ ! -f "$config_file" ]]; then
        error "config.json not found in $SCRIPT_DIR"
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        log "Installing jq for JSON processing..."
        apt-get update -qq
        apt-get install -y jq
    fi
    
    if ! jq . "$config_file" >/dev/null 2>&1; then
        error "config.json is not valid JSON"
    fi
    
    local wallet_address
    wallet_address=$(jq -r '.user' "$config_file" 2>/dev/null)
    
    if [[ -z "$wallet_address" || "$wallet_address" == "null" ]]; then
        error "No wallet address found in config.json (missing 'user' field)"
    fi
    
    if [[ ${#wallet_address} -ne 95 ]]; then
        warning "Wallet address length is ${#wallet_address} characters. Standard Monero addresses are 95 characters."
    fi
    
    if [[ ! "$wallet_address" =~ ^4[0-9A-Za-z]+$ ]]; then
        warning "Wallet address format may be incorrect. Should start with '4'."
    fi
    
    local worker_id
    worker_id=$(jq -r '.["worker-id"]' "$config_file" 2>/dev/null)
    
    if [[ -z "$worker_id" || "$worker_id" == "null" ]]; then
        warning "No worker-id found in config.json"
    fi
    
    log "Configuration validated"
    log "Wallet: ${wallet_address:0:10}...${wallet_address: -10}"
    log "Worker ID: $worker_id"
}

show_system_info() {
    log "==> System Information"
    info "OS: $(lsb_release -d | cut -f2)"
    info "Kernel: $(uname -r)"
    info "Architecture: $(uname -m)"
    info "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
    info "CPU Cores: $(nproc)"
    info "Memory: $(free -h | grep 'Mem:' | awk '{print $2}')"
    info "Disk Space: $(df -h / | awk 'NR==2{print $4}') available"
    info "Hostname: $(hostname)"
    info "IP Address: $(hostname -I | awk '{print $1}')"
}

check_dependencies() {
    log "Checking system dependencies..."
    
    local missing_deps=()
    local required_commands=("curl" "wget" "tar" "systemctl")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warning "Missing dependencies: ${missing_deps[*]}"
        log "Installing missing dependencies..."
        apt-get update -qq
        apt-get install -y "${missing_deps[@]}"
    fi
    
    log "All dependencies satisfied"
}

main() {
    log "==> Starting Monero Mining Pre-installation Checks"
    
    check_root
    check_system
    verify_network
    check_dependencies
    check_config
    show_system_info
    
    log "==> Pre-installation checks completed successfully"
    log "System is ready for mining software installation"
    log ""
    log "Next steps:"
    log "1. Run: sudo bash deploy/module-1.sh (system optimization)"
    log "2. Run: sudo bash deploy/module-3.sh (mining software installation)"
}

main "$@"