#!/bin/bash

# Monero Mining Setup Script
# Builds Monero, XMRig, and P2Pool from source with checksum verification

set -euo pipefail

# Configuration
WALLET_ADDRESS="461rx8xiZNDDBv3SyUVhqS1tFo8FaGTaUhZ3HYNMnsK5FesEgreFYPoj3L2ubRFXUYEdzrauYCM2XdtEg2K5Fxio4kK9Bvm"
WORKER_ID="RYZEN_01"
DONATION_LEVEL=0

# Version information
MONERO_VERSION="v0.18.4.0"
XMRIG_VERSION="v6.24.0"
P2POOL_VERSION="17.0"

# Directory setup
WORK_DIR="$HOME/monero-mining"
BUILD_DIR="$WORK_DIR/build"
INSTALL_DIR="$WORK_DIR/install"

# Known commit hashes for verification
MONERO_COMMIT_HASH="518ec06a2612edd943bf6b59a7b6feeda45eec68"
XMRIG_COMMIT_HASH="3be6ce9c4eaa0b32e32f3e5e3ace26fb61c8f1b3"
P2POOL_COMMIT_HASH="2459a1d41eaee0e48a86d6b2f3cb6dc24c38ba55"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root"
fi

# Function to install dependencies
install_dependencies() {
    log "Installing dependencies..."
    
    sudo apt-get update
    sudo apt-get install -y \
        build-essential \
        cmake \
        pkg-config \
        libboost-all-dev \
        libssl-dev \
        libzmq3-dev \
        libunbound-dev \
        libsodium-dev \
        libunwind8-dev \
        liblzma-dev \
        libreadline6-dev \
        libldns-dev \
        libexpat1-dev \
        doxygen \
        graphviz \
        libpgm-dev \
        libhidapi-dev \
        libusb-1.0-0-dev \
        libprotobuf-dev \
        protobuf-compiler \
        libudev-dev \
        libhwloc-dev \
        git \
        curl \
        wget \
        tar \
        gzip \
        ca-certificates \
        gnupg2 \
        jq \
        bc \
        netcat-openbsd
}

# Function to verify Git repository integrity
verify_git_integrity() {
    local repo_name=$1
    local expected_commit=$2
    local repo_dir=$3
    
    cd "$repo_dir"
    
    local current_commit=$(git rev-parse HEAD)
    
    if [[ "$current_commit" == "$expected_commit" ]]; then
        log "$repo_name repository verified (commit: ${current_commit:0:8})"
        return 0
    else
        error "$repo_name repository verification failed. Expected: $expected_commit, Got: $current_commit"
        return 1
    fi
}

# Function to download and verify source with Git
download_and_verify_git() {
    local name=$1
    local repo_url=$2
    local tag=$3
    local expected_commit=$4
    local dir_name=$5
    
    if [[ -d "$dir_name" ]]; then
        cd "$dir_name"
        git fetch origin
        git checkout "$tag"
    else
        git clone --recursive --branch "$tag" "$repo_url" "$dir_name"
    fi
    
    verify_git_integrity "$name" "$expected_commit" "$dir_name"
}

# Function to check and configure huge pages
check_huge_pages() {
    local huge_pages_nr=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo "0")
    local available_hugepages=$(grep HugePages_Free /proc/meminfo | awk '{print $2}' || echo "0")
    
    if [[ "$available_hugepages" -gt 0 ]]; then
        log "Huge pages available: $available_hugepages"
        HUGE_PAGES_AVAILABLE=true
    else
        warning "No huge pages available. Performance may be reduced."
        HUGE_PAGES_AVAILABLE=false
    fi
}

# Function to build Monero
build_monero() {
    log "Building Monero..."
    
    cd "$BUILD_DIR"
    
    download_and_verify_git "Monero" "https://github.com/monero-project/monero.git" "$MONERO_VERSION" "$MONERO_COMMIT_HASH" "monero"
    
    cd monero
    git submodule update --init --recursive
    
    mkdir -p build
    cd build
    
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
          -DBUILD_TESTS=OFF \
          -DBUILD_SHARED_LIBS=OFF \
          ..
    
    make -j$(nproc)
    make install
}

# Function to build XMRig with hardcoded 0% donation
build_xmrig() {
    log "Building XMRig with hardcoded 0% donation..."
    
    cd "$BUILD_DIR"
    
    download_and_verify_git "XMRig" "https://github.com/xmrig/xmrig.git" "$XMRIG_VERSION" "$XMRIG_COMMIT_HASH" "xmrig"
    
    cd xmrig
    
    # Backup and modify donate.h
    cp src/donate.h src/donate.h.backup
    
    cat > src/donate.h << 'EOF'
#ifndef XMRIG_DONATE_H
#define XMRIG_DONATE_H

constexpr const int kDefaultDonateLevel = 0;
constexpr const int kMinimumDonateLevel = 0;

#endif // XMRIG_DONATE_H
EOF
    
    mkdir -p build
    cd build
    
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
          -DWITH_HTTPD=ON \
          -DWITH_TLS=ON \
          -DWITH_HWLOC=ON \
          -DWITH_MSR=ON \
          -DWITH_CUDA=OFF \
          -DWITH_OPENCL=OFF \
          -DARM_TARGET=8 \
          ..
    
    make -j$(nproc)
    
    mkdir -p "$INSTALL_DIR/bin"
    cp xmrig "$INSTALL_DIR/bin/"
}

# Function to build P2Pool
build_p2pool() {
    log "Building P2Pool..."
    
    cd "$BUILD_DIR"
    
    download_and_verify_git "P2Pool" "https://github.com/SChernykh/p2pool.git" "$P2POOL_VERSION" "$P2POOL_COMMIT_HASH" "p2pool"
    
    cd p2pool
    git submodule update --init --recursive
    
    mkdir -p build
    cd build
    
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
          -DSTATIC_BINARY=ON \
          -DWITH_RANDOMX=ON \
          ..
    
    make -j$(nproc)
    
    mkdir -p "$INSTALL_DIR/bin"
    cp p2pool "$INSTALL_DIR/bin/"
}

# Function to create XMRig config
create_xmrig_config() {
    mkdir -p "$INSTALL_DIR/etc"
    mkdir -p "$INSTALL_DIR/data"
    mkdir -p "$INSTALL_DIR/p2pool-data"
    mkdir -p "$INSTALL_DIR/logs"
    
    cat > "$INSTALL_DIR/etc/xmrig-config.json" << EOF
{
    "api": {
        "id": null,
        "worker-id": "$WORKER_ID"
    },
    "http": {
        "enabled": true,
        "host": "0.0.0.0",
        "port": 8080,
        "access-token": null,
        "restricted": false
    },
    "autosave": true,
    "background": false,
    "colors": true,
    "title": true,
    "randomx": {
        "init": -1,
        "mode": "auto",
        "1gb-pages": false,
        "rdmsr": true,
        "wrmsr": true,
        "cache_qos": false,
        "numa": true,
        "scratchpad_prefetch_mode": 1
    },
    "cpu": {
        "enabled": true,
        "huge-pages": true,
        "huge-pages-jit": false,
        "hw-aes": null,
        "priority": 2,
        "memory-pool": false,
        "yield": true,
        "max-threads-hint": 100,
        "asm": true,
        "argon2-impl": null,
        "astrobwt-max-size": 550,
        "astrobwt-avx2": false,
        "cn/0": false,
        "cn-lite/0": false
    },
    "opencl": {
        "enabled": false
    },
    "cuda": {
        "enabled": false
    },
    "donate-level": $DONATION_LEVEL,
    "donate-over-proxy": $DONATION_LEVEL,
    "log-file": "$INSTALL_DIR/logs/xmrig.log",
    "pools": [
        {
            "algo": null,
            "coin": "monero",
            "url": "127.0.0.1:3333",
            "user": "$WALLET_ADDRESS",
            "pass": "$WORKER_ID",
            "rig-id": null,
            "nicehash": false,
            "keepalive": true,
            "enabled": true,
            "tls": false,
            "daemon": false
        }
    ],
    "print-time": 60,
    "health-print-time": 60,
    "dmi": true,
    "retries": 5,
    "retry-pause": 5,
    "syslog": false,
    "verbose": 1,
    "watch": true,
    "pause-on-battery": false,
    "pause-on-active": false
}
EOF
    
    sudo chown root:root "$INSTALL_DIR/etc/xmrig-config.json"
    sudo chmod 644 "$INSTALL_DIR/etc/xmrig-config.json"
    sudo chown root:root "$INSTALL_DIR/bin/xmrig"
    sudo chmod 755 "$INSTALL_DIR/bin/xmrig"
}

# Function to create service management scripts
create_service_scripts() {
    cat > "$INSTALL_DIR/mining-control.sh" << 'EOF'
#!/bin/bash

show_usage() {
    echo "Usage: $0 {start|stop|restart|status|enable|disable|logs}"
}

start_services() {
    echo "Starting mining services..."
    sudo systemctl start monerod.service
    sleep 10
    sudo systemctl start p2pool.service
    sleep 10
    sudo systemctl start xmrig.service
}

stop_services() {
    echo "Stopping mining services..."
    sudo systemctl stop xmrig.service
    sudo systemctl stop p2pool.service
    sudo systemctl stop monerod.service
}

restart_services() {
    echo "Restarting mining services..."
    stop_services
    sleep 5
    start_services
}

show_status() {
    echo "=== Mining Services Status ==="
    echo
    echo "Monerod Status:"
    sudo systemctl status monerod.service --no-pager -l
    echo
    echo "P2Pool Status:"
    sudo systemctl status p2pool.service --no-pager -l
    echo
    echo "XMRig Status:"
    sudo systemctl status xmrig.service --no-pager -l
    echo
    echo "=== Service Enable Status ==="
    systemctl is-enabled monerod.service p2pool.service xmrig.service
    echo
}

enable_services() {
    echo "Enabling services for automatic startup..."
    sudo systemctl enable monerod.service
    sudo systemctl enable p2pool.service
    sudo systemctl enable xmrig.service
}

disable_services() {
    echo "Disabling services from automatic startup..."
    sudo systemctl disable xmrig.service
    sudo systemctl disable p2pool.service
    sudo systemctl disable monerod.service
}

show_logs() {
    echo "=== Recent Logs ==="
    echo
    echo "Monerod Logs (last 20 lines):"
    sudo journalctl -u monerod.service -n 20 --no-pager
    echo
    echo "P2Pool Logs (last 20 lines):"
    sudo journalctl -u p2pool.service -n 20 --no-pager
    echo
    echo "XMRig Logs (last 20 lines):"
    sudo journalctl -u xmrig.service -n 20 --no-pager
    echo
}

case "$1" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    status)
        show_status
        ;;
    enable)
        enable_services
        ;;
    disable)
        disable_services
        ;;
    logs)
        show_logs
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
EOF
    
    chmod +x "$INSTALL_DIR/mining-control.sh"
    sudo ln -sf "$INSTALL_DIR/mining-control.sh" /usr/local/bin/mining-control
}

# Function to create MSR module loading script
create_msr_setup() {
    sudo tee /etc/systemd/system/msr-tools.service > /dev/null << 'EOF'
[Unit]
Description=Load MSR kernel module for XMRig
Before=xmrig.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/modprobe msr
ExecStart=/bin/chmod 644 /dev/cpu/*/msr

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl enable msr-tools.service
}

# Function to add user to required groups
setup_user_permissions() {
    sudo usermod -a -G dialout,plugdev "$(whoami)"
    
    sudo tee /etc/udev/rules.d/99-msr.rules > /dev/null << 'EOF'
KERNEL=="msr[0-9]*", GROUP="root", MODE="0644"
EOF
    
    sudo udevadm control --reload-rules
    sudo udevadm trigger
}

# Function to optimize system for mining
optimize_system() {
    sudo tee -a /etc/sysctl.conf > /dev/null << 'EOF'

# Monero mining optimizations
vm.swappiness=1
kernel.numa_balancing=0
kernel.sched_autogroup_enabled=0
EOF
    
    sudo sysctl -p
    
    if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
        echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1 || true
    fi
}

# Function to create systemd services
create_systemd_services() {
    # Create monerod service
    sudo tee /etc/systemd/system/monerod.service > /dev/null << EOF
[Unit]
Description=Monero Daemon
After=network.target
Wants=network.target

[Service]
Type=forking
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/monerod --detach --data-dir $INSTALL_DIR/data --log-file $INSTALL_DIR/logs/monerod.log --zmq-pub tcp://127.0.0.1:18083 --disable-dns-checkpoints --enable-dns-blocklist --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18081 --restricted-rpc --confirm-external-bind --log-level 1 --max-concurrency 2 --block-sync-size 10 --check-updates disabled
ExecStop=/bin/kill -TERM \$MAINPID
PIDFile=$INSTALL_DIR/data/monerod.pid
Restart=always
RestartSec=10
TimeoutStartSec=300
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF

    # Create p2pool service
    sudo tee /etc/systemd/system/p2pool.service > /dev/null << EOF
[Unit]
Description=P2Pool Monero Mining Pool
After=network.target monerod.service
Wants=network.target
Requires=monerod.service

[Service]
Type=simple
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/p2pool --host 127.0.0.1 --rpc-port 18081 --zmq-port 18083 --wallet $WALLET_ADDRESS --stratum 127.0.0.1:3333 --p2p 127.0.0.1:37889 --addpeers 65.21.227.114:37889,node.p2pool.io:37889,p2pool.hashvault.pro:37889,auto.hashvault.pro:37889 --loglevel 1 --mini --data-dir $INSTALL_DIR/p2pool-data --stratum-port 3333 --p2p-port 37889 --light-mode
Restart=always
RestartSec=10
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

    # Create xmrig service
    sudo tee /etc/systemd/system/xmrig.service > /dev/null << EOF
[Unit]
Description=XMRig Monero Miner
After=network.target p2pool.service
Wants=network.target
Requires=p2pool.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStartPre=/bin/sleep 30
ExecStart=$INSTALL_DIR/bin/xmrig --config=$INSTALL_DIR/etc/xmrig-config.json
Restart=always
RestartSec=10
TimeoutStartSec=60
Nice=-10
IOSchedulingClass=1
IOSchedulingPriority=4

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
}

# Main function
main() {
    log "Starting Monero mining setup"
    log "Wallet: $WALLET_ADDRESS"
    log "Worker ID: $WORKER_ID"
    log "Donation Level: $DONATION_LEVEL%"
    
    if ! sudo -n true 2>/dev/null; then
        error "This script requires sudo privileges"
        exit 1
    fi
    
    mkdir -p "$WORK_DIR" "$BUILD_DIR" "$INSTALL_DIR"
    cd "$WORK_DIR"
    
    install_dependencies
    setup_user_permissions
    check_huge_pages
    optimize_system
    
    build_monero
    build_xmrig
    build_p2pool
    
    create_xmrig_config
    create_service_scripts
    create_msr_setup
    create_systemd_services
    
    log "Enabling and starting services..."
    sudo systemctl enable msr-tools.service
    sudo systemctl enable monerod.service
    sudo systemctl enable p2pool.service
    sudo systemctl enable xmrig.service
    
    sudo systemctl start msr-tools.service
    sudo systemctl start monerod.service
    sleep 30
    sudo systemctl start p2pool.service
    sleep 15
    sudo systemctl start xmrig.service
    sleep 10
    
    log "Checking mining status..."
    local hashrate=$(curl -s http://127.0.0.1:8080/2/summary 2>/dev/null | jq -r '.hashrate.total[0] // 0' 2>/dev/null || echo "0")
    local donation_level=$(curl -s http://127.0.0.1:8080/2/summary 2>/dev/null | jq -r '.donate_level // "unknown"' 2>/dev/null || echo "unknown")
    local worker_id=$(curl -s http://127.0.0.1:8080/2/summary 2>/dev/null | jq -r '.worker_id // "unknown"' 2>/dev/null || echo "unknown")
    local pool_url=$(curl -s http://127.0.0.1:8080/2/summary 2>/dev/null | jq -r '.connection.pool // "unknown"' 2>/dev/null || echo "unknown")
    
    log "Setup completed"
    log "Installation directory: $INSTALL_DIR"
    
    log "Security verification:"
    log "  All source code built from verified Git commits"
    log "  Monero: ${MONERO_COMMIT_HASH:0:8}"
    log "  XMRig: ${XMRIG_COMMIT_HASH:0:8} with hardcoded 0% donation"
    log "  P2Pool: ${P2POOL_COMMIT_HASH:0:8}"
    
    log "Mining status:"
    log "  Mining Address: $WALLET_ADDRESS"
    log "  Worker ID: $worker_id"
    log "  Current Hashrate: $hashrate H/s"
    log "  Donation Level: $donation_level%"
    log "  Pool: $pool_url"
    
    log "Service management:"
    log "  mining-control start|stop|restart|status|logs"
    log "  systemctl status monerod.service"
    log "  systemctl status p2pool.service"
    log "  systemctl status xmrig.service"
    
    log "Monitoring:"
    log "  XMRig API: http://localhost:8080"
    log "  Monero RPC: http://localhost:18081"
    log "  Live logs: journalctl -u xmrig.service -f"
    
    if [[ "$hashrate" != "0" ]] && [[ "$hashrate" != "null" ]] && [[ -n "$hashrate" ]]; then
        success "Mining active with hashrate $hashrate H/s"
        success "Mining to address: $WALLET_ADDRESS"
        success "Donation level: $donation_level%"
    else
        warning "Mining may not be fully active yet. Check status with 'mining-control status'"
    fi
}

main "$@"