#!/bin/bash

set -euo pipefail

WALLET_ADDRESS="461rx8xiZNDDBv3SyUVhqS1tFo8FaGTaUhZ3HYNMnsK5FesEgreFYPoj3L2ubRFXUYEdzrauYCM2XdtEg2K5Fxio4kK9Bvm"
WORKER_ID="RYZEN_01"
DONATION_LEVEL=0

MONERO_VERSION="v0.18.4.0"
XMRIG_VERSION="v6.24.0"
P2POOL_VERSION="v3.10"

if ! sudo -n true 2>/dev/null; then
    echo "This script requires sudo privileges. Please run with sudo or configure passwordless sudo."
    exit 1
fi

if [[ "$EUID" -eq 0 ]] && [[ -z "$SUDO_USER" ]]; then
   echo "This script should not be run as the root user directly. Use sudo with a regular user account."
   exit 1
fi

if [[ -n "$SUDO_USER" ]]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME=$(eval echo ~$SUDO_USER)
else
    REAL_USER="$USER"
    REAL_HOME="$HOME"
fi

WORK_DIR="$REAL_HOME/monero-mining"
BUILD_DIR="$WORK_DIR/build"
INSTALL_DIR="$WORK_DIR/install"

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

download_git_source() {
    local name=$1
    local repo_url=$2
    local tag=$3
    local dir_name=$4
    local start_dir=$(pwd)
    local attempt=1
    local max_attempts=3
    local success=0

    log "Downloading $name $tag..."

    while [[ $attempt -le $max_attempts ]]; do
        if [[ -d "$dir_name" ]]; then
            cd "$dir_name"
            if git fetch origin && git checkout "$tag"; then
                local current_commit=$(git rev-parse HEAD)
                log "$name updated (commit: ${current_commit:0:8})"
                success=1
                cd "$start_dir"
                break
            else
                warning "$name fetch/checkout failed (attempt $attempt/$max_attempts), retrying in 5s..."
                cd "$start_dir"
                sleep 5
                rm -rf "$dir_name"
            fi
        else
            if git clone --recursive --branch "$tag" "$repo_url" "$dir_name"; then
                cd "$dir_name"
                local current_commit=$(git rev-parse HEAD)
                log "$name cloned (commit: ${current_commit:0:8})"
                success=1
                cd "$start_dir"
                break
            else
                warning "$name clone failed (attempt $attempt/$max_attempts), retrying in 5s..."
                rm -rf "$dir_name"
                sleep 5
            fi
        fi
        attempt=$((attempt+1))
    done

    if [[ $success -ne 1 ]]; then
        error "Failed to download $name after $max_attempts attempts."
    fi
}

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
        libuv1-dev \
        libcurl4-openssl-dev \
        libbrotli-dev \
        libzstd-dev \
        libnghttp2-dev \
        libidn2-dev \
        libpsl-dev \
        autotools-dev \
        autoconf \
        automake \
        libtool \
        git \
        curl \
        wget \
        tar \
        gzip \
        ca-certificates \
        gnupg2 \
        jq \
        bc \
        netcat-openbsd \
        msr-tools
}

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

setup_user_permissions() {
    sudo usermod -a -G dialout,plugdev "$REAL_USER"
    
    sudo tee /etc/udev/rules.d/99-msr.rules > /dev/null << 'EOF'
KERNEL=="msr[0-9]*", GROUP="root", MODE="0644"
EOF
    
    sudo udevadm control --reload-rules
    sudo udevadm trigger
}

optimize_system() {
    if ! grep -q "# Monero mining optimizations" /etc/sysctl.conf; then
        sudo tee -a /etc/sysctl.conf > /dev/null << 'EOF'

# Monero mining optimizations
vm.swappiness=1
kernel.numa_balancing=0
kernel.sched_autogroup_enabled=0
EOF
        
        sudo sysctl -p
    else
        log "System optimizations already applied"
    fi
    
    if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
        echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1 || true
    fi
}

build_monero() {
    log "Building Monero..."
    
    cd "$BUILD_DIR"
    
    if [[ -f "$INSTALL_DIR/bin/monerod" ]]; then
        log "Monero already built, skipping..."
        return 0
    fi
    
    download_git_source "Monero" "https://github.com/monero-project/monero.git" "$MONERO_VERSION" "monero"
    
    cd monero
    git submodule update --init --recursive
    
    rm -rf build
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

build_xmrig() {
    log "Building XMRig with hardcoded 0% donation..."
    
    cd "$BUILD_DIR"
    
    if [[ -f "$INSTALL_DIR/bin/xmrig" ]]; then
        log "XMRig already built, skipping..."
        return 0
    fi
    
    download_git_source "XMRig" "https://github.com/xmrig/xmrig.git" "$XMRIG_VERSION" "xmrig"
    
    cd xmrig
    
    cp src/donate.h src/donate.h.backup
    
    cat > src/donate.h << 'EOF'
#ifndef XMRIG_DONATE_H
#define XMRIG_DONATE_H

constexpr const int kDefaultDonateLevel = 0;
constexpr const int kMinimumDonateLevel = 0;

#endif // XMRIG_DONATE_H
EOF
    
    rm -rf build
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
          ..
    
    make -j$(nproc)
    
    mkdir -p "$INSTALL_DIR/bin"
    cp xmrig "$INSTALL_DIR/bin/"
}

build_p2pool() {
    log "Building P2Pool..."
    
    cd "$BUILD_DIR"
    
    if [[ -f "$INSTALL_DIR/bin/p2pool" ]]; then
        log "P2Pool already built, skipping..."
        return 0
    fi
    
    if [[ -d "p2pool" ]]; then
        rm -rf p2pool
    fi
    
    download_git_source "P2Pool" "https://github.com/SChernykh/p2pool.git" "$P2POOL_VERSION" "p2pool"
    
    cd p2pool
    
    git submodule update --init --recursive --force
    
    if [[ ! -f "external/src/libzmq/build/lib/libzmq.a" ]]; then
        log "Building libzmq dependency..."
        cd external/src/libzmq
        rm -rf build
        mkdir build
        cd build
        
        cmake -DCMAKE_BUILD_TYPE=Release \
              -DZMQ_BUILD_TESTS=OFF \
              -DWITH_PERF_TOOL=OFF \
              -DZMQ_BUILD_FRAMEWORK=OFF \
              -DBUILD_STATIC=ON \
              -DBUILD_SHARED=OFF \
              ..
        
        make -j$(($(nproc)/2))
        
        mkdir -p lib
        if [[ -f libzmq.a ]]; then
            cp libzmq.a lib/
        fi
        
        cd "$BUILD_DIR/p2pool"
    else
        log "libzmq already built, skipping..."
    fi
    
    if [[ ! -f "external/src/libuv/build/libuv.a" ]]; then
        log "Building libuv dependency..."
        cd external/src/libuv
        rm -rf build
        mkdir build
        cd build
        
        cmake -DCMAKE_BUILD_TYPE=Release \
              -DBUILD_TESTING=OFF \
              -DLIBUV_BUILD_SHARED=OFF \
              ..
        
        make -j$(($(nproc)/2))
        
        cd "$BUILD_DIR/p2pool"
    else
        log "libuv already built, skipping..."
    fi
    
    log "Building P2Pool main binary..."
    rm -rf build
    mkdir -p build
    cd build
    
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
          -DSTATIC_BINARY=OFF \
          -DWITH_RANDOMX=ON \
          -DCMAKE_CXX_FLAGS="-fno-lto" \
          -DCMAKE_C_FLAGS="-fno-lto" \
          ..
    
    mkdir -p "$INSTALL_DIR/bin"
    cp p2pool "$INSTALL_DIR/bin/"
}

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
        "hw-aes": true,
        "priority": 5,
        "memory-pool": false,
        "yield": true,
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
        },
        {
            "algo": null,
            "coin": "monero",
            "url": "p2pool-eu.mine.xmrpool.net:3333",
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
    "retries": 5,
    "retry-pause": 5,
    "syslog": false,
    "verbose": 0,
    "watch": true,
    "pause-on-battery": false,
    "pause-on-active": false
}
EOF
    
    sudo chown root:root "$INSTALL_DIR/etc/xmrig-config.json"
    sudo chmod 644 "$INSTALL_DIR/etc/xmrig-config.json"
    sudo chown root:root "$INSTALL_DIR/bin/xmrig"
    sudo chmod 755 "$INSTALL_DIR/bin/xmrig"
    
    sudo chown -R "$REAL_USER:$REAL_USER" "$INSTALL_DIR" 2>/dev/null || true
    sudo chown root:root "$INSTALL_DIR/bin/xmrig"
    sudo chown root:root "$INSTALL_DIR/etc/xmrig-config.json"
}

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
    
    sudo chown "$REAL_USER:$REAL_USER" "$INSTALL_DIR/mining-control.sh"
}

create_msr_setup() {
    sudo tee /etc/systemd/system/msr-tools.service > /dev/null << 'EOF'
[Unit]
Description=Load MSR kernel module and configure permissions for XMRig
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'modprobe msr 2>/dev/null || echo "MSR module not available - continuing"'
ExecStart=/bin/bash -c 'if [ -d /dev/cpu ]; then find /dev/cpu -name "msr" -type c -exec chmod 644 {} \; 2>/dev/null; fi || true'
ExecStart=/bin/bash -c 'if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null 2>&1; fi || true'
StandardOutput=journal
StandardError=journal
SuccessExitStatus=0 1

[Install]
WantedBy=multi-user.target
EOF
    
    sudo tee /usr/local/bin/setup-msr > /dev/null << 'EOF'
#!/bin/bash

# Helper script to manually load MSR module and set permissions
echo "Loading MSR kernel module..."
if ! lsmod | grep -q "^msr "; then
    if modprobe msr 2>/dev/null; then
        echo "MSR module loaded successfully"
    else
        echo "Warning: Could not load MSR module. Some performance features may be disabled."
        echo "This is not critical for mining operation."
        exit 0
    fi
else
    echo "MSR module already loaded"
fi

# Set permissions if MSR devices exist
if [ -d /dev/cpu ]; then
    echo "Setting MSR device permissions..."
    find /dev/cpu -name "msr" -type c -exec chmod 644 {} \; 2>/dev/null || true
    echo "MSR permissions set"
else
    echo "Warning: MSR devices not found. Performance monitoring may be limited."
fi

# Set CPU governor to performance if available
if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    echo "Setting CPU governor to performance..."
    echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null 2>&1 || true
    echo "CPU governor set to performance"
else
    echo "CPU frequency scaling not available"
fi

echo "MSR setup complete"
exit 0
EOF
    
    sudo chmod +x /usr/local/bin/setup-msr
    
    sudo systemctl enable msr-tools.service || warning "Could not enable MSR service - will continue without it"
}

create_systemd_services() {
    sudo tee /etc/systemd/system/monerod.service > /dev/null << EOF
[Unit]
Description=Monero Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
User=$REAL_USER
Group=$REAL_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/monerod --non-interactive --data-dir $INSTALL_DIR/data --log-file $INSTALL_DIR/logs/monerod.log --zmq-pub tcp://127.0.0.1:18083 --disable-dns-checkpoints --enable-dns-blocklist --rpc-bind-ip 127.0.0.1 --rpc-bind-port 18081 --restricted-rpc --confirm-external-bind --log-level 1 --out-peers 32 --in-peers 64 --add-priority-node=p2pmd.xmrvsbeast.com:18080 --add-priority-node=nodes.hashvault.pro:18080 --check-updates disabled
Restart=always
RestartSec=10
TimeoutStartSec=600
TimeoutStopSec=60
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/p2pool.service > /dev/null << EOF
[Unit]
Description=P2Pool Monero Mining Pool
After=network.target monerod.service
Wants=network.target
Requires=monerod.service

[Service]
Type=simple
User=$REAL_USER
Group=$REAL_USER
WorkingDirectory=$INSTALL_DIR/p2pool-data
ExecStart=$INSTALL_DIR/bin/p2pool --host 127.0.0.1 --rpc-port 18081 --zmq-port 18083 --wallet $WALLET_ADDRESS --stratum 127.0.0.1:3333 --p2p 127.0.0.1:37889 --addpeers 65.21.227.114:37889,node.p2pool.io:37889 --loglevel 1 --mini --light-mode
Restart=always
RestartSec=10
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/xmrig.service > /dev/null << EOF
[Unit]
Description=XMRig Monero Miner
After=network.target p2pool.service msr-tools.service
Wants=network.target
Requires=p2pool.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStartPre=/bin/sleep 30
ExecStartPre=/usr/local/bin/setup-msr
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

setup_msr_safely() {
    log "Setting up MSR module (performance optimization)..."
    
    if sudo modprobe msr 2>/dev/null; then
        log "MSR module loaded successfully"
        if [ -d /dev/cpu ]; then
            sudo find /dev/cpu -name "msr" -type c -exec chmod 644 {} \; 2>/dev/null || true
            log "MSR device permissions configured"
        fi
    else
        warning "Could not load MSR module - this is not critical for mining"
        warning "Some performance monitoring features may be disabled"
    fi
    
    if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
        echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1 || true
        log "CPU governor set to performance"
    fi
}

ensure_hugepages() {
    local desired=6144
    local current=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)
    if [[ "$current" -lt "$desired" ]]; then
        warning "System has $current huge pages, but $desired are recommended. Setting now..."
        sudo sysctl -w vm.nr_hugepages=$desired
    else
        log "System has $current huge pages (OK)"
    fi
}

cleanup_build_dependencies() {
    log "Cleaning up build dependencies for security..."
    
    if [[ -d "$BUILD_DIR" ]]; then
        rm -rf "$BUILD_DIR"
        log "Removed build directory"
    fi
    
    sudo apt-get autoremove --purge -y \
        build-essential \
        cmake \
        pkg-config \
        doxygen \
        graphviz \
        autotools-dev \
        autoconf \
        automake \
        libtool \
        git \
        libboost-all-dev \
        libssl-dev \
        libzmq3-dev \
        libunbound-dev \
        libsodium-dev \
        liblzma-dev \
        libreadline6-dev \
        libldns-dev \
        libexpat1-dev \
        libpgm-dev \
        libhidapi-dev \
        libusb-1.0-0-dev \
        libprotobuf-dev \
        protobuf-compiler \
        libudev-dev \
        libhwloc-dev \
        libuv1-dev \
        libcurl4-openssl-dev \
        libbrotli-dev \
        libzstd-dev \
        libnghttp2-dev \
        libidn2-dev \
        libpsl-dev \
        2>/dev/null || true
    
    sudo apt-get autoremove -y
    sudo apt-get autoclean
    
    log "Build dependencies removed for security"
}

show_setup_summary() {
    log "Checking final mining status..."
    local hashrate=$(curl -s http://127.0.0.1:8080/2/summary 2>/dev/null | jq -r '.hashrate.total[0] // 0' 2>/dev/null || echo "0")
    local donation_level=$(curl -s http://127.0.0.1:8080/2/summary 2>/dev/null | jq -r '.donate_level // "unknown"' 2>/dev/null || echo "unknown")
    local worker_id=$(curl -s http://127.0.0.1:8080/2/summary 2>/dev/null | jq -r '.worker_id // "unknown"' 2>/dev/null || echo "unknown")
    local pool_url=$(curl -s http://127.0.0.1:8080/2/summary 2>/dev/null | jq -r '.connection.pool // "unknown"' 2>/dev/null || echo "unknown")
    
    log "Setup completed"
    log "Installation directory: $INSTALL_DIR"
    
    log "Security verification:"
    log "  All source code built from official Git repositories"
    log "  Monero: Built from tag $MONERO_VERSION"
    log "  XMRig: Built from tag $XMRIG_VERSION with hardcoded 0% donation"
    log "  P2Pool: Built from tag $P2POOL_VERSION"
    
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

main() {
    log "Starting Monero mining setup"
    log "User: $REAL_USER"
    log "Install directory: $INSTALL_DIR"
    log "Wallet: $WALLET_ADDRESS"
    log "Worker ID: $WORKER_ID"
    log "Donation Level: $DONATION_LEVEL%"
    
    mkdir -p "$WORK_DIR" "$BUILD_DIR" "$INSTALL_DIR"
    cd "$WORK_DIR"
    
    install_dependencies
    setup_user_permissions
    check_huge_pages
    optimize_system
    
    ensure_hugepages
    
    build_monero
    build_xmrig
    build_p2pool
    
    create_xmrig_config
    create_service_scripts
    create_msr_setup
    create_systemd_services
    
    log "Enabling services..."
    if sudo systemctl enable msr-tools.service; then
        log "MSR service enabled"
    else
        warning "MSR service could not be enabled - continuing without it"
    fi
    
    sudo systemctl enable monerod.service
    sudo systemctl enable p2pool.service
    sudo systemctl enable xmrig.service
    
    log "Starting services..."
    if sudo systemctl start msr-tools.service; then
        log "MSR service started successfully"
    else
        warning "MSR service could not be started - will setup MSR manually"
        setup_msr_safely
    fi
    
    log "Starting monerod service (this may take several hours to sync)..."
    sudo systemctl start monerod.service &
    MONEROD_PID=$!
    
    sleep 10
    
    log "Starting p2pool service..."
    sudo systemctl start p2pool.service &
    P2POOL_PID=$!
    
    sleep 5
    
    log "Starting xmrig service..."
    sudo systemctl start xmrig.service &
    XMRIG_PID=$!
    
    sleep 15
    
    log "Services have been started. They may take several minutes to fully initialize."
    log "Use 'mining-control status' to check their current state."
    
    cleanup_build_dependencies
    
    show_setup_summary
}

main "$@"