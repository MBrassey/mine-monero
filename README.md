# AMD Ryzen Monero (XMR) Mining Suite

<img align="left" src="https://s2.coinmarketcap.com/static/img/coins/128x128/328.png" alt="Monero Logo" width="128" height="128">

&nbsp;&nbsp;&nbsp;&nbsp;Automated deployment system for streamlined Monero mining with P2Pool decentralized mining, XMRig optimization, and enterprise-grade monitoring & reliability.

<br clear="left"/>

## Recommended Hardware Build

This mining setup is optimized for the following hardware configuration:

### Core Components

| Component | Specification | Model |
|-----------|---------------|-------|
| **CPU** | AMD Ryzen™ 9 9950X 16-Core, 32-Thread | Unlocked Desktop Processor |
| **CPU Cooler** | AMD Wraith Prism Cooler | RGB-Controlled Illumination |
| **RAM** | 16GB DDR5 6000MHz CL30 (1x16GB) | XPG Lancer Blade RGB DDR5 PC5-48000 (AX5U6000C3016G-DTLABRBK) |
| **Storage** | 500GB NVMe M.2 2280 | XPG SPECTRIX S20G RGB PCIe Gen3x4 NVMe 1.3 (ASPECTRIXS20G-500G-C) |
| **Motherboard** | ASRock B650M PG Lightning WiFi 6E | AMD Socket AM5 B650 DDR5 up to 7200+ MHz Micro ATX |
| **Power Supply** | 650W ATX3.0 80 Plus Gold | XPG Core Reactor II Modular PSU (COREREACTORII650G-BKCUS) |
| **Case** | Stackable Open Air Computer Case Rack | Modular PC Frame Chassis for ATX/MATX/ITX |

### Performance Specifications

**CPU Performance:**
- **Cores/Threads:** 16-Core, 32-Thread processing
- **Base/Boost Clock:** Optimized for RandomX algorithm
- **TDP Configuration:** 105W (configured in BIOS)
- **Expected Hashrate:** ~18,000-22,000 H/s (RandomX)

**Memory Configuration:**
- **Capacity:** 16GB (1x16GB single-channel)
- **Speed:** DDR5-6000 MHz CL30
- **Slot Placement:** Install in second RAM slot from CPU (A2/DIMM2)
- **Placement Reason:** Optimal signal integrity and stability for high-speed DDR5 memory
- **Huge Pages Support:** 1GB and 2MB pages for RandomX optimization

**Storage & Connectivity:**
- **NVMe SSD:** 2,500/1,800 MB/s read/write speeds
- **Network:** Gigabit Ethernet (REMOVE THE WIFI CARD FOR SECURITY)
- **Expansion:** Multiple PCIe slots for future upgrades

### Case Assembly Instructions

**Stackable Open Air Case Setup:**
- **Case Type:** Modular open-air design for optimal cooling
- **Motherboard Support:** ATX/MATX/ITX compatibility
- **Stacking Capability:** Multiple rigs can be stacked vertically
- **Assembly Guide:** <a href="https://www.ediy.cc/en/2589.htm" target="_blank">Complete installation instructions</a>

**Key Assembly Points:**
- Install isolation pillars and motherboard mounting
- Secure power supply positioning and cable management
- Leg post installation for stacking capability
- Proper component spacing for airflow

**Benefits for Mining:**
- **Superior Cooling:** Open-air design maximizes heat dissipation
- **Easy Maintenance:** Direct access to all components
- **Scalability:** Stack multiple mining rigs in minimal space
- **Cost Effective:** Eliminates traditional case limitations

## Deployment Instructions

### Phase 1: BIOS Upgrade and Configuration

**Step 1: BIOS Access and Current Version Documentation**
1. Power on mining rig
2. Press **F2** repeatedly during boot to enter BIOS setup
3. **Document current BIOS version** displayed on main BIOS homepage
4. Navigate to Security settings and **disable TPM (Trusted Platform Module)**
5. Save settings and reboot

**Step 2: BIOS Update Preparation**
1. Download latest BIOS version from: https://pg.asrock.com/mb/AMD/B650M%20PG%20Lightning%20WiFi/index.us.asp
2. Format USB drive with **FAT32** file system
3. Place downloaded BIOS zip file in **root directory** of USB drive
4. **Unzip the file** so `.rom` file is directly in root directory of USB
5. Safely eject USB drive

**Step 3: BIOS Flash Process**
1. Insert prepared USB drive into mining rig
2. Reboot and press **F2** to enter BIOS
3. Navigate to **Tool Menu**
4. Select **Fast Flash / BIOS Update** option
5. Select `.rom` file from USB drive
6. **Confirm flash operation** (system will reboot automatically when complete)
7. After reboot, press **F2** again to verify **BIOS version is updated** on main page

**Step 4: BIOS Performance Configuration**
1. Enter BIOS setup (press **F2** during boot)
2. Navigate to **OC Tweaker** menu
3. Locate **TDP** setting and change to **105W Enabled**
4. **Save and Exit** (F10) to apply changes and reboot

### Phase 2: Ubuntu Installation and Repository Setup

**Step 5: Ubuntu 24.04 Installation**
1. Connect video card to mining rig
2. Insert Ubuntu 24.04 installation USB
3. Boot from USB and perform **complete Ubuntu installation**
4. Configure initial user account during installation
5. **Use DHCP for network configuration** (module-1.sh will configure static IP later)
6. Ensure network connectivity is established

**Step 6: Initial System Setup**
1. Log into freshly installed Ubuntu system
2. Update package repository and install essential tools:
   ```bash
   sudo apt update
   sudo apt install git vim
   ```

**Step 7: Clone Mining Repository**
1. Clone the mine-monero repository:
   ```bash
   git clone https://github.com/MBrassey/mine-monero.git
   cd mine-monero/deploy
   ```

### Phase 3: Configuration Setup

**Step 8: Update Configuration Files**

Before running the modules, update the following configuration files in the `deploy` directory:

**Update config.json with your Monero wallet address:**
```bash
vim config.json
# Replace "WALLET_ADDRESS_PLACEHOLDER" with your actual Monero wallet address
# Update "RYZEN_01" to your desired rig identifier if needed
```

**Update module-1.sh with your network details:**
```bash
vim module-1.sh
# Update line 12: STATIC_IP="10.10.10.2" # Change to desired IP
# Update line 18: ENGINEER_PUBLIC_KEY="ssh-rsa AAAAB3Nza..." # Replace with your SSH public key
```

**Update module-2.sh with your desired RGB color (optional):**
```bash
vim module-2.sh
# Update TARGET_COLOR variable to desired RGB color (e.g., "00FF00" for green)
```

### Phase 4: Module Execution

**Step 9: System Preparation and Network Configuration**
1. Make scripts executable and run system preparation:
   ```bash
   chmod +x module-1.sh module-2.sh module-3.sh
   ./module-1.sh
   ```
   This script will:
   - Configure static IP address
   - Enable SSH service  
   - Add engineer public key to authorized_keys
   - Configure huge pages and CPU optimizations
   - **Prompt for system reboot** (required for optimal performance)

**Step 10: Test SSH Access and Prepare for Headless Operation**
1. **Reboot system** when prompted by module-1.sh
2. Test SSH connectivity from remote workstation:
   ```bash
   ssh [username]@[static-ip-address]
   ```
3. Verify remote access is working properly
4. **Shut down the system**:
   ```bash
   sudo shutdown now
   ```
5. **Remove video card** from mining rig for headless operation
6. **Boot system back up** (headless mode)

**Step 11: Remote RGB Configuration (Optional)**
1. SSH into the headless system:
   ```bash
   ssh [username]@[static-ip-address]
   cd mine-monero/deploy
   ```
2. Execute RGB control configuration (**optional aesthetic enhancement**):
   ```bash
   sudo ./module-2.sh
   ```
   This script will:
   - Install OpenRGB universal RGB controller
   - Detect all RGB devices (motherboard, RAM, coolers)
   - Apply synchronized color scheme system-wide
   - Configure persistent RGB settings with auto-restore

**Step 12: Mining Software Installation**
1. Via SSH session, execute mining software installation:
   ```bash
   ./module-3.sh
   ```
   This script will:
   - Install and configure XMRig miner
   - Set up P2Pool decentralized mining
   - Configure Monero node
   - Initialize monitoring services
   - Start all mining operations **immediately**

**Step 13: Operation Verification**
1. Verify all services are running via SSH:
   ```bash
   sudo systemctl status xmrig p2pool monerod
   ```
2. Monitor real-time mining performance:
   ```bash
   curl -s http://localhost:18088/1/summary | jq '.hashrate'
   ```
3. Follow service logs if needed:
   ```bash
   # XMRig mining logs
   sudo journalctl -u xmrig -f
   
   # P2Pool operations logs
   sudo journalctl -u p2pool -f
   
   # Monero daemon logs
   sudo journalctl -u monerod -f
   ```

---

## System Architecture

| Component | Implementation | Configuration |
|-----------|----------------|---------------|
| **Mining Pool** | P2Pool (decentralized) | No fees, direct payouts |
| **Miner Software** | XMRig (compiled with -DDEV_DONATION_LEVEL=0) | No donation, 0% overhead |
| **Blockchain Node** | Monero daemon (pruned) | Required for P2Pool operation |
| **Minimum Payout** | P2Pool threshold | ~0.00027 XMR |
| **Network Architecture** | Distributed P2P | No central servers |
| **Payout Method** | Direct to wallet | No intermediary custody |

## System Components

### P2Pool - Decentralized Mining Pool
- Fully decentralized pool implementation
- Zero fees permanently
- Direct wallet payouts
- Low minimum payout threshold: ~0.00027 XMR
- No registration required

### XMRig - Optimized Miner
- Compiled with 0% donation level
- Advanced build with static dependencies
- RandomX algorithm optimizations
- Huge pages memory support

### Monitoring Stack
- XMRig HTTP API for real-time statistics
- Prometheus exporters for metrics collection
- P2Pool Observer integration
- Comprehensive logging system

### Implementation Features
- Automated verification of mining operation
- Service dependency management and startup sequencing
- Systemd security restrictions
- Error handling and verification at each installation step
- Pool failover configuration (P2Pool primary + 3 backup pools: SupportXMR, Nanopool, MineXMR)

## Prerequisites

- Ubuntu 20.04+ or Debian 11+ (x64 or ARM64)
- Minimum 4GB RAM (8GB recommended)
- Minimum 50GB free disk space
- Stable internet connection

## Dependencies & Repositories

Mining deployment system automatically downloads and configures the following open-source components:

### Core Mining Components
| Component | Repository | Purpose |
|-----------|------------|---------|
| **Monero Daemon** | <a href="https://github.com/monero-project/monero" target="_blank">github.com/monero-project/monero</a> | Official Monero blockchain node and daemon |
| **P2Pool** | <a href="https://github.com/SChernykh/p2pool" target="_blank">github.com/SChernykh/p2pool</a> | Decentralized mining pool implementation |
| **XMRig** | <a href="https://github.com/xmrig/xmrig" target="_blank">github.com/xmrig/xmrig</a> | High-performance Monero miner |

### Monitoring & Metrics
| Component | Repository | Purpose |
|-----------|------------|---------|
| **XMRig Exporter** | <a href="https://github.com/ArnyminerZ/xmrig-exporter" target="_blank">github.com/ArnyminerZ/xmrig-exporter</a> | Prometheus metrics exporter for XMRig |
| **Node Exporter** | <a href="https://github.com/prometheus/node_exporter" target="_blank">github.com/prometheus/node_exporter</a> | System metrics exporter for Prometheus |

### Version Management
- **Automatic Updates**: All components downloaded from latest stable releases
- **2025 Current Versions**: XMRig (latest from GitHub), Monero v0.18.4.0+, P2Pool v4.2+, Node Exporter v1.8.2+
- **Version Fallbacks**: Tested fallback versions used if latest releases unavailable
- **Source Compilation**: XMRig compiled from source with zero donation configuration
- **Binary Downloads**: P2Pool, Node Exporter use pre-compiled binaries for faster deployment

**Note**: Deployment modules automatically handle version detection, downloading, and configuration of all dependencies. No manual dependency management required.

## Enterprise Features

**Automated Monitoring & Recovery:**
- Service health monitoring with systemd restart logic
- Thermal management with dynamic frequency scaling
- Hardware optimization service applies settings at boot
- Prometheus metrics export for external monitoring

**Security & Reliability:**
- SSH hardening with fail2ban brute-force protection
- Firewall configuration with mining network access
- Systemd service dependencies and restart logic
- Thermal monitoring with frequency scaling protection
- Comprehensive logging via systemd journal

**Performance Optimization:**
- Hardware-specific XMRig compilation and tuning
- MSR (CPU register) optimizations for RandomX
- Memory bandwidth testing and optimization
- IRQ affinity isolation for mining cores
- 4-pool failover system (P2Pool primary + 3 backup pools: SupportXMR, Nanopool, MineXMR)

**Recommended Wallet:**
- Official Monero CLI/GUI v0.18.1.0+ - <a href="https://www.getmonero.org/downloads/" target="_blank">Download from getmonero.org</a>
- Always use a Local Node / one you manage. 

**Note:** Primary wallet addresses required (starting with '4'). Subaddresses not supported.

## Installation Process

Mining deployment uses two-phase approach for maximum reliability and security:

### Phase 1: System Preparation (module-1.sh)

**Before running module-1.sh**, update configuration variables:

```bash
vim module-1.sh
# Update line 12: STATIC_IP="10.10.10.2" # UPDATE
# Change to desired IP (e.g., STATIC_IP="10.10.10.3")

# Update line 18: ENGINEER_PUBLIC_KEY="ssh-rsa AAAAB3Nza..."
# Replace with SSH public key for remote access
```

**What it does:**
- Verifies root access and detects network interface
- Configures network interface with static IP (10.10.10.X)
- Updates system packages and installs essential tools (bpytop, net-tools, jq, curl, git, etc.)
- Hardens SSH security with fail2ban brute-force protection and engineer key access
- Configures firewall (UFW) with mining network access and metrics ports (9100, 9101, 18088)
- Disables unnecessary services (bluetooth, cups, avahi-daemon, snapd, etc.)
- **Configures 1GB and 2MB huge pages for RandomX performance**
- **Applies MSR (CPU register) optimizations and performance governor**
- **Sets up IRQ affinity optimization (isolates system IRQs to cores 0-1)**
- **Configures persistent CPU optimizations and thermal monitoring**
- Creates system utilities (system-info command) and mining directories
- **Requires reboot to enable all hardware optimizations**

```bash
chmod +x module-1.sh
./module-1.sh
# System will prompt for reboot to apply optimizations
```

### Phase 2: RGB Control Configuration (module-2.sh) - OPTIONAL
**What it does:**
- Installs OpenRGB universal RGB device controller
- Detects all RGB hardware (motherboard, RAM, coolers, GPU, SSDs)
- Categorizes devices by type for systematic control
- Applies synchronized color scheme across all RGB components
- Creates permanent RGB profiles with systemd auto-restore service
- Configures boot-time RGB restoration for persistent aesthetics

```bash
# Optional RGB configuration (aesthetic enhancement):
chmod +x module-2.sh
sudo ./module-2.sh
# Edit TARGET_COLOR variable before running
```

### Phase 3: Mining Software Installation (module-3.sh)
**What it does:**
- Detects hardware configuration and installs mining-specific build dependencies
- Downloads and compiles latest XMRig from GitHub source with 0% donation level
- Downloads and installs latest Monero daemon (pruned blockchain mode)
- Downloads and installs latest P2Pool decentralized mining pool
- **Configures 4-pool failover system (P2Pool primary + 3 backup pools: SupportXMR, Nanopool, MineXMR)**
- Applies hardware-specific optimizations (memory bandwidth testing, CPU tuning, cache optimization)
- **Installs Prometheus metrics exporters (XMRig Exporter, Node Exporter)**
- Creates systemd services with proper dependencies and restart logic
- **Starts all services in sequence: Node Exporter → Monero → P2Pool → XMRig → XMRig Exporter**
- Verifies all APIs respond and mining is active with payment address validation

```bash
# After reboot from module-1:
chmod +x module-3.sh
./module-3.sh
# Mining starts immediately when complete
```

### Configuration Setup

**Before running module-3.sh**, update configuration:

```bash
vim config.json
```

**Required Updates:**
1. **Wallet Address**: Replace `WALLET_ADDRESS_PLACEHOLDER` with Monero rewards wallet address
2. **Rig ID**: Update `RYZEN_01` to desired rig identifier

```json
{
    "pools": [
        {
            "url": "127.0.0.1:3333",
            "user": "REWARDS_WALLET_ADDRESS_HERE",
            "rig-id": "RYZEN_01",
            ...
        }
    ],
    "api": {
        "worker-id": "RYZEN_01",
        ...
    }
}
```

**Important Notes:**
- **Wallet Address**: Use primary Monero wallet address (starts with '4'). Subaddresses not supported.
- **Rig ID**: If running multiple mining rigs, use unique identifiers like `RYZEN_01`, `RYZEN_02`, etc.
- **Configuration**: config.json is pre-configured for 2025 XMRig v6.23.0+ with external API access on port 18088.

## Monitoring and Management

### Service Status Verification
```bash
# Check all mining services
sudo systemctl status xmrig p2pool monerod

# Check monitoring services
sudo systemctl status thermal-monitor xmrig_exporter node_exporter

# Follow real-time logs for each service:

# XMRig mining logs
sudo journalctl -u xmrig -f

# P2Pool operations logs
sudo journalctl -u p2pool -f

# Monero daemon logs
sudo journalctl -u monerod -f

# Thermal monitoring logs
sudo journalctl -u thermal-monitor -f

# XMRig exporter logs
sudo journalctl -u xmrig_exporter -f

# Node exporter logs
sudo journalctl -u node_exporter -f
```

### Performance Monitoring
```bash
# View current hashrate and mining stats
curl -s http://localhost:18088/1/summary | jq
# Or remotely: curl -s http://[rig-ip]:18088/1/summary | jq

# Check system temperatures
sensors

# Monitor mining services
sudo systemctl status xmrig p2pool monerod

# Follow mining service logs:
sudo journalctl -u xmrig -f
sudo journalctl -u p2pool -f
sudo journalctl -u monerod -f

# Check thermal monitoring logs
sudo journalctl -u thermal-monitor -n 20

# Check service status
sudo systemctl status xmrig p2pool monerod xmrig_exporter node_exporter
```

### External Monitoring
- **P2Pool Observer:** https://p2pool.observer (enter wallet address)

### Metrics Endpoints

**XMRig Direct API:**
- **Endpoint:** `http://[rig-ip]:18088/1/summary`
- **Format:** JSON
- **Update Interval:** Real-time
- **Contains:** Hashrate, connection status, worker info
- **External Access:** Available on network

**XMRig Prometheus Metrics:**
- **Endpoint:** `http://[rig-ip]:9100/metrics`
- **Job Name:** `xmrig-metrics`
- **Format:** Prometheus
- **Update Interval:** 15 seconds
- **Contains:** Mining performance, hashrate trends, pool connectivity
- **External Access:** Available on network

**System Metrics (Node Exporter):**
- **Endpoint:** `http://[rig-ip]:9101/metrics`
- **Job Name:** `mining-system-metrics`
- **Format:** Prometheus
- **Update Interval:** 30 seconds
- **Contains:** CPU, memory, disk, network, temperatures
- **External Access:** Available on network

**Custom Mining Metrics:**
- **Endpoint:** `http://[rig-ip]:9101/metrics` (included in system metrics)
- **Namespace:** `mining_service_*`, `xmrig_*`, `node_*`
- **Update Interval:** 30 seconds
- **Contains:** Service health, system performance, mining statistics
- **External Access:** Available on network

### External Network Access

All metrics and monitoring endpoints are accessible externally on network:

**From Remote Monitoring System:**
```bash
# Replace [rig-ip] with actual mining rig IP (e.g., 10.10.10.2)

# XMRig mining stats (JSON format)
curl -s http://[rig-ip]:18088/1/summary | jq

# XMRig Prometheus metrics
curl -s http://[rig-ip]:9100/metrics

# System and custom metrics  
curl -s http://[rig-ip]:9101/metrics
```

**Firewall Configuration:**
- Port 9100/tcp: XMRig Exporter (mining metrics)
- Port 9101/tcp: Node Exporter (system metrics)
- Port 18088/tcp: XMRig API (real-time mining data)

**Prometheus Configuration:**
```yaml
# Add to prometheus.yml targets section
- job_name: 'xmrig-metrics'
  static_configs:
    - targets: ['[rig-ip]:9100']

- job_name: 'mining-system-metrics'
  static_configs:
    - targets: ['[rig-ip]:9101']
```

### Key Metrics for Grafana Dashboards

**Mining Performance:**
```promql
# Total hashrate
rate(xmrig_hashrate_total[5m])

# Mining efficiency
xmrig_hashrate_total / node_load1

# Pool connection uptime
up{job="xmrig-metrics"}
```

**Service Monitoring:**
```promql
# Service status monitoring
up{job="xmrig-metrics"}
up{job="mining-system-metrics"}

# Mining service health
systemd_unit_state{name="xmrig.service",state="active"}
systemd_unit_state{name="p2pool.service",state="active"}
systemd_unit_state{name="monerod.service",state="active"}
```

**System Health:**
```promql
# CPU temperature
node_hwmon_temp_celsius{chip="coretemp-isa-0000"}

# Memory usage percentage
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# Disk space usage
(1 - (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})) * 100

# CPU usage
100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
```

### Prometheus Configuration

Complete `prometheus.yml` configuration file is included for monitoring multiple mining rigs:

```yaml
# Copy provided prometheus.yml file to Prometheus server
# Update target IPs to match mining rig network addresses
# Default network: 10.10.10.0/24 with rigs RYZEN_01, RYZEN_02, RYZEN_03, etc.
```

**Quick Setup:**
1. Copy `prometheus.yml` to Prometheus configuration directory
2. Update target IP addresses to match mining rigs
3. Restart Prometheus
4. Import Grafana dashboard templates (queries provided above)

### Mining Configuration Monitoring

System includes automated monitoring to ensure proper mining configuration:

**Service Health Monitoring:**
- **Mining Services:** Monitors XMRig, P2Pool, and Monero daemon status via systemd
- **Automatic Restart:** Systemd service dependencies with restart on failure
- **API Monitoring:** REST endpoint verification for all services
- **Configuration Validation:** Payment address verification during installation

**Prometheus Metrics Available:**
```promql
# Service status monitoring
up{job="xmrig-metrics"}
up{job="mining-system-metrics"}

# Mining performance tracking
xmrig_hashrate_total
xmrig_pool_connection_status

# System health monitoring
node_cpu_seconds_total
node_memory_MemAvailable_bytes
```

**Monitoring Features:**
- **Service Dependencies:** Systemd restart logic with proper service ordering
- **API Monitoring:** XMRig, P2Pool, and Monero daemon status via REST APIs
- **Hardware Monitoring:** CPU temperatures, frequencies, and thermal management
- **Metrics Export:** Prometheus-compatible metrics for external monitoring systems

## System Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Monero    │◄───┤   P2Pool    │◄───┤   XMRig     │
│   Node      │    │ (0% fees)   │    │ (0% donation)│
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Blockchain  │    │Direct Payouts│    │  Mining     │
│    Sync     │    │ to Wallet   │    │  Hardware   │
└─────────────┘    └─────────────┘    └─────────────┘
```

### P2Pool Operation

1. **Decentralized Pool** - No central server dependency
2. **Side Chain** - Separate blockchain for pool coordination  
3. **Direct Payouts** - Block rewards distributed directly to miners
4. **PPLNS Rewards** - Pay-per-last-N-shares reward system
5. **Uncle Blocks** - No share loss, comprehensive accounting

### Expected Operation Timeline

- **Initial 10 minutes**: Service initialization and synchronization
- **First hour**: P2Pool synchronization, initial share submission  
- **24-168 hours**: First payout (share contribution dependent)
- **Ongoing**: Regular payouts at ~0.00027 XMR threshold

## Hardware Optimization

Modules automatically detect and optimize for specific hardware configuration:

### Automatic Hardware Detection
- **CPU**: Model, core count, frequency capabilities, NUMA topology
- **Memory**: Speed (MT/s), rank configuration, bandwidth testing
- **Storage**: Disk type and I/O scheduler optimization

### Applied Optimizations

**Module-1 System Optimizations (require reboot):**
- **Huge Pages**: 1GB and 2MB pages configured for maximum RandomX performance
- **MSR Optimizations**: CPU register tuning for enhanced RandomX mining
- **CPU Performance**: Governor set to "performance" mode (persistent)
- **IRQ Affinity**: System interrupts isolated to cores 0-1, mining cores 2-31
- **Memory Tuning**: Bandwidth, latency, and allocation optimizations
- **Storage I/O**: mq-deadline scheduler for all storage devices
- **Thermal Management**: Advanced monitoring with frequency scaling
- **System Services**: Unnecessary services disabled (bluetooth, cups, etc.)

**Module-3 Mining Optimizations (immediate):**
- **XMRig Compilation**: Hardware-specific build with 0% donation
- **Pool Failover**: 4-pool failover system (P2Pool primary + 3 backup pools: SupportXMR, Nanopool, MineXMR)
- **Service Dependencies**: Proper startup sequence with restart logic
- **Performance Tuning**: Hardware-specific optimization and memory bandwidth testing
- **Thread Affinity**: Optimized for detected CPU topology
- **Memory Testing**: STREAM benchmark and latency validation
- **Cache Optimization**: RandomX-specific settings for mining workload

### Verification Commands

After running both modules, verify optimizations:

```bash
# Check applied CPU optimizations
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | head -4
grep MHz /proc/cpuinfo | head -4

# Verify memory configuration
cat /proc/meminfo | grep -E 'HugePages|MemAvailable'

# Check thermal monitoring
sensors
sudo systemctl status thermal-monitor

# Verify mining services
sudo systemctl status xmrig p2pool monerod

# View current mining performance
curl -s http://localhost:18088/1/summary | jq '.hashrate'
# Or remotely: curl -s http://[rig-ip]:18088/1/summary | jq '.hashrate'
```

**Note:** All optimizations applied automatically. No manual BIOS changes required.

### P2Pool Parameters

- **Host**: 127.0.0.1 (localhost connection)
- **Port**: 3333 (XMRig connection endpoint)
- **Log level**: 2 (balanced verbosity)
- **PPLNS window**: Maximum 6 hours
- **Block time**: 10 seconds

### Monero Node Configuration

- **Pruned blockchain** - 70% disk space reduction
- **ZMQ enabled** - Required for P2Pool integration
- **Peer configuration** - 32 outbound, 64 inbound connections
- **DNS blocklist** - Malicious node filtering
- **Priority nodes** - Reliable connection endpoints

## Troubleshooting

### Common Issues

**Mining Inactive Status**
```bash
# Verify P2Pool operation
sudo systemctl status p2pool

# Check P2Pool-Monero connectivity
sudo journalctl -u p2pool -n 50

# Sequential service restart
sudo systemctl restart monerod
sleep 30
sudo systemctl restart p2pool  
sleep 15
sudo systemctl restart xmrig
```

**P2Pool Synchronization Failure**
```bash
# Verify Monero node synchronization
~/monero/monerod status

# Synchronization requirement: Height: XXXX/XXXX (100.0%)
```

**Missing Payouts**
```bash
# Verify mining statistics at P2Pool Observer
# Navigate to: https://p2pool.observer
# Input wallet address for status verification

# Check if wallet address is configured correctly
grep -v "WALLET_ADDRESS_PLACEHOLDER" ~/xmrig_config/config.json

# Verify mining is active
curl -s http://localhost:18088/1/summary | jq '.hashrate'
# Or remotely: curl -s http://[rig-ip]:18088/1/summary | jq '.hashrate'

# Check service monitoring status
curl -s http://localhost:9101/metrics | grep mining_service
# Or remotely: curl -s http://[rig-ip]:9101/metrics | grep mining_service
```

**Automated Recovery Features**
- **Service Dependencies**: Systemd services configured with proper restart logic and dependencies
- **Thermal Management**: thermal-monitor adjusts CPU frequency if temperature > 85°C (continuous)
- **Mining Optimization**: mining-optimization service applies performance settings at boot
- **Hardware Monitoring**: Sensors and performance governors automatically optimize for mining workload

### Recovery Procedures

**Complete System Restart:**
```bash
sudo systemctl stop xmrig xmrig_exporter p2pool monerod
sleep 10
sudo systemctl start monerod
sleep 30  
sudo systemctl start p2pool
sleep 15
sudo systemctl start xmrig xmrig_exporter
```

**P2Pool Reset:**
```bash
sudo systemctl stop xmrig p2pool
rm -rf ~/p2pool/p2pool_cache
sudo systemctl start p2pool
sleep 15
sudo systemctl start xmrig
```

**Monero Blockchain Re-synchronization:**
```bash
sudo systemctl stop p2pool xmrig monerod
rm -rf ~/.bitmonero
sudo systemctl start monerod
# Full synchronization required (hours to days)
```

## Security Configuration

### Network Security
- **External firewall ports:** 9100 (XMRig Exporter), 9101 (Node Exporter), 18088 (XMRig API)
- **Mining network access:** 18080 (Monero P2P), 37889 (P2Pool) accessible via 10.10.10.0/24
- Network service monitoring enabled
- External metrics access available for monitoring

### Operational Security
- Non-root service execution
- Systemd security restrictions
- Regular software updates
- Log monitoring for anomalies

### Wallet Security
- Public address visibility on P2Pool network
- Dedicated mining wallet recommended
- Private key backup requirements
- Cold storage for significant balances

## Maintenance

### Automated Maintenance
System includes automated maintenance features:
- **Systemd service management** with automatic restart on failure
- **Thermal monitoring** with dynamic frequency scaling
- **Hardware optimization** applied at boot via mining-optimization service

### Manual Maintenance Tasks

**Weekly:**
- Check P2Pool Observer for payout confirmation
- Review service logs: `sudo journalctl -u thermal-monitor -n 50`

**Monthly:**
- System package updates: `sudo apt update && sudo apt upgrade`
- Review mining service status: `sudo systemctl status xmrig p2pool monerod`

### Update Procedures

**System Updates:**
```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Restart mining services if needed
sudo systemctl restart monerod p2pool xmrig
```

**Component Updates:**
```bash
# Modules automatically fetch latest versions
# To update, re-run module-2.sh which pulls latest releases
chmod +x module-2.sh
./module-2.sh
```

## Technical Reference

**Mining Operation:**
- **Algorithm**: RandomX (optimized for CPU mining)
- **Pool**: P2Pool decentralized (0% fees)
- **Minimum Payout**: ~0.00027 XMR (automatic)
- **Payout Time**: 24-168 hours depending on share contribution

**Address Requirements:**  
- Primary wallet addresses only (starts with '4')
- Subaddresses and integrated addresses not supported

**Automated Features:**
- Systemd service dependencies and restart logic
- Thermal management with performance optimization
- Hardware optimization service at boot
- Prometheus metrics export for monitoring

**Security:**
- SSH hardening with fail2ban protection
- Firewall configuration
- Non-root service execution
- Comprehensive logging and alerting

## Support

**For issues, check logs:**
```bash
# Mining services
sudo journalctl -u xmrig p2pool monerod -n 50

# Monitoring services  
sudo journalctl -u thermal-monitor xmrig_exporter node_exporter -n 50

# Check service status
sudo systemctl status xmrig p2pool monerod thermal-monitor
```

**Community Support:**
- P2Pool: #p2pool-log on Libera.Chat
- Monero: r/MoneroMining