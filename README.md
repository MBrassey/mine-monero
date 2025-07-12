# AMD Ryzen Monero (XMR) Mining Suite

<img align="left" src="https://s2.coinmarketcap.com/static/img/coins/128x128/328.png" alt="Monero Logo" width="128" height="128">

Automated deployment system for streamlined Monero mining with P2Pool decentralized mining, XMRig optimization, and enterprise-grade monitoring & reliability.

&nbsp;• **Zero Mining Fees** P2Pool  
&nbsp;• **Zero Donation** XMRig

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
- **NVMe SSD:** 500GB (Sufficient storage for the chain data, backups, metrics, logs etc.)
- **Network:** Gigabit Ethernet (REMOVE WIFI MODULE FOR SECURITY)

### Case Assembly Instructions

**Stackable Open Air Case Setup:**
- **Case Type:** Modular open-air design for optimal cooling
- **Motherboard Support:** Stable VRM design for 24/7 mining loads and DDR5-6000 memory bus speeds
- **Stacking Capability:** Multiple rigs can be stacked vertically
- **Assembly Guide:** <a href="https://www.ediy.cc/en/2589.htm" target="_blank">Complete installation instructions</a>

**Key Assembly Points:**
- Install isolation pillars and motherboard mounting
- Secure power supply positioning and cable management
- Leg post installation for stacking capability
- Proper component spacing for airflow

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
3. Boot from USB and select **Minimal installation** option
4. Create user account with username "ubuntu" during installation
5. Configure network settings during installation:
   - Set static internal IP address manually within 192.168.1.0/24 subnet
   - Example: IP: 192.168.1.xxx, Netmask: 255.255.255.0, Gateway: 192.168.1.1
   - Record the IP for SSH access configuration
6. Ensure network connectivity is established
7. After installation completes, run system update:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

**Step 6: Initial System Setup**
1. Log into freshly installed Ubuntu system as user "ubuntu"
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

**Step 8: Network and Firewall Configuration**

The mining setup uses the following network configuration:
- Subnet: 192.168.1.0/24
- Required open ports:
  ```
  Mining Ports:
  • P2Pool Stratum: 3333/tcp
  • P2Pool P2P: 37889/tcp
  • P2Pool Mini P2P: 37888/tcp
  • Monero P2P: 18080/tcp
  • Monero RPC: 18081/tcp
  • XMRig API: 18088/tcp
  
  Monitoring Ports:
  • XMRig Exporter: 9100/tcp
  • Node Exporter: 9101/tcp
  
  Access Ports:
  • SSH: 22/tcp
  ```

**Customizing Network Configuration:**
1. If using a different subnet, edit module-1.sh:
   ```bash
   vim module-1.sh
   ```
   Find the line:
   ```bash
   sudo ufw allow from 192.168.1.0/24 comment 'Mining Network'
   ```
   Replace 192.168.1.0/24 with your subnet.

2. Verify your network configuration:
   ```bash
   ip addr show
   ```
   Ensure your IP is within the configured subnet.

3. The firewall configuration will:
   - Allow all outbound traffic
   - Allow inbound traffic only on specified ports
   - Allow all traffic from mining network (192.168.1.0/24)
   - Block all other inbound traffic

4. After module-1.sh completes, verify firewall status:
   ```bash
   sudo ufw status numbered
   ```
   This will show all active firewall rules.

### Phase 4: Transitioning to Headless Operation

**Step 9: Verify Remote Access**

After running module-1.sh, it's critical to verify SSH access before proceeding:

1. Open a new terminal on your workstation
2. Test SSH connection:
   ```bash
   ssh ubuntu@<your-mining-rig-ip>
   ```
3. Verify you can successfully log in
4. Run a test command:
   ```bash
   uptime
   ```
5. Exit the SSH session:
   ```bash
   exit
   ```

**Step 10: Prepare for Headless Operation**

Once SSH access is confirmed:

1. Shut down the mining rig:
   ```bash
   sudo halt
   ```
2. Wait for complete shutdown (all lights off)
3. **IMPORTANT:** Remove the video card
4. Power on the mining rig
5. Wait 2-3 minutes for full boot
6. Connect via SSH from your workstation:
   ```bash
   ssh ubuntu@<your-mining-rig-ip>
   ```

**Step 11: Verify Headless Operation**

After connecting via SSH to the headless system:
1. Verify system status:
   ```bash
   uptime
   ip addr show
   sudo ufw status numbered
   ```
2. If all checks pass, proceed with module-2 installation

**CRITICAL:** Do not proceed with module-2 until:
- SSH access is verified working
- Video card has been removed
- Headless operation is confirmed working

**Step 12: Update Configuration Files**

Before running the modules, update the following configuration files in the `deploy` directory:

**Configure config.json:**
```bash
vim config.json
# Replace "WALLET_ADDRESS_PLACEHOLDER" with the target Monero wallet address
# Update "RYZEN_01" to the required rig identifier
```

**Configure module-1.sh:**
```bash
vim module-1.sh
# Set ENGINEER_PUBLIC_KEY to the required SSH public key
```

**Configure module-2.sh (optional):**
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
   - Update and configure system packages
   - Apply CPU and memory optimizations
   - Configure SSH key authentication
   - Create mining optimization service
   - **Prompt for system reboot** (required for optimal performance)

**Step 10: Test SSH Access and Prepare for Headless Operation**
1. **Reboot system** when prompted by module-1.sh
2. Test SSH connectivity from remote workstation:
   ```bash
   ssh [username]@[ip-address]
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
   ssh [username]@[ip-address]
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
- Minimum 80GB free disk space
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
- **Version Fallbacks**: Tested fallback versions used if latest releases unavailable
- **Source Compilation**: XMRig compiled from source with zero donation configuration
- **Binary Downloads**: P2Pool, Node Exporter use pre-compiled binaries for faster deployment

**Note**: Deployment modules automatically handle version detection, downloading, and configuration of all dependencies. No manual dependency management required.

## Enterprise Features

**Automated Monitoring & Recovery:**
- Service health monitoring with systemd restart logic
- Performance management with dynamic frequency scaling
- Hardware optimization service applies settings at boot
- Prometheus metrics export for external monitoring

**Security & Reliability:**
- SSH hardening with fail2ban brute-force protection
- Firewall configuration with mining network access
- Systemd service dependencies and restart logic
- Performance monitoring with frequency scaling protection
- Comprehensive logging via systemd journal

**Performance Optimization:**
- Hardware-specific XMRig compilation and tuning
- MSR (CPU register) optimizations for RandomX
- Memory bandwidth testing and optimization
- IRQ affinity isolation for mining cores
- 2-pool failover system (P2Pool primary + SupportXMR backup)

**Recommended Wallet:**
- Official Monero CLI/GUI v0.18.1.0+ - <a href="https://www.getmonero.org/downloads/" target="_blank">Download from getmonero.org</a>
- Always use a Local Node / one you manage. 

**Note:** Primary wallet addresses required (starting with '4'). Subaddresses not supported.

## Installation Process

Mining deployment uses two-phase approach for maximum reliability and security:

### Phase 1: System Preparation (module-1.sh)

**Before running module-1.sh**, update configuration:

```bash
vim module-1.sh
# Set ENGINEER_PUBLIC_KEY to the required SSH public key
```

**What it does:**
- Updates system packages and installs essential tools (build-essential, msr-tools)
- **Automatic disk expansion**: Detects and expands LVM volumes to use full disk capacity
- **Comprehensive firewall setup**: Configures UFW with mining-specific rules for all required ports
- **Installs and configures Node Exporter**: Sets up Prometheus metrics collection with custom system metrics (Note: Module-3 installs a second Node Exporter instance on port 9101)
- Disables and removes system services that could impact performance (thermald, power-profiles-daemon, etc.)
- **Configures SSH with specific public key authentication**: Sets up hardened SSH configuration with pre-configured key
- Applies CPU optimizations:
  - Sets CPU governor to "performance" mode
  - Enables CPU boost
  - Removes frequency limits
  - Disables Intel pstate power saving
- Configures memory optimizations:
  - Sets vm.swappiness=1
  - Configures huge pages (vm.nr_hugepages=6144)
  - Optimizes memory management parameters
  - Disables transparent huge pages
- Applies MSR optimizations for all CPU cores
- **Package cleanup and management**: Removes problematic PPAs and cleans package cache
- Creates a systemd service (mining-opt.service) to maintain optimizations across reboots
- Requires system reboot after completion for full optimization

```bash
chmod +x module-1.sh
./module-1.sh
# System will prompt for reboot to apply optimizations
```

### Phase 2: RGB Control Configuration (module-2.sh) - OPTIONAL
**What it does:**
- Optional module for RGB device control
- Installs OpenRGB universal controller from official Debian package
- **Hardware-specific RGB configuration**: Detects and configures ENE DRAM, AMD Wraith Prism cooler, and ASRock motherboard RGB
- **Kernel module setup**: Configures i2c modules and GRUB parameters for RGB device access
- **Creates persistent systemd service**: Automatically restores RGB colors on boot
- **Permission and group management**: Sets up proper access permissions for RGB devices
- **i2c bus scanning**: Includes XPG NVMe drive detection functionality

```bash
# Optional RGB configuration (aesthetic enhancement):
chmod +x module-2.sh
sudo ./module-2.sh
# Edit TARGET_COLOR variable before running
```

### Phase 3: Mining Software Installation (module-3.sh)
**What it does:**
- Performs hardware detection and dependency verification
- Downloads and verifies mining components with integrity checks:
  - XMRig miner (compiled from source with 0% donation)
  - P2Pool for decentralized mining (0% fees)
  - Monero daemon with minimal configuration for P2Pool
- Applies hardware-specific optimizations:
  - Memory bandwidth testing and tuning
  - CPU cache and thread affinity optimization
  - RandomX-specific performance settings
- Sets up comprehensive monitoring:
  - XMRig HTTP API for real-time statistics
  - XMRig Exporter for Prometheus metrics collection (port 9100)
  - **Installs additional Node Exporter instance** on port 9101 (in addition to module-1's instance)
  - Automated service health checks and recovery systems
- Configures 2-pool failover system:
  - P2Pool (primary, localhost:3333)
  - SupportXMR backup pool (disabled by default)
- Creates systemd services with proper dependencies and restart logic
- Includes automated recovery and monitoring features:
  - Service health monitoring with automatic recovery
  - Performance protection with dynamic frequency scaling
  - Wallet address verification and monitoring
  - Comprehensive logging system
- Verifies all installations, APIs, and mining activity before completion
- Starts all services in correct sequence with health checks

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
sudo systemctl status xmrig_exporter node_exporter

# Follow real-time logs for each service:

# XMRig mining logs
sudo journalctl -u xmrig -f

# P2Pool operations logs
sudo journalctl -u p2pool -f

# Monero daemon logs
sudo journalctl -u monerod -f

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

# Check system performance
htop

# Monitor mining services
sudo systemctl status xmrig p2pool monerod

# Follow mining service logs:
sudo journalctl -u xmrig -f
sudo journalctl -u p2pool -f
sudo journalctl -u monerod -f

# Check performance monitoring logs
sudo journalctl -u xmrig_exporter -n 20

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
# Update target IPs to match the mining rig addresses
# Example: RYZEN_01, RYZEN_02, RYZEN_03, etc.
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
- **Hardware Monitoring:** CPU frequencies and performance management
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

### Hardware Optimization

Modules automatically detect and optimize for specific hardware configuration:

### Applied Optimizations

**Module-1 System Optimizations (require reboot):**
- **CPU Performance**: Governor set to "performance" mode with boost enabled
- **Memory Tuning**: Swappiness, huge pages, and memory management optimizations
- **MSR Optimizations**: CPU register tuning for enhanced performance
- **Transparent Huge Pages**: Disabled for better performance
- **System Services**: Unnecessary services disabled (thermald, power-profiles-daemon, etc.)
- **SSH Security**: Key-based authentication configuration
- **Persistent Settings**: Systemd service ensures optimizations persist across reboots

**Module-3 Mining Optimizations (immediate):**
- **XMRig Compilation**: Hardware-specific build with 0% donation
- **Pool Failover**: 2-pool failover system (P2Pool primary + SupportXMR backup)
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

# Check performance monitoring
sudo systemctl status xmrig_exporter node_exporter

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

- **Minimal configuration** - Optimized for P2Pool requirements
- **ZMQ enabled** - Required for P2Pool integration (tcp://127.0.0.1:18083)
- **RPC binding** - localhost:18081 for P2Pool connectivity
- **Non-interactive mode** - Automated operation without user prompts
- **Default synchronization** - Full blockchain sync (storage requirements apply)

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
- **Performance Management**: System monitoring with automatic performance optimization
- **Mining Optimization**: mining-optimization service applies performance settings at boot
- **Hardware Monitoring**: Performance governors automatically optimize for mining workload

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
- **Mining ports:** 18080 (Monero P2P), 37889 (P2Pool)
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
- **Performance monitoring** with dynamic frequency scaling
- **Hardware optimization** applied at boot via mining-optimization service

### Manual Maintenance Tasks

**Weekly:**
- Check P2Pool Observer for payout confirmation
- Review service logs: `sudo journalctl -u xmrig_exporter -n 50`

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
# To update mining components, re-run module-3.sh which pulls latest releases
chmod +x module-3.sh
./module-3.sh
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
- Performance management with system optimization
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
sudo journalctl -u xmrig_exporter node_exporter -n 50

# Check service status
sudo systemctl status xmrig p2pool monerod xmrig_exporter node_exporter
```

**Community Support:**
- P2Pool: #p2pool-log on Libera.Chat
- Monero: r/MoneroMining

## License

`mine-monero` is published under the **CC0_1.0_Universal** license.

> The Creative Commons CC0 Public Domain Dedication waives copyright interest in a work you've created and dedicates it to the world-wide public domain. Use CC0 to opt out of copyright entirely and ensure your work has the widest reach. As with the Unlicense and typical software licenses, CC0 disclaims warranties. CC0 is very similar to the Unlicense.