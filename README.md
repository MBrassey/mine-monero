# AMD Ryzen Monero (XMR) Mining Suite

<img align="left" src="https://s2.coinmarketcap.com/static/img/coins/128x128/328.png" alt="Monero Logo" width="128" height="128">

Automated deployment system for streamlined Monero mining with P2Pool decentralized mining, XMRig optimization, and enterprise-grade reliability.

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
- **NVMe SSD:** 500GB (Sufficient storage for blockchain data, logs etc.)
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
1. Connect monitor to onboard HDMI port on motherboard
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
   sudo apt install git vim -y
   ```

**Step 7: Clone Mining Repository**
1. Clone the mine-monero repository:
   ```bash
   git clone https://github.com/MBrassey/mine-monero.git
   cd mine-monero/deploy
   ```

### Phase 3: System Optimization

**Step 8: Execute Module-1 (System Preparation)**

Module-1 performs comprehensive system optimization for mining workloads.

**Run Module-1:**
```bash
chmod +x module-1.sh
sudo ./module-1.sh
```

**What module-1.sh does:**

**System Cleanup & Package Management:**
- **Cleans previous configurations**: Removes any conflicting services and configurations
- **Package management cleanup**: Removes problematic PPAs and cleans package cache
- **Repository management**: Ensures clean package repository state

**Disk Space Management:**
- **Automatic LVM expansion**: Detects and expands logical volumes to use full disk capacity
- **Interactive disk expansion**: Prompts user before expanding disk space
- **Space verification**: Reports before/after disk usage statistics

**Security & Network Configuration:**
- **Firewall setup**: Comprehensive UFW configuration with mining-specific rules
- **SSH hardening**: Configures key-based authentication with specific public key
- **Network access control**: Allows LAN access to mining ports, blocks unnecessary external access

**Performance Optimizations:**
- **Service management**: Disables throttling services (thermald, power-profiles-daemon, etc.)
- **CPU optimization**: Sets all CPU cores to "performance" governor
- **CPU boost**: Enables CPU boost and removes frequency limits
- **Memory optimization**: Configures huge pages (6144 pages = 12GB)
- **Kernel parameters**: Sets vm.swappiness=1, disables NUMA balancing
- **MSR optimization**: Loads MSR module and applies RandomX optimizations
- **Transparent huge pages**: Disables THP for better RandomX performance

**Monitoring Infrastructure:**
- **Node Exporter**: Installs Prometheus Node Exporter v1.7.0+ 
- **System metrics**: Custom metrics collector for CPU temperature, frequency, huge pages
- **Metrics endpoint**: Exposes metrics on port 9100 for external monitoring

**Persistent Optimizations:**
- **Systemd service**: Creates mining-opt.service to maintain optimizations across reboots
- **Boot parameters**: Adds intel_pstate=disable to GRUB configuration
- **Module loading**: Ensures MSR module loads automatically on boot

**Network Ports Configured:**
- SSH (22): Allowed from anywhere
- Monero P2P (18080): Allowed from LAN
- Monero RPC (18081): Allowed from LAN  
- P2Pool Mining (3333): Allowed from anywhere
- P2Pool P2P (37889): Allowed from LAN
- Node Exporter (9100): Allowed from LAN
- XMRig API (18088): Allowed from LAN

**Important Notes:**
- **Requires sudo**: Module-1 must be run with root privileges
- **May require reboot**: If GRUB parameters are updated, system reboot is needed
- **SSH key configured**: Installs specific SSH public key for authentication
- **Disk expansion**: Offers to expand disk to full capacity if LVM detected
- **Service removal**: Removes throttling services that impact mining performance

**Post-Execution:**
- System may prompt for reboot if kernel parameters were changed
- All optimizations persist across reboots via systemd service
- SSH is configured for key-based authentication only
- Firewall is enabled with mining-optimized ruleset

### Phase 4: RGB Control (Optional)

**Step 9: Execute Module-2 (RGB Device Control)**

This is an optional aesthetic enhancement module that provides unified RGB control for your mining hardware.

**What module-2.sh does:**
- **Installs OpenRGB**: Universal RGB controller from official Debian package
- **Hardware Detection**: Automatically detects and configures:
  - ENE DRAM (XPG Lancer Blade RGB memory)
  - AMD Wraith Prism CPU cooler
  - ASRock motherboard RGB
  - XPG NVMe drive (not yet working)
- **Kernel Configuration**: 
  - Loads i2c kernel modules for RGB device access
  - Updates GRUB with required kernel parameters
  - Sets up udev rules for device permissions
- **Systemd Service**: Creates persistent service to restore RGB colors on boot
- **User Permissions**: Configures proper access permissions for RGB devices

**Usage:**
```bash
# Run with default blue color (0000FF)
sudo ./module-2.sh

# Run with custom color (6-digit hex)
sudo ./module-2.sh FF0000  # Red
sudo ./module-2.sh 00FF00  # Green  
sudo ./module-2.sh FFFFFF  # White
sudo ./module-2.sh 800080  # Purple
```

**Important Notes:**
- **Requires sudo**: Module-2 must be run with root privileges
- **May require reboot**: If GRUB parameters are updated, system reboot is needed
- **Purely aesthetic**: This module only affects RGB lighting, not mining performance
- **Optional**: Mining will work perfectly without RGB control

**Supported Hardware:**
- XPG Lancer Blade RGB DDR5 memory
- AMD Wraith Prism RGB CPU cooler  
- ASRock motherboard RGB lighting
- XPG SPECTRIX S20G RGB NVMe SSD

### Phase 6: Configuration Setup

**Step 10: Update Module-3 Configuration**

Before running module-3.sh, update the following variables at the top of the script:

```bash
vim module-3.sh
```

**Required Updates:**
1. **Wallet Address**: Replace the placeholder with your Monero wallet address
2. **Worker ID**: Update to desired rig identifier (e.g., RYZEN_01, RYZEN_02)
3. **Donation Level**: Set to 0 (already configured)

Example:
```bash
WALLET_ADDRESS="YOUR_MONERO_WALLET_ADDRESS_HERE"
WORKER_ID="RYZEN_01"
DONATION_LEVEL=0
```

**Important Notes:**
- **Wallet Address**: Use primary Monero wallet address (starts with '4'). Subaddresses not supported.
- **Worker ID**: Use unique identifiers for multiple rigs

### Phase 7: Mining Software Installation

**Step 11: Execute Module-3**
1. Make the script executable and run:
   ```bash
   chmod +x module-3.sh
   ./module-3.sh
   ```

**What module-3.sh does:**
- **Installs dependencies**: build tools, libraries needed for compiling
- **Downloads and builds from source**:
  - Monero daemon (monerod) from official repository
  - XMRig miner with 0% donation hardcoded
  - P2Pool from official repository
- **Creates optimized XMRig configuration**:
  - Configured for Ryzen 9950X with huge pages enabled
  - Primary pool: localhost:3333 (local P2Pool Mini)
  - Backup pool: pool.supportxmr.com:3333
- **Sets up systemd services** with proper dependencies:
  - monerod.service (Monero daemon)
  - p2pool.service (P2Pool Mini with --mini flag)
  - xmrig.service (XMRig miner)
  - msr-tools.service (MSR optimization)
- **Configures system optimizations**:
  - Huge pages setup (6144 pages = 12GB)
  - MSR (CPU register) optimizations
  - CPU performance governor
- **Creates management script**: mining-control for easy service management
- **Removes build dependencies** after compilation for security
- **Starts all services** in correct order with health checks



## System Architecture

| Component | Implementation | Configuration |
|-----------|----------------|---------------|
| **Mining Pool** | P2Pool Mini (decentralized) | No fees, direct payouts |
| **Miner Software** | XMRig (compiled with 0% donation) | No donation, 0% overhead |
| **Blockchain Node** | Monero daemon (full node) | Required for P2Pool operation |
| **Minimum Payout** | P2Pool threshold | ~0.00027 XMR |
| **Network Architecture** | Distributed P2P | No central servers |
| **Payout Method** | Direct to wallet | No intermediary custody |

## System Components

### P2Pool Mini - Decentralized Mining Pool
- Fully decentralized pool implementation with --mini flag
- Zero fees permanently
- Direct wallet payouts
- Low minimum payout threshold: ~0.00027 XMR
- No registration required

### XMRig - Optimized Miner
- Compiled from source with 0% donation level hardcoded
- Advanced build with RandomX optimizations
- Huge pages memory support (6144 pages = 12GB)
- Hardware-specific CPU optimizations

### Service Management
- Systemd services with proper dependencies
- Automatic restart on failure
- MSR optimization service for CPU performance
- mining-control script for easy management

## Prerequisites

- Ubuntu 20.04+ or Debian 11+ (x64)
- Minimum 16GB RAM (for huge pages allocation)
- Minimum 100GB free disk space (for full Monero blockchain)
- Stable internet connection

## Dependencies & Repositories

Mining deployment system automatically downloads and configures the following open-source components:

### Core Mining Components
| Component | Repository | Purpose |
|-----------|------------|---------|
| **Monero Daemon** | <a href="https://github.com/monero-project/monero.git" target="_blank">github.com/monero-project/monero</a> | Official Monero blockchain node and daemon |
| **P2Pool** | <a href="https://github.com/SChernykh/p2pool.git" target="_blank">github.com/SChernykh/p2pool</a> | Decentralized mining pool implementation |
| **XMRig** | <a href="https://github.com/xmrig/xmrig.git" target="_blank">github.com/xmrig/xmrig</a> | High-performance Monero miner |

### Version Management
- **Tagged Releases**: Uses specific version tags (MONERO_VERSION, XMRIG_VERSION, P2POOL_VERSION)
- **Source Compilation**: All components compiled from source with optimizations
- **Retry Logic**: Git downloads include retry logic for network reliability

**Note**: Module-3 automatically handles version detection, downloading, and configuration of all dependencies. No manual dependency management required.

## Service Management

### Mining Control Script
Module-3 creates a convenient management script:

```bash
# Check status of all mining services
mining-control status

# Start all mining services
mining-control start

# Stop all mining services
mining-control stop

# Restart all mining services
mining-control restart

# View recent logs
mining-control logs

# Enable services for automatic startup
mining-control enable

# Disable services from automatic startup
mining-control disable
```

### Individual Service Management
```bash
# Check individual service status
sudo systemctl status monerod.service
sudo systemctl status p2pool.service
sudo systemctl status xmrig.service

# Follow service logs
sudo journalctl -u monerod.service -f
sudo journalctl -u p2pool.service -f
sudo journalctl -u xmrig.service -f
```

### XMRig API Access
```bash
# View mining statistics (local)
curl -s http://127.0.0.1:8080/2/summary | jq

# View mining statistics (remote)
curl -s http://[rig-ip]:8080/2/summary | jq
```

## Expected Operation Timeline

1. **Module-3 execution**: 30-60 minutes (compilation and setup)
2. **Monerod sync**: Several hours to days (full blockchain download)
3. **P2Pool sync**: 5-10 minutes after monerod is synced
4. **Mining starts**: Immediately when P2Pool is ready
5. **First shares**: Within minutes of mining start
6. **First payout**: 24-168 hours (depends on pool luck and your contribution)

## Monitoring

### XMRig HTTP API
- **Endpoint**: `http://127.0.0.1:8080` (local) or `http://[rig-ip]:8080` (remote)
- **Port**: 8080 (configured in XMRig config)
- **Access**: Enabled and accessible from network

### Service Status
```bash
# Quick status check
mining-control status

# Detailed service status
sudo systemctl status monerod p2pool xmrig msr-tools

# Check if services are enabled for startup
sudo systemctl is-enabled monerod p2pool xmrig
```

### P2Pool Monitoring
- **P2Pool Mini Observer**: https://mini.p2pool.observer/miner/ (enter your wallet address at the end)
- **Usage**: Visit https://mini.p2pool.observer/miner/YOUR_WALLET_ADDRESS_HERE
- **Local P2Pool**: Wait for monerod to fully sync first

## Troubleshooting

### Common Issues

**Services not starting**
```bash
# Check service dependencies
sudo systemctl list-dependencies xmrig.service

# Restart in correct order
mining-control restart
```

**P2Pool not connecting**
```bash
# Check if monerod is fully synced
sudo journalctl -u monerod.service -n 20

# P2Pool requires fully synced monerod
# Look for: "Height: XXXX/XXXX (100.0%)" in monerod logs
```

**XMRig not connecting to P2Pool**
```bash
# Check P2Pool status
sudo systemctl status p2pool.service

# Check XMRig logs for connection errors
sudo journalctl -u xmrig.service -n 20
```

**Low hashrate**
```bash
# Verify huge pages are enabled
grep HugePages /proc/meminfo

# Check MSR service status
sudo systemctl status msr-tools.service

# Verify CPU governor
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
```

### Recovery Procedures

**Complete restart**
```bash
mining-control stop
sleep 10
mining-control start
```

**Reset P2Pool (if sync issues)**
```bash
sudo systemctl stop p2pool xmrig
sudo rm -rf ~/monero-mining/install/p2pool-data/*
sudo systemctl start p2pool
# Wait for P2Pool to sync, then start XMRig
sudo systemctl start xmrig
```

## Configuration Details

### XMRig Configuration
Module-3 creates an optimized configuration at `~/monero-mining/install/etc/xmrig-config.json`:

- **Algorithm**: RandomX optimized for AMD Ryzen
- **Huge Pages**: Enabled (requires 6144 huge pages)
- **Hardware AES**: Enabled for better performance
- **CPU Priority**: Set to 5 for mining priority
- **Donation Level**: Hardcoded to 0%
- **Pool Failover**: Local P2Pool primary, SupportXMR backup

### P2Pool Configuration
P2Pool runs with the following settings:

- **Mini Mode**: `--mini` flag for lower difficulty
- **Light Mode**: `--light-mode` for reduced memory usage
- **Wallet**: Your specified wallet address
- **Local Stratum**: Port 3333 for XMRig connection
- **Log Level**: 1 for minimal verbosity

### Service Dependencies
Services are configured with proper dependencies:

1. **monerod.service**: Independent, starts first
2. **p2pool.service**: Requires monerod.service
3. **xmrig.service**: Requires p2pool.service
4. **msr-tools.service**: Independent optimization service

## Security

### Network Configuration
- **XMRig API**: Port 8080 (HTTP, read-only)
- **Monero P2P**: Port 18080 (blockchain sync)
- **Monero RPC**: Port 18081 (localhost only)
- **P2Pool P2P**: Port 37888 (P2Pool Mini network)
- **P2Pool Stratum**: Port 3333 (localhost only)

### Build Security
- **Source Compilation**: All software built from official sources
- **Dependency Cleanup**: Build tools removed after compilation
- **Runtime Libraries**: Only essential runtime libraries kept
- **Service Isolation**: Services run as non-root users where possible

## Support

**For issues, check logs:**
```bash
# All mining services
mining-control logs

# Specific service logs
sudo journalctl -u [service-name] -n 50
```

**Community Support:**
- P2Pool: #p2pool-mini on Libera.Chat
- Monero: r/MoneroMining

## License

`mine-monero` is published under the **CC0_1.0_Universal** license.

> The Creative Commons CC0 Public Domain Dedication waives copyright interest in a work you've created and dedicates it to the world-wide public domain. Use CC0 to opt out of copyright entirely and ensure your work has the widest reach. As with the Unlicense and typical software licenses, CC0 disclaims warranties. CC0 is very similar to the Unlicense.