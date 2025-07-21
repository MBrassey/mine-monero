# Monero (XMR) Mining Suite

<img align="left" src="https://s2.coinmarketcap.com/static/img/coins/128x128/328.png" alt="Monero Logo" width="128" height="128">

Automated deployment system for Monero mining with P2Pool and XMRig.

&nbsp;• **Zero Mining Fees** local P2Pool  
&nbsp;• **Zero Donation** XMRig

<br clear="left"/>

## Reference Hardware Configuration

This deployment has been tested with the following hardware:

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
- **Expected Hashrate:** ~18,000-21,000 H/s (RandomX)

**Memory Configuration:**
- **Capacity:** 16GB (1x16GB single-channel)
- **Speed:** DDR5-6000 MHz CL30
- **Slot Placement:** Install in second RAM slot from CPU (A2/DIMM2)
- **Placement Reason:** Optimal signal integrity and stability for high-speed DDR5 memory
- **Huge Pages Support:** 1GB and 2MB pages for RandomX optimization

**Storage & Connectivity:**
- **NVMe SSD:** 500GB (More than sufficient for pruned blockchain ~5GB + logs)
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

```bash
chmod +x module-1.sh
sudo ./module-1.sh
```

**module-1.sh functions:**

**System cleanup:**
- Removes conflicting services and configurations
- Cleans package management state (removes problematic PPAs)
- Updates system packages

**System optimizations:**
- Disables throttling services (thermald, power-profiles-daemon, bluetooth, cups, snapd, etc.)
- Sets CPU governor to performance mode
- Enables CPU boost, removes frequency limits
- Configures kernel parameters: vm.swappiness=1, vm.nr_hugepages=6144, disables NUMA balancing
- Loads MSR module and applies RandomX CPU optimizations
- Disables transparent huge pages
- Creates systemd service to persist optimizations on boot

**Security configuration:**
- Configures UFW firewall with mining port rules
- Installs SSH public key for key-based authentication
- Disables password authentication

**Monitoring:**
- Installs Prometheus Node Exporter on port 9100
- Sets up custom metrics collection for CPU temperature and huge pages

**Disk management:**
- Detects LVM configuration and offers disk expansion

**Network ports configured:**
- SSH (22): open
- Monero P2P (18080): LAN only
- Monero RPC (18081): LAN only  
- P2Pool Mining (3333): open
- P2Pool P2P (37889): LAN only
- Node Exporter (9100): LAN only
- XMRig API (8080): LAN only

### Phase 4: RGB Control (Optional)

**Step 9: Execute Module-2 (RGB Device Control) - Optional**

```bash
# Default blue (0000FF)
sudo ./module-2.sh

# Custom color (6-digit hex)
sudo ./module-2.sh FF0000
```

**module-2.sh functions:**
- Installs OpenRGB from Debian package
- Loads i2c kernel modules (i2c-dev, i2c-piix4, i2c_amd_ryzen)
- Updates GRUB with kernel parameters: acpi_enforce_resources=lax amd_iommu=on iommu=pt
- Creates udev rules for device permissions
- Creates systemd service to set RGB colors on boot
- Scans i2c buses for devices

**RGB devices controlled:**
- ENE DRAM (memory modules)
- AMD Wraith Prism (CPU cooler)
- ASRock (motherboard)

**Note:** NVMe drive RGB scanning implemented but control not functional

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
WALLET_ADDRESS="MONERO_WALLET_ADDRESS_HERE"
WORKER_ID="RYZEN_01"
DONATION_LEVEL=0
```

**Important Notes:**
- **Wallet Address**: Use primary Monero wallet address (starts with '4'). Subaddresses not supported.
- **Worker ID**: Use unique identifiers for multiple rigs

### Phase 7: Mining Software Installation

**Step 11: Execute Module-3**
```bash
chmod +x module-3.sh
sudo ./module-3.sh
```

**module-3.sh functions:**
- Installs build dependencies (build-essential, cmake, boost, etc.)
- Downloads and compiles from source:
  - Monero daemon (monerod) with pruned blockchain support
  - XMRig with hardcoded 0% donation level
  - P2Pool
- Creates XMRig configuration targeting localhost:3333 (P2Pool stratum)
- Creates systemd services:
  - monerod.service (runs with --prune-blockchain --sync-pruned-blocks)
  - p2pool.service (runs with --mini flag)
  - xmrig.service
  - msr-tools.service
- Creates mining-control management script
- Enables and starts all services

## System Architecture

| Component | Implementation | Configuration |
|-----------|----------------|---------------|
| **Mining Pool** | P2Pool Mini | No fees, direct payouts |
| **Miner Software** | XMRig (0% donation) | Local compilation |
| **Blockchain Node** | Monero daemon (pruned) | ~5GB storage vs ~160GB full |
| **Minimum Payout** | P2Pool threshold | ~0.00027 XMR |
| **Payout Method** | Direct to wallet | No intermediary custody |

## System Components

### P2Pool Mini - Local Mining Pool
- Local P2Pool instance with --mini flag
- Zero fees
- Direct wallet payouts
- Low minimum payout threshold: ~0.00027 XMR
- No registration required
- Connects to P2Pool network for block discovery

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
- Minimum 20GB free disk space (for pruned blockchain ~5GB + system)
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
2. **Monerod sync**: 15-30 minutes (pruned blockchain download)
3. **P2Pool sync**: 5-10 minutes after monerod is synced
4. **Mining starts**: Immediately when P2Pool is ready
5. **First shares**: Within minutes of mining start
6. **First payout**: 24-168 hours (depends on pool luck and your contribution)

## Monitoring

### XMRig HTTP API
- **Endpoint**: `http://127.0.0.1:8080` (local) or `http://[rig-ip]:8080` (remote)
- **Port**: 8080 (configured in XMRig config)
- **Access**: Enabled and accessible from network

### Live Hashrate Monitoring
```bash
# Monitor XMRig hashrate in real-time
sudo journalctl -u xmrig -f | grep speed

# Monitor monerod blockchain sync progress
sudo journalctl -u monerod -f | grep HEIGHT
```

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
- **P2Pool Mini Observer**: https://mini.p2pool.observer/miner/WALLET_ADDRESS_HERE
- **Local P2Pool status**: Wait for monerod to sync before P2Pool connects to network

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
# Check if monerod is synced
sudo journalctl -u monerod.service -n 20

# P2Pool requires synced monerod
sudo journalctl -u monerod -f | grep HEIGHT
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
- **Pool**: Local P2Pool ONLY (127.0.0.1:3333)

### P2Pool Configuration
P2Pool runs with: `--host 127.0.0.1 --rpc-port 18081 --zmq-port 18083 --wallet WALLET_ADDRESS --stratum 127.0.0.1:3333 --p2p 127.0.0.1:37889 --loglevel 1 --mini`

- **Mini Mode**: `--mini` flag for lower difficulty
- **Wallet**: Your specified wallet address
- **Local Stratum**: Port 3333 for XMRig connection
- **P2P Port**: 37889 for P2Pool network communication
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
- **P2Pool P2P**: Port 37889 (P2Pool Mini network)
- **P2Pool Stratum**: Port 3333 (localhost only)

### Build Security
- **Source Compilation**: All software built from official sourcecode
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