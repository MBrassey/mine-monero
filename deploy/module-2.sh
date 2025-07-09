#!/bin/bash

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Run with sudo"
        exit 1
    fi
    
# Basic logging
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
error() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2; }

echo "=== Universal RGB Control Script for Ubuntu 24.04 ==="
echo "Compatible with: ALL OpenRGB-supported devices including:"
echo "   ASRock B650M PG Lightning WiFi 6E Motherboard"
echo "   AMD Wraith Prism CPU Cooler"
echo "   XPG Lancer Blade RGB RAM"
echo "   XPG SPECTRIX S20G M.2 SSD"
echo "   GPU RGB (NVIDIA/AMD)"
echo "   Any other OpenRGB-compatible RGB devices"
echo

# Set target color (red by default)
TARGET_COLOR="FF0000"

echo "Target Color: #${TARGET_COLOR}"
echo

# Install dependencies
log "Installing dependencies..."
# Disable PackageKit temporarily for apt operations
systemctl stop packagekit >/dev/null 2>&1 || true

DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    i2c-tools \
    wget \
    git \
    build-essential \
    qtbase5-dev \
    qtchooser \
    qt5-qmake \
    qtbase5-dev-tools \
    libusb-1.0-0-dev \
    libhidapi-dev \
    pkgconf \
    cmake \
    qttools5-dev-tools

# Build OpenRGB from source
log "Building OpenRGB from source..."
cd /tmp
rm -rf OpenRGB || true
git clone --depth 1 https://gitlab.com/CalcProgrammer1/OpenRGB
cd OpenRGB

# Clean any previous builds
make clean || true

# Configure build with correct prefix
if ! qmake PREFIX=/usr OpenRGB.pro; then
    error "Failed to run qmake"
    exit 1
fi

# Build OpenRGB
if ! make -j$(nproc); then
    error "Failed to build OpenRGB"
    exit 1
fi

# Install the binary and support files
log "Installing OpenRGB..."
make install INSTALL_ROOT=/ || true

# Verify binary exists and is executable
if [ ! -x "/usr/bin/openrgb" ]; then
    error "OpenRGB binary not found or not executable"
    exit 1
fi

# Enable direct hardware access
log "Setting up hardware access..."

# Create i2c group if it doesn't exist
if ! getent group i2c >/dev/null; then
    groupadd i2c
fi

# Add current user to required groups
if [ -n "$SUDO_USER" ]; then
    usermod -a -G i2c,input,video "$SUDO_USER"
fi

# Install additional tools for hardware detection
apt-get install -y pciutils lm-sensors

# Detect and configure SMBus/I2C devices
log "Detecting SMBus/I2C devices..."
sensors-detect --auto > /dev/null 2>&1 || true

# Enable hardware access modules with specific options
modules=(
    "i2c-dev"
    "i2c-piix4"
    "i2c-i801"
    "i2c-nct6775"
    "i2c-acpi"
    "i2c_hid"
    "ch341"
    "it87"
    "nct6775"
    "w83795"
    "w83627hf"
)

# Load and configure modules with options
for module in "${modules[@]}"; do
    # Try to load with different options
    case "$module" in
        "i2c-piix4")
            modprobe $module force=1 2>/dev/null || true
            ;;
        "i2c-i801")
            modprobe $module force_addr=1 2>/dev/null || true
            ;;
        *)
            modprobe $module 2>/dev/null || true
            ;;
    esac
    
    if ! grep -q "^$module" /etc/modules; then
        echo "$module" >> /etc/modules
    fi
done

# Update module configuration
log "Updating module configuration..."
if ! grep -q "i2c-piix4 force=1" /etc/modprobe.d/i2c.conf 2>/dev/null; then
    echo "options i2c-piix4 force=1" > /etc/modprobe.d/i2c.conf
    echo "options i2c-i801 force_addr=1" >> /etc/modprobe.d/i2c.conf
fi

# Update module dependencies
depmod -a

# Set up proper SMBus permissions
log "Setting up SMBus permissions..."
# Give access to all possible i2c devices
for i in $(seq 0 9); do
    if [ -e "/dev/i2c-$i" ]; then
        chmod 666 "/dev/i2c-$i"
        chown root:i2c "/dev/i2c-$i"
    fi
done

# Create comprehensive udev rules for SMBus/I2C access
cat > /etc/udev/rules.d/99-i2c.rules << EOF
# Give permissions to the i2c bus
KERNEL=="i2c-[0-9]*", GROUP="i2c", MODE="0666"

# AMD SMBus
SUBSYSTEM=="i2c-dev", DRIVER=="piix4_smbus", GROUP="i2c", MODE="0666"

# Intel SMBus
SUBSYSTEM=="i2c-dev", DRIVER=="i801_smbus", GROUP="i2c", MODE="0666"

# Generic I2C
SUBSYSTEM=="i2c-dev", GROUP="i2c", MODE="0666"

# AMD Wraith Prism
SUBSYSTEMS=="usb", ATTR{idVendor}=="2516", ATTR{idProduct}=="0051", MODE="0666"
SUBSYSTEMS=="usb", ATTR{idVendor}=="2516", ATTR{idProduct}=="0047", MODE="0666"

# XPG/ADATA Products
SUBSYSTEMS=="usb", ATTR{idVendor}=="125f", MODE="0666"
EOF

# Update udev rules
udevadm control --reload-rules
udevadm trigger

# Fix any double-slash paths
for file in /usr/bin/openrgb /usr/share/applications/org.openrgb.OpenRGB.desktop /usr/share/icons/hicolor/128x128/apps/org.openrgb.OpenRGB.png /usr/share/metainfo/org.openrgb.OpenRGB.metainfo.xml; do
    if [ -e "/${file}" ]; then
        mv "/${file}" "${file}"
    fi
done

# Reload udev
udevadm control --reload-rules
udevadm trigger

# Create desktop entry with correct path
log "Creating desktop entry..."
mkdir -p /usr/share/applications
cat > /usr/share/applications/openrgb.desktop << EOF
[Desktop Entry]
Name=OpenRGB
Comment=RGB Control Utility
Exec=/usr/bin/openrgb
Icon=utilities-terminal
Terminal=false
Type=Application
Categories=Utility;
EOF

# Try to set colors now
log "Attempting to set colors..."
echo "Setting all devices to color #${TARGET_COLOR}..."

# Stop any existing OpenRGB processes
killall openrgb 2>/dev/null || true
sleep 2

# Start fresh OpenRGB server
openrgb --server &
sleep 3

# Set each device individually
echo "Setting RAM modules..."
openrgb --device 0 --mode direct --color ${TARGET_COLOR}
openrgb --device 1 --mode direct --color ${TARGET_COLOR}
sleep 1

echo "Setting motherboard..."
# Try different modes for the motherboard
openrgb --device 2 --mode direct --color ${TARGET_COLOR}
sleep 1
openrgb --device 2 --mode static --color ${TARGET_COLOR}
sleep 1

# Try to detect and set AMD Wraith Prism
echo "Setting CPU Cooler..."
for i in {3..5}; do
    if openrgb --device $i 2>/dev/null | grep -q "AMD"; then
        echo "Found AMD Wraith Prism at device $i"
        openrgb --device $i --mode direct --color ${TARGET_COLOR}
        openrgb --device $i --mode static --color ${TARGET_COLOR}
        break
    fi
done

# Try to detect and set XPG SPECTRIX
echo "Setting M.2 SSD..."
for i in {3..5}; do
    if openrgb --device $i 2>/dev/null | grep -q "XPG"; then
        echo "Found XPG SPECTRIX at device $i"
        openrgb --device $i --mode direct --color ${TARGET_COLOR}
        openrgb --device $i --mode static --color ${TARGET_COLOR}
        break
    fi
done

# Set all devices together with different modes
echo "Setting all devices together..."
modes=("direct" "static")
for mode in "${modes[@]}"; do
    echo "Trying mode: $mode"
    openrgb --mode $mode --color ${TARGET_COLOR}
    sleep 1
done

# Create a profile for the current settings
echo "Creating default color profile..."
mkdir -p /root/.config/OpenRGB/
cat > /root/.config/OpenRGB/default.orp << EOF
{
    "devices": [
        {
            "name": "ENE DRAM",
            "type": "DRAM",
            "description": "ENE SMBus Device",
            "version": "AUDA0-E6K5-0101",
            "serial": "",
            "location": "I2C: /dev/i2c-2, address 0x71",
            "mode": "Direct",
            "colors": ["${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}"]
        },
        {
            "name": "ENE DRAM",
            "type": "DRAM",
            "description": "ENE SMBus Device",
            "version": "AUDA0-E6K5-0101",
            "serial": "",
            "location": "I2C: /dev/i2c-2, address 0x73",
            "mode": "Direct",
            "colors": ["${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}", "${TARGET_COLOR}"]
        },
        {
            "name": "ASRock B650M PG Lightning WiFi",
            "type": "Motherboard",
            "description": "ASRock Polychrome USB Device",
            "version": "",
            "serial": "",
            "location": "HID: /dev/hidraw0",
            "mode": "Direct",
            "colors": ["${TARGET_COLOR}"]
        },
        {
            "name": "AMD Wraith Prism",
            "type": "Cooler",
            "mode": "Direct",
            "colors": ["${TARGET_COLOR}"]
        },
        {
            "name": "XPG SPECTRIX",
            "type": "Storage",
            "mode": "Direct",
            "colors": ["${TARGET_COLOR}"]
        }
    ]
}
EOF

# Update systemd service to load profile and ensure USB device access
log "Updating systemd service..."
cat > /etc/systemd/system/openrgb.service << EOF
[Unit]
Description=OpenRGB LED Control
After=multi-user.target
Wants=modprobe@i2c_dev.service modprobe@i2c_piix4.service modprobe@i2c_i801.service

[Service]
Type=simple
# Load required modules with options
ExecStartPre=/sbin/modprobe i2c_dev
ExecStartPre=/sbin/modprobe i2c_piix4 force=1
ExecStartPre=/sbin/modprobe i2c_i801 force_addr=1
# Set permissions for all possible devices
ExecStartPre=/bin/sh -c 'for i in \$(seq 0 9); do if [ -e "/dev/i2c-\$i" ]; then chmod 666 "/dev/i2c-\$i"; fi; done'
ExecStartPre=/bin/sh -c 'for dev in /dev/hidraw*; do chmod 666 "\$dev"; done'
# Start OpenRGB and load profile
ExecStart=/usr/bin/openrgb --server --profile default
Restart=on-failure
RestartSec=3
User=root
Environment=DISPLAY=:0
# Add proper device permissions
SupplementaryGroups=i2c input video plugdev
# Add proper capabilities
AmbientCapabilities=CAP_SYS_RAWIO CAP_SYS_ADMIN CAP_IPC_LOCK
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and restart service
systemctl daemon-reload
systemctl enable openrgb
systemctl restart openrgb

# Wait for service to initialize
sleep 5

# Show current status
echo
echo "Current OpenRGB device status:"
openrgb --list-devices

echo
echo "A reboot is REQUIRED to properly initialize all hardware:"
echo "1. Load all kernel modules with correct options"
echo "2. Initialize SMBus and I2C controllers with proper parameters"
echo "3. Apply all user and device permissions"
echo "4. Initialize USB and PCI device detection"
echo
echo "After reboot:"
echo "1. The systemd service will automatically set colors to #${TARGET_COLOR}"
echo "2. You can verify by running: openrgb --list-devices"
echo "3. To change colors manually: openrgb --color RRGGBB"
echo "4. To use the GUI: just run 'openrgb'"
echo
echo "Would you like to reboot now? [y/N] "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    reboot
fi

echo
echo "If you choose not to reboot now, please reboot manually before using OpenRGB."
echo "After reboot, the systemd service will automatically set your devices to #${TARGET_COLOR}"