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

# Enable hardware access modules
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

# Load and configure modules
for module in "${modules[@]}"; do
    modprobe "$module" 2>/dev/null || true
    if ! grep -q "^$module" /etc/modules; then
        echo "$module" >> /etc/modules
    fi
done

# Update module dependencies
depmod -a

# Set up proper SMBus permissions
log "Setting up SMBus permissions..."
for i2c_dev in /dev/i2c-*; do
    if [ -e "$i2c_dev" ]; then
        chmod 666 "$i2c_dev"
        chown root:i2c "$i2c_dev"
    fi
done

# Create udev rules for SMBus/I2C access
cat > /etc/udev/rules.d/99-i2c.rules << EOF
KERNEL=="i2c-[0-9]*", GROUP="i2c", MODE="0666"
EOF

# Update udev rules with correct paths
log "Updating udev rules..."
# Remove any existing rules first
rm -f /etc/udev/rules.d/60-openrgb.rules
rm -f /usr/lib/udev/rules.d/60-openrgb.rules

# Install new rules
mkdir -p /usr/lib/udev/rules.d/
cp 60-openrgb.rules /usr/lib/udev/rules.d/60-openrgb.rules
chmod 644 /usr/lib/udev/rules.d/60-openrgb.rules

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

# Update systemd service with proper permissions
log "Updating systemd service..."
cat > /etc/systemd/system/openrgb.service << EOF
[Unit]
Description=OpenRGB LED Control
After=multi-user.target
Wants=modprobe@i2c_dev.service

[Service]
Type=simple
ExecStartPre=/sbin/modprobe i2c_dev
ExecStartPre=/bin/sh -c 'for i2c in /dev/i2c-*; do chmod 666 \$i2c; done'
ExecStart=/usr/bin/openrgb --server --noautoconnect --brightness 100 --color ${TARGET_COLOR}
Restart=on-failure
RestartSec=3
User=root
Environment=DISPLAY=:0
# Add proper device permissions
SupplementaryGroups=i2c input video
# Add proper capabilities
AmbientCapabilities=CAP_SYS_RAWIO CAP_SYS_ADMIN
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

# Try to set colors now
log "Attempting to set colors..."
echo "Setting all devices to red (#FF0000)..."
openrgb --noautoconnect --brightness 100 --color FF0000

# Show current status
echo
echo "Current OpenRGB device status:"
openrgb --list-devices

echo
echo "A reboot is REQUIRED to properly initialize all hardware:"
echo "1. Load all kernel modules"
echo "2. Initialize SMBus and I2C controllers"
echo "3. Apply all user permissions"
echo "4. Initialize USB device detection"
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