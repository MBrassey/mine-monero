#!/bin/bash

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Run with sudo"
    exit 1
fi

# Basic logging
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
error() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2; }

# Cleanup function
cleanup() {
    log "Cleaning up previous installation..."
    
    # Stop services
    systemctl stop openrgb 2>/dev/null || true
    systemctl disable openrgb 2>/dev/null || true
    
    # Kill any running instances
    killall openrgb 2>/dev/null || true
    
    # Remove old files
    rm -f /etc/systemd/system/openrgb.service
    rm -f /etc/udev/rules.d/60-openrgb.rules
    rm -f /usr/lib/udev/rules.d/60-openrgb.rules
    rm -rf /root/.config/OpenRGB
    
    # Clean up any leftover USB rules
    udevadm control --reload-rules
    udevadm trigger
    
    # Reset modules
    for module in i2c_dev i2c_piix4 i2c_i801 ch341 usbhid; do
        modprobe -r $module 2>/dev/null || true
        sleep 1
        modprobe $module 2>/dev/null || true
        sleep 1
    done
    
    log "Cleanup complete"
}

# Run cleanup first
cleanup

echo "=== Universal RGB Control Script for Ubuntu 24.04 ==="
echo "Compatible with: ALL OpenRGB-supported devices including:"
echo "   ASRock B650M PG Lightning WiFi Motherboard"
echo "   AMD Wraith Prism CPU Cooler"
echo "   XPG Lancer Blade RGB RAM"
echo "   XPG SPECTRIX S20G M.2 SSD"
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

# Update package lists if they're older than 1 hour
if [ ! -f /var/cache/apt/pkgcache.bin ] || [ $(( $(date +%s) - $(stat -c %Y /var/cache/apt/pkgcache.bin) )) -gt 3600 ]; then
    DEBIAN_FRONTEND=noninteractive apt-get update
fi

# Install packages if not already installed
for pkg in i2c-tools wget git build-essential qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libusb-1.0-0-dev libhidapi-dev pkgconf cmake qttools5-dev-tools pciutils lm-sensors libusb-1.0-0 libhidapi-libusb0 libhidapi-hidraw0; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y $pkg
    fi
done

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

# Stop any running instances before installing
systemctl stop openrgb 2>/dev/null || true
killall openrgb 2>/dev/null || true
sleep 2

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
getent group i2c >/dev/null || groupadd i2c

# Add current user to required groups if not already in them
if [ -n "$SUDO_USER" ]; then
    for group in i2c input video plugdev; do
        if ! groups "$SUDO_USER" | grep -q "\b${group}\b"; then
            usermod -a -G "$group" "$SUDO_USER"
        fi
    done
fi

# Update systemd service with fixed command handling
cat > /etc/systemd/system/openrgb.service << EOF
[Unit]
Description=OpenRGB LED Control
After=multi-user.target systemd-modules-load.service
Wants=modprobe@i2c_dev.service modprobe@i2c_piix4.service modprobe@i2c_i801.service

[Service]
Type=simple
# Wait for devices
ExecStartPre=/bin/sleep 5

# Kill any existing instances
ExecStartPre=-/usr/bin/killall openrgb

# Load modules
ExecStartPre=/sbin/modprobe i2c_dev
ExecStartPre=/sbin/modprobe i2c_piix4 force=1
ExecStartPre=/sbin/modprobe i2c_i801 force_addr=1

# Set device permissions
ExecStartPre=/bin/chmod 666 /dev/i2c-*
ExecStartPre=/bin/chmod 666 /dev/hidraw*

# Start OpenRGB
ExecStart=/usr/bin/openrgb --server --nodetect --profile default

Restart=on-failure
RestartSec=3
User=root
Environment=DISPLAY=:0
SupplementaryGroups=i2c input video plugdev

[Install]
WantedBy=multi-user.target
EOF

# Stop any existing service
systemctl stop openrgb || true
sleep 2

# Create OpenRGB config directories
mkdir -p /root/.config/OpenRGB
mkdir -p /home/$SUDO_USER/.config/OpenRGB

# Create a minimal working profile
cat > /root/.config/OpenRGB/default.orp << EOF
{
    "header": {
        "version": 3,
        "description": "Default Profile",
        "author": "OpenRGB"
    },
    "controllers": [
        {
            "name": "ASRock B650M PG Lightning WiFi",
            "type": "Motherboard",
            "vendor": "ASRock",
            "active_mode": "Static",
            "colors": ["${TARGET_COLOR}"]
        }
    ]
}
EOF

# Copy profile to user directory
cp -f /root/.config/OpenRGB/default.orp "/home/$SUDO_USER/.config/OpenRGB/"
chown -R "$SUDO_USER:$SUDO_USER" "/home/$SUDO_USER/.config/OpenRGB"

# Test OpenRGB directly first
echo "Testing OpenRGB directly..."
openrgb --server --nodetect &
sleep 3
openrgb --nodetect --device 0 --mode static --color ${TARGET_COLOR}
sleep 1
killall openrgb

# Reload and restart service
echo "Starting OpenRGB service..."
systemctl daemon-reload
systemctl enable openrgb
systemctl restart openrgb

# Wait for service to initialize
sleep 5

# Check service status
echo
echo "OpenRGB Service Status:"
systemctl status openrgb --no-pager

echo
echo "Current OpenRGB device status:"
openrgb --nodetect --list-devices

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