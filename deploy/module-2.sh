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

# Install required packages first
log "Installing required packages..."
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y psmisc # for killall

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

# Stop any running OpenRGB instances
pkill openrgb || true
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

# Stop any existing service
systemctl stop openrgb || true
sleep 2

# Remove any existing config and service files
rm -f /etc/systemd/system/openrgb.service
rm -rf /root/.config/OpenRGB
rm -rf /home/$SUDO_USER/.config/OpenRGB

# Create fresh config directories
mkdir -p /root/.config/OpenRGB
mkdir -p /home/$SUDO_USER/.config/OpenRGB

# Set colors directly first
log "Setting colors for all devices..."

# Start OpenRGB server first
openrgb --server &
sleep 3

# Set CPU Cooler - Device 0 (each LED and zone)
log "Setting CPU Cooler..."
# Set overall mode first
openrgb --device 0 --mode direct --color ${TARGET_COLOR}
sleep 1

# Set each zone
openrgb --device 0 --zone 0 --color ${TARGET_COLOR} # Logo
openrgb --device 0 --zone 1 --color ${TARGET_COLOR} # Fan
openrgb --device 0 --zone 2 --color ${TARGET_COLOR} # Ring
sleep 1

# Set each individual LED
for i in {0..15}; do
    openrgb --device 0 --led $i --color ${TARGET_COLOR}
    sleep 0.1
done

# Set Motherboard - Device 1
log "Setting Motherboard..."
# Set overall mode first
openrgb --device 1 --mode direct --color ${TARGET_COLOR}
sleep 1

# Set each zone
for zone in {0..4}; do
    openrgb --device 1 --zone $zone --color ${TARGET_COLOR}
    sleep 0.1
done

# Set each LED individually
for led in {0..244}; do
    openrgb --device 1 --led $led --color ${TARGET_COLOR}
    sleep 0.05
done

# Create a proper profile that includes all devices and zones
cat > /root/.config/OpenRGB/default.orp << EOF
{
    "version": 3,
    "controllers": [
        {
            "name": "AMD Wraith Prism",
            "type": "Cooler",
            "description": "AMD Wraith Prism Device",
            "version": "V1.01.00",
            "location": "HID: /dev/hidraw2",
            "active_mode": "Direct",
            "colors": ["${TARGET_COLOR}"],
            "zones": [
                {
                    "name": "Logo",
                    "colors": ["${TARGET_COLOR}"]
                },
                {
                    "name": "Fan",
                    "colors": ["${TARGET_COLOR}"]
                },
                {
                    "name": "Ring",
                    "colors": ["${TARGET_COLOR}"]
                }
            ]
        },
        {
            "name": "ASRock B650M PG Lightning WiFi",
            "type": "Motherboard",
            "description": "ASRock Polychrome USB Device",
            "location": "HID: /dev/hidraw0",
            "active_mode": "Direct",
            "colors": ["${TARGET_COLOR}"],
            "zones": [
                {
                    "name": "RGB LED 1 Header",
                    "colors": ["${TARGET_COLOR}"]
                },
                {
                    "name": "Addressable Header 1",
                    "colors": ["${TARGET_COLOR}"]
                },
                {
                    "name": "Addressable Header 2",
                    "colors": ["${TARGET_COLOR}"]
                },
                {
                    "name": "PCB",
                    "colors": ["${TARGET_COLOR}"]
                },
                {
                    "name": "Addressable Header 3/Audio",
                    "colors": ["${TARGET_COLOR}"]
                }
            ]
        }
    ]
}
EOF

# Copy profile to user directory
cp -f /root/.config/OpenRGB/default.orp "/home/$SUDO_USER/.config/OpenRGB/"
chown -R "$SUDO_USER:$SUDO_USER" "/home/$SUDO_USER/.config/OpenRGB"

# Update systemd service to be more thorough
cat > /etc/systemd/system/openrgb.service << EOF
[Unit]
Description=OpenRGB LED Control
After=multi-user.target systemd-modules-load.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 5

# Start server
ExecStart=/bin/bash -c '\
    /usr/bin/openrgb --server & \
    sleep 3 && \
    # Set CPU Cooler \
    /usr/bin/openrgb --device 0 --mode direct --color ${TARGET_COLOR} && \
    sleep 1 && \
    /usr/bin/openrgb --device 0 --zone 0 --color ${TARGET_COLOR} && \
    /usr/bin/openrgb --device 0 --zone 1 --color ${TARGET_COLOR} && \
    /usr/bin/openrgb --device 0 --zone 2 --color ${TARGET_COLOR} && \
    for i in {0..15}; do \
        /usr/bin/openrgb --device 0 --led $i --color ${TARGET_COLOR}; \
        sleep 0.1; \
    done && \
    # Set Motherboard \
    /usr/bin/openrgb --device 1 --mode direct --color ${TARGET_COLOR} && \
    for zone in {0..4}; do \
        /usr/bin/openrgb --device 1 --zone $zone --color ${TARGET_COLOR}; \
        sleep 0.1; \
    done && \
    for led in {0..244}; do \
        /usr/bin/openrgb --device 1 --led $led --color ${TARGET_COLOR}; \
        sleep 0.05; \
    done'

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload
systemctl enable openrgb
systemctl restart openrgb

# Wait for service to initialize
sleep 5

# Verify status
log "Checking OpenRGB status..."
systemctl status openrgb --no-pager

echo
echo "Current OpenRGB device status:"
openrgb --list-devices

echo
echo "A reboot is REQUIRED to properly initialize all hardware."
echo "Would you like to reboot now? [y/N] "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    reboot
fi