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

# Build and install OpenRGB from source
log "Building OpenRGB from source..."
cd /tmp
rm -rf OpenRGB || true
git clone --depth 1 https://gitlab.com/CalcProgrammer1/OpenRGB
cd OpenRGB

# Build OpenRGB
if ! qmake OpenRGB.pro; then
    error "Failed to run qmake"
    exit 1
fi

if ! make -j$(nproc); then
    error "Failed to build OpenRGB"
    exit 1
fi

if ! sudo make install; then
    error "Failed to install OpenRGB"
    exit 1
fi

# Verify installation
if ! which openrgb >/dev/null 2>&1; then
    error "OpenRGB installation verification failed"
    exit 1
fi

cd ..
rm -rf OpenRGB

# Enable I2C/SMBus access
log "Setting up I2C/SMBus access..."
if ! grep -q "^i2c-dev" /etc/modules; then
    echo "i2c-dev" >> /etc/modules
fi

# Create i2c group if it doesn't exist
if ! getent group i2c >/dev/null; then
    groupadd i2c
fi

# Add current user to i2c group
if [ -n "$SUDO_USER" ]; then
    usermod -a -G i2c "$SUDO_USER"
fi

# Load all potentially needed kernel modules
log "Loading kernel modules..."
modules=(
    "i2c-dev"
    "i2c-piix4"
    "i2c-i801"
    "i2c-nct6775"  # Common for motherboard sensors
    "i2c-acpi"     # ACPI I2C
    "i2c_hid"      # HID devices over I2C
    "ch341"        # Common USB-to-I2C adapter
)

for module in "${modules[@]}"; do
    modprobe "$module" 2>/dev/null || true
    if ! grep -q "^$module" /etc/modules; then
        echo "$module" >> /etc/modules
    fi
done

# Update module dependencies
log "Updating module dependencies..."
depmod -a

# Create udev rules for RGB devices
log "Creating udev rules..."
cat > /etc/udev/rules.d/60-openrgb.rules << 'EOF'
# AMD Wraith Prism
SUBSYSTEMS=="usb", ATTR{idVendor}=="2516", ATTR{idProduct}=="0051", MODE="0666"
SUBSYSTEMS=="usb", ATTR{idVendor}=="2516", ATTR{idProduct}=="0047", MODE="0666"

# ASRock Polychrome
SUBSYSTEMS=="usb", ATTR{idVendor}=="26CE", MODE="0666"

# ASUS Aura
SUBSYSTEMS=="usb", ATTR{idVendor}=="0B05", MODE="0666"

# XPG/ADATA Products
SUBSYSTEMS=="usb", ATTR{idVendor}=="125F", MODE="0666"

# I2C/SMBus Access
KERNEL=="i2c-[0-9]*", GROUP="i2c", MODE="0666"
EOF
    
    # Reload udev rules
    udevadm control --reload-rules
    udevadm trigger
    
# Create desktop entry
log "Creating desktop entry..."
cat > /usr/share/applications/openrgb.desktop << EOF
[Desktop Entry]
Name=OpenRGB
Comment=RGB Control Utility
Exec=openrgb
Icon=utilities-terminal
Terminal=false
Type=Application
Categories=Utility;
EOF

# Create OpenRGB systemd service
log "Creating OpenRGB service..."
cat > /etc/systemd/system/openrgb.service << EOF
[Unit]
Description=OpenRGB LED Control
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/bin/openrgb --server --noautoconnect --brightness 100 --color ${TARGET_COLOR}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Enable and start OpenRGB service
    systemctl daemon-reload
systemctl enable openrgb
systemctl start openrgb

# Wait for OpenRGB to start and initialize
log "Waiting for OpenRGB to initialize..."
sleep 10

# Set all devices to target color
log "Setting all devices to target color..."

# Check if any RGB devices are detected
if ! openrgb --list-devices 2>/dev/null | grep -q "Device:"; then
    error "No RGB devices detected. Please check your hardware connections and drivers."
    echo "You may need to reboot for device detection to work properly."
    echo "Would you like to reboot now? [y/N] "
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        reboot
    fi
    exit 1
fi

# Try to set colors multiple times to ensure it takes effect
for i in {1..3}; do
    log "Attempt $i to set RGB color..."
    if openrgb --noautoconnect --brightness 100 --color ${TARGET_COLOR}; then
        break
    fi
    sleep 2
done

log "RGB configuration complete!"
echo
echo "All RGB devices should now be set to color #${TARGET_COLOR}"
echo "RGB settings will persist across reboots"
echo
echo "You can control RGB in three ways:"
echo "1. Run 'openrgb' to launch the GUI"
echo "2. Edit TARGET_COLOR in this script and run it again"
echo "3. Use the command: openrgb --color RRGGBB"
echo "   Example: openrgb --color FF0000 (for red)"
echo
echo "NOTE: A reboot is recommended for all changes to take effect."
echo "Would you like to reboot now? [y/N] "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    reboot
fi

log "A reboot is REQUIRED for the following reasons:"
echo "1. Enable newly installed kernel modules"
echo "2. Apply SMBus/I2C permissions"
echo "3. Initialize hardware drivers"
echo "4. Apply udev rules for USB device permissions"
echo
echo "Would you like to reboot now? [y/N] "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    reboot
fi

echo
echo "If you choose not to reboot now, please reboot manually before using OpenRGB."
echo "After reboot, RGB settings will be automatically applied via the systemd service."