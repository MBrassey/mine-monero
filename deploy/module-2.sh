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
# Add current user to required groups
if [ -n "$SUDO_USER" ]; then
    usermod -a -G i2c,input,uucp,video "$SUDO_USER"
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
    "it87"        # Common motherboard sensor
    "nct6775"     # Common motherboard sensor
    "w83795"      # Another common sensor
    "w83627hf"    # Another common sensor
)

for module in "${modules[@]}"; do
    modprobe "$module" 2>/dev/null || true
    if ! grep -q "^$module" /etc/modules; then
        echo "$module" >> /etc/modules
    fi
done

# Update udev rules with correct paths
log "Updating udev rules..."
mkdir -p /usr/lib/udev/rules.d/
cp 60-openrgb.rules /usr/lib/udev/rules.d/
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

# Update systemd service
log "Updating systemd service..."
cat > /etc/systemd/system/openrgb.service << EOF
[Unit]
Description=OpenRGB LED Control
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/bin/openrgb --server --noautoconnect --brightness 100 --color ${TARGET_COLOR}
Restart=on-failure
RestartSec=3
User=root
Environment=DISPLAY=:0

[Install]
WantedBy=multi-user.target
EOF

# Clean up
cd ..
rm -rf OpenRGB

# Reload and restart services
log "Restarting services..."
systemctl daemon-reload
systemctl enable openrgb
systemctl restart openrgb

# Wait for service to initialize
sleep 5

# Try to detect hardware
log "Checking for RGB hardware..."
echo "Running hardware detection..."

# Try to detect devices with SMBus scanning
if ! i2cdetect -l 2>/dev/null | grep -q "SMBus"; then
    echo "No SMBus controllers detected. This might be normal depending on your hardware."
else
    echo "SMBus controllers found. This is good!"
fi

# Check USB devices
echo "Checking USB devices..."
lsusb

echo
echo "A reboot is REQUIRED to properly initialize all hardware:"
echo "1. Load all kernel modules"
echo "2. Initialize SMBus and I2C controllers"
echo "3. Apply all user permissions"
echo "4. Initialize USB device detection"
echo
echo "Would you like to reboot now? [y/N] "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    reboot
fi

echo
echo "If you choose not to reboot now, please reboot manually before using OpenRGB."
echo "After reboot, run 'openrgb --list-devices' to verify device detection."