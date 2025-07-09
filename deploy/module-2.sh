#!/bin/bash

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Run with sudo"
    exit 1
fi

# Check if OpenRGB exists, if not install it
if ! command -v openrgb &> /dev/null; then
    echo "OpenRGB not found. Installing from source..."
    
    # Install build dependencies
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y git build-essential qtbase5-dev libusb-1.0-0-dev libhidapi-dev pkgconf cmake qt5-qmake i2c-tools

    # Build from source
    cd /tmp
    rm -rf OpenRGB || true
    git clone --depth 1 https://gitlab.com/CalcProgrammer1/OpenRGB
    cd OpenRGB
    qmake PREFIX=/usr OpenRGB.pro
    make -j$(nproc)
    make install INSTALL_ROOT=/

    # Add udev rules for hardware access
    cp 60-openrgb.rules /etc/udev/rules.d/
    udevadm control --reload-rules
    udevadm trigger
    
    # Verify installation
    if ! command -v openrgb &> /dev/null; then
        echo "Failed to install OpenRGB"
        exit 1
    fi
fi

# Load i2c modules and setup SMBus
echo "Setting up hardware access..."
modprobe i2c_dev
modprobe i2c_piix4
modprobe i2c_smbus

# Create i2c devices if they don't exist
if [ ! -e "/dev/i2c-0" ]; then
    mknod /dev/i2c-0 c 89 0
fi
if [ ! -e "/dev/i2c-1" ]; then
    mknod /dev/i2c-1 c 89 1
fi

# Set aggressive permissions
echo "Setting device permissions..."
chown root:root /dev/i2c-* /dev/hidraw* 2>/dev/null || true
chmod 666 /dev/i2c-* /dev/hidraw* 2>/dev/null || true

# Add current user to required groups
usermod -a -G i2c,plugdev $SUDO_USER 2>/dev/null || true

# Kill any existing OpenRGB processes
killall openrgb 2>/dev/null || true
sleep 2

# Try to detect SMBus devices
echo "Detecting SMBus devices..."
i2cdetect -l

# Set colors with direct hardware access
echo "Setting all RGB devices to red..."
openrgb --noautoconnect --mode direct --color FF0000 --detect-smbus-devices
sleep 1

echo "Done."