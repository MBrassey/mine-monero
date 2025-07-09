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
fi

# Load ALL necessary modules for device detection
echo "Loading required modules..."
modprobe i2c_dev
modprobe i2c_piix4
modprobe i2c_smbus
modprobe raydium_i2c
modprobe nvme
modprobe msr
modprobe k10temp

# Set permissions for all possible devices
echo "Setting device permissions..."
chmod 666 /dev/i2c-* 2>/dev/null || true
chmod 666 /dev/hidraw* 2>/dev/null || true
chmod 666 /dev/nvme* 2>/dev/null || true
chmod 666 /dev/port 2>/dev/null || true

# Kill any existing OpenRGB processes
killall openrgb 2>/dev/null || true
sleep 2

# First check what devices are detected
echo "Detected devices:"
openrgb --list-devices

echo
echo "Setting all devices to red..."
# Try both methods to ensure all devices are set
openrgb --color FF0000
sleep 1
openrgb --mode direct --color FF0000

echo "Done."