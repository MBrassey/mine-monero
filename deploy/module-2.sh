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

# Load required modules
modprobe i2c-dev
modprobe i2c-piix4
modprobe i2c-nct6775

# Set permissions
chmod 777 /dev/i2c-* 2>/dev/null || true
chmod 777 /dev/hidraw* 2>/dev/null || true

# Kill any existing OpenRGB processes
killall openrgb 2>/dev/null || true
sleep 1

# Direct mode, no server, just set everything red
echo "Setting all RGB devices to red..."
openrgb --noautoconnect --mode direct --color FF0000

echo "Done."