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

# Set aggressive permissions
echo "Setting device permissions..."
chown root:root /dev/i2c-* /dev/hidraw* 2>/dev/null || true
chmod 666 /dev/i2c-* /dev/hidraw* 2>/dev/null || true

# Add current user to required groups
usermod -a -G i2c,plugdev $SUDO_USER 2>/dev/null || true

# Kill any existing OpenRGB processes
killall openrgb 2>/dev/null || true
sleep 2

# First detect devices
echo "Detecting RGB devices..."
openrgb --list-devices

# Now set everything to red
echo "Setting all RGB devices to red..."
for i in {0..10}; do
    openrgb --device $i --mode direct --color FF0000 2>/dev/null || true
done

echo "Done."