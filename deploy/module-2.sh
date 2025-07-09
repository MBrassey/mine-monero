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

# Enable i2c/SMBus access
echo "Enabling SMBus access..."
modprobe i2c_dev
modprobe i2c_piix4
modprobe amdgpu

# Create i2c group if it doesn't exist
getent group i2c >/dev/null || groupadd i2c

# Add current user to i2c group
usermod -a -G i2c $SUDO_USER

# Set permissions
echo "Setting device permissions..."
chown root:i2c /dev/i2c-* 2>/dev/null || true
chmod 660 /dev/i2c-* 2>/dev/null || true
chmod 660 /dev/hidraw* 2>/dev/null || true

# Kill any existing OpenRGB processes
killall openrgb 2>/dev/null || true
sleep 2

# Show detected devices
echo "Detected devices:"
openrgb -l

echo
echo "Setting all devices to red..."
openrgb -d 0 -m direct -c FF0000
openrgb -d 1 -m direct -c FF0000
openrgb -d 2 -m direct -c FF0000
openrgb -d 3 -m direct -c FF0000

echo "Done."