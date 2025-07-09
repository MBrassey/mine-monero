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

# Add kernel parameters for AMD B650M
if ! grep -q "acpi_enforce_resources=lax amd_iommu=off" /etc/default/grub; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="acpi_enforce_resources=lax amd_iommu=off /' /etc/default/grub
    update-grub
fi

# Load required modules in correct order
echo "Loading required modules..."
modprobe i2c_dev
sleep 1
modprobe i2c_piix4
sleep 1

# Enable i2c in modules
if ! grep -q "^i2c_dev" /etc/modules; then
    echo "i2c_dev" >> /etc/modules
    echo "i2c_piix4" >> /etc/modules
fi

# Set permissions
echo "Setting device permissions..."
chmod 666 /dev/i2c-* 2>/dev/null || true
chmod 666 /dev/hidraw* 2>/dev/null || true

# Create i2c group and add user
getent group i2c >/dev/null || groupadd i2c
usermod -a -G i2c $SUDO_USER

# Kill any existing OpenRGB processes
killall openrgb 2>/dev/null || true
sleep 2

# Check available i2c buses
echo "Available I2C buses:"
i2cdetect -l

# Try to set colors with different methods
echo "Setting all devices to red..."
openrgb -d 0 -m direct -c FF0000
openrgb -d 1 -m direct -c FF0000
openrgb -d 2 -m direct -c FF0000
openrgb -d 3 -m direct -c FF0000
sleep 1
openrgb --mode direct --color FF0000

echo "Done. A reboot is required for kernel parameter changes to take effect."
echo "Would you like to reboot now? [y/N] "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    reboot
fi