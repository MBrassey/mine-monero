#!/bin/bash

echo "=== SMBus/I2C Diagnostic Tool ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo)"
    exit 1
fi

echo "1. Checking kernel modules..."
{
    echo "Currently loaded I2C modules:"
    lsmod | grep -E "i2c|smbus"
    
    echo -e "\nTrying to load required modules..."
    modprobe i2c-dev
    modprobe i2c-piix4
    modprobe i2c_amd_mp2 2>/dev/null || echo "Note: i2c_amd_mp2 not available"
    modprobe amd_mp2_dev 2>/dev/null || echo "Note: amd_mp2_dev not available"
    modprobe i2c_amd_ryzen 2>/dev/null || echo "Note: i2c_amd_ryzen not available"
} 2>&1

echo -e "\n2. Checking kernel parameters..."
{
    echo "Current kernel command line:"
    cat /proc/cmdline
    
    if ! grep -q "acpi_enforce_resources=lax" /proc/cmdline; then
        echo "Warning: acpi_enforce_resources=lax not set"
    fi
    
    if ! grep -q "amd_iommu=on" /proc/cmdline; then
        echo "Warning: amd_iommu=on not set"
    fi
} 2>&1

echo -e "\n3. Checking I2C buses..."
{
    echo "Available I2C buses:"
    i2cdetect -l
    
    echo -e "\nDetailed I2C bus scan:"
    for i in $(seq 0 9); do
        if [ -e "/dev/i2c-$i" ]; then
            echo -e "\nBus i2c-$i:"
            i2cdetect -y $i 2>/dev/null
        fi
    done
} 2>&1

echo -e "\n4. Checking permissions..."
{
    echo "I2C group existence:"
    getent group i2c || echo "Warning: i2c group does not exist"
    
    echo -e "\nI2C device permissions:"
    ls -l /dev/i2c* 2>/dev/null
} 2>&1

echo -e "\n5. Checking OpenRGB detection..."
{
    echo "OpenRGB device list:"
    openrgb --verbose --list-devices
} 2>&1

echo -e "\n=== Diagnostic Summary ==="
echo "To enable SMBus access, you need to:"
echo "1. Add these parameters to GRUB:"
echo "   acpi_enforce_resources=lax amd_iommu=on iommu=pt"
echo "2. Create/update /etc/modprobe.d/i2c.conf with:"
echo "   softdep i2c_piix4 pre: i2c_amd_mp2"
echo "3. Ensure the i2c group exists and your user is in it:"
echo "   sudo groupadd i2c"
echo "   sudo usermod -aG i2c $SUDO_USER"
echo "4. Update GRUB and reboot:"
echo "   sudo update-grub"
echo "   sudo reboot" 