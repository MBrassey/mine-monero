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

# Add kernel parameters for AMD B650M and XPG devices
if ! grep -q "pci=nocrs acpi_enforce_resources=lax" /etc/default/grub; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="pci=nocrs acpi_enforce_resources=lax /' /etc/default/grub
    update-grub
fi

# Load all required modules for AMD and XPG devices
echo "Loading required modules..."
modprobe i2c_dev
modprobe i2c_piix4
modprobe i2c_amd_mp2
modprobe nvme
modprobe ee1004    # For XPG RAM
modprobe i2c_smbus # For XPG devices

# Add modules to load at boot
cat > /etc/modules-load.d/rgb.conf << EOF
i2c_dev
i2c_piix4
i2c_amd_mp2
nvme
ee1004
i2c_smbus
EOF

# Set permissions for all device types
echo "Setting device permissions..."
chmod 666 /dev/hidraw* 2>/dev/null || true
chmod 666 /dev/i2c-* 2>/dev/null || true
chmod 666 /dev/nvme* 2>/dev/null || true
chown root:plugdev /dev/hidraw* 2>/dev/null || true
chown root:i2c /dev/i2c-* 2>/dev/null || true

# Add user to required groups
usermod -a -G plugdev,i2c $SUDO_USER

# Kill any existing OpenRGB processes
killall openrgb 2>/dev/null || true
sleep 2

# Try to detect devices
echo "Detecting devices..."
openrgb --detect-controllers

echo
echo "Setting all devices to red..."
# Try different modes to ensure all devices are set
openrgb --mode direct --color FF0000 --use-usb
sleep 1
openrgb --mode direct --color FF0000
sleep 1
# Try setting devices individually
for i in {0..5}; do
    openrgb -d $i -m direct -c FF0000 2>/dev/null || true
    sleep 0.5
done

echo "Done. A reboot is required for kernel parameter changes to take effect."
echo "Would you like to reboot now? [y/N] "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    reboot
fi