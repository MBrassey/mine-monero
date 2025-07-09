#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

echo "Fixing SMBus configuration for AMD B650..."

# 1. Clean up GRUB configuration
echo "1. Cleaning up GRUB configuration..."
GRUB_FILE="/etc/default/grub"
cp "$GRUB_FILE" "${GRUB_FILE}.backup"

# Remove existing parameters we want to manage
sed -i 's/acpi_enforce_resources=[^ ]* *//g' "$GRUB_FILE"
sed -i 's/amd_iommu=[^ ]* *//g' "$GRUB_FILE"
sed -i 's/iommu=[^ ]* *//g' "$GRUB_FILE"
sed -i 's/pci=nocrs *//g' "$GRUB_FILE"

# Add our clean parameters
PARAMS="acpi_enforce_resources=lax amd_iommu=on iommu=pt"
CMDLINE=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_FILE" | cut -d'"' -f2)
NEW_CMDLINE="$CMDLINE $PARAMS"
NEW_CMDLINE=$(echo "$NEW_CMDLINE" | tr -s ' ' | sed 's/^ *//;s/ *$//')
sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"$NEW_CMDLINE\"/" "$GRUB_FILE"

# 2. Set up module dependencies
echo "2. Setting up module dependencies..."
cat > /etc/modprobe.d/i2c.conf << EOF
softdep i2c_piix4 pre: i2c_amd_mp2
softdep i2c_piix4 pre: i2c_amd_ryzen
EOF

# 3. Add required modules to /etc/modules
echo "3. Adding required modules..."
for module in i2c_dev i2c_piix4 i2c_amd_ryzen; do
    if ! grep -q "^$module" /etc/modules; then
        echo "$module" >> /etc/modules
    fi
done

# 4. Install required packages
echo "4. Installing required packages..."
apt-get update
apt-get install -y i2c-tools dkms build-essential linux-headers-$(uname -r)

# 5. Set up udev rules
echo "5. Setting up udev rules..."
cat > /etc/udev/rules.d/60-openrgb.rules << EOF
SUBSYSTEM=="hidraw*", GROUP="plugdev", MODE="0666"
SUBSYSTEM=="usb", ATTRS{idVendor}=="2516", MODE="0666"
SUBSYSTEM=="i2c-dev", GROUP="i2c", MODE="0660"
KERNEL=="i2c-[0-9]*", GROUP="i2c", MODE="0660"
EOF

# 6. Set up groups
echo "6. Setting up groups..."
getent group i2c > /dev/null || groupadd i2c
getent group plugdev > /dev/null || groupadd plugdev

if [ -n "$SUDO_USER" ]; then
    usermod -aG i2c,plugdev "$SUDO_USER"
fi

# 7. Update GRUB
echo "7. Updating GRUB..."
update-grub

echo "Configuration complete!"
echo "You MUST reboot for changes to take effect."
echo "After reboot, run: sudo openrgb --verbose --list-devices"
echo
echo "Would you like to reboot now? [y/N] "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    reboot
fi 