#!/bin/bash

COLOR="${1:-0000FF}"

if ! [[ $COLOR =~ ^[0-9A-Fa-f]{6}$ ]]; then
    echo ":: Error: Invalid color format. Please use 6-digit hex color (e.g., FFFFFF for white, FF0000 for red)"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo ":: Run with sudo"
    exit 1
fi

setup_initial_config() {
    if ! command -v openrgb &> /dev/null; then
        echo ":: OpenRGB not found. Installing from Debian package..."
        cd /tmp
        wget https://openrgb.org/releases/release_0.9/openrgb_0.9_amd64_bookworm_b5f46e3.deb
        apt --fix-broken install -y ./openrgb_0.9_amd64_bookworm_b5f46e3.deb
    fi

    echo ":: Installing required packages..."
    apt-get update
    apt-get install -y i2c-tools dkms build-essential linux-headers-$(uname -r)

    echo ":: Loading required kernel modules..."
    modprobe i2c-dev
    modprobe i2c-piix4
    modprobe i2c_amd_mp2 2>/dev/null || true
    modprobe amd_mp2_dev 2>/dev/null || true
    modprobe i2c_amd_ryzen 2>/dev/null || true

    for module in i2c_dev i2c_piix4 i2c_amd_ryzen; do
        if ! grep -q "^$module" /etc/modules; then
            echo "$module" >> /etc/modules
        fi
    done

    if [ ! -f /etc/modprobe.d/i2c.conf ]; then
        echo ":: Setting up module dependencies..."
        cat > /etc/modprobe.d/i2c.conf << EOF
softdep i2c_piix4 pre: i2c_amd_mp2
softdep i2c_piix4 pre: i2c_amd_ryzen
EOF
    fi

    if ! grep -q "acpi_enforce_resources=lax.*amd_iommu=on.*iommu=pt" /etc/default/grub; then
        echo ":: Updating GRUB configuration..."
        GRUB_FILE="/etc/default/grub"
        cp "$GRUB_FILE" "${GRUB_FILE}.backup"

        sed -i 's/acpi_enforce_resources=lax *//g' "$GRUB_FILE"
        sed -i 's/amd_iommu=[^ ]* *//g' "$GRUB_FILE"
        sed -i 's/iommu=[^ ]* *//g' "$GRUB_FILE"
        sed -i 's/pci=nocrs *//g' "$GRUB_FILE"

        PARAMS="acpi_enforce_resources=lax amd_iommu=on iommu=pt"
        CMDLINE=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "$GRUB_FILE" | cut -d'"' -f2)
        NEW_CMDLINE="$CMDLINE $PARAMS"
        NEW_CMDLINE=$(echo "$NEW_CMDLINE" | tr -s ' ' | sed 's/^ *//;s/ *$//')
        sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"$NEW_CMDLINE\"/" "$GRUB_FILE"

        update-grub
        NEEDS_REBOOT=1
    fi

    if [ ! -f /etc/udev/rules.d/60-openrgb.rules ]; then
        echo ":: Setting up udev rules..."
        cat > /etc/udev/rules.d/60-openrgb.rules << EOF
SUBSYSTEM=="hidraw*", GROUP="plugdev", MODE="0666"
SUBSYSTEM=="usb", ATTRS{idVendor}=="2516", MODE="0666"
SUBSYSTEM=="i2c-dev", GROUP="i2c", MODE="0660"
KERNEL=="i2c-[0-9]*", GROUP="i2c", MODE="0660"
EOF
        udevadm control --reload-rules
        udevadm trigger
    fi

    echo ":: Setting up groups..."
    getent group i2c > /dev/null || groupadd i2c
    getent group plugdev > /dev/null || groupadd plugdev

    if [ -n "$SUDO_USER" ]; then
        if ! groups "$SUDO_USER" | grep -q '\bi2c\b'; then
            usermod -aG i2c,plugdev "$SUDO_USER"
            NEEDS_REGROUP=1
        fi
    fi

    if [ -n "$SUDO_USER" ]; then
        echo ":: Setting up OpenRGB configuration..."
        mkdir -p "/home/$SUDO_USER/.config/OpenRGB/"{logs,profiles}
        cat > "/home/$SUDO_USER/.config/OpenRGB/profiles/default.orp" << EOF
{
    "version": 3,
    "controllers": []
}
EOF
        chown -R "$SUDO_USER:$SUDO_USER" "/home/$SUDO_USER/.config/OpenRGB"
    fi

    SERVICE_FILE="/etc/systemd/system/openrgb.service"
    if [ ! -f "$SERVICE_FILE" ] || ! grep -q "ExecStart.*$COLOR" "$SERVICE_FILE"; then
        echo ":: Creating/Updating systemd service..."
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=OpenRGB LED Control
After=multi-user.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
Environment="DISPLAY=:0"
ExecStartPre=/bin/sleep 10
# First detect devices
ExecStart=/bin/bash -c '/usr/bin/openrgb --noautoconnect -l > /dev/null 2>&1'
# RAM sticks (ENE DRAM) - Static mode
ExecStart=/bin/bash -c '/usr/bin/openrgb --noautoconnect -d "ENE DRAM" -m Static -c $COLOR'
# CPU Cooler - Set all zones at once
ExecStart=/bin/bash -c '/usr/bin/openrgb --noautoconnect -d "AMD Wraith Prism" -m Direct -c $COLOR'
# Motherboard (ASRock) - Static mode
ExecStart=/bin/bash -c '/usr/bin/openrgb --noautoconnect -d "ASRock" -m Static -c $COLOR'

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable openrgb.service
    fi
}

scan_nvme() {
    echo ":: Scanning for XPG NVMe drive..."
    for i in $(seq 0 11); do
        if [ -e "/dev/i2c-$i" ]; then
            echo ":: Scanning bus i2c-$i..."
            i2cdetect -y $i 2>/dev/null
        fi
    done
}

set_colors() {
    local color=$1
    
    echo ":: Stopping any running OpenRGB processes..."
    killall openrgb 2>/dev/null || true
    sleep 2

    chmod 666 /dev/hidraw* 2>/dev/null || true
    chmod 660 /dev/i2c* 2>/dev/null || true

    echo ":: Setting all devices to color #$color..."
    
    openrgb --noautoconnect -l > /dev/null 2>&1
    sleep 1

    for i in {1..3}; do
        if openrgb --noautoconnect -d "ENE DRAM" -m Static -c "$color" 2>/dev/null && \
           openrgb --noautoconnect -d "AMD Wraith Prism" -m Direct -c "$color" 2>/dev/null && \
           openrgb --noautoconnect -d "ASRock" -m Static -c "$color" 2>/dev/null; then
            echo ":: Colors set successfully!"
            return 0
        fi
        echo ":: Attempt $i failed, retrying..."
        sleep 1
    done
    echo ":: Warning: Some devices may not have been set correctly."
}

setup_initial_config

scan_nvme 2>/dev/null

set_colors "$COLOR"

if [ "$NEEDS_REBOOT" = "1" ]; then
    echo ":: IMPORTANT: System needs to reboot for kernel parameter changes to take effect."
    echo ":: Would you like to reboot now? [y/N] "
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        reboot
    fi
elif [ "$NEEDS_REGROUP" = "1" ]; then
    echo ":: IMPORTANT: You need to log out and back in for group changes to take effect."
fi