#!/bin/bash

echo "=== Kernel I2C Module Status ==="
lsmod | grep -E "i2c|piix|mp2|ryzen"

echo -e "\n=== Available I2C Buses ==="
i2cdetect -l

echo -e "\n=== Scanning Each I2C Bus ==="
for i in $(seq 0 9); do
    if [ -e "/dev/i2c-$i" ]; then
        echo -e "\nScanning bus i2c-$i:"
        i2cdetect -y $i
    fi
done

echo -e "\n=== OpenRGB Device List ==="
openrgb --noautoconnect -l

echo -e "\n=== System Information ==="
echo "Kernel: $(uname -r)"
echo "Motherboard: $(dmidecode -t baseboard 2>/dev/null | grep -i 'Product Name' | cut -d: -f2- || echo 'Unknown')"
echo "CPU: $(lscpu | grep 'Model name' | cut -d: -f2- || echo 'Unknown')"

echo -e "\n=== PCI Devices ==="
lspci | grep -i 'smbus\|i2c' 