#!/bin/bash

# Module 2: RGB Control System
# Universal RGB device controller for all OpenRGB-supported hardware
# Persistent configuration with auto-restore on boot

# ================================
# CONFIGURATION
# ================================
TARGET_COLOR="FF0000"  # CHANGE - Set desired hex color (without #)

# ================================
# VALIDATION FUNCTIONS
# ================================

# Color validation function
validate_color() {
    if [[ ! "$1" =~ ^[0-9A-Fa-f]{6}$ ]]; then
        echo "Error: Invalid hex color format. Use 6 digits (e.g., FF0000 for red)"
        exit 1
    fi
}

# Check if running as root for SMBus access
check_permissions() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: Root privileges required for SMBus access (RAM control)"
        echo "Run with sudo: sudo $0"
        exit 1
    fi
}

# ================================
# INSTALLATION FUNCTIONS
# ================================

# Install OpenRGB if not present
install_openrgb() {
    if ! command -v openrgb &> /dev/null; then
        echo "OpenRGB not found. Installing..."
        
        # Update system
        apt update
        
        # Download and install OpenRGB for Ubuntu 24.04
        cd /tmp
        wget -q https://openrgb.org/releases/release_0.9/openrgb_0.9_amd64_bookworm_b5f46e3.deb
        
        if [ $? -eq 0 ]; then
            echo "Installing OpenRGB..."
            apt install -y ./openrgb_0.9_amd64_bookworm_b5f46e3.deb
            
            # Install udev rules for proper device access
            if [ -f /usr/share/OpenRGB/60-openrgb.rules ]; then
                cp /usr/share/OpenRGB/60-openrgb.rules /etc/udev/rules.d/
                udevadm control --reload-rules
                udevadm trigger
                echo "udev rules installed for device access"
            fi
        else
            echo "Error: Failed to download OpenRGB package"
            exit 1
        fi
    else
        echo "OpenRGB is already installed"
    fi
}

# ================================
# UTILITY FUNCTIONS
# ================================

# Convert hex to RGB values
hex_to_rgb() {
    local hex=$1
    local r=$((16#${hex:0:2}))
    local g=$((16#${hex:2:2}))
    local b=$((16#${hex:4:2}))
    echo "$r $g $b"
}

# ================================
# DEVICE DETECTION
# ================================

# Detect and classify all RGB devices
detect_devices() {
    echo "Scanning for RGB devices..."
    
    # Create temporary file for device list
    local device_file="/tmp/openrgb_devices.txt"
    openrgb --list-devices > "$device_file" 2>/dev/null
    
    echo "Device detection output:"
    echo "================================"
    cat "$device_file"
    echo "================================"
    echo ""
    
    # Initialize device tracking
    local found_motherboard=false
    local found_wraith=false
    local found_ram=false
    local found_ssd=false
    local found_gpu=false
    local found_other=false
    
    local motherboard_devices=()
    local wraith_devices=()
    local ram_devices=()
    local ssd_devices=()
    local gpu_devices=()
    local other_devices=()
    local all_devices=()
    
    # Parse all devices and categorize them
    echo "Categorizing detected RGB devices..."
    
    # Read device list line by line and extract device information
    local device_count=0
    while IFS= read -r line; do
        if [[ $line =~ ^Device\ ([0-9]+):\ (.+)$ ]]; then
            local device_index="${BASH_REMATCH[1]}"
            local device_name="${BASH_REMATCH[2]}"
            
            all_devices+=("$device_index:$device_name")
            device_count=$((device_count + 1))
            
            # Categorize devices based on name patterns
            local device_lower=$(echo "$device_name" | tr '[:upper:]' '[:lower:]')
            
            # Check for ASRock motherboard RGB
            if [[ $device_lower =~ asrock|polychrome|b650m|pg.*lightning ]]; then
                found_motherboard=true
                motherboard_devices+=("$device_index:$device_name")
                echo "FOUND: ASRock Motherboard RGB - $device_name"
            
            # Check for generic motherboard RGB controllers
            elif [[ $device_lower =~ motherboard|aura.*smc|polychrome|msi.*mystic|gigabyte.*fusion|asrock ]]; then
                found_motherboard=true
                motherboard_devices+=("$device_index:$device_name")
                echo "FOUND: Motherboard RGB Controller - $device_name"
            
            # Check for AMD Wraith coolers
            elif [[ $device_lower =~ wraith|amd.*cooler|amd.*fan ]]; then
                found_wraith=true
                wraith_devices+=("$device_index:$device_name")
                echo "FOUND: AMD Cooler - $device_name"
            
            # Check for RAM RGB
            elif [[ $device_lower =~ dram|ram|aura.*dram|xpg|lancer|corsair.*vengeance|g\.skill|crucial.*ballistix ]]; then
                found_ram=true
                ram_devices+=("$device_index:$device_name")
                echo "FOUND: RAM RGB - $device_name"
            
            # Check for SSD RGB
            elif [[ $device_lower =~ ssd|spectrix|s20g|nvme|m\.2 ]]; then
                found_ssd=true
                ssd_devices+=("$device_index:$device_name")
                echo "FOUND: SSD RGB - $device_name"
            
            # Check for GPU RGB
            elif [[ $device_lower =~ gpu|graphics|nvidia|amd.*radeon|geforce|rtx|gtx|rx.*[0-9] ]]; then
                found_gpu=true
                gpu_devices+=("$device_index:$device_name")
                echo "FOUND: GPU RGB - $device_name"
            
            # Everything else
            else
                found_other=true
                other_devices+=("$device_index:$device_name")
                echo "FOUND: Other RGB Device - $device_name"
            fi
        fi
    done < "$device_file"
    
    echo ""
    echo "Device Detection Summary:"
    echo "========================"
    echo "Total RGB devices detected: $device_count"
    echo ""
    echo "Device Categories:"
    echo "Motherboard RGB: $([ "$found_motherboard" = true ] && echo "${#motherboard_devices[@]} device(s)" || echo "Not Found")"
    if [ "$found_motherboard" = true ]; then
        for device in "${motherboard_devices[@]}"; do
            echo "   - ${device#*:}"
        done
    fi
    
    echo "CPU Cooler RGB: $([ "$found_wraith" = true ] && echo "${#wraith_devices[@]} device(s)" || echo "Not Found")"
    if [ "$found_wraith" = true ]; then
        for device in "${wraith_devices[@]}"; do
            echo "   - ${device#*:}"
        done
    fi
    
    echo "RAM RGB: $([ "$found_ram" = true ] && echo "${#ram_devices[@]} device(s)" || echo "Not Found")"
    if [ "$found_ram" = true ]; then
        for device in "${ram_devices[@]}"; do
            echo "   - ${device#*:}"
        done
    fi
    
    echo "SSD RGB: $([ "$found_ssd" = true ] && echo "${#ssd_devices[@]} device(s)" || echo "Not Found")"
    if [ "$found_ssd" = true ]; then
        for device in "${ssd_devices[@]}"; do
            echo "   - ${device#*:}"
        done
    fi
    
    echo "GPU RGB: $([ "$found_gpu" = true ] && echo "${#gpu_devices[@]} device(s)" || echo "Not Found")"
    if [ "$found_gpu" = true ]; then
        for device in "${gpu_devices[@]}"; do
            echo "   - ${device#*:}"
        done
    fi
    
    echo "Other RGB Devices: $([ "$found_other" = true ] && echo "${#other_devices[@]} device(s)" || echo "Not Found")"
    if [ "$found_other" = true ]; then
        for device in "${other_devices[@]}"; do
            echo "   - ${device#*:}"
        done
    fi
    
    echo ""
    
    # Store all device info in format the calling function can use
    echo "DEVICES:${all_devices[*]}"
}

# ================================
# RGB CONFIGURATION
# ================================

# Set RGB lighting for ALL detected devices
set_rgb_lighting() {
    local color=$1
    local rgb_values=$(hex_to_rgb $color)
    
    echo "Setting RGB lighting to color: #$color"
    echo "RGB values: $rgb_values"
    echo ""
    
    # Wait for devices to be ready
    sleep 2
    
    # Detect all devices
    local device_info=$(detect_devices)
    local devices_line=$(echo "$device_info" | grep "^DEVICES:")
    local all_devices_str="${devices_line#DEVICES:}"
    
    # Convert space-separated string back to array
    local all_devices=()
    if [ -n "$all_devices_str" ]; then
        IFS=' ' read -ra all_devices <<< "$all_devices_str"
    fi
    
    # Check if any devices were found
    if [ ${#all_devices[@]} -eq 0 ]; then
        echo "Error: No RGB devices found"
        echo "Troubleshooting:"
        echo "   - Ensure all devices are properly connected and powered"
        echo "   - For motherboard RGB: Enable RGB headers in BIOS"
        echo "   - For RAM: Close any other RGB software (Corsair iCUE, etc.)"
        echo "   - For coolers: Use USB connector, not just RGB header"
        echo "   - Try running: sudo openrgb --list-devices"
        return 1
    fi
    
    echo "Applying color to all detected devices..."
    echo "========================================"
    
    # First, try global color setting
    echo "Setting global color for all devices..."
    if openrgb --color $rgb_values --mode static 2>/dev/null; then
        echo "Global color setting successful"
    else
        echo "Global color setting failed, trying individual device control..."
    fi
    
    # Set color for each device individually
    local success_count=0
    local total_devices=${#all_devices[@]}
    
    for device_info in "${all_devices[@]}"; do
        local device_index="${device_info%%:*}"
        local device_name="${device_info#*:}"
        
        echo ""
        echo "Configuring Device $device_index: $device_name"
        
        # Try multiple methods to set device color
        local device_success=false
        
        # Method 1: By device index
        if openrgb --device "$device_index" --color $rgb_values --mode static 2>/dev/null; then
            echo "Success (method: device index)"
            device_success=true
        # Method 2: By device name
        elif openrgb --device "$device_name" --color $rgb_values --mode static 2>/dev/null; then
            echo "Success (method: device name)"
            device_success=true
        # Method 3: Try different modes
        elif openrgb --device "$device_index" --color $rgb_values --mode direct 2>/dev/null; then
            echo "Success (method: direct mode)"
            device_success=true
        # Method 4: Try without mode specification
        elif openrgb --device "$device_index" --color $rgb_values 2>/dev/null; then
            echo "Success (method: no mode)"
            device_success=true
        else
            echo "Failed to configure device"
            
            # Provide device-specific troubleshooting
            local device_lower=$(echo "$device_name" | tr '[:upper:]' '[:lower:]')
            if [[ $device_lower =~ asrock|motherboard|polychrome ]]; then
                echo "   Motherboard RGB: Check if RGB headers are enabled in BIOS"
                echo "   Try using ASRock Polychrome Sync software first, then this script"
            elif [[ $device_lower =~ dram|ram ]]; then
                echo "   RAM RGB: Ensure no other RGB software is running"
                echo "   Try reseating RAM modules or enabling XMP profile"
            elif [[ $device_lower =~ wraith|cooler ]]; then
                echo "   Cooler RGB: Ensure USB connector is used, not just RGB header"
            elif [[ $device_lower =~ ssd|nvme ]]; then
                echo "   SSD RGB: May require motherboard RGB software for control"
            fi
        fi
        
        if [ "$device_success" = true ]; then
            success_count=$((success_count + 1))
        fi
        
        # Small delay between devices
        sleep 0.5
    done
    
    # Save profile permanently and set up auto-restore
    echo ""
    echo "Making RGB settings permanent..."
    
    # Create permanent profile directory
    local profile_dir="/etc/openrgb"
    mkdir -p "$profile_dir"
    
    # Save permanent profile
    local profile_name="$profile_dir/permanent_rgb_profile.orp"
    if openrgb --save-profile "$profile_name" 2>/dev/null; then
        echo "Permanent profile saved: $profile_name"
        
        # Create systemd service for auto-restore on boot
        create_systemd_service "$profile_name" "$color"
        
    else
        echo "Profile save failed, trying alternative method..."
        # Alternative: Save color settings to simple config file
        echo "$color" > "$profile_dir/rgb_color.conf"
        echo "Color settings saved to: $profile_dir/rgb_color.conf"
        
        # Create systemd service with color-based restore
        create_systemd_service_fallback "$color"
    fi
    
    # Final status report
    echo ""
    echo "RGB Configuration Complete"
    echo "=========================="
    echo "Target Color: #$color"
    echo "Total devices detected: $total_devices"
    echo "Successfully configured: $success_count/$total_devices devices"
    echo ""
    
    if [ $success_count -eq $total_devices ]; then
        echo "ALL RGB devices configured successfully"
        echo "System is now displaying color #$color"
        echo "Settings are PERMANENT - will persist through reboots"
    elif [ $success_count -gt 0 ]; then
        echo "$success_count devices configured successfully"
        echo "$((total_devices - success_count)) devices may need manual attention"
        echo "Successfully configured devices will maintain their color permanently"
    else
        echo "No devices were successfully configured"
        echo "Run 'sudo openrgb --gui' to manually configure devices"
    fi
    
    # Clean up temporary files
    rm -f /tmp/openrgb_devices.txt
}

# ================================
# SYSTEM VALIDATION
# ================================

# Validate system prerequisites
validate_system() {
    echo "Validating system prerequisites..."
    
    # Check for required tools
    local missing_tools=()
    
    if ! command -v wget &> /dev/null; then
        missing_tools+=("wget")
    fi
    
    if ! command -v udevadm &> /dev/null; then
        missing_tools+=("udev")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo "Missing required tools: ${missing_tools[*]}"
        echo "Installing missing tools..."
        apt update && apt install -y "${missing_tools[@]}"
    fi
    
    # Check Ubuntu version
    local ubuntu_version=$(lsb_release -rs 2>/dev/null || echo "unknown")
    if [ "$ubuntu_version" != "unknown" ]; then
        echo "Ubuntu version: $ubuntu_version"
        if [[ "$ubuntu_version" < "22.04" ]]; then
            echo "Warning: This script is optimized for Ubuntu 22.04+. Different packages may be required."
        fi
    fi
    
    # Check if other RGB software is running
    local conflicting_processes=()
    if pgrep -f "icue\|corsair" > /dev/null; then
        conflicting_processes+=("Corsair iCUE")
    fi
    if pgrep -f "aura\|armoury" > /dev/null; then
        conflicting_processes+=("ASUS Aura/Armoury Crate")
    fi
    if pgrep -f "msi.*center\|mystic" > /dev/null; then
        conflicting_processes+=("MSI Center/Mystic Light")
    fi
    if pgrep -f "polychrome\|asrock" > /dev/null; then
        conflicting_processes+=("ASRock Polychrome Sync")
    fi
    
    if [ ${#conflicting_processes[@]} -gt 0 ]; then
        echo "Warning: Conflicting RGB software detected: ${conflicting_processes[*]}"
        echo "   Consider stopping these processes for better compatibility"
        echo "   Close all manufacturer RGB software before running this script"
    fi
    
    echo "System validation complete"
}

# ================================
# PERSISTENCE FUNCTIONS
# ================================

# Create systemd service for permanent RGB restoration
create_systemd_service() {
    local profile_path="$1"
    local color="$2"
    
    echo "Setting up automatic RGB restoration on boot..."
    
    # Create systemd service file
    cat > /etc/systemd/system/rgb-restore.service << EOF
[Unit]
Description=RGB Lighting Restoration Service
After=graphical-session.target
Wants=graphical-session.target

[Service]
Type=oneshot
ExecStart=/usr/bin/openrgb --load-profile $profile_path
ExecStartPost=/bin/sleep 2
ExecStartPost=/usr/bin/openrgb --color $(hex_to_rgb $color) --mode static
User=root
RemainAfterExit=yes
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start service
    systemctl daemon-reload
    systemctl enable rgb-restore.service
    
    echo "RGB auto-restore service created and enabled"
    echo "   RGB settings will be restored automatically on every boot"
}

# Fallback systemd service using color values
create_systemd_service_fallback() {
    local color="$1"
    local rgb_values=$(hex_to_rgb $color)
    
    echo "Setting up automatic RGB color restoration on boot (fallback method)..."
    
    # Create systemd service file with direct color application
    cat > /etc/systemd/system/rgb-restore.service << EOF
[Unit]
Description=RGB Lighting Restoration Service
After=graphical-session.target
Wants=graphical-session.target

[Service]
Type=oneshot
ExecStart=/usr/bin/openrgb --color $rgb_values --mode static
ExecStartPost=/bin/sleep 3
ExecStartPost=/usr/bin/openrgb --color $rgb_values --mode static
User=root
RemainAfterExit=yes
TimeoutStartSec=30
Restart=no

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start service
    systemctl daemon-reload
    systemctl enable rgb-restore.service
    
    echo "RGB auto-restore service created and enabled (color-based)"
    echo "   RGB color #$color will be restored automatically on every boot"
}

# ================================
# MAIN EXECUTION
# ================================

main() {
    echo "=== Universal RGB Control Script for Ubuntu 24.04 ==="
    echo "Compatible with: ALL OpenRGB-supported devices including:"
    echo "   ASRock B650M PG Lightning WiFi 6E Motherboard"
    echo "   AMD Wraith Prism CPU Cooler"
    echo "   XPG Lancer Blade RGB RAM"
    echo "   XPG SPECTRIX S20G M.2 SSD"
    echo "   GPU RGB (NVIDIA/AMD)"
    echo "   Any other OpenRGB-compatible RGB devices"
    echo ""
    echo "Target Color: #$TARGET_COLOR"
    echo ""
    
    # Validate color format
    validate_color $TARGET_COLOR
    
    # Check permissions
    check_permissions
    
    # Validate system
    validate_system
    
    # Install OpenRGB if needed
    install_openrgb
    
    # Set RGB lighting for ALL devices
    set_rgb_lighting $TARGET_COLOR
    
    echo ""
    echo "Script execution complete"
    echo "========================"
    echo "ALL RGB devices should now be displaying color: #$TARGET_COLOR"
    echo "RGB settings are now PERMANENT and will survive reboots"
    echo ""
    echo "To change colors in the future:"
    echo "   1. Edit the TARGET_COLOR variable at the top of this script"
    echo "   2. Run: sudo ./$(basename "$0")"
    echo "   3. New color will be applied and made permanent automatically"
    echo ""
    echo "RGB Persistence:"
    echo "   Colors will automatically restore on every boot"
    echo "   No need to run this script again unless changing colors"
    echo "   systemd service 'rgb-restore' handles auto-restoration"
    echo ""
    echo "If devices aren't working:"
    echo "   - Run: sudo openrgb --gui (for manual configuration)"
    echo "   - For motherboard RGB: Enable RGB headers in BIOS settings"
    echo "   - Close all manufacturer RGB software (iCUE, Aura, Polychrome, etc.)"
    echo "   - Check all connections and ensure devices are properly powered"
    echo "   - Check service status: sudo systemctl status rgb-restore"
    echo "=================================================="
}

# Handle script interruption
trap 'echo ""; echo "Script interrupted by user"; exit 1' INT

# Run main function
main "$@"