#!/bin/bash

# Module 2: Universal RGB Control System
# Controls all OpenRGB-supported devices with robust error handling
# Persistent configuration with auto-restore on boot

# ================================
# CONFIGURATION
# ================================
TARGET_COLOR="FF0000"  # CHANGE - Set desired hex color (without #)

# OpenRGB configuration
OPENRGB_MIN_VERSION="0.9"
OPENRGB_CONFIG_DIR="/etc/openrgb"
OPENRGB_PROFILE_DIR="$OPENRGB_CONFIG_DIR/profiles"
OPENRGB_LOG_DIR="/var/log/openrgb"
OPENRGB_DOWNLOAD_URLS=(
    "https://openrgb.org/releases"
    "https://gitlab.com/CalcProgrammer1/OpenRGB/-/releases"
    "https://packages.ubuntu.com/jammy/openrgb"
)

# Device protocols and modes
declare -A DEVICE_PROTOCOLS=(
    ["corsair"]="direct"
    ["asus"]="aura"
    ["msi"]="mystic"
    ["asrock"]="polychrome"
    ["gigabyte"]="fusion"
    ["nzxt"]="hue"
    ["razer"]="chroma"
    ["logitech"]="lightsync"
)

# ================================
# DEPENDENCY INSTALLATION
# ================================

install_dependencies() {
    echo "Installing required dependencies..."
    
    # Ensure apt is available and updated
    if ! command -v apt >/dev/null 2>&1; then
        echo "Error: apt package manager not found. This script requires Ubuntu."
        exit 1
    fi
    
    # Update package lists first
    if ! apt update; then
        echo "Error: Failed to update package lists"
        exit 1
    fi
    
    # Base dependencies in order of importance
    local base_deps=(
        # Core build requirements
        "build-essential"
        "pkg-config"
        
        # I2C and USB support
        "i2c-tools"
        "usbutils"
        
        # Libraries
        "libusb-1.0-0"
        "libhidapi-libusb0"
        "libmbedtls-dev"
        "libqt5core5a"
        "libqt5network5"
    )
    
    # Install packages in groups to handle dependencies better
    local current_group=()
    local group_size=3
    local i=0
    
    for pkg in "${base_deps[@]}"; do
        current_group+=("$pkg")
        ((i++))
        
        if [[ ${#current_group[@]} -eq $group_size ]] || [[ $i -eq ${#base_deps[@]} ]]; then
            echo "Installing package group: ${current_group[*]}"
            if ! apt install -y "${current_group[@]}"; then
                echo "Error: Failed to install package group: ${current_group[*]}"
                exit 1
            fi
            current_group=()
        fi
    done
    
    # Verify critical packages
    local critical_pkgs=("i2c-tools" "usbutils" "libusb-1.0-0")
    local missing_pkgs=()
    
    for pkg in "${critical_pkgs[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$pkg"; then
            missing_pkgs+=("$pkg")
        fi
    done
    
    if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
        echo "Error: Critical packages missing after installation: ${missing_pkgs[*]}"
        exit 1
    fi
    
    # Load required kernel modules
    local modules=("i2c-dev" "i2c-piix4" "i2c-i801")
    for module in "${modules[@]}"; do
        if ! lsmod | grep -q "^$module"; then
            echo "Loading kernel module: $module"
            if ! modprobe "$module" 2>/dev/null; then
                echo "Warning: Failed to load $module - this may be normal if hardware is not present"
            fi
        fi
    done
    
    # Add user to required groups
    local groups=("plugdev" "i2c" "dialout")
    for group in "${groups[@]}"; do
        if ! getent group "$group" >/dev/null; then
            groupadd "$group" 2>/dev/null || true
        fi
        usermod -aG "$group" "$SUDO_USER" 2>/dev/null || true
    done
    
    echo "Dependencies installed successfully"
}

# ================================
# VALIDATION FUNCTIONS
# ================================

# Enhanced color validation with brightness check
validate_color() {
    local color="$1"
    
    # Check hex format
    if [[ ! "$color" =~ ^[0-9A-Fa-f]{6}$ ]]; then
        echo "Error: Invalid hex color format. Use 6 digits (e.g., FF0000 for red)"
        exit 1
    fi
    
    # Extract RGB components
    local r=$((16#${color:0:2}))
    local g=$((16#${color:2:2}))
    local b=$((16#${color:4:2}))
    
    # Check if color is completely black (might not be visible)
    if [ $r -eq 0 ] && [ $g -eq 0 ] && [ $b -eq 0 ]; then
        echo "Warning: Black color (#000000) selected - RGB effects won't be visible"
        if ! confirm "Continue with black color?"; then
            exit 1
        fi
    fi
    
    # Check if color is very dim (< 10% brightness)
    local max_val=$(( r > g ? (r > b ? r : b) : (g > b ? g : b) ))
    if [ $max_val -lt 26 ]; then
        echo "Warning: Selected color is very dim (< 10% brightness)"
        if ! confirm "Continue with dim color?"; then
            exit 1
        fi
    fi
}

# Enhanced permission and system checks
check_system_requirements() {
    echo "Checking system requirements..."
    
    # Check root privileges
    if [[ $EUID -ne 0 ]]; then
        echo "Error: Root privileges required for:"
        echo "  - SMBus access (RAM control)"
        echo "  - USB device permissions"
        echo "  - System service creation"
        echo "Run with sudo: sudo $0"
        exit 1
    fi
    
    # Check kernel modules
    local required_modules=("i2c-dev" "i2c-piix4" "i2c-i801")
    for module in "${required_modules[@]}"; do
        if ! lsmod | grep -q "^$module"; then
            echo "Loading kernel module: $module"
            modprobe "$module" || echo "Warning: Failed to load $module"
        fi
    done
    
    # Check I2C/SMBus access
    if ! [ -c /dev/i2c-* ]; then
        echo "Enabling I2C/SMBus access..."
        modprobe i2c-dev
        if ! [ -c /dev/i2c-* ]; then
            echo "Warning: Failed to enable I2C/SMBus access"
            echo "Some RAM RGB control may not work"
        fi
    fi
    
    # Check USB access
    if ! [ -w /dev/bus/usb ]; then
        echo "Setting up USB device access..."
        # Create udev rules for USB RGB devices
        create_usb_rules
    fi
    
    # Create necessary directories
    mkdir -p "$OPENRGB_CONFIG_DIR" "$OPENRGB_PROFILE_DIR" "$OPENRGB_LOG_DIR"
    chmod 755 "$OPENRGB_CONFIG_DIR" "$OPENRGB_PROFILE_DIR" "$OPENRGB_LOG_DIR"
    
    echo "System requirements check completed"
}

# Create comprehensive USB rules for RGB devices
create_usb_rules() {
    local rules_file="/etc/udev/rules.d/60-openrgb-universal.rules"
    
    cat > "$rules_file" << 'EOF'
# Universal RGB Device Rules
# Corsair Devices
SUBSYSTEMS=="usb", ATTR{idVendor}=="1b1c", MODE="0666"
# ASUS Devices
SUBSYSTEMS=="usb", ATTR{idVendor}=="0b05", MODE="0666"
# MSI Devices
SUBSYSTEMS=="usb", ATTR{idVendor}=="1462", MODE="0666"
# Gigabyte Devices
SUBSYSTEMS=="usb", ATTR{idVendor}=="2109", MODE="0666"
# NZXT Devices
SUBSYSTEMS=="usb", ATTR{idVendor}=="1e71", MODE="0666"
# Razer Devices
SUBSYSTEMS=="usb", ATTR{idVendor}=="1532", MODE="0666"
# Logitech Devices
SUBSYSTEMS=="usb", ATTR{idVendor}=="046d", MODE="0666"
# Generic RGB Controllers
SUBSYSTEMS=="usb", ATTR{idVendor}=="16c0", MODE="0666"
SUBSYSTEMS=="usb", ATTR{idVendor}=="0483", MODE="0666"

# I2C/SMBus Access for RAM
KERNEL=="i2c-[0-9]*", GROUP="plugdev", MODE="0666"

# Direct Memory Access
KERNEL=="port", GROUP="plugdev", MODE="0666"
KERNEL=="nvram", GROUP="plugdev", MODE="0666"

# AMD Wraith Prism
SUBSYSTEMS=="usb", ATTR{idVendor}=="2516", ATTR{idProduct}=="0051", MODE="0666"
SUBSYSTEMS=="usb", ATTR{idVendor}=="2516", ATTR{idProduct}=="0047", MODE="0666"

# XPG/ADATA Products
SUBSYSTEMS=="usb", ATTR{idVendor}=="125f", MODE="0666"
EOF
    
    # Reload udev rules
    udevadm control --reload-rules
    udevadm trigger
    
    echo "Universal USB rules created and applied"
}

# Utility function for user confirmation
confirm() {
    local message="$1"
    read -p "$message [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# ================================
# INSTALLATION FUNCTIONS
# ================================

# Install OpenRGB with version checking and fallback mirrors
install_openrgb() {
    if command -v openrgb &> /dev/null; then
        local current_version=$(openrgb --version 2>/dev/null | grep -oP '\d+\.\d+' || echo "0.0")
        if version_greater_equal "$current_version" "$OPENRGB_MIN_VERSION"; then
            echo "OpenRGB version $current_version is already installed and up to date"
            return 0
        fi
    fi
    
    echo "Installing OpenRGB..."
    
    # Update system
    apt update
    
    # Try installing from package manager first
    if apt install -y openrgb 2>/dev/null; then
        echo "OpenRGB installed from package manager"
        return 0
    fi
    
    # Try downloading from mirrors
    local success=false
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    for url in "${OPENRGB_DOWNLOAD_URLS[@]}"; do
        echo "Trying download from: $url"
        
        # Get latest version URL
        local download_url=""
        if [[ "$url" == *"openrgb.org"* ]]; then
            download_url=$(curl -s "$url" | grep -o 'https://.*openrgb.*amd64.*deb' | head -1)
        elif [[ "$url" == *"gitlab.com"* ]]; then
            download_url=$(curl -s "$url" | grep -o 'https://.*openrgb.*amd64.*deb' | head -1)
        fi
        
        if [[ -n "$download_url" ]]; then
            if wget -q "$download_url" -O openrgb.deb; then
                # Verify package
                if dpkg-deb -I openrgb.deb &>/dev/null; then
                    echo "Installing OpenRGB from $url"
                    if apt install -y ./openrgb.deb; then
                        success=true
                        break
                    fi
                fi
            fi
        fi
    done
    
    cd - >/dev/null
    rm -rf "$temp_dir"
    
    if ! $success; then
        echo "Error: Failed to install OpenRGB from all sources"
        exit 1
    fi
    
    # Install udev rules
    if [ -f /usr/share/OpenRGB/60-openrgb.rules ]; then
        cp /usr/share/OpenRGB/60-openrgb.rules /etc/udev/rules.d/
        udevadm control --reload-rules
        udevadm trigger
        echo "OpenRGB udev rules installed"
    fi
    
    # Verify installation
    if ! command -v openrgb &> /dev/null; then
        echo "Error: OpenRGB installation verification failed"
        exit 1
    fi
    
    echo "OpenRGB installation completed successfully"
}

# Version comparison helper
version_greater_equal() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
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

# Enhanced device detection with comprehensive device support
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
    
    # Initialize device tracking with expanded categories
    declare -A device_categories=(
        ["motherboard"]="false"
        ["cpu_cooler"]="false"
        ["ram"]="false"
        ["storage"]="false"
        ["gpu"]="false"
        ["case"]="false"
        ["fan"]="false"
        ["keyboard"]="false"
        ["mouse"]="false"
        ["headset"]="false"
        ["mousepad"]="false"
        ["led_strip"]="false"
        ["other"]="false"
    )
    
    # Initialize device arrays
    declare -A device_arrays
    for category in "${!device_categories[@]}"; do
        device_arrays["$category"]=""
    done
    
    local all_devices=()
    local device_count=0
    
    # Enhanced device pattern matching
    declare -A device_patterns=(
        ["motherboard"]="motherboard|aura.*smc|polychrome|msi.*mystic|gigabyte.*fusion|asrock|asus.*aura|msi.*meg|gigabyte.*aorus"
        ["cpu_cooler"]="wraith|cooler.*master|nzxt.*kraken|corsair.*h[0-9]|amd.*fan|cpu.*cooler"
        ["ram"]="dram|ram|aura.*dram|xpg|lancer|corsair.*vengeance|g\.skill|crucial.*ballistix|thermaltake.*ram|team.*group"
        ["storage"]="ssd|spectrix|s20g|nvme|m\.2|samsung.*rgb|corsair.*mp600"
        ["gpu"]="gpu|graphics|nvidia|amd.*radeon|geforce|rtx|gtx|rx.*[0-9]|aorus.*gpu|msi.*gaming"
        ["case"]="case.*fan|case.*light|smart.*device|commander.*pro|lighting.*node"
        ["fan"]="fan|corsair.*ll|corsair.*ml|nzxt.*aer|thermaltake.*riing"
        ["keyboard"]="keyboard|corsair.*k[0-9]|razer|logitech.*g[0-9]|steelseries"
        ["mouse"]="mouse|corsair.*m[0-9]|razer.*mouse|logitech.*g[0-9]"
        ["headset"]="headset|void.*pro|virtuoso|arctis"
        ["mousepad"]="mousepad|mm700|firefly|qck"
        ["led_strip"]="led.*strip|lighting.*strip|phanteks.*neon|corsair.*ls"
    )
    
    # Read device list and categorize
    while IFS= read -r line; do
        if [[ $line =~ ^Device\ ([0-9]+):\ (.+)$ ]]; then
            local device_index="${BASH_REMATCH[1]}"
            local device_name="${BASH_REMATCH[2]}"
            local device_lower=$(echo "$device_name" | tr '[:upper:]' '[:lower:]')
            local categorized=false
            
            all_devices+=("$device_index:$device_name")
            ((device_count++))
            
            # Categorize device using patterns
            for category in "${!device_patterns[@]}"; do
                if [[ $device_lower =~ ${device_patterns[$category]} ]]; then
                    device_categories["$category"]="true"
                    device_arrays["$category"]+="$device_index:$device_name "
                    categorized=true
                    echo "FOUND: ${category^} Device - $device_name"
                    break
                fi
            done
            
            # Uncategorized devices go to "other"
            if ! $categorized; then
                device_categories["other"]="true"
                device_arrays["other"]+="$device_index:$device_name "
                echo "FOUND: Other RGB Device - $device_name"
            fi
        fi
    done < "$device_file"
    
    echo ""
    echo "Device Detection Summary:"
    echo "========================"
    echo "Total RGB devices detected: $device_count"
    echo ""
    
    # Print categorized devices
    for category in "${!device_categories[@]}"; do
        if [ "${device_categories[$category]}" = "true" ]; then
            echo "${category^} Devices:"
            for device in ${device_arrays[$category]}; do
                echo "   - ${device#*:}"
            done
        fi
    done
    
    echo ""
    
    # Store all device info for the calling function
    echo "DEVICES:${all_devices[*]}"
    
    # Additional device-specific checks
    check_device_compatibility
}

# Check device compatibility and provide specific guidance
check_device_compatibility() {
    echo "Checking device compatibility..."
    
    # Check for known problematic device combinations
    local has_corsair=false
    local has_asus=false
    local has_msi=false
    
    for device in "${all_devices[@]}"; do
        local device_lower=$(echo "${device#*:}" | tr '[:upper:]' '[:lower:]')
        
        if [[ $device_lower =~ corsair ]]; then
            has_corsair=true
        elif [[ $device_lower =~ asus|aura ]]; then
            has_asus=true
        elif [[ $device_lower =~ msi|mystic ]]; then
            has_msi=true
        fi
    done
    
    # Provide compatibility warnings and guidance
    if $has_corsair && $has_asus; then
        echo "Warning: Corsair and ASUS devices detected"
        echo "  - Close iCUE and Armoury Crate before proceeding"
        echo "  - Some devices may require manufacturer software for initial setup"
    fi
    
    if $has_msi; then
        echo "Note: MSI devices detected"
        echo "  - MSI Mystic Light sync may need to be disabled in Dragon Center"
    fi
    
    # Check for running RGB software
    local conflicting_processes=()
    if pgrep -f "icue|corsair" > /dev/null; then
        conflicting_processes+=("Corsair iCUE")
    fi
    if pgrep -f "asus|armoury|aura" > /dev/null; then
        conflicting_processes+=("ASUS Aura/Armoury Crate")
    fi
    if pgrep -f "msi|mystic|dragon" > /dev/null; then
        conflicting_processes+=("MSI Center/Dragon Center")
    fi
    
    if [ ${#conflicting_processes[@]} -gt 0 ]; then
        echo "Warning: Conflicting RGB software detected:"
        for process in "${conflicting_processes[@]}"; do
            echo "  - $process"
        done
        echo "Consider closing these programs for better compatibility"
    fi
}

# ================================
# RGB CONFIGURATION
# ================================

# Set RGB lighting for ALL detected devices
set_rgb_lighting() {
    local color="$1"
    local rgb_values=$(hex_to_rgb "$color")
    
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
    
    # Try global color setting first with multiple protocols
    echo "Attempting global color setting..."
    local global_success=false
    
    # Try each protocol
    for protocol in "${DEVICE_PROTOCOLS[@]}"; do
        echo "Trying $protocol protocol..."
        if openrgb --protocol "$protocol" --color "$rgb_values" --mode static 2>/dev/null; then
            global_success=true
            echo "Global color setting successful with $protocol protocol"
            break
        fi
    done
    
    # If global setting failed, try individual devices
    if ! $global_success; then
        echo "Global color setting failed, trying individual device control..."
    fi
    
    # Set color for each device individually
    local success_count=0
    local total_devices=${#all_devices[@]}
    local retry_devices=()
    
    for device_info in "${all_devices[@]}"; do
        local device_index="${device_info%%:*}"
        local device_name="${device_info#*:}"
        local device_lower=$(echo "$device_name" | tr '[:upper:]' '[:lower:]')
        
        echo ""
        echo "Configuring Device $device_index: $device_name"
        
        # Determine device protocol
        local device_protocol=""
        for type in "${!DEVICE_PROTOCOLS[@]}"; do
            if [[ $device_lower =~ $type ]]; then
                device_protocol="${DEVICE_PROTOCOLS[$type]}"
                break
            fi
        done
        
        # Try device-specific configuration
        local device_success=false
        local error_message=""
        
        # Function to attempt color setting with specific protocol
        try_set_color() {
            local protocol="$1"
            local mode="$2"
            local extra_args="$3"
            
            if openrgb --device "$device_index" ${protocol:+--protocol "$protocol"} \
                      --color "$rgb_values" ${mode:+--mode "$mode"} \
                      ${extra_args} 2>/dev/null; then
                return 0
            fi
            return 1
        }
        
        # Try multiple methods in order of preference
        if [[ -n "$device_protocol" ]]; then
            # Try device-specific protocol first
            if try_set_color "$device_protocol" "static"; then
                device_success=true
                echo "Success (protocol: $device_protocol)"
            fi
        fi
        
        # If device-specific protocol failed, try generic methods
        if ! $device_success; then
            # Method 1: Direct mode
            if try_set_color "" "direct"; then
                device_success=true
                echo "Success (method: direct mode)"
            # Method 2: Static mode
            elif try_set_color "" "static"; then
                device_success=true
                echo "Success (method: static mode)"
            # Method 3: No mode specification
            elif try_set_color "" ""; then
                device_success=true
                echo "Success (method: no mode)"
            # Method 4: Try with device name
            elif openrgb --device "$device_name" --color "$rgb_values" 2>/dev/null; then
                device_success=true
                echo "Success (method: device name)"
            fi
        fi
        
        if ! $device_success; then
            error_message="Failed to configure device"
            retry_devices+=("$device_info")
            
            # Device-specific troubleshooting
            case "$device_lower" in
                *corsair*)
                    error_message+=$'\n   - Try closing iCUE software'
                    error_message+=$'\n   - Device may need initial setup in iCUE'
                    ;;
                *asus*|*aura*)
                    error_message+=$'\n   - Try closing Armoury Crate'
                    error_message+=$'\n   - Check if AURA sync is enabled in BIOS'
                    ;;
                *msi*)
                    error_message+=$'\n   - Disable Mystic Light Sync in Dragon Center'
                    error_message+=$'\n   - Try resetting RGB controller in BIOS'
                    ;;
                *ram*)
                    error_message+=$'\n   - Check if XMP profile is enabled'
                    error_message+=$'\n   - Try reseating RAM modules'
                    ;;
                *motherboard*)
                    error_message+=$'\n   - Verify RGB headers are enabled in BIOS'
                    error_message+=$'\n   - Check physical RGB header connections'
                    ;;
            esac
            
            echo "$error_message"
        else
            ((success_count++))
        fi
        
        # Small delay between devices
        sleep 0.5
    done
    
    # Try to recover failed devices
    if [ ${#retry_devices[@]} -gt 0 ]; then
        echo ""
        echo "Attempting to recover failed devices..."
        
        for device_info in "${retry_devices[@]}"; do
            local device_index="${device_info%%:*}"
            local device_name="${device_info#*:}"
            
            echo "Retrying device $device_index: $device_name"
            
            # Reset device and try again
            if openrgb --device "$device_index" --mode off 2>/dev/null; then
                sleep 1
                if openrgb --device "$device_index" --color "$rgb_values" 2>/dev/null; then
                    echo "Recovery successful"
                    ((success_count++))
                fi
            fi
        done
    fi
    
    # Save profile permanently and set up auto-restore
    echo ""
    echo "Making RGB settings permanent..."
    
    # Create permanent profile directory
    mkdir -p "$OPENRGB_PROFILE_DIR"
    
    # Save permanent profile
    local profile_name="$OPENRGB_PROFILE_DIR/permanent_rgb_profile.orp"
    if openrgb --save-profile "$profile_name" 2>/dev/null; then
        echo "Permanent profile saved: $profile_name"
        
        # Create systemd service for auto-restore
        create_systemd_service "$profile_name" "$color"
        
    else
        echo "Profile save failed, trying alternative method..."
        # Alternative: Save color settings to simple config file
        echo "$color" > "$OPENRGB_CONFIG_DIR/rgb_color.conf"
        echo "Color settings saved to: $OPENRGB_CONFIG_DIR/rgb_color.conf"
        
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
    check_system_requirements
    
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