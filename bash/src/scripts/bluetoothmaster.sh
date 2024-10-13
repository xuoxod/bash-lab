#!/bin/bash

# --- Constants ---
readonly EXIT_PROG=0
readonly ROOT_UID=0
readonly NON_ROOT=121
readonly EXIT_UNKNOWN_USER=120
readonly EXIT_UNKNOWN_GROUP=119

# --- Color definitions for a dark background ---
readonly COLOR_RESET="\033[0m"
readonly COLOR_BOLD="\033[1m"
readonly COLOR_GREEN="\033[0;32m"
readonly COLOR_ORANGE="\033[0;33m"
readonly COLOR_BLUE="\033[0;34m"
readonly COLOR_WHITE="\033[1;37m"
readonly COLOR_LIGHT_GOLD="\033[1;33m"   # A softer, more elegant yellow
readonly COLOR_PALE_YELLOW="\033[1;93m"  # Even lighter, almost cream
readonly COLOR_SOFT_AQUA="\033[0;96m"    # A cool aqua that complements yellows
readonly COLOR_LIGHT_GRAY="\033[0;37m"   # A light gray, close to white
readonly COLOR_LIGHT_PURPLE="\033[1;35m" # A bright, but not harsh, purple
readonly COLOR_RED="\033[0;31m"          # For errors

# --- Global Variables ---
declare -A discovered_devices   # Associative array to store discovered devices
declare -i device_color_index=0 # Index to cycle through device colors
declare -i scan_process_pid=0   # Process ID of the background scan process

# --- Functions ---

# Function to display an error message and exit
error_exit() {
    echo -e "${COLOR_RED}Error:${COLOR_RESET} $1" >&2
    exit 1
}

# Function to check for root privileges (if needed)
check_privileges() {
    if [[ $EUID -ne $ROOT_UID ]]; then
        error_exit "This script requires root privileges. Please run with sudo."
    fi
}

# Function to scan for Bluetooth devices in the background
scan_devices_background() {
    while true; do
        # Use a longer scan duration for more reliable discovery
        bluetoothctl --timeout 5 scan on >/dev/null 2>&1
        sleep 2
        bluetoothctl --timeout 1 scan off >/dev/null 2>&1
        sleep 3
    done
}

# Function to process Bluetooth events and update discovered devices
process_bluetooth_events() {
    while read -r line; do
        if [[ $line =~ Device\ ([0-9A-F:]+)\ (.+) ]]; then
            mac_address="${BASH_REMATCH[1]}"
            device_name="${BASH_REMATCH[2]}"
            discovered_devices[$mac_address]="$device_name"
        fi
    done < <(bluetoothctl monitor 2>&1)
}

# Function to display discovered devices with color and spacing
display_discovered_devices() {
    clear
    echo -e "${COLOR_BLUE}Discovered Bluetooth Devices:${COLOR_RESET}"
    echo

    local -i i=0
    if [[ ${#discovered_devices[@]} -eq 0 ]]; then
        echo "  ${COLOR_ORANGE}No devices found. Make sure Bluetooth is enabled and devices are discoverable.${COLOR_RESET}"
    else
        for mac_address in "${!discovered_devices[@]}"; do
            device_name="${discovered_devices[$mac_address]}"

            # Cycle through colors
            case $((i % 4)) in
            0) color="$COLOR_LIGHT_GOLD" ;;
            1) color="$COLOR_SOFT_AQUA" ;;
            2) color="$COLOR_LIGHT_GRAY" ;;
            3) color="$COLOR_LIGHT_PURPLE" ;;
            esac

            printf "  ${color}%-22s ${COLOR_WHITE}%-40s${COLOR_RESET}\n" \
                "$mac_address" "$device_name"
            i=$((i + 1))
        done
    fi

    echo
}

# Function to list paired devices with error handling
list_paired_devices() {
    echo -e "${COLOR_GREEN}Paired Bluetooth devices:${COLOR_RESET}"
    paired_devices=$(bluetoothctl paired-devices 2>&1)
    if [[ $? -ne 0 ]]; then
        echo "  ${COLOR_RED}Error listing paired devices. Is Bluetooth enabled?${COLOR_RESET}"
    elif [[ -z "$paired_devices" ]]; then
        echo "  No paired devices found."
    else
        echo "$paired_devices" | sed 's/^/  /' # Add spacing
    fi
    echo
}

# ... (Rest of the functions: connect_device, disconnect_device,
#      trust_device, pair_device, remove_device, device_info remain the same)

# --- Main Script Logic ---

# Check for root privileges (if needed)
# check_privileges # Uncomment if root is required

# Start background Bluetooth scanning and event processing
scan_devices_background &
scan_process_pid=$! # Store the process ID
process_bluetooth_events &

# Main loop
while true; do
    # Display discovered devices
    display_discovered_devices

    # Display a message indicating that the background scan is active
    echo -e "${COLOR_LIGHT_GRAY}Scanning in background (PID: $scan_process_pid). Press Ctrl+C to stop.${COLOR_RESET}"

    # Interactive menu
    echo -e "${COLOR_BLUE}Bluetooth Menu:${COLOR_RESET}"
    echo "1. List paired devices"
    echo "2. Connect to a device"
    echo "3. Disconnect from a device"
    echo "4. Trust a device"
    echo "5. Pair with a device"
    echo "6. Remove a device"
    echo "7. Device Info"
    echo "8. Exit"
    read -p "Enter your choice: " choice

    case $choice in
    1) list_paired_devices ;;
    2) connect_device ;;
    3) disconnect_device ;;
    4) trust_device ;;
    5) pair_device ;;
    6) remove_device ;;
    7) device_info ;;
    8)
        # Stop background processes before exiting
        kill "$scan_process_pid" 2>/dev/null # Suppress error if process doesn't exist
        pkill -f "bluetoothctl monitor" 2>/dev/null
        exit 0
        ;;
    *) echo "Invalid choice." ;;
    esac

    sleep 2 # Adjust refresh rate as needed
done
