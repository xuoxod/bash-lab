#!/bin/bash

# Check if bluetoothctl is available
if ! command -v bluetoothctl &>/dev/null; then
    echo "Error: bluetoothctl command not found. Please install bluez."
    exit 1
fi

# Function to scan for Bluetooth devices
scan_devices() {
    echo "Scanning for Bluetooth devices..."
    bluetoothctl <<EOF
  power on
  scan on
EOF
    read -p "Press Enter to stop scanning..."
    bluetoothctl <<EOF
  scan off
EOF
}

# Function to list paired devices
list_paired_devices() {
    echo "Paired Bluetooth devices:"
    bluetoothctl <<EOF
  paired-devices
EOF
}

# Function to connect to a device
connect_device() {
    read -p "Enter the MAC address of the device to connect: " mac_address
    bluetoothctl <<EOF
  connect $mac_address
EOF
}

# Function to disconnect from a device
disconnect_device() {
    read -p "Enter the MAC address of the device to disconnect: " mac_address
    bluetoothctl <<EOF
  disconnect $mac_address
EOF
}

# Main menu
while true; do
    echo "Bluetooth Menu:"
    echo "1. Scan for devices"
    echo "2. List paired devices"
    echo "3. Connect to a device"
    echo "4. Disconnect from a device"
    echo "5. Exit"
    read -p "Enter your choice: " choice

    case $choice in
    1) scan_devices ;;
    2) list_paired_devices ;;
    3) connect_device ;;
    4) disconnect_device ;;
    5) exit 0 ;;
    *) echo "Invalid choice." ;;
    esac
done
