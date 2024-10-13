#!/bin/bash

# Function to display an error message and exit
error_exit() {
  echo -e "\033[31mError:\033[0m $1" >&2
  exit 1
}

# Check if bluetoothctl is available
if ! command -v bluetoothctl &>/dev/null; then
  error_exit "bluetoothctl command not found. Please install bluez."
fi

# Function to scan for Bluetooth devices
scan_devices() {
  echo -e "\033[32mScanning for Bluetooth devices...\033[0m"
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
  echo -e "\033[32mPaired Bluetooth devices:\033[0m"
  paired_devices=$(bluetoothctl paired-devices | awk '{print $2}')
  if [[ -z "$paired_devices" ]]; then
    echo "No paired devices found."
  else
    echo "$paired_devices"
  fi
}

# Function to connect to a device
connect_device() {
  read -p "Enter the MAC address of the device to connect: " mac_address
  if [[ ! "$mac_address" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
    error_exit "Invalid MAC address format."
  fi
  if ! bluetoothctl connect "$mac_address" &>/dev/null; then
    error_message=$(bluetoothctl connect "$mac_address" 2>&1)
    case "$error_message" in
    *"Device not available"*) error_exit "Device not available. Ensure it's powered on and in range." ;;
    *"Connection attempt failed"*) error_exit "Connection attempt failed. Try again later." ;;
    *) error_exit "Failed to connect to device $mac_address. $error_message" ;;
    esac
  fi
  echo -e "\033[32mConnected to $mac_address.\033[0m"
}

# Function to disconnect from a device
disconnect_device() {
  read -p "Enter the MAC address of the device to disconnect: " mac_address
  if [[ ! "$mac_address" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
    error_exit "Invalid MAC address format."
  fi
  if ! bluetoothctl disconnect "$mac_address" &>/dev/null; then
    error_exit "Failed to disconnect from device $mac_address."
  fi
  echo -e "\033[32mDisconnected from $mac_address.\033[0m"
}

# Function to check if a device is connected
is_connected() {
  bluetoothctl info "$1" | grep -q "Connected: yes"
}

# Function to trust a device
trust_device() {
  read -p "Enter the MAC address of the device to trust: " mac_address
  if [[ ! "$mac_address" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
    error_exit "Invalid MAC address format."
  fi
  if ! bluetoothctl trust "$mac_address" &>/dev/null; then
    error_exit "Failed to trust device $mac_address."
  fi
  echo -e "\033[32mDevice $mac_address trusted.\033[0m"
}

# Function to pair with a device
pair_device() {
  read -p "Enter the MAC address of the device to pair: " mac_address
  if [[ ! "$mac_address" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
    error_exit "Invalid MAC address format."
  fi
  if ! bluetoothctl pair "$mac_address" &>/dev/null; then
    error_message=$(bluetoothctl pair "$mac_address" 2>&1)
    case "$error_message" in
    *"Pairing failed: org.bluez.Error.AlreadyExists"*) error_exit "Device already paired." ;;
    *"Pairing failed: org.bluez.Error.AuthenticationFailed"*) error_exit "Authentication failed. Check the pairing code." ;;
    *) error_exit "Failed to pair with device $mac_address. $error_message" ;;
    esac
  fi
  echo -e "\033[32mPaired with $mac_address.\033[0m"
  # Attempt to connect after successful pairing
  if ! is_connected "$mac_address"; then
    echo "Attempting to connect to $mac_address..."
    connect_device "$mac_address"
  fi
}

# Function to remove a device
remove_device() {
  read -p "Enter the MAC address of the device to remove: " mac_address
  if [[ ! "$mac_address" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
    error_exit "Invalid MAC address format."
  fi
  if ! bluetoothctl remove "$mac_address" &>/dev/null; then
    error_exit "Failed to remove device $mac_address."
  fi
  echo -e "\033[32mDevice $mac_address removed.\033[0m"
}

# Function to display device information
device_info() {
  read -p "Enter the MAC address of the device: " mac_address
  if [[ ! "$mac_address" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
    error_exit "Invalid MAC address format."
  fi
  bluetoothctl info "$mac_address"
}

# Main menu
while true; do
  echo -e "\033[34mBluetooth Menu:\033[0m"
  echo "1. Scan for devices"
  echo "2. List paired devices"
  echo "3. Connect to a device"
  echo "4. Disconnect from a device"
  echo "5. Trust a device"
  echo "6. Pair with a device"
  echo "7. Remove a device"
  echo "8. Device Info"
  echo "9. Exit"
  read -p "Enter your choice: " choice

  case $choice in
  1) scan_devices ;;
  2) list_paired_devices ;;
  3) connect_device ;;
  4) disconnect_device ;;
  5) trust_device ;;
  6) pair_device ;;
  7) remove_device ;;
  8) device_info ;;
  9) exit 0 ;;
  *) echo "Invalid choice." ;;
  esac
done
