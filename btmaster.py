#!/usr/bin/env python3

import re
import subprocess


# ANSI escape codes for colored output
class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def error_exit(message):
    print(f"{bcolors.FAIL}Error:{bcolors.ENDC} {message}")
    exit(1)


def run_bluetoothctl(command):
    """Runs a command using bluetoothctl and returns the output."""
    process = subprocess.Popen(["bluetoothctl", command], stdout=subprocess.PIPE)
    output, error = process.communicate()
    if error:
        error_exit(f"bluetoothctl error: {error.decode()}")
    return output.decode()


def scan_devices():
    """Scans for Bluetooth devices."""
    print(f"{bcolors.OKGREEN}Scanning for Bluetooth devices...{bcolors.ENDC}")
    run_bluetoothctl("power on")
    run_bluetoothctl("scan on")
    input("Press Enter to stop scanning...")
    run_bluetoothctl("scan off")


def list_paired_devices():
    """Lists paired Bluetooth devices."""
    print(f"{bcolors.OKGREEN}Paired Bluetooth devices:{bcolors.ENDC}")
    paired_devices = run_bluetoothctl("paired-devices")
    if paired_devices:
        for line in paired_devices.splitlines():
            mac_address = line.split()[1]
            print(mac_address)
    else:
        print("No paired devices found.")


def connect_device():
    """Connects to a Bluetooth device."""
    mac_address = input("Enter the MAC address of the device to connect: ")
    if not re.match(
        "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}",
        mac_address,
    ):
        error_exit("Invalid MAC address format.")
    output = run_bluetoothctl(f"connect {mac_address}")
    if "Connection successful" in output:
        print(f"{bcolors.OKGREEN}Connected to {mac_address}.{bcolors.ENDC}")
    else:
        error_exit(f"Failed to connect to device {mac_address}.")


def disconnect_device():
    """Disconnects from a Bluetooth device."""
    mac_address = input("Enter the MAC address of the device to disconnect: ")
    if not re.match(
        "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}",
        mac_address,
    ):
        error_exit("Invalid MAC address format.")
    output = run_bluetoothctl(f"disconnect {mac_address}")
    if "Successful disconnected" in output:
        print(f"{bcolors.OKGREEN}Disconnected from {mac_address}.{bcolors.ENDC}")
    else:
        error_exit(f"Failed to disconnect from device {mac_address}.")


def trust_device():
    """Trusts a Bluetooth device."""
    mac_address = input("Enter the MAC address of the device to trust: ")
    if not re.match(
        "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}",
        mac_address,
    ):
        error_exit("Invalid MAC address format.")
    output = run_bluetoothctl(f"trust {mac_address}")
    if "trust succeeded" in output:
        print(f"{bcolors.OKGREEN}Device {mac_address} trusted.{bcolors.ENDC}")
    else:
        error_exit(f"Failed to trust device {mac_address}.")


def pair_device():
    """Pairs with a Bluetooth device."""
    mac_address = input("Enter the MAC address of the device to pair: ")
    if not re.match(
        "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}",
        mac_address,
    ):
        error_exit("Invalid MAC address format.")
    output = run_bluetoothctl(f"pair {mac_address}")
    if "Pairing successful" in output:
        print(f"{bcolors.OKGREEN}Paired with {mac_address}.{bcolors.ENDC}")
    else:
        error_exit(f"Failed to pair with device {mac_address}.")


def remove_device():
    """Removes a Bluetooth device."""
    mac_address = input("Enter the MAC address of the device to remove: ")
    if not re.match(
        "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}",
        mac_address,
    ):
        error_exit("Invalid MAC address format.")
    output = run_bluetoothctl(f"remove {mac_address}")
    if "Device has been removed" in output:
        print(f"{bcolors.OKGREEN}Device {mac_address} removed.{bcolors.ENDC}")
    else:
        error_exit(f"Failed to remove device {mac_address}.")


def device_info():
    """Displays information about a Bluetooth device."""
    mac_address = input("Enter the MAC address of the device: ")
    if not re.match(
        "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}",
        mac_address,
    ):
        error_exit("Invalid MAC address format.")
    output = run_bluetoothctl(f"info {mac_address}")
    print(output)


# Main menu loop
while True:
    print(f"{bcolors.OKBLUE}Bluetooth Menu:{bcolors.ENDC}")
    print("1. Scan for devices")
    print("2. List paired devices")
    print("3. Connect to a device")
    print("4. Disconnect from a device")
    print("5. Trust a device")
    print("6. Pair with a device")
    print("7. Remove a device")
    print("8. Device Info")
    print("9. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        scan_devices()
    elif choice == "2":
        list_paired_devices()
    elif choice == "3":
        connect_device()
    elif choice == "4":
        disconnect_device()
    elif choice == "5":
        trust_device()
    elif choice == "6":
        pair_device()
    elif choice == "7":
        remove_device()
    elif choice == "8":
        device_info()
    elif choice == "9":
        break
    else:
        print("Invalid choice.")
