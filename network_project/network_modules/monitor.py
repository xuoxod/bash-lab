#!/usr/bin/python3

import sys
import subprocess
import time
import psutil  # Install with: pip install psutil
import os

# Configuration (adjust as needed)
PROCESS_NAME = "python3"  # Name of the process to monitor
MAX_RUNTIME = 60 * 60  # Maximum allowed runtime in seconds (1 hour here)
CHECK_INTERVAL = 10  # Check every 10 seconds


def find_process(process_name):
    """Finds a process by name."""
    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info["name"] == process_name:
            return proc
    return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_ip> [<interface>]")
        sys.exit(1)

    target_ip = sys.argv[1]
    interface = sys.argv[2] if len(sys.argv) > 2 else None

    # Get the absolute path of the current script (monitor.py)
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Construct the absolute path to netintercept.py
    netintercept_script = os.path.join(script_dir, "netintercept.py")

    # Construct the command list, including the interface argument
    netintercept_command = ["python3", netintercept_script, target_ip]
    if interface is not None:
        netintercept_command.extend(["-i", interface])

    # Start the NetIntercept process using the correct command
    netintercept_process = subprocess.Popen(netintercept_command)

    start_time = time.time()
    while True:
        process = find_process(PROCESS_NAME)
        if process is None:
            print(f"[Monitor] Process '{PROCESS_NAME}' not found. Exiting.")
            break

        runtime = time.time() - start_time
        if runtime > MAX_RUNTIME:
            print(f"[Monitor] '{PROCESS_NAME}' exceeded maximum runtime. Terminating.")
            process.terminate()  # Gracefully terminate
            time.sleep(2)  # Give time to terminate
            if process.is_running():
                print(f"[Monitor] Forcefully killing '{PROCESS_NAME}'.")
                process.kill()  # Forcefully kill if still running
            break

        time.sleep(CHECK_INTERVAL)

    print("[Monitor] Exiting.")
