# 🧪 Code Laboratory 🧪

Welcome to my coding playground! This repository is a space for me to experiment with different programming languages, tools, and concepts. Think of it as a digital workbench where I tinker with code, explore new technologies, and push my programming boundaries.

## Current Experiments

Right now, I'm diving into:

- **Bash Scripting:** Automating tasks, managing the system, and generally bending the command line to my will.
- **Python Development:** From web scraping to data analysis, Python's versatility is endlessly fascinating.
- **C Development:** Getting down to the nitty-gritty of systems programming and low-level interactions.
- **Network Programming:** Building tools like NetSage to understand and interact with networks at a deeper level.

## Projects

### Bluetooth Device Discovery (C)

This project focuses on using the Bluez library (`libbluetooth`) to create a program that scans for and lists nearby Bluetooth devices. It explores concepts like:

- Bluetooth protocol basics
- Socket programming in C
- Working with C libraries
- Hardware interaction (Bluetooth adapter)

### NetSage: Your Network Oracle

<img src="https://cdn.pixabay.com/photo/2016/08/08/11/11/binary-1578145_1280.jpg" alt="Network Visualization" width="400">

NetSage is a versatile network scanning tool built in Python. It offers multiple scanning methods, including pure Python, Nmap integration, and Scapy-based scanning, providing flexibility and efficiency for network exploration and security auditing.

#### Features

- **Multiple Scanning Methods:**
  - **Pure Python:** Fast and lightweight scanning using native sockets.
  - **Nmap Integration:** Leverages the power and features of Nmap for comprehensive scans.
  - **Scapy-Based Scanning:** Provides packet-level control for advanced network analysis.
- **Customizable Configuration:** Configure default ports, timeouts, Nmap arguments, and output formats.
- **User-Friendly Output:** Results are presented in clear text, CSV, or JSON format.
- **Extensible Design:** Easily integrate new scanning modules and functionalities.

#### Requirements

- **Python 3.6 or higher**
- **Nmap (optional, for `nmapscan` command)**: Install Nmap from [https://nmap.org/](https://nmap.org/)
- **Scapy (optional, for `scapyscan` command)**: Install Scapy with `pip install scapy`

#### Installation

#### Contributing

While this is primarily a personal learning space, I'm always open to feedback and suggestions. Feel free to open an issue if you have any ideas or spot any areas for improvement!

Let's build something awesome together! 🚀

Programs
This directory contains a collection of bash scripts I've written. Each script is designed to perform a specific task or set of tasks.

Please note: This is a scratch directory, so the scripts here may be experimental, incomplete, or not well-documented. Use them at your own risk!

1. **Clone the repository:**

   ```bash
   (Recommended) Create a virtual environment:
   python3 -m venv venv
   source venv/bin/activate

   Install dependencies:
   pip install -r requirements.txt
   ```

- Usage
  - Scan a target host using pure Python scanning:
    python netsage.py scan -t 192.168.1.1
  - Scan a target network using Nmap scanning:
    python netsage.py scan -t 192.168.1.0/24 -m nmapscan
  - Scan a target network using Scapy scanning:
    python netsage.py scan -t 192.168.1.0/24 -m scapyscan
  - Get help and see all options:
    python netsage.py --help
    python netsage.py scan --help
    python netsage.py nmapscan --help

git clone https://github.com/yourusername/netsage.git
cd netsage
