# 🧪 Code Laboratory 🧪

Welcome to my coding playground! This repository is a space for me to experiment with different programming languages, tools, and concepts. Think of it as a digital workbench where I tinker with code, explore new technologies, and push my programming boundaries.

## Current Experiments

Right now, I'm diving into:

- **Bash Scripting:** Automating tasks, managing the system, and generally bending the command line to my will.
- **Python Development:** From web scraping to data analysis, Python's versatility is endlessly fascinating.
- **C Development:** Getting down to the nitty-gritty of systems programming and low-level interactions.

## Projects

### NetSage: Your Network Oracle

<img src="https://cdn.pixabay.com/photo/2016/08/08/11/11/binary-1578145_1280.jpg" alt="Network Visualization" width="400">

NetSage is a versatile network scanning tool built in Python. It offers multiple scanning methods, including pure Python, Nmap integration, and Scapy-based scanning, providing flexibility and efficiency for network exploration and security auditing.

#### Features

- **Multiple Scanning Methods**
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

#### Installation & Usage

(Recommended) Create a virtual environment:

```bash
python3 -m venv project-dir:
cd project-dir

Activate the virtual environment:
source ./bin/activate

Deactivate the virtual environment (when done):
deactivate

Install dependencies:
pip install -r requirements.txt

Clone the repository:
git clone https://github.com/xuoxod/bash-lab.git
cd netsage

Detailed
    Important Notes:

    Python Version: Ensure you have Python 3.3 or later installed. You can check your version with python3 --version or python --version.
    Package Managers: Use your system's package manager (like apt, yum, brew) to install Python if it's not already available.

    1. Windows

        Using venv (Recommended for Python 3.3+)

        Open Command Prompt or PowerShell.
        Install venv (if not already included with Python):
        python -m ensurepip --upgrade
        That's it! venv is typically included with Python installations on Windows.
        Using virtualenv (Alternative)

        Open Command Prompt or PowerShell.
        Install virtualenv using pip:
        pip install virtualenv

    2. macOS

        Using venv (Recommended for Python 3.3+)

        Open Terminal.
        Install venv (if not already included with Python):
        /Applications/Python\ 3.x/Install\ Certificates.command
        (Replace 3.x with your Python 3 version)
        That's it! venv is typically included with Python installations on macOS.
        Using virtualenv (Alternative)

        Open Terminal.
        Install virtualenv using pip:
        pip install virtualenv

    3. Linux

        Using venv (Recommended for Python 3.3+)

        Open Terminal.
        Install venv (if not already included with Python):
        Debian/Ubuntu:
        sudo apt-get update
        sudo apt-get install python3-venv
        Fedora/CentOS/RHEL:
        sudo yum install python3-venv
        That's it! venv is often included by default, but you might need to install it separately.
        Using virtualenv (Alternative)

        Open Terminal.
        Install virtualenv using pip:
        pip install virtualenv
        After Installation (Creating and Activating Environments):

        The process for creating and activating virtual environments is the same across platforms once you have either venv or virtualenv installed. Here's a quick guide:

        Navigate to your project directory:

        cd /path/to/your/project
        Create a virtual environment:

    4. Using venv:
        python3 -m venv .venv
        Using virtualenv:
        virtualenv .venv
        Activate the virtual environment:

        Linux/macOS:
        source .venv/bin/activate

        Windows:
        .venv\Scripts\activate

Usage
    - Scan a target host using pure Python scanning:
        - python netsage.py scan -t 192.168.1.1

    - Scan a target network using Nmap scanning:
        - python netsage.py scan -t 192.168.1.0/24 -m nmapscan

    - Scan a target network using Scapy scanning:
        - python netsage.py scan -t 192.168.1.0/24 -m scapyscan

    - Get help and see all options:
        - python netsage.py --help
        - python netsage.py scan --help
        - python netsage.py nmapscan --help

```

Contributing
While this is primarily a personal learning space, I'm always open to feedback and suggestions. Feel free to open an issue if you have any ideas or spot any areas for improvement!

Let's build something awesome together! 🚀
