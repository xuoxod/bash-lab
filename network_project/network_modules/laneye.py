#!/usr/bin/python3

import scapy.all as scapy
import ipaddress
import json
import csv
import random


# ANSI escape codes for text coloring
class TextColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


# Function to generate a random ANSI color code
def get_random_ansi_color():
    return f"\033[38;5;{random.randint(31, 37)}m"


class NetworkScanner:
    def __init__(self):
        pass  # No initial configuration needed for now

    def scan_network(self, net_address):
        """Sends ARP requests and returns a dictionary of IP-MAC mappings."""
        try:
            ipaddress.ip_network(net_address, strict=False)  # Validate the input
        except ipaddress.AddressValueError:  # Catch the specific error
            raise ValueError(
                f"Invalid IP address or CIDR range: {net_address}"
            ) from None  # Only raise the exception

        results = {}  # Use a dictionary to store results
        arp_request = scapy.ARP(pdst=net_address)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        for element in answered_list:
            client_ip = element[1].psrc
            client_mac = element[1].hwsrc
            results[client_ip] = client_mac  # Store in the dictionary
        return results

    def print_results(self, results):
        """Prints the results to the console with color and formatting."""

        print(
            f"\n{TextColors.BOLD}{TextColors.OKGREEN}IP Address\t\tMAC Address{TextColors.ENDC}"
        )
        print(f"{TextColors.OKBLUE}-{TextColors.ENDC}" * 40)

        ip_colors = {}  # Store colors for each IP

        for ip, mac in results.items():
            if ip not in ip_colors:
                ip_colors[ip] = get_random_ansi_color()
            color = ip_colors[ip]
            print(f"{color}{ip}\t\t{mac}{TextColors.ENDC}")

    def save_to_csv(self, results, filename="network_scan.csv"):
        """Saves the results to a CSV file."""

        with open(filename, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP Address", "MAC Address"])
            for ip, mac in results.items():
                writer.writerow([ip, mac])

    def save_to_json(self, results, filename="network_scan.json"):
        """Saves the results to a JSON file."""

        data = []
        for ip, mac in results.items():
            data.append({"IP Address": ip, "MAC Address": mac})

        with open(filename, "w") as jsonfile:
            json.dump(data, jsonfile, indent=4)

    def save_to_html(self, results, filename="network_scan.html"):
        """Saves the results to an HTML file with color and formatting."""

        html = """
        <!DOCTYPE html>
        <html>
        <head>
        <title>Network Scan Results</title>
        <style>
        body {font-family: monospace;}
        table {border-collapse: collapse; width: 50%;}
        th, td {border: 1px solid black; padding: 8px; text-align: left;}
        th {background-color: #f2f2f2;}
        </style>
        </head>
        <body>
        <h2>Network Scan Results</h2>
        <table>
        <tr>
        <th>IP Address</th>
        <th>MAC Address</th>
        </tr>
        """

        ip_colors = {}  # Store colors for each IP

        for ip, mac in results.items():
            if ip not in ip_colors:
                ip_colors[ip] = get_random_ansi_color()
            color = ip_colors[ip]
            html += f"<tr><td style='color:{color}'>{ip}</td><td>{mac}</td></tr>"

        html += """
        </table>
        </body>
        </html>
        """
        with open(filename, "w") as htmlfile:
            htmlfile.write(html)
