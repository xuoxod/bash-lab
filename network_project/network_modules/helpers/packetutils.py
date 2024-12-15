import socket
from scapy.all import *


class PacketUtils:
    @staticmethod
    def craft_ethernet_header(src_mac, dst_mac="ff:ff:ff:ff:ff:ff"):
        return Ether(src=src_mac, dst=dst_mac)

    @staticmethod
    def craft_ip_header(src_ip, dst_ip, protocol=socket.IPPROTO_TCP):
        return IP(src=src_ip, dst=dst_ip, proto=protocol)

    @staticmethod
    def craft_tcp_header(src_port, dst_port, flags="S"):
        return TCP(sport=src_port, dport=dst_port, flags=flags)

    @staticmethod
    def craft_udp_header(src_port, dst_port):
        return UDP(sport=src_port, dport=dst_port)

    @staticmethod
    def craft_icmp_header(type=8, code=0):  # ICMP header
        return ICMP(type=type, code=code)

    @staticmethod
    def dissect_packet(packet):
        """Dissects a packet and returns a dictionary of layered information."""

        dissected_data = {}
        layers = []

        # Iterate through packet layers
        while packet:
            layer_name = packet.name
            layer_fields = packet.fields

            dissected_layer = {
                "name": layer_name,
                "fields": {},
            }  # Store data for fields in dictionary

            for field in layer_fields:  # Add fields to the layer dictionary
                dissected_layer["fields"][field] = packet.getfieldval(field)

            layers.append(dissected_layer)
            packet = packet.payload

        dissected_data["layers"] = layers
        return dissected_data
