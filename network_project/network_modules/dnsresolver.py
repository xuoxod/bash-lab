import socket
from scapy.all import *


class DNSResolver:
    def __init__(self, dns_server="8.8.8.8", timeout=5):
        self.dns_server = dns_server
        self.timeout = timeout

    def resolve(self, domain, record_type="A"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # DNS Query Construction:
            dns_query = (
                IP(dst=self.dns_server)
                / UDP(sport=RandShort(), dport=53)
                / DNS(rd=1, qd=DNSQR(qname=domain, qtype=record_type))
            )

            sock.sendto(bytes(dns_query), (self.dns_server, 53))

            response, _ = sock.recvfrom(4096)

            # DNS Response Parsing (using Scapy):
            dns_response = DNS(response)  # Parse the response packet

            sock.close()

            # Return based on record type:
            if dns_response.an:  # Check if there are answers.
                if record_type == "A":
                    return dns_response.an[0].rdata  # Return IP address for A records
                elif record_type == "SOA":
                    return {  # Return a dictionary for SOA records
                        "mname": dns_response.an[0].mname,
                        "rname": dns_response.an[0].rname,
                    }
                elif record_type == "MX":
                    return [x.exchange for x in dns_response.an]  # List of MX records

            return None  # No answers found.

        except socket.timeout:
            print("DNS request timed out.")
            return None
        except Exception as e:
            print(f"DNS request error: {e}")
            return None
