from scapy.all import rdpcap, IP, TCP, UDP, DNSQR, EAPOL, Raw, ARP
from collections import Counter, defaultdict
from rich.console import Console
from rich.table import Table
import json
import re


class PacketAnalysis:
    def load_pcap(self, pcap_file):
        self.packets = rdpcap(pcap_file)
        self.analysis_results = {"Total Packets": len(self.packets)}

    def detect_eapol(self):
        eapol_packets = [pkt for pkt in self.packets if EAPOL in pkt]
        self.analysis_results["EAPOL Packets"] = len(eapol_packets)

    def summarize_traffic(self):
        ip_packets = [pkt for pkt in self.packets if IP in pkt]
        tcp_packets = [pkt for pkt in self.packets if TCP in pkt]
        self.analysis_results["Total IP Packets"] = len(ip_packets)
        self.analysis_results["Total TCP Packets"] = len(tcp_packets)

    def list_ips(self):
        src_ips = set(pkt[IP].src for pkt in self.packets if IP in pkt)
        dst_ips = set(pkt[IP].dst for pkt in self.packets if IP in pkt)

        self.analysis_results["Unique Source IPs"] = src_ips
        self.analysis_results["Unique Destination IPs"] = dst_ips

    def detect_arp_spoofing(self):
        arp_table = {}
        arp_spoofing_detected = False
        for packet in self.packets:
            if ARP in packet and packet[ARP].op == 2:  # ARP response
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc

                if ip not in arp_table:
                    arp_table[ip] = set()
                arp_table[ip].add(mac)

                if len(arp_table[ip]) > 1:
                    arp_spoofing_detected = True

        self.analysis_results["ARP Spoofing Detected"] = arp_spoofing_detected

    def count_tcp_streams(self):
        stream_set = set()
        for packet in self.packets:
            if IP in packet and TCP in packet:
                stream_identifier = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
                stream_set.add(stream_identifier)
        self.analysis_results["Total TCP Streams"] = len(stream_set)

    def list_unique_ports(self):
        tcp_ports = set()
        udp_ports = set()
        for packet in self.packets:
            if TCP in packet:
                tcp_ports.add(packet[TCP].sport)
                tcp_ports.add(packet[TCP].dport)
            elif UDP in packet:
                udp_ports.add(packet[UDP].sport)
                udp_ports.add(packet[UDP].dport)

        self.analysis_results["Unique TCP Ports"] = tcp_ports
        self.analysis_results["Unique UDP Ports"] = udp_ports

    def detect_mac_spoofing(self):
        ip_mac_mapping = defaultdict(set)
        mac_spoofing_detected = False

        for packet in self.packets:
            if ARP in packet and packet[ARP].op in (1, 2):  # ARP request or reply
                ip_address = packet[ARP].psrc
                mac_address = packet[ARP].hwsrc
                ip_mac_mapping[ip_address].add(mac_address)

                if len(ip_mac_mapping[ip_address]) > 1:
                    mac_spoofing_detected = True

        self.analysis_results["MAC Spoofing Detected"] = mac_spoofing_detected

    def common_ports(self):
        ports = [pkt[TCP].dport for pkt in self.packets if TCP in pkt]
        port_counts = Counter(ports).most_common(5)
        self.analysis_results["Common Ports"] = port_counts

    def detect_dns_requests(self):
        dns_requests = [pkt[DNSQR].qname.decode() for pkt in self.packets if DNSQR in pkt and UDP in pkt and pkt[UDP].dport == 53]
        self.analysis_results["DNS Requests"] = dns_requests

    def detect_credentials(self):
        credential_patterns = [r'username', r'password', r'passwd', r'user', r'pass']
        credential_packets = [pkt for pkt in self.packets if TCP in pkt and Raw in pkt and any(re.search(pattern, str(pkt[Raw].load), re.IGNORECASE) for pattern in credential_patterns)]
        self.analysis_results["Potential Credential Packets"] = len(credential_packets)

    def display_results(self):
        console = Console()
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Metric", style="dim")
        table.add_column("Value")

        for key, value in self.analysis_results.items():
            if isinstance(value, set):
                value_str = ', '.join(value)
            else:
                value_str = str(value)
            table.add_row(key, value_str)

        console.print(table)

    def save_results_to_json(self, json_file):
        with open(json_file, "w") as file:
            # Convert sets to lists for JSON serialization
            output_data = {k: list(v) if isinstance(v, set) else v for k, v in self.analysis_results.items()}
            json.dump(output_data, file, indent=4)

    def perform_full_analysis(self, pcap_path, json_path):
        self.load_pcap(pcap_path)
        self.summarize_traffic()
        self.list_ips()
        self.common_ports()
        self.detect_dns_requests()
        self.detect_credentials()
        self.detect_arp_spoofing()
        self.detect_mac_spoofing()
        self.detect_eapol()
        self.display_results()
        self.save_results_to_json(json_path)
