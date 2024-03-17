import json
import re
import platform
from subprocess import run, PIPE, STDOUT
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from rich import print
from rich.console import Console
from rich.table import Table
import shlex  # For argument sanitization

console = Console()


class PacketAnalysis:
    tshark_loc = ""
    services = []
    tcp_streams = []
    source_addresses = []
    destination_addresses = []
    resolved_sources = []
    dns_query_names = []
    dns_resp_names = []
    unique_eapol_data = []
    combined_json = []

    def __init__(self):
        self.detect_tshark()

    def detect_tshark(self) -> None:
        try:
            osp = platform.system()
            match osp:
                case 'Darwin':
                    self.tshark_loc = "tshark"
                case 'Linux':
                    self.tshark_loc = "tshark"
                case 'Windows':
                    self.tshark_loc = '"C:\\Program Files\\Wireshark\\tshark.exe"'
        except Exception:
            pass

    def extract_network_info(self, json_data):
        services = set()
        tcp_streams = set()
        source_addresses = set()
        destination_addresses = set()
        resolved_sources = set()
        dns_query_names = set()
        dns_resp_names = set()
        unique_eapol_data = set()

        for entry in json_data:
            layers = entry.get('_source', {}).get('layers', {})

            tcp_layer = layers.get('tcp', {})
            if tcp_layer:
                service = tcp_layer.get('tcp.srcport')
                if service:
                    services.add(service)
                tcp_stream_val = tcp_layer.get('tcp.stream')
                if tcp_stream_val:
                    tcp_streams.add(tcp_stream_val)

            ip_layer = layers.get('ip', {})
            if ip_layer:
                source_address = ip_layer.get('ip.src_host')
                destination_address = ip_layer.get('ip.dst_host')
                if source_address:
                    source_addresses.add(source_address)
                if destination_address:
                    destination_addresses.add(destination_address)

            eth_layer = layers.get('eth', {})
            if eth_layer:
                source_mac = eth_layer.get('eth.src')
                resolved_source_mac = eth_layer.get('eth.src_tree', {}).get('eth.src_resolved')
                if source_mac and resolved_source_mac:
                    resolved_sources.add(resolved_source_mac)

            dns_layer = layers.get('dns', {})
            if dns_layer:
                queries = dns_layer.get('Queries', [])
                if isinstance(queries, list):
                    for query in queries:
                        query_name = query.get('dns.qry.name')
                        if query_name:
                            dns_query_names.add(query_name)
                elif isinstance(queries, dict):
                    for query_name, query_info in queries.items():
                        dns_query_names.add(query_info.get('dns.qry.name'))
                answers = dns_layer.get('Answers', [])
                if isinstance(answers, list):
                    for answer in answers:
                        resp_name = answer.get('dns.resp.name')
                        if resp_name:
                            dns_resp_names.add(resp_name)
                elif isinstance(answers, dict):
                    for resp_name, resp_info in answers.items():
                        dns_resp_names.add(resp_info.get('dns.resp.name'))

            eapol_layer = layers.get('eapol', {})
            if eapol_layer:
                eapol_data = eapol_layer.get('wlan_rsna_eapol.keydes.data', "")
                unique_eapol_data.add(eapol_data)

        self.services = list(services)
        self.tcp_streams = list(tcp_streams)
        self.source_addresses = list(source_addresses)
        self.destination_addresses = list(destination_addresses)
        self.resolved_sources = list(resolved_sources)
        self.dns_query_names = list(dns_query_names)
        self.dns_resp_names = list(dns_resp_names)
        self.unique_eapol_data = list(unique_eapol_data)

    def run_tshark_command(self, service, source, streams):
        # Sanitize arguments to prevent command injection
        sanitized_service = shlex.quote(str(service))
        sanitized_source = shlex.quote(str(source))
        sanitized_streams = shlex.quote(str(streams))

        stream_cmd = f'{self.tshark_loc} -r test.pcap -q -z follow,tcp,raw,{sanitized_streams} -Y "ip.addr=={sanitized_source} and tcp.port=={sanitized_service}"'
        runner = run(stream_cmd, shell=True, stdout=PIPE, stderr=STDOUT, text=True)
        output_lines = runner.stdout.splitlines()
        node_regex = re.compile(r'Node (\d+): (.+)$')
        data_regex = re.compile(r'\s+(.+)$')
        node_0, node_1, data = None, None, None
        for line in output_lines:
            node_match = node_regex.match(line)
            data_match = data_regex.match(line)
            if node_match:
                node_num, node_value = node_match.groups()
                if node_num == '0':
                    node_0 = node_value
                elif node_num == '1':
                    node_1 = node_value
            elif data_match:
                data = data_match.group(1)

        if node_0 is not None and node_1 is not None and data is not None:
            return ['Source: ' f'{node_0}', 'Destination: ' f'{node_1}', 'stream: ' f'{streams}']
        else:
            return []

    def flatten_json(self, data: Any, separator: Any = '.') -> Any:
        flattened_data = {}
        for key, value in data.items():
            if isinstance(value, dict):
                nested_data = self.flatten_json(value, separator)
                for nested_key, nested_value in nested_data.items():
                    flattened_data[key + separator + nested_key] = nested_value
            else:
                flattened_data[key] = value
        return flattened_data

    def stream(self, service_list, source_list, tcp_streams_list, max_workers=20):
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            command_params = [(service, source, streams) for service in service_list for source in source_list for streams in tcp_streams_list]
            print("Total Streams combination: ", len(command_params))
            print("Number of workers in progress: ", max_workers)
            results = list(executor.map(lambda params: self.run_tshark_command(*params), command_params))
        results = [result for result in results if result]
        self.combined_json = results

    def perform_full_analysis(self, pcap_path, json_path, max_workers=20):
        print('Collecting Json Data')

        # Sanitize pcap_path to prevent command injection
        sanitized_pcap_path = shlex.quote(pcap_path)

        raw_pcap = run(f"{self.tshark_loc} -r {sanitized_pcap_path} -T json", shell=True, capture_output=True, text=True)
        try:
            raw_data = raw_pcap.stdout
            json_data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            json_data = []

        print('Extracting IP details...')
        print('Extracting DNS details...')
        print('Extracting EAPOL details...')
        self.extract_network_info(json_data)

        print('Extracting TCP STREAMS details...')
        print('TCP streams can take some time..')
        self.stream(service_list=self.services,
                    source_list=self.source_addresses,
                    tcp_streams_list=self.tcp_streams,
                    max_workers=max_workers)

        print("Completed")
        filtered_stream_data = self.combined_json
        values = {
            "PacketAnalysis": {
                "Services": self.services,
                "TCP Streams": self.tcp_streams,
                "Sources Address": self.source_addresses,
                "Destination Address": self.destination_addresses,
                "DNS Resolved": self.resolved_sources,
                "DNS Query": self.dns_query_names,
                "DNS Response": self.dns_resp_names,
                "EAPOL Data": self.unique_eapol_data,
                "Stream Data": filtered_stream_data
            }
        }
        table_val = {
            "PacketAnalysis": {
                "Services": self.services,
                "TCP Streams": self.tcp_streams,
                "Sources Address": self.source_addresses,
                "Destination Address": self.destination_addresses,
                "DNS Resolved": self.resolved_sources,
                "DNS Query": self.dns_query_names,
                "DNS Response": self.dns_resp_names,
                "EAPOL Data": self.unique_eapol_data,
                " Total Streams Data": str(len(filtered_stream_data))
            }
        }
        table = Table(title="GVA Report for PCAP", show_header=True, header_style="bold magenta")
        table.add_column("Identifiers", style="cyan")
        table.add_column("Data", style="green")

        flattened_data: dict = self.flatten_json(table_val, separator='.')

        for key, value in flattened_data.items():
            value_str = str(value)
            table.add_row(key, str(value_str))

        console = Console()
        console.print(table)
        with open(f'{json_path}', 'w+') as file:
            file.write(str(json.dumps(values)))
