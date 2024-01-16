import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sr1

class PortScanner:
    def __init__(self, ip, ports, timeout, num_threads, verbose, guess):
        self.ip = ip
        self.ports = self.parse_ports(ports)
        self.timeout = timeout
        self.num_threads = num_threads
        self.verbose = verbose
        self.guess = guess

    def run_scan(self):
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = [executor.submit(self.worker, protocol, port)
                       for protocol in self.ports
                       for port in self.ports[protocol]]

            open_ports = [future.result() for future in futures if future.result()]

        open_ports.sort(key=lambda port: port.port)

        for port in open_ports:
            print(port)

    def worker(self, protocol, port):
        if protocol == 'tcp':
            return self.scan_tcp(port)
        elif protocol == 'udp':
            return self.scan_udp(port)
        else:
            raise ValueError(f"Unknown protocol {protocol}")

    def scan_tcp(self, port):
        try:
            tcp_syn_packet = IP(dst=self.ip) / TCP(dport=port, flags="S")
            response = sr1(tcp_syn_packet, timeout=self.timeout, verbose=False)

            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                service = self.guess_service(response)
                return Port(port, 'TCP', response.time - tcp_syn_packet.time, service) if self.verbose else Port(port, 'TCP')
            return None
        except Exception:
            return None

    def scan_udp(self, port):
        try:
            udp_packet = IP(dst=self.ip) / UDP(dport=port)
            response = sr1(udp_packet, timeout=self.timeout, verbose=False)

            if response and response.haslayer(UDP):
                service = self.guess_service(response)
                return Port(port, 'UDP', response.time - udp_packet.time, service) if self.verbose else Port(port, 'UDP')
            return None
        except Exception:
            return None

    def guess_service(self, response):
        if response.haslayer(HTTP):
            return "HTTP"
        elif response.haslayer(DNS):
            return "DNS"
        elif "ECHO" in str(response.payload):
            return "ECHO"
        else:
            return "-"

    def parse_ports(self, input_ports):
        ports = defaultdict(set)
        for ports_range in input_ports:
            protocol, port_range = ports_range.split('/')
            for p in port_range.split(','):
                if '-' in p:
                    start_port, end_port = map(int, p.split('-'))
                    ports[protocol].update(range(start_port, end_port + 1))
                else:
                    ports[protocol].add(int(p))
        return ports

class Port:
    def __init__(self, port, protocol, timing=None, service=None):
        self.port = port
        self.protocol = protocol
        self.timing = timing
        self.service = service

    def __str__(self):
        result = f"{self.protocol} {self.port}"
        if self.timing is not None:
            result += f" {self.timing:.4f}, ms"
        if self.service:
            result += f" {self.service}"
        return result

def parse_args():
    parser = argparse.ArgumentParser(description="TCP and UDP port scanner")

    parser.add_argument("ip_address", type=str, help="Target IP address")
    parser.add_argument("ports", nargs="+", type=str,
                        help="Ports to scan in the format {tcp|udp}"
                             "[/[PORT|PORT-PORT],...]")
    parser.add_argument("-t", "--timeout", type=int, default=2,
                        help="Timeout for response (default: 2 seconds)")
    parser.add_argument("-j", "--num-threads", type=int, default=1,
                        help="Number of threads")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose mode")
    parser.add_argument("-g", "--guess", action="store_true",
                        help="Guess application layer protocol")

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    scanner = PortScanner(args.ip_address, args.ports, args.timeout, args.num_threads, args.verbose, args.guess)
    scanner.run_scan()
