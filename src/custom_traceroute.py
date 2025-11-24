from netfilterqueue import NetfilterQueue
from scapy.all import IP, ICMP, UDP, DNS, DNSRR, Raw, send
import argparse
import sys
import os

DEFAULT_TRIGGER = "rerand0m.ru"
DEFAULT_PREFIX = "10.0.0."
DEFAULT_QUEUE_ID = 1
MAX_HOPS = 255

DNS_TYPE_A = 1
DNS_TYPE_PTR = 12
DNS_CLASS_IN = "IN"
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
ICMP_DEST_UNREACHABLE = 3
ICMP_CODE_PORT_UNREACHABLE = 3
DNS_PORT = 53

DEFAULT_SONG_LINES = [
    "poker.face.on.the.table",
    "i.hold.my.cards.tight", 
    "face.like.a.mask",
    "no.tells.in.the.light",
    "bluff.and.ache",
    "stony.gaze.unmoved",
    "bets.fall.like.rain",
    "my.hand.is.proved",
    "fold.and.rise",
    "the.game.is.the.place",
    "calm.as.still.water",
    "wearing.my.poker.face"
]


class DNSHandler:    
    def __init__(self, route_simulator):
        self.route_simulator = route_simulator
    
    def _create_a_record_response(self, ip_pkt, udp, dns):
        return (
            IP(src=ip_pkt.dst, dst=ip_pkt.src) /
            UDP(sport=udp.dport, dport=udp.sport) /
            DNS(
                id=dns.id, 
                qr=1, 
                qd=dns.qd,
                an=DNSRR(
                    rrname=dns.qd.qname, 
                    type="A", 
                    rclass=DNS_CLASS_IN, 
                    rdata=self.route_simulator.dest_ip()
                )
            )
        )
    
    def _create_ptr_record_response(self, ip_pkt, udp, dns, hostname):
        return (
            IP(src=ip_pkt.dst, dst=ip_pkt.src) /
            UDP(sport=udp.dport, dport=udp.sport) /
            DNS(
                id=dns.id,
                qr=1,
                qd=dns.qd,
                an=DNSRR(
                    rrname=dns.qd.qname,
                    type="PTR", 
                    rclass=DNS_CLASS_IN,
                    rdata=hostname
                )
            )
        )
    
    def _parse_ptr_query(self, ptr_name):
        ptr_name = ptr_name.rstrip(".")
        suffix = ".in-addr.arpa"
        
        if not ptr_name.endswith(suffix):
            return None
        
        raw_ip = ptr_name[:-len(suffix)]
        ip_parts = raw_ip.split(".")
        return ".".join(reversed(ip_parts))
    
    def _handle_a_query(self, packet, ip_pkt, udp, dns, query_name):
        if query_name == self.route_simulator.trigger:
            response = self._create_a_record_response(ip_pkt, udp, dns)
            send(response, verbose=0)
            packet.drop()
            return True
        return False
    
    def _handle_ptr_query(self, packet, ip_pkt, udp, dns, query_name):
        ip_address = self._parse_ptr_query(query_name)
        
        if not ip_address or not ip_address.startswith(self.route_simulator.prefix):
            return False
        
        try:
            hop_index = int(ip_address.split(".")[-1])
        except (ValueError, IndexError):
            return False
        
        if 0 <= hop_index < self.route_simulator.total_hops:
            hostname = self.route_simulator.get_hostname_for_hop(hop_index)
            response = self._create_ptr_record_response(ip_pkt, udp, dns, hostname)
            send(response, verbose=0)
            packet.drop()
            return True
        
        return False
    
    def process_dns_packet(self, packet, ip_pkt):
        udp = ip_pkt[UDP]
        dns = ip_pkt[DNS]
        
        if dns.qr != 0:
            packet.accept()
            return
        
        query_name = dns.qd.qname.decode().rstrip(".")
        query_type = dns.qd.qtype
        
        if query_type == DNS_TYPE_A:
            if self._handle_a_query(packet, ip_pkt, udp, dns, query_name):
                return
        
        elif query_type == DNS_TYPE_PTR:
            if self._handle_ptr_query(packet, ip_pkt, udp, dns, query_name):
                return
        
        packet.accept()


class ICMPHandler:    
    def __init__(self, route_simulator):
        self.route_simulator = route_simulator
    
    def _create_icmp_time_exceeded(self, ip_pkt, hop_index):
        src_ip = self.route_simulator.get_ip_for_hop(hop_index)
        return (
            IP(src=src_ip, dst=ip_pkt.src) /
            ICMP(type=ICMP_TIME_EXCEEDED, code=0) /
            Raw(bytes(ip_pkt))
        )
    
    def _create_icmp_echo_reply(self, ip_pkt, icmp):
        src_ip = self.route_simulator.dest_ip()
        return (
            IP(src=src_ip, dst=ip_pkt.src) /
            ICMP(type=ICMP_ECHO_REPLY, id=icmp.id, seq=icmp.seq) /
            icmp.payload
        )
    
    def process_icmp_packet(self, packet, ip_pkt):
        icmp = ip_pkt[ICMP]
        
        if icmp.type != ICMP_ECHO_REQUEST:
            packet.accept()
            return
        
        if ip_pkt.dst != self.route_simulator.dest_ip():
            packet.accept()
            return
        
        if ip_pkt.ttl < self.route_simulator.total_hops:
            response = self._create_icmp_time_exceeded(ip_pkt, ip_pkt.ttl - 1)
        else:
            response = self._create_icmp_echo_reply(ip_pkt, icmp)
        
        send(response, verbose=0)
        packet.drop()


class UDPHandler:    
    def __init__(self, route_simulator):
        self.route_simulator = route_simulator
    
    def _create_udp_time_exceeded(self, ip_pkt, hop_index):
        src_ip = self.route_simulator.get_ip_for_hop(hop_index)
        return (
            IP(src=src_ip, dst=ip_pkt.src) /
            ICMP(type=ICMP_TIME_EXCEEDED, code=0) /
            Raw(bytes(ip_pkt))
        )
    
    def _create_udp_port_unreachable(self, ip_pkt):
        src_ip = self.route_simulator.dest_ip()
        return (
            IP(src=src_ip, dst=ip_pkt.src) /
            ICMP(type=ICMP_DEST_UNREACHABLE, code=ICMP_CODE_PORT_UNREACHABLE) /
            Raw(bytes(ip_pkt))
        )
    
    def process_udp_packet(self, packet, ip_pkt):
        udp = ip_pkt[UDP]
        
        if udp.dport == DNS_PORT or udp.sport == DNS_PORT:
            packet.accept()
            return
        
        if ip_pkt.dst != self.route_simulator.dest_ip():
            packet.accept()
            return
        
        if ip_pkt.ttl < self.route_simulator.total_hops:
            response = self._create_udp_time_exceeded(ip_pkt, ip_pkt.ttl - 1)
        else:
            response = self._create_udp_port_unreachable(ip_pkt)
        
        send(response, verbose=0)
        packet.drop()


class PacketProcessor:    
    def __init__(self, route_simulator):
        self.route_simulator = route_simulator
        self.dns_handler = DNSHandler(route_simulator)
        self.icmp_handler = ICMPHandler(route_simulator)
        self.udp_handler = UDPHandler(route_simulator)
    
    def process_packet(self, packet):
        try:
            ip_payload = IP(packet.get_payload())
            
            if ip_payload.haslayer(DNS):
                self.dns_handler.process_dns_packet(packet, ip_payload)
            elif ip_payload.haslayer(ICMP):
                self.icmp_handler.process_icmp_packet(packet, ip_payload)
            elif ip_payload.haslayer(UDP):
                self.udp_handler.process_udp_packet(packet, ip_payload)
            else:
                packet.accept()
                
        except Exception as e:
            print(f"Error processing packet: {e}", file=sys.stderr)
            packet.accept()


class RouteSimulator:    
    def __init__(self, song_lines=None, trigger=DEFAULT_TRIGGER, prefix=DEFAULT_PREFIX):
        self.trigger = trigger
        self.prefix = prefix
        self.song_lines = self._validate_song_lines(song_lines or DEFAULT_SONG_LINES)
        self.total_hops = len(self.song_lines)
        
        if not (1 <= self.total_hops <= MAX_HOPS):
            raise ValueError(f"Song must have between 1 and {MAX_HOPS} lines")
    
    def _validate_song_lines(self, song_lines):
        return [line.strip() for line in song_lines if line.strip()]
    
    def get_ip_for_hop(self, hop_index):
        return f"{self.prefix}{hop_index}"
    
    def dest_ip(self):
        return self.get_ip_for_hop(self.total_hops - 1)
    
    def get_hostname_for_hop(self, hop_index):
        if 0 <= hop_index < self.total_hops:
            return ".".join(self.song_lines[hop_index].strip().lower().split())
        return None
    
    def run(self, queue_id=DEFAULT_QUEUE_ID):
        packet_processor = PacketProcessor(self)
        nfq = NetfilterQueue()
        
        try:
            print(f"Starting RouteSimulator with {self.total_hops} hops")
            print(f"Trigger domain: {self.trigger} -> {self.dest_ip()}")
            print("Press Ctrl+C to stop")
            
            nfq.bind(queue_id, packet_processor.process_packet)
            nfq.run()
            
        except KeyboardInterrupt:
            print("\nStopping RouteSimulator...")
        finally:
            nfq.unbind()


def read_song_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading song file: {e}", file=sys.stderr)
        return None


def setup_argument_parser():
    parser = argparse.ArgumentParser(
        description="Route simulator that creates a poetic traceroute experience"
    )
    parser.add_argument(
        '--song-file', 
        type=str,
        help='Path to file containing song/poem lines (one per line)'
    )
    parser.add_argument(
        '--trigger', 
        type=str, 
        default=DEFAULT_TRIGGER,
        help=f'Domain name to trigger the simulation (default: {DEFAULT_TRIGGER})'
    )
    parser.add_argument(
        '--prefix', 
        type=str, 
        default=DEFAULT_PREFIX,
        help=f'IP prefix for simulated hops (default: {DEFAULT_PREFIX})'
    )
    parser.add_argument(
        '--queue', 
        type=int, 
        default=DEFAULT_QUEUE_ID,
        help=f'NetfilterQueue ID (default: {DEFAULT_QUEUE_ID})'
    )
    
    return parser


def main():
    parser = setup_argument_parser()
    args = parser.parse_args()

    if args.song_file:
        if not os.path.exists(args.song_file):
            print(f"Error: Song file '{args.song_file}' not found", file=sys.stderr)
            return 1
        
        song_lines = read_song_from_file(args.song_file)
        if not song_lines:
            print("Error: No valid lines found in song file", file=sys.stderr)
            return 1
    else:
        song_lines = DEFAULT_SONG_LINES
    
    try:
        simulator = RouteSimulator(
            song_lines=song_lines,
            trigger=args.trigger,
            prefix=args.prefix
        )
        simulator.run(queue_id=args.queue)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())