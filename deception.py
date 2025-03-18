from scapy.all import sendp, sniff, IP, IPv6, TCP, Ether
from detected_ip import Detected_ip

class Deception:
    def __init__(self):
        self.targeted_ip = "192.168.35.45" # our own ip
        self.protected_ports = [53, 80, 433]
        self.honeypot_ports = [8080, 8443]
        self.src_ip = None

        b_ip = Detected_ip()
        self.blocked = b_ip.blocked_source


    def analyze_p(self, packet):

        if not packet[TCP].flags & 0x02: 
            return
        '''If the packet is not a connection initiation packet, it is ignored.'''
        
        if packet.haslaye(IP):
            response = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                       IP(src=packet[IP].dst, dst=packet[IP].src) / \
                       TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, ack=packet[TCP].seq + 1)
            '''[ack=packet[TCP].seq + 1] ACK number: TCP uses sequence and acknowledgment
numbers to help the systems keep track of where they are in the
conversation. The ACK number in the response should be one
more than the SEQ number in the request.'''

            self.src_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            response = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                       IPv6(src=packet[IPv6].dst, dst=packet[IPv6].src) / \
                       TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, ack=packet[TCP].seq + 1)
            self.src_ip = packet[IPv6].src

        targeted_port = packet[TCP].dport

        #checking if the source IP is already blocked or not
        if self.src_ip in self.blocked:
            if targeted_port in self.protected_ports:
                response[TCP].flags == "RA"
                print(f"Blocked source {self.src_ip} attempted to access protected port {targeted_port}. Sending RST.")
            elif targeted_port in self.honeypot_ports:
                response[TCP].flags == "SA"
                print(f"Blocked source {self.src_ip} probed honeypot port {targeted_port}. Sending deceptive SYN-ACK.")

            else:
                return
            sendp(response, timeout = 0, verbose=0)
        
    def sniffer(self):
        # Sniffing filter to capture only TCP packets destined for the target IP
        filter_rule = f"dst host {self.targeted_ip} and tcp"

        # Start sniffing packets and analyze them with the analyze_packets function
        print(f"Starting packet sniffing on {self.targeted_ip}...")
        sniff(filter=filter_rule, prn=self.analyze_p)

    def run_deception(self):
        self.sniffer()
