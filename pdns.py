import scapy.all as scapy
import ipaddress
#from scapy.all import sr1, IP, UDP, DNS, DNSQR, TCP
from ports import Ports
import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)


class Scan:
    #A class for the scanning the ports and the DNS
    def __init__(self, target=None, domain=None):
        #initialinzing the target and the ports attributs
        self.target = target
        self.domain = domain
        
        
    def port_scanner(self, port):
        #creating a TCP packet
        synPacket = scapy.IP(src="192.168.43.198",dst=self.target)/scapy.TCP(sport=20, dport=port, flags="S")
        response = scapy.sr1(synPacket, timeout=1) # sending the packet and reciving the response.

        if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags =="SA":
            print(f"{Fore.GREEN}{Style.BRIGHT}[+] {Fore.CYAN}Port {port} is open")
            rst_packet = scapy.IP(src="127.0.0.1", dst=self.target)/scapy.TCP(sport=20, dport=port, flags="R")     #sending back the packet with flage of the reset[R]
            scapy.send(rst_packet)
            return port
        else:
            print(f"{Fore.YELLOW}{Style.BRIGHT}[-] {Fore.CYAN}Ports {port} is closed ot filterd")
        

    def dns_service_scanner(self, domain, port=53):
        print(f"{Fore.MAGENTA}Scanning {self.target} to identify DNS service provider on port {port}...")

        # Construct the DNS request packet
        dns_request = scapy.IP(dst=self.target) / scapy.UDP(dport=port) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=domain))

        try:
            # Send the packet and wait for a response
            response = scapy.sr1(dns_request, timeout=1, verbose=0)

            if response and response.haslayer(scapy.DNS):
                dns_response = response[scapy.DNS]
                print(f"{Fore.GREEN}{Style.BRIGHT}[+] {Fore.CYAN}DNS server is running on {self.target}:{port}!")

                # Extract authoritative nameserver information if available
                if dns_response.an:  # Answer section
                    print(f"{Fore.GREEN}{Style.BRIGHT}[+] {Fore.CYAN}Answer Section:")
                    for ans in dns_response.an:
                        print(f"    {ans.rdata}")

                if dns_response.ns:  # Nameserver section
                    print(f"{Fore.GREEN}{Style.BRIGHT}[+] {Fore.CYAN}Nameserver Section:")
                    for ns in dns_response.ns:
                        print(f"    {ns.rdata}")

                if dns_response.ar:  # Additional section
                    print(f"{Fore.GREEN}{Style.BRIGHT}[+] {Fore.CYAN}Additional Section:")
                    for ar in dns_response.ar:
                        print(f"    {ar.rdata}")

            else:
                print(f"{Fore.RED}{Style.BRIGHT}[-] {Fore.CYAN}No DNS response from {self.target}:{port}. Server might not be running or reachable.")

        except Exception as e:
            print(f"{Fore.RED}{Style.BRIGHT}[!] An error occurred: {e}")

    def ip_validation(self, target):
        # Handle single IP or subnet
        try:
            ip_network = ipaddress.ip_network(target, strict=False)
        except ValueError as e:
            print(f"Invalid IP or subnet: {e}")
            exit(1)


    

'''p = Ports()
s = Scan("103.105.78.137")
x = [] #initial return value of the port_scanner
for port in p.ports:
    s.ip_validation(s.target)
    open_port = s.port_scanner(port)
    x.append(open_port)

open_ports = [port for port in x if type(port) == int]
print(f"Open Ports = {open_ports}")
s.dns_service_scanner("google.com")    '''
