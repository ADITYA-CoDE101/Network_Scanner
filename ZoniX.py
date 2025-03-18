from pdns import Scan
from ports import Ports
from datetime import datetime
import pyfiglet
import colorama
from colorama import Fore, Back, Style
from portScanDEtect import Delection
from deception import Deception
from DNS_expo import Dns_exploere
from m2 import Monitor
from workspace1 import Requirments
#dns.dns_service_scanner("8.8.8.8", "google.com" )
#ps.main("8.8.8.8","1-20")
colorama.init(autoreset=True)
print(pyfiglet.figlet_format("-by       ", justify="right", font="wideterm"))
print(pyfiglet.figlet_format("Aditya", justify="right", font="digital"))
print(pyfiglet.figlet_format("Vipul Dhiman", justify="right", font="digital"))
print(pyfiglet.figlet_format("Varsha Rajbhar", justify="right", font="digital"))
print(pyfiglet.figlet_format("ZoniX", justify="center", font="bigmono9"))
print(pyfiglet.figlet_format("Network Scanning Tool.", justify="center", font="mini"))
# port scaner
# dns scanner
# port scan detectiion
# dns scan detection
# port deception
# dns explorer
# Network and processes monitoring


print(f"ZoniX Networking Tool.")
avtivation = True

# def log_entry(file_path, event, data):
#     with open(file_path, "a") as f:
#         entry = f"{[datetime.now()]} {event}: {data}\n"
#         f.write(entry)

d = Delection()
pd = Deception()
dx = Dns_exploere()
# workspace = str(input("Create a workspace-"
#                       "\n Name - "))
r = Requirments()
r.workspace()

while avtivation:
    cmd = input(f"┌──({Fore.YELLOW}{Style.BRIGHT}{r.dirName}$commnad)-[{Fore.WHITE}{Style.BRIGHT}~{datetime.now()}]"
                f"\n└─{Fore.BLUE}{Style.BRIGHT}#{Fore.CYAN} ")

    # [-pS, -dS, -psD, -dsD, --deception/-pd, -dexp, -mo, -q/ --exit]
    # -q or --exit to exit from the tool

    
    p = Ports()
    
    if cmd == "-pS":
        targetIP = str(input("Target>"))
        s = Scan(target=targetIP)
        x = [] #initial return value of the port_scanner
        
        for port in p.ports:
            s.ip_validation(s.target)
            open_port = s.port_scanner(port)
            x.append(open_port)

        open_ports = [port for port in x if type(port) == int]
        print(f"{Fore.MAGENTA}{Style.BRIGHT}Open Ports = {open_ports}")
        file_path = "openPort.txt"
        data = ["Port_scan",open_ports]
        r.log(r.dirName, file_path, data)
        # log_entry(file_path, "Port_scan",open_ports)
        
        
    elif cmd == "-dS":
        target = str(input("Target>"))
        domain = str(input("Domain>"))
        s = Scan(target=target, domain=domain)
        s.dns_service_scanner(s.domain)

    elif cmd == "-psD":
        d.dirname = r.dirName
        d.packetSniffer1()
    elif cmd == "-dsD":
        d.dirname = r.dirName
        d.packetSniffer2()
    elif cmd in ("--deception", "-pd"):
        pd.run_deception()
    elif cmd == "-dexp":
        target = str(input("Target>"))
        dx.run_DNS_Expl(target)
    elif cmd == "-mo":
        m = Monitor()
        m.worksp = r.dirName
        m.run_monitoring()
    elif cmd == "-h":
        with open("help.txt", "r") as f:
            content = f.read()
            print(f"{Fore.YELLOW}{Back.BLACK}{Style.BRIGHT}{content}")
    elif cmd in ["-q", "--exit"]:
        print(pyfiglet.figlet_format("...EXITING...", justify="center", font="wideterm"))
        print("")
        avtivation = False
    
