from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
from datetime import datetime
import subprocess
# from detected_ip import Detected_ip
from workspace1 import Requirments

r = Requirments()
class Delection:
    def __init__(self):
        self.PORT_SCAN_THRUSHOLD = 10
        self.DNS_SCAN_THRUSHOLD = 10
        self.MONITOR_INTERVAL = 10
        self.network_activity = defaultdict(list) #Port / DNS
        self.src_ip = None
        self.dst_port = None
        self.current_time = time.time()
        self.dirname  = None

        

    
    # def log_event(self,event_type, details):
    #     #Egvent logs
    #     d_ip = Detected_ip()


    #     with open("Detection_log.txt", "a") as f:
    #         content = f"[{datetime.now} {event_type}: {details}]"
    #         f.write(f"{content}\n")
    #     d_ip.addTOlist(self.src_ip) # adding to the Block List
    #     '''print("do you want to run deception?")
    #        run_deception here!!'''

 

    def notify(self, event_type, details):
        #Notify the user about the potentioal scan detection
        subprocess.run(["notify-send", event_type, details])


    # CHecking the Thrushold            
    def chech_thrushold(self, thrushold):
        count = 0
        for port , entry_time in self.network_activity[self.src_ip]:
            count+=1
            print(f"\n[*] Port {port}",
                  f"[cT] {entry_time}")  # [ct] = current time
        print(f"\t[*] Monitored-count {count}")
        if count > thrushold:
            if thrushold == self.PORT_SCAN_THRUSHOLD:
                self.notify("Network Alert ",f"Potential Port Sacn Detected: {self.src_ip}:{self.dst_port}")
                data = ["Network Alert ",f"Potential Port Sacn Detected: {self.src_ip}:{self.dst_port}"]
                r.log(self.dirname, "Detection_log.txt", data)
                # self.log_event("Network Alert ",f"Potential Port Sacn Detected: {self.src_ip}:{self.dst_port}")
                print(f"\t[ALERT] Potential port scan detected from IP: {self.src_ip}\n\n")
            elif thrushold == self.DNS_SCAN_THRUSHOLD:
                self.notify("Network Alert ",f"Potential DNS Sacn Detected: {self.src_ip}")
                data = ["Network Alert ",f"Potential DNS Sacn Detected: {self.src_ip}"]
                r.log(self.dirname, "Detection_log.txt", data)
                # self.log_event("Network Alert ",f"Potential DNS Sacn Detected: {self.src_ip}")
                print(f"\t[ALERT] Potential port scan detected from IP: {self.src_ip}\n\n")

    

    # Track the port activities
    def trckP_activity(self, event): # event - Port ACtivity / DSN Activity
        self.network_activity[self.src_ip].append((self.dst_port, self.current_time))
        print(f"\n[*] {event} {self.network_activity}\n")
        # Remove the old Acvtivity
        self.network_activity[self.src_ip] = [entry for entry in self.network_activity[self.src_ip] if (self.current_time - entry[1]) <= self.MONITOR_INTERVAL]
        print(f"\n[*] new_{event} {self.network_activity[self.src_ip]}\n")

        for entry in self.network_activity[self.src_ip]:
            print(f"[cT] {self.current_time} : [ET] {entry[1]}")
            print(f"[ETD] {self.current_time - entry[1]}")
 
    
    def detect_port_scan(self, packet):
        print(f"[<*>] Packets {packet}")
        if packet.haslayer(TCP):
            
            self.src_ip = packet[IP].src
            self.dst_port = packet[TCP].dport
            if self.src_ip != "192.168.43.198":
                print(f"\n\t[+] Source IP:PORT {self.src_ip}:{self.dst_port}")     
                
                self.trckP_activity("Port Activity")   
                self.chech_thrushold(self.PORT_SCAN_THRUSHOLD)
            else:
                print("Own!") 
 

    def detect_dns_scan(self, packet):
        print(f"[<*>] Packets {packet}")
        if packet.haslayer(UDP) and packet[UDP].dport == 53:
            self.src_ip = packet[IP].src
            if self.src_ip == "192.168.43.198":
                print(f"\n\t[+] Source IP {self.src_ip}")     
                
                self.trckP_activity("DNS Activity")   
                self.chech_thrushold(self.DNS_SCAN_THRUSHOLD)
            else:
                print("Own!") 
            
    def packet_handler1(self, packet):
            print("------------------------------------------------------------------------------------------------------------")
            if packet.haslayer(IP):
                self.detect_port_scan(packet)
    def packet_handler2(self, packet):
        print("------------------------------------------------------------------------------------------------------------")
        if packet.haslayer(IP):
            self.detect_dns_scan(packet)
    
 
    def packetSniffer1(self):
        print("[INFO] Starting network scan detection...")
        try :
            sniff(filter="ip", prn=self.packet_handler1, store=False)
        except KeyboardInterrupt:
            print("\n[INFO] Stopping network scan detection.")
    def packetSniffer2(self):
        print("[INFO] Starting network scan detection...")
        try :
            sniff(filter="ip", prn=self.packet_handler2, store=False)
        except KeyboardInterrupt:
            print("\n[INFO] Stopping network scan detection.")

if __name__ == "__main__":
    d = Delection()
    d.packetSniffer2()
