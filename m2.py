import os
from scapy.all import sniff, IP, TCP
from datetime import datetime
import subprocess
import re
import time
from workspace1 import Requirments

r = Requirments()
data = []
class Monitor:
    def __init__(self):
        self.worksp = None
        self.location = "security_log.txt"



    # Network monitoring
    def monitor_network(self, packet):
        """Monitor incoming and outgoing network traffic."""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

                # Check for unusual connections (example: non-standard ports)
                if dst_port not in range(1, 1024):
                    data = ["Network Alert", f"Suspicious connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"]
                    # log_event("Network Alert", f"Suspicious connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    r.log(self.worksp, self.location,data)
                    self.notify_user("Network Alert", f"Suspicious connection detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

    # Alternative Process Monitoring Using /proc
    def monitor_processes(self):
        """Monitor running processes for unauthorized activities."""
        allowed_processes = ["sshd", "firefox", "chrome", "python3","/sbin/initsplash"]  # Modify based on your use case
        try:
            for pid in os.listdir('/proc'):
                if pid.isdigit():
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmdline = f.read()
                            process_name = re.split(r'\\x00|\\0', cmdline)[0]
                            if process_name and process_name not in allowed_processes:
                                data = ["Process Alert", f"Unauthorized process detected: {process_name} (PID: {pid})"]
                                r.log(self.worksp, self.location, data)
                                self.notify_user("Process Alert", f"Unauthorized process detected: {process_name}")
                    except (FileNotFoundError, PermissionError):
                        continue
        except Exception as e:
            data = [f"Process Alert",f"Process Monitoring Error {str(e)}"]
            r.log(self.worksp, self.location, data)

    def notify_user(self, title, message):
        """Send a desktop notification."""
        subprocess.run(["notify-send", title, message])

    def run_monitoring(self):
        # Run network monitoring in a separate thread
        from threading import Thread

        network_thread = Thread(target=lambda: sniff(prn=self.monitor_network, store=False))
        network_thread.daemon = True
        network_thread.start()

        print("Monitoring network and processes... Press Ctrl+C to exit.")

        try:
            while True:
                self.monitor_processes()
                time.sleep(5)  # Check processes every 5 seconds
        except KeyboardInterrupt:
            print("Exiting program.")
