class Detected_ip:
    def __init__(self):
        self.blocked_source = []
    
    def addTOlist(self, ip):
        self.blocked_source.append(ip)
        print(f"\n\t[/|*] IP {ip} added to the blocked sources.")
    