import dns.exception
import dns.resolver
import socket

class Dns_exploere:
    def __init__(self):
        self.domains = {}
        self.subs_file = "dns_search.txt"
        self.target_domain = None
        self.inclued_numbers = True
        
        self.res = dns.resolver.Resolver()
        self.res.nameservers = ["8.8.8.8"]
        self.res.port = 53

    def reverse_dns(self, ip):
        try:
            result = socket.gethostbyaddr(ip)
            return [result[0]] + result[2]
        except socket.herror:
            return []
        
    def dns_request(self, domain):

        try:
            result = self.res.resolve(domain)
            addres = [str(a) for a in result]

            if domain in self.domains:
                self.domains[domain] = set()
                self.domains[domain].update(addres)
            else:
                self.domains[domain] = set(addres)
            
            for ip in addres:
                reverse_domain = self.reverse_dns(ip)
                for rev_domain in reverse_domain:
                    if rev_domain in reverse_domain:
                        self.domains[rev_domain] = {ip}
                    else:
                        self.domains[rev_domain].add(ip)

        except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass

    def subdomain_search(self, domain, subdomain_list, include_no = False):
        for sub in subdomain_list:
            full_domain = f"{sub}.{domain}"
            self.dns_request(full_domain)

            if include_no:
                for i in range(10):
                    numbered_domain = f"{sub}{i}.{domain}"
                    self.dns_request(numbered_domain)

    def load_subdomains(self, file_path):
        with open(file_path, "r") as f:
            return f.read().splitlines()
        
    def run_DNS_Expl(self, target_d):
        self.target_domain = target_d
        subdomain_list = self.load_subdomains(self.subs_file)
        # Perform the subdomain search
        self.subdomain_search(self.target_domain, subdomain_list, self.inclued_numbers)

        # print result
        for domain, ip in self.domains.items():
            print(f"[+] {domain}: {', '.join(ip)}")

'''if __name__ == "__main__":
    d = Dns_exploere()
    d.run_DNS_Expl()'''




        
