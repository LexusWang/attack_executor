import subprocess
import sys

import nmap as pynamp
import xml.etree.ElementTree as ET


class NmapExecutor:
    def __init__(self):
        """
        It sets up the initial state by assigning values to instance attributes.
        """
        pass

    def run_nmap(self, target):
        # Run an Nmap scan with no host discovery (-Pn), default NSE scripts (-sC), service version detection (-sV), and return XML output as a string.
        cmd = ["nmap", "-Pn", "-sC", "-sV", "-oN", "-", target]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            print(f"[!] nmap error: {res.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
        return res.stdout

    def parse_nmap(self, xml_data):
        """Parse nmap XML and return list of open ports with service info."""
        ports = []
        root = ET.fromstring(xml_data)
        # pull every <port>, then check its <state> child
        for p in root.findall(".//port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": p.get("portid"),
                "proto": p.get("protocol"),
                "name": svc.get("name", ""),
                "product": svc.get("product", ""),
                "version": svc.get("version", "")
            })
        return ports

    def scan_xml(self, target):
        xml_out = self.run_nmap(target)
        services = self.parse_nmap(xml_out)

        return services

    def scan(self,
             target,
             options):        
        self.scanner = pynamp.PortScanner()
        # Run a basic scan on the target
        self.scanner.scan(target, arguments=options)

        # Print the scan results
        for host in self.scanner.all_hosts():
            print("Host: ", host)
            print("State: ", self.scanner[host].state())
            for proto in self.scanner[host].all_protocols():
                print("Protocol: ", proto)
                ports = self.scanner[host][proto].keys()
                for port in ports:
                    print("Port: ", port, "State: ", self.scanner[host][proto][port]['state'])
                    
if __name__ == "__main__":            
    nmapper = NmapExecutor()
    # nmapper.scan(target="10.129.144.184",
    #        options = "-sS -sV -O -A")
    nmapper.run_nmap("10.129.144.184")


