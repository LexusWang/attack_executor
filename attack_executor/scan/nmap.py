import nmap

class NmapExecutor:
    def __init__(self):
        """
        It sets up the initial state by assigning values to instance attributes.
        """
        self.scanner = nmap.PortScanner()

    def scan(self,
             target,
             options):        

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
                    
                    
nmape = NmapExecutor()
nmape.scan(target="10.10.10.3",
           options = "-sS -sV -O -A -p 1-1000")


