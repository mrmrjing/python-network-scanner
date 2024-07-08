import nmap

def scan_network(ip_range, ports="1-1024"): 
    # Create a scanner object 
    scanner = nmap.PortScanner()

    # Scan the specified IP range and port range 
    scanner.scan(hosts=ip_range, arguments=f"-p {ports}")

    # Iterate over all the hosts in the scan results that are up 
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")

        # Iterate over all scanned protocols (TCP/UDP)
        for protocol in scanner[host].all_protocols():
            print(f'----------')
            print(f"Protocol: {protocol}")

            # Get all ports for the protocol and print the port number and state
            lport = scanner[host][protocol].keys()
            for port in lport:
                print(f"Port: {port}\tState: {scanner[host][protocol][port]['state']}")

    print("Netwok scan completed successfully!")
    
if __name__ == "__main__":
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    ports = input("Enter the range of ports to scan (default is 1-1024): ")
    print("You entered IP range: " + ip_range + " and ports: " + ports)
    scan_network(ip_range, ports)
