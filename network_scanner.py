import nmap
from concurrent.futures import ThreadPoolExecutor

def scan_ports(ip_range, port_start, port_end):
    print(f"Starting scan for {ip_range} on ports {port_start}-{port_end}...")
    
    # Create a scanner object
    nm = nmap.PortScanner()
    
    # Scan the specified IP range and port range
    nm.scan(hosts=ip_range, arguments=f'-p {port_start}-{port_end}')
    
    # Iterate over all hosts in the scan results that are up
    for host in nm.all_hosts():
        print(f'Host : {host} ({nm[host].hostname()})')
        print(f'State : {nm[host].state()}')

        # Iterate over all scanned protocols (TCP/UDP)
        for proto in nm[host].all_protocols():
            print('----------')
            print(f'Protocol : {proto}')

            # Get all ports for the protocol
            lport = nm[host][proto].keys()
            for port in lport:
                print(f'port : {port}\tstate : {nm[host][proto][port]["state"]}')

def main():
    ip_range = input("Enter the IP range to scan (e.g., 192.168.10.0/24): ")
    port_start = 1
    port_end = 1024
    num_threads = 4  # Number of threads to use for scanning different port ranges

    # Calculate the number of ports per thread
    ports_per_thread = (port_end - port_start + 1) // num_threads

    # Using ThreadPoolExecutor to manage multiple threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for i in range(num_threads):
            start = port_start + i * ports_per_thread
            if i == num_threads - 1:
                end = port_end  # Ensure the last segment includes any remainder
            else:
                end = start + ports_per_thread - 1
            futures.append(executor.submit(scan_ports, ip_range, start, end))
        for future in futures:
            future.result()  # Wait for all threads to complete

    print("Network scan completed successfully for all port ranges.")

if __name__ == "__main__":
    main()
