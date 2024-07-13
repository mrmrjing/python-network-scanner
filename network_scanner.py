import nmap
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse
import logging

# Set up basic configuration for logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_ports(ip_range, port_start, port_end, results, lock):
    logging.info(f"Starting scan for {ip_range} on ports {port_start}-{port_end}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip_range, arguments=f'-p {port_start}-{port_end}')
    except nmap.PortScannerError as e:
        logging.error(f"Scan failed: {e}")
        return
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return

    for host in nm.all_hosts():
        host_info = {
            'host': host,
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'protocols': {}
        }
        for proto in nm[host].all_protocols():
            ports_info = []
            for port in nm[host][proto].keys():
                ports_info.append({
                    'port': port,
                    'state': nm[host][proto][port]['state']
                })
            host_info['protocols'][proto] = ports_info
        
        # Lock the results list only when necessary
        with lock:
            existing = next((r for r in results if r['host'] == host), None)
            if existing:
                for proto, ports in host_info['protocols'].items():
                    if proto in existing['protocols']:
                        existing['protocols'][proto].extend(ports)
                    else:
                        existing['protocols'][proto] = ports
            else:
                results.append(host_info)

def write_results_to_file(results, filename):
    with open(filename, 'w') as file:
        json.dump(results, file, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument('--ip', required=True, help='IP range to scan, e.g., 192.168.10.0/24')
    parser.add_argument('--start_port', type=int, default=1, help='Start of the port range')
    parser.add_argument('--end_port', type=int, default=1024, help='End of the port range')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads to use')
    parser.add_argument('--output', type=str, default='scan_results.json', help='Output file name')
    args = parser.parse_args()

    results = []
    lock = threading.Lock()
    ports_per_thread = (args.end_port - args.start_port + 1) // args.threads
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for i in range(args.threads):
            start = args.start_port + i * ports_per_thread
            end = start + ports_per_thread - 1 if i < args.threads - 1 else args.end_port
            futures.append(executor.submit(scan_ports, args.ip, start, end, results, lock))
        for future in futures:
            future.result()

    write_results_to_file(results, args.output)
    logging.info("Network scan completed successfully. Results have been saved to %s", args.output)

if __name__ == "__main__":
    main()
