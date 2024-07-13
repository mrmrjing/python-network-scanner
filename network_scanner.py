import nmap
import json
import threading
from concurrent.futures import ThreadPoolExecutor

lock = threading.Lock()

def scan_ports(ip_range, port_start, port_end, results):
    print(f"Starting scan for {ip_range} on ports {port_start}-{port_end}...")
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments=f'-p {port_start}-{port_end}')

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

        with lock:
            # Check if the host is already in the results to prevent duplicates
            if not any(res['host'] == host for res in results):
                results.append(host_info)

def write_results_to_file(results):
    with open('scan_results.json', 'w') as file:
        json.dump(results, file, indent=4)

def remove_duplicates(results):
    unique_results = []
    seen_hosts = set()
    for result in results:
        if result['host'] not in seen_hosts:
            unique_results.append(result)
            seen_hosts.add(result['host'])
    return unique_results

def main():
    ip_range = input("Enter the IP range to scan (e.g., 192.168.10.0/24): ")
    port_start = 1
    port_end = 1024
    num_threads = 4
    results = []

    ports_per_thread = (port_end - port_start + 1) // num_threads
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for i in range(num_threads):
            start = port_start + i * ports_per_thread
            end = start + ports_per_thread - 1 if i < num_threads - 1 else port_end
            futures.append(executor.submit(scan_ports, ip_range, start, end, results))
        for future in futures:
            future.result()

    # Remove duplicates after all threads are done
    clean_results = remove_duplicates(results)
    write_results_to_file(clean_results)
    print("Network scan completed successfully and results logged to JSON file.")

if __name__ == "__main__":
    main()
