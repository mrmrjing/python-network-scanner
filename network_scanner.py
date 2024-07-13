import asyncio
import nmap
import json
import argparse
import logging

# Set up basic configuration for logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def scan_ports(ip_range, port_start, port_end, results):
    logging.info(f"Starting async scan for {ip_range} on ports {port_start}-{port_end}")
    nm = nmap.PortScanner()
    try:
        await asyncio.get_running_loop().run_in_executor(None, lambda: nm.scan(hosts=ip_range, arguments=f'-p {port_start}-{port_end}'))
    except nmap.PortScannerError as e:
        logging.error(f"Scan failed: {e}")
        return
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return

    for host in nm.all_hosts():
        if host not in results:
            results[host] = {
                'ip': host,
                'hostname': nm[host].hostname(),
                'state': nm[host].state(),
                'protocols': {}
            }

        for proto in nm[host].all_protocols():
            if proto not in results[host]['protocols']:
                results[host]['protocols'][proto] = []
                
            for port in nm[host][proto].keys():
                port_info = {
                    'port': port,
                    'state': nm[host][proto][port]['state']
                }
                if port_info not in results[host]['protocols'][proto]:
                    results[host]['protocols'][proto].append(port_info)

async def main():
    parser = argparse.ArgumentParser(description="Async Network Scanner Tool")
    parser.add_argument('--ip', required=True, help='IP range to scan, e.g., 192.168.10.0/24')
    parser.add_argument('--start_port', type=int, default=1, help='Start of the port range')
    parser.add_argument('--end_port', type=int, default=1024, help='End of the port range')
    args = parser.parse_args()

    results = {}
    tasks = []

    task_count = 10  # Example: Split the port range into 10 parts
    ports_per_task = (args.end_port - args.start_port + 1) // task_count

    for i in range(task_count):
        start = args.start_port + i * ports_per_task
        end = start + ports_per_task - 1 if i < task_count - 1 else args.end_port
        tasks.append(scan_ports(args.ip, start, end, results))

    await asyncio.gather(*tasks)

    # Write updated results back to the file, converting dictionary to list if needed for JSON serialization
    with open('scan_results.json', 'w') as file:
        json.dump(list(results.values()), file, indent=4)
    logging.info("Network scan completed successfully. Updated results have been saved to scan_results.json")

if __name__ == "__main__":
    asyncio.run(main())
