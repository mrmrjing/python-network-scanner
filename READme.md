# Python Network Scanner
## Overview
This Python Network Scanner allows users to scan specified IP ranges and port ranges within a network. It identifies hosts that are up and checks for open ports on these hosts, providing insights into network security and configuration. This tool leverages the python-nmap library, which is a Python wrapper for Nmap, one of the most popular network scanning tools.

## Features
- Host Discovery: Detect active devices within a specified IP range.
- Port Scanning: Scan for open ports on discovered hosts within a specified port range.
- Protocol Identification: Identify protocols used by open ports.

## Purpose of network scanning 
Network scanning for open ports is a critical activity in network security management. By identifying which ports are open, security practitioners can determine what services are exposed on a network device, such as a personal computer or a router. This information is crucial for both securing and managing network resources effectively.

### For Security Practitioners:
- **Vulnerability Assessment:** Open ports can reveal what services are running on a device. Each open port may correspond to a service that could have vulnerabilities.
- **Security Posture:** Knowing which ports are open helps in hardening security, such as closing unnecessary ports, applying necessary patches, and configuring firewalls.
- **Compliance Checks:** Ensures that the network complies with security policies and standards by verifying that only authorized ports are open.

### For Attackers:
- **Entry Points:** Open ports serve as gateways into the network. Attackers scan for open ports as the first step in an attack vector to exploit vulnerabilities in services running on these ports.
- **Service Identification:** By determining what services are running, attackers can tailor their attacks using known exploits that target specific vulnerabilities of those services.

## Installation
### Prerequisites
- Python 3.x
- pip (Python package installer)

### Setup
1. Clone the Repository (if applicable):

git clone https://github.com/mrmrjing/python-network-scanner.git
cd network-scanner


2. Install Dependencies:

pip install python-nmap

## Usage
To use the network scanner, follow these steps:
1. Modify the script parameters as necessary, particularly the target IP addresses and the desired port range.
2. Run the script from the command line:
```bash
python network_scanner.py --ip 192.168.10.0/24 --start_port 1 --end_port 65535
```

The output JSON file (scan_results.json) will contain detailed information on each host scanned, including IP addresses, hostnames, port states, and any detected protocols.

## Disclaimer 
This tool is meant for educational and security assessment purposes only, and should only be used on networks where you have permission to perform such scans. Unauthorized scanning of networks can be illegal and unethical.