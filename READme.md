# Python Network Scanner
## Overview
This Python Network Scanner allows users to scan specified IP ranges and port ranges within a network. It identifies hosts that are up and checks for open ports on these hosts, providing insights into network security and configuration. This tool leverages the python-nmap library, which is a Python wrapper for Nmap, one of the most popular network scanning tools.

## Features
- Host Discovery: Detect active devices within a specified IP range.
- Port Scanning: Scan for open ports on discovered hosts within a specified port range.
- Protocol Identification: Identify protocols used by open ports.

## Installation
### Prerequisites
- Python 3.x
- pip (Python package installer)

### Setup
1. Clone the Repository (if applicable):

git clone https://your-repository-url
cd network-scanner


2. Install Dependencies:

pip install python-nmap


## Usage
To use the network scanner, follow these steps:

1. Run the Script:

python network_scanner.py

2. Enter the IP Range:

When prompted, enter the IP range you wish to scan (e.g., 192.168.1.0/24).

3. Enter the Port Range:

Optionally, enter the range of ports to scan (default is 1-1024).

The script will output the status of each host within the range, listing open ports and their states.

