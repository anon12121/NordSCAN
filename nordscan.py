python
import argparse
import requests
import socket
from bs4 import BeautifulSoup

# Banner
BANNER = """
  _   _ ____  _____ ____  _____ _   _ ____  
 | \ | |  _ \| ____|  _ \| ____| \ | |  _ \ 
 |  \| | |_) |  _| | |_) |  _| |  \| | | | |
 | |\  |  _ <| |___|  __/| |___| |\  | |_| |
 |_| \_|_| \_\_____|_|   |_____|_| \_|____/ 

 NordSCAN - Lightweight Vulnerability Scanner
"""

print(BANNER)

# Function to check for open ports
def port_scan(target, ports):
    print(f"[+] Scanning ports on {target}...")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is open")
            sock.close()
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")

# Function to check for directory traversal vulnerability
def check_directory_traversal(url):
    print(f"[+] Checking for directory traversal vulnerabilities on {url}...")
    payloads = ["../", "../../", "../../../"]
    for payload in payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200 and "root" in response.text.lower():
                print(f"[!] Potential directory traversal vulnerability found: {test_url}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error testing directory traversal: {e}")

# Function to check for outdated software versions
def check_outdated_software(url):
    print(f"[+] Checking for outdated software versions on {url}...")
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if 'generator' in tag.get('name', '').lower():
                print(f"[+] Software version detected: {tag.get('content')}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error checking software versions: {e}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="NordSCAN - Lightweight Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target URL or IP address")
    parser.add_argument("--ports", nargs="+", type=int, default=[21, 22, 80, 443, 8080], help="Ports to scan")
    parser.add_argument("--output", help="Save results to a file")
    args = parser.parse_args()

    target = args.target
    ports = args.ports

    # Perform scans
    port_scan(target, ports)
    check_directory_traversal(target)
    check_outdated_software(target)

    # Save results to file if specified
    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Scan results for {target}\n")
            f.write("Open ports: " + ", ".join(map(str, ports)) + "\n")
        print(f"[+] Results saved to {args.output}")

    print("\n[+] Scan complete!")

if __name__ == "__main__":
    main()
