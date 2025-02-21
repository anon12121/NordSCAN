# NordSCAN 🛡️

NordSCAN is a lightweight, customizable vulnerability scanner designed for red teamers and penetration testers. It automates common security tasks such as port scanning, directory traversal detection, and outdated software version checks.

---

## Features ✨
- **Port Scanning**: Scans common ports for open services.
- **Directory Traversal Detection**: Tests for path traversal vulnerabilities.
- **Outdated Software Detection**: Identifies software versions from HTML meta tags.
- **Customizable**: Easily extendable with new vulnerability checks.

---

## Installation 🛠️

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/NordSCAN.git
   cd NordSCAN

    Install dependencies:
    bash
    Copy

    pip install -r requirements.txt

Usage �

Run NordSCAN with the following command:
bash
Copy

python nordscan.py --target <target_url_or_ip>

Example:
bash
Copy

python nordscan.py --target http://example.com

Options ⚙️

    --target: Target URL or IP address.

    --ports: Custom ports to scan (default: 21, 22, 80, 443, 8080).

    --output: Save results to a file (e.g., --output scan_results.txt).

Contributing 🤝

Contributions are welcome! Feel free to open an issue or submit a pull request.