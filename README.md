# NetScan

NetScan is an advanced network scanning tool developed in Python, designed to provide comprehensive insights into network devices and services. It incorporates cutting-edge techniques and features for efficient and thorough network reconnaissance.

## Features

### 1. Modern Graphical User Interface
- **User-Friendly Design:** Modern tkinter-based GUI with tabbed interface
- **Real-Time Monitoring:** Live progress tracking with detailed scan logs
- **Interactive Results Viewer:** Sortable table with detailed host information
- **Visual Network Topology:** Embedded matplotlib graphs showing network structure
- **Theme Support:** Light and dark theme options
- **Export Capabilities:** Multiple export formats (JSON, CSV, XML) directly from GUI
- **Scan Profiles:** Pre-configured scan settings (Quick, Normal, Deep)
- **Scan History:** Track and review all previous scans

### 2. Advanced Scanning Techniques
- **Service Detection:** Identify running services and their versions on open ports.
- **Operating System Detection:** Determine the operating system of detected devices.
- **Traceroute:** Trace the path packets take to reach target devices.
- **Banner Grabbing:** Gather service banners for detailed information.
- **Port Range Customization:** Configure specific port ranges to scan

### 3. Parallel and Asynchronous Scanning
- **Multithreading or Asynchronous I/O:** Implements parallel scanning for faster results.
- **Rate Limiting:** Control scanning rates to avoid network congestion or detection.
- **Configurable Workers:** Adjust the number of concurrent scan threads

### 4. Network Visualization
- **Interactive Network Map:** Visualize network topology using NetworkX and Matplotlib.
- **Detailed Reports:** Comprehensive, filterable reports saved in JSON format.
- **GUI-Integrated Topology:** View network diagrams directly in the application

## Installation

### Prerequisites
- Python 3.8 or higher
- Nmap (for advanced scanning features)
- Npcap (Windows only, for packet capturing)

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/OussamaERrafif/NetScan.git
   cd NetScan
   ```

2. **Create and activate a virtual environment (recommended):**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On Unix or MacOS
   source venv/bin/activate
   ```

3. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Nmap:**
   Download and install [Nmap](https://nmap.org/download.html) for additional scanning capabilities.

5. **Install Npcap (Windows only):**
   Download and install [Npcap](https://nmap.org/npcap/) to enable packet capturing and transmission on Windows.

## Usage

### GUI Application (Recommended)

NetScan now includes a modern graphical user interface for easier network scanning:

```bash
python launch_gui.py
```

Or from the src directory:

```bash
cd src
python gui.py
```

**GUI Features:**
- **Visual Scan Configuration**: Easy-to-use interface for network selection and scan profiles
- **Real-time Progress**: Live progress bar and detailed scan logs
- **Interactive Results**: Browse scan results in a sortable table, double-click for details
- **Network Topology Visualization**: Interactive network map with matplotlib
- **Export Options**: Export results to JSON, CSV, or XML formats
- **Scan Profiles**: Quick, Normal, and Deep scan presets
- **Scan History**: Track all previous scans with timestamps
- **Theme Support**: Switch between light and dark themes
- **Port Range Customization**: Configure which ports to scan

![NetScan GUI](https://github.com/user-attachments/assets/a240db97-b50e-4503-a513-8f16e02428ec)

### Command-Line Interface

Run the main application to scan your local network:

```bash
cd src
python app.py
```

The tool will:
1. Automatically detect your Wi-Fi network interface
2. Discover all active hosts on the network
3. Scan each host for services, OS information, and traceroute data
4. Save results to `scan_results.json`
5. Display a visual network topology

### Running Individual Modules

You can also use individual modules programmatically:

```python
import getipaddr
import discoverhosts

# Get local network
network = getipaddr.get_wifi_ip()
print(f"Scanning network: {network}")

# Discover hosts
hosts = discoverhosts.DiscoverHosts.discover_hosts(network)
print(f"Found {len(hosts)} hosts")
```

## Project Structure

```
NetScan/
├── src/
│   ├── app.py              # Main CLI application entry point
│   ├── gui.py              # Modern GUI application (NEW!)
│   ├── discoverhosts.py    # Host discovery and scanning
│   ├── getipaddr.py        # Network interface detection
│   ├── hostinfo.py         # Service and OS detection
│   ├── bannergrabbing.py   # Banner grabbing functionality
│   ├── traceroute.py       # Traceroute implementation
│   ├── rendertopo.py       # Network topology visualization
│   ├── export.py           # Export functionality (JSON, CSV, XML)
│   └── config.py           # Configuration management
├── launch_gui.py           # GUI launcher script (NEW!)
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── .gitignore            # Git ignore rules
```

## Output

Scan results are saved in `scan_results.json` with the following structure:

```json
[
    {
        "ip": "192.168.1.100",
        "mac": "AA:BB:CC:DD:EE:FF",
        "services": {
            "hostname": "device-hostname",
            "state": "up",
            "protocols": { ... }
        },
        "os": [ ... ],
        "traceroute": [ ... ]
    }
]
```

## Code Quality

This project follows PEP 8 style guidelines and includes:
- Comprehensive docstrings for all modules, classes, and functions
- Type hints where applicable
- Error handling for network operations
- Clean, maintainable code structure

## Security Considerations

⚠️ **Important:** This tool should only be used on networks you own or have explicit permission to scan. Unauthorized network scanning may be illegal in your jurisdiction.

- The tool performs active network scanning which may be detected by IDS/IPS systems
- OS detection requires elevated privileges (root/administrator)
- Always ensure you have proper authorization before scanning any network

## Future Enhancements

The following features are planned for future releases:

- **Customizable Scan Profiles:** Quick, full, and stealth scan presets
- **IPv6 Support:** Extend scanning capabilities to IPv6 networks
- **SNMP Scanning:** Gather detailed information from network devices
- **Web Interface:** Access and control via Flask web application
- **Vulnerability Detection:** Integration with CVE databases
- **Export Formats:** Support for XML and CSV output
- **Scheduling:** Automated scans at specified intervals
- **Machine Learning:** Anomaly detection and predictive analysis

## Dependencies

- **scapy:** Packet manipulation and network scanning
- **python-nmap:** Python wrapper for Nmap
- **psutil:** System and network utilities
- **networkx:** Network topology graph creation
- **matplotlib:** Network visualization

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have permission before scanning any network.

## References

- [Nmap](https://github.com/nmap/nmap) - The quintessential network scanning tool
- [Masscan](https://github.com/robertdavidgraham/masscan) - High-speed port scanning tool
- [ZMap](https://github.com/zmap/zmap) - Fast single-packet network scanner

## Author

OussamaERrafif

## Acknowledgments

Special thanks to the open-source community and the developers of Scapy, Nmap, and NetworkX for their excellent tools and libraries.
