# NetScan Quick Start Guide

This guide will help you get started with NetScan quickly.

## Prerequisites

Before you begin, ensure you have:
- Python 3.8 or higher installed
- Administrator/root privileges (required for network scanning)
- Nmap installed on your system

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/OussamaERrafif/NetScan.git
cd NetScan
```

### Step 2: Create Virtual Environment

```bash
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on Linux/Mac
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

## Basic Usage

### Run a Simple Scan

The simplest way to run NetScan is to let it auto-detect your network:

```bash
cd src
python app.py
```

This will:
1. Detect your Wi-Fi network automatically
2. Scan all hosts on the network
3. Display results and generate a network topology visualization

### Specify a Network

To scan a specific network:

```bash
python app.py --network 192.168.1.0/24
```

### Skip Topology Visualization

If you don't want the topology graph to display:

```bash
python app.py --no-topology
```

### Use a Configuration File

First, create a configuration file:

```bash
python app.py --create-config
```

This creates `config.json` with default settings. Edit it to customize your scans.

Then use it:

```bash
python app.py --config config.json
```

## Understanding the Output

### JSON Output

Results are saved in `scan_results.json` with the following structure:

```json
[
    {
        "ip": "192.168.1.100",
        "mac": "AA:BB:CC:DD:EE:FF",
        "services": {
            "192.168.1.100": {
                "hostname": "my-computer",
                "state": "up",
                "protocols": {
                    "tcp": {
                        "services": [
                            {
                                "port": 80,
                                "name": "http",
                                "version": "Apache 2.4"
                            }
                        ]
                    }
                }
            }
        },
        "os": [...],
        "traceroute": [...]
    }
]
```

## Advanced Features

### Export to Different Formats

Edit your `config.json` to export results in different formats:

```json
{
    "output": {
        "format": "csv",  // or "xml", "json"
        "file": "scan_results.csv"
    }
}
```

### Configure Scan Settings

Edit `config.json` to customize scan behavior:

```json
{
    "scan": {
        "max_workers": 5,      // Increase for faster scans
        "timeout": 5,          // Increase for slow networks
        "exclude_ips": [       // IPs to skip
            "192.168.1.1",
            "192.168.1.254"
        ]
    }
}
```

### Disable Specific Features

You can disable features you don't need:

```json
{
    "features": {
        "service_detection": true,
        "os_detection": false,     // Disable OS detection
        "banner_grabbing": true,
        "traceroute": false        // Disable traceroute
    }
}
```

## Common Issues

### Permission Denied

Network scanning requires elevated privileges:

**Windows:**
```bash
# Run Command Prompt as Administrator
python app.py
```

**Linux/Mac:**
```bash
sudo python app.py
```

### No Network Detected

If automatic detection fails:

1. Check your network connection
2. List available interfaces:
   ```python
   import getipaddr
   interfaces = getipaddr.get_all_network_interfaces()
   print(interfaces)
   ```
3. Specify network manually:
   ```bash
   python app.py --network YOUR_NETWORK/24
   ```

### Nmap Not Found

Install Nmap:
- **Windows**: Download from https://nmap.org/download.html
- **Linux**: `sudo apt-get install nmap`
- **Mac**: `brew install nmap`

## Getting Help

For more information:

```bash
python app.py --help
```

For issues or questions:
- Check the [README.md](README.md)
- Review [CONTRIBUTING.md](CONTRIBUTING.md)
- Open an issue on GitHub

## Next Steps

- Explore the [full documentation](README.md)
- Customize your configuration
- Learn about security considerations
- Contribute to the project!

## Security Warning

⚠️ **Important**: Only scan networks you own or have explicit permission to scan. Unauthorized network scanning may be illegal.
