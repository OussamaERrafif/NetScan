# NetScan GUI Feature Summary

## Overview

NetScan now includes a modern graphical user interface (GUI) that makes network scanning accessible to all users, regardless of their command-line expertise.

## Quick Start

Launch the GUI with:
```bash
python launch_gui.py
```

## Main Features

### 1. Scan Tab
- **Auto-detect Network**: Automatically finds your network interface
- **Scan Profiles**: 
  - Quick Scan (2 workers, 2s timeout)
  - Normal Scan (4 workers, 5s timeout)
  - Deep Scan (8 workers, 10s timeout)
- **Port Range**: Customize which ports to scan
- **Real-time Progress**: Live progress bar and detailed logs

### 2. Results Tab
- **Interactive Table**: View all discovered hosts
- **Detailed Information**: Double-click any host for full details
- **Export Options**: Save results as JSON, CSV, or XML
- **Service Detection**: See all open ports and services

### 3. Topology Tab
- **Visual Network Map**: Graphical representation using matplotlib
- **Auto-refresh**: Updates after each scan
- **Interactive**: Zoom and pan the network graph

### 4. Settings Tab
- **Scan Profiles Info**: View details of each scan profile
- **Theme Selector**: Switch between light and dark themes
- **About Information**: App version and feature list

## Keyboard Shortcuts

- `Ctrl+N` - New Scan
- `Ctrl+S` - Start Scan (on Scan tab)
- `Ctrl+O` - Open Results
- `Ctrl+T` - Toggle Theme
- `F1` - Show Documentation
- `F5` - Refresh Topology
- `Escape` - Stop Current Scan
- `Ctrl+Q` - Quit Application

## User Interface Elements

### Status Bar
The bottom status bar shows:
- Current application status (left)
- Version information (right)

### Tooltips
Hover over any button or input field to see helpful tooltips explaining their function.

### Menu Bar
- **File**: New scan, open results, export options
- **View**: Scan history, network topology, toggle theme
- **Help**: Keyboard shortcuts, documentation, about

## Features Overview

| Feature | Description |
|---------|-------------|
| Auto-detect Network | Automatically finds your WiFi or Ethernet network |
| Scan Profiles | Pre-configured settings for different scanning speeds |
| Real-time Progress | Live updates on scan status with detailed logs |
| Interactive Results | Sortable table with detailed host information |
| Network Topology | Visual graph of your network structure |
| Export Formats | Save results as JSON, CSV, or XML |
| Scan History | Track all previous scans with timestamps |
| Keyboard Shortcuts | Efficient navigation with keyboard commands |
| Theme Support | Choose between light and dark themes |
| Tooltips | Helpful hints on all interactive elements |

## Security Notes

⚠️ **Important**: 
- Only scan networks you own or have permission to scan
- Some features require administrator/root privileges
- Network scanning may be detected by IDS/IPS systems

## CLI Still Available

The command-line interface remains fully functional:
```bash
cd src
python app.py
```

## Technical Details

- Built with Python tkinter and ttk
- Uses matplotlib for topology visualization
- NetworkX for graph generation
- Threaded scanning for responsive UI
- JSON-based scan history storage

## Getting Help

- Press `F1` in the app for documentation
- Check the Help menu for keyboard shortcuts
- See README.md for complete documentation
- Visit QUICKSTART.md for step-by-step guide

## System Requirements

- Python 3.8 or higher
- tkinter (usually included with Python)
- All dependencies from requirements.txt
- Administrator/root privileges for full functionality

## Troubleshooting

**GUI won't launch:**
- Ensure tkinter is installed: `python -m tkinter`
- Install if needed: `sudo apt-get install python3-tk` (Linux)

**Auto-detect fails:**
- Manually enter your network (e.g., 192.168.1.0/24)
- Check network connection
- Try Ethernet if WiFi detection fails

**Scan not working:**
- Run with administrator/root privileges
- Check firewall settings
- Ensure Nmap is installed

## Version Information

- NetScan Version: 2.0.0
- GUI Added: 2025
- License: MIT

## Feedback

For bugs, features, or improvements:
- Open an issue on GitHub
- See CONTRIBUTING.md for guidelines
