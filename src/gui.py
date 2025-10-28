"""
NetScan GUI - Modern graphical interface for NetScan.

This module provides a comprehensive GUI for the NetScan network scanning tool
with features including scan configuration, real-time progress, results viewing,
and network visualization.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import json
import os
from datetime import datetime
import discoverhosts
import getipaddr
import export
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx


class ToolTip:
    """Create a tooltip for a given widget."""

    def __init__(self, widget, text):
        """
        Initialize tooltip.

        Args:
            widget: The widget to attach the tooltip to
            text (str): The tooltip text
        """
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        """Show the tooltip."""
        if self.tooltip_window or not self.text:
            return

        # Get widget position safely
        try:
            if isinstance(self.widget, (tk.Text, tk.Entry)):
                x, y, _, _ = self.widget.bbox("insert")
            else:
                x, y = 0, 0
        except (AttributeError, tk.TclError):
            x, y = 0, 0

        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")

        label = tk.Label(tw, text=self.text, justify='left',
                        background="#ffffe0", relief='solid', borderwidth=1,
                        font=("Arial", 9))
        label.pack(ipadx=1)

    def hide_tooltip(self, event=None):
        """Hide the tooltip."""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None


class NetScanGUI:
    """Main GUI application for NetScan."""

    # Tab indices for navigation
    SCAN_TAB = 0
    RESULTS_TAB = 1
    TOPOLOGY_TAB = 2
    SETTINGS_TAB = 3

    def __init__(self, root):
        """
        Initialize the NetScan GUI.

        Args:
            root (tk.Tk): The root window
        """
        self.root = root
        self.root.title("NetScan - Advanced Network Scanner")
        self.root.geometry("1200x800")

        # Theme colors
        self.themes = {
            'light': {
                'bg': '#f0f0f0',
                'fg': '#000000',
                'accent': '#0078d4',
                'success': '#28a745',
                'warning': '#ffc107',
                'danger': '#dc3545'
            },
            'dark': {
                'bg': '#1e1e1e',
                'fg': '#ffffff',
                'accent': '#0078d4',
                'success': '#28a745',
                'warning': '#ffc107',
                'danger': '#dc3545'
            }
        }
        self.current_theme = 'light'

        # Scan profiles
        self.scan_profiles = {
            'Quick Scan': {'workers': 2, 'timeout': 2},
            'Normal Scan': {'workers': 4, 'timeout': 5},
            'Deep Scan': {'workers': 8, 'timeout': 10}
        }

        # State variables
        self.scan_running = False
        self.scan_results = []
        self.scan_history = []

        # Configure styles
        self.setup_styles()

        # Create menu bar
        self.create_menu()

        # Create main interface
        self.create_widgets()

        # Create status bar
        self.create_status_bar()

        # Set up keyboard shortcuts
        self.setup_keyboard_shortcuts()

        # Load scan history
        self.load_scan_history()

        # Set window icon (if available)
        try:
            self.root.iconbitmap('icon.ico')
        except (FileNotFoundError, tk.TclError):
            pass  # Icon not found, continue without it

    def setup_styles(self):
        """Configure TTK styles for the application."""
        style = ttk.Style()
        style.theme_use('clam')

        # Configure colors based on theme
        theme = self.themes[self.current_theme]

        style.configure('Title.TLabel', font=('Arial', 16, 'bold'),
                        foreground=theme['accent'])
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Success.TLabel', foreground=theme['success'])
        style.configure('Warning.TLabel', foreground=theme['warning'])
        style.configure('Danger.TLabel', foreground=theme['danger'])
        style.configure('Action.TButton', font=('Arial', 10, 'bold'))

    def create_menu(self):
        """Create the application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self.new_scan)
        file_menu.add_command(label="Open Results", command=self.open_results)
        file_menu.add_separator()
        file_menu.add_command(label="Export as JSON", command=lambda: self.export_results('json'))
        file_menu.add_command(label="Export as CSV", command=lambda: self.export_results('csv'))
        file_menu.add_command(label="Export as XML", command=lambda: self.export_results('xml'))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Scan History", command=self.show_scan_history)
        view_menu.add_command(label="Network Topology", command=self.show_topology)
        view_menu.add_separator()
        view_menu.add_command(label="Toggle Theme", command=self.toggle_theme)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Keyboard Shortcuts", command=self.show_shortcuts)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)

    def create_widgets(self):
        """Create the main GUI widgets."""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # Create tabs
        self.create_scan_tab()
        self.create_results_tab()
        self.create_topology_tab()
        self.create_settings_tab()

    def create_scan_tab(self):
        """Create the scan configuration tab."""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="  Scan  ")

        # Title
        title_frame = ttk.Frame(scan_frame)
        title_frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(title_frame, text="Network Scanner",
                 style='Title.TLabel').pack(anchor='w')

        # Configuration frame
        config_frame = ttk.LabelFrame(scan_frame, text="Scan Configuration", padding=10)
        config_frame.pack(fill='x', padx=10, pady=5)

        # Network input
        ttk.Label(config_frame, text="Network:").grid(row=0, column=0, sticky='w', pady=5)
        self.network_var = tk.StringVar()
        network_entry = ttk.Entry(config_frame, textvariable=self.network_var, width=30)
        network_entry.grid(row=0, column=1, sticky='ew', pady=5, padx=5)
        ToolTip(network_entry, "Enter network in CIDR notation (e.g., 192.168.1.0/24)")

        detect_button = ttk.Button(config_frame, text="Auto-detect",
                  command=self.auto_detect_network)
        detect_button.grid(row=0, column=2, pady=5)
        ToolTip(detect_button, "Automatically detect your network interface")

        # Scan profile
        ttk.Label(config_frame, text="Scan Profile:").grid(row=1, column=0, sticky='w', pady=5)
        self.profile_var = tk.StringVar(value='Normal Scan')
        profile_combo = ttk.Combobox(config_frame, textvariable=self.profile_var,
                                     values=list(self.scan_profiles.keys()),
                                     state='readonly', width=28)
        profile_combo.grid(row=1, column=1, sticky='ew', pady=5, padx=5)
        ToolTip(profile_combo, "Choose scan speed: Quick (fast), Normal (balanced), or Deep (thorough)")

        # Port range
        ttk.Label(config_frame, text="Port Range:").grid(row=2, column=0, sticky='w', pady=5)
        self.port_range_var = tk.StringVar(value="1-1000")
        port_entry = ttk.Entry(config_frame, textvariable=self.port_range_var, width=30)
        port_entry.grid(row=2, column=1, sticky='ew', pady=5, padx=5)
        ToolTip(port_entry, "Specify port range to scan (e.g., 1-1000, 80,443,8080)")

        config_frame.columnconfigure(1, weight=1)

        # Control buttons
        button_frame = ttk.Frame(scan_frame)
        button_frame.pack(fill='x', padx=10, pady=10)

        self.start_button = ttk.Button(button_frame, text="Start Scan",
                                       style='Action.TButton',
                                       command=self.start_scan)
        self.start_button.pack(side='left', padx=5)
        ToolTip(self.start_button, "Start scanning the network (Ctrl+S)")

        self.stop_button = ttk.Button(button_frame, text="Stop Scan",
                                      command=self.stop_scan, state='disabled')
        self.stop_button.pack(side='left', padx=5)
        ToolTip(self.stop_button, "Stop the current scan (Escape)")

        # Progress frame
        progress_frame = ttk.LabelFrame(scan_frame, text="Scan Progress", padding=10)
        progress_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                           maximum=100, mode='determinate')
        self.progress_bar.pack(fill='x', pady=5)

        # Status label
        self.status_var = tk.StringVar(value="Ready to scan")
        ttk.Label(progress_frame, textvariable=self.status_var).pack(anchor='w', pady=5)

        # Log text area
        log_frame = ttk.Frame(progress_frame)
        log_frame.pack(fill='both', expand=True)

        ttk.Label(log_frame, text="Scan Log:", style='Header.TLabel').pack(anchor='w')

        self.log_text = scrolledtext.ScrolledText(log_frame, height=15,
                                                   wrap=tk.WORD, state='disabled')
        self.log_text.pack(fill='both', expand=True, pady=5)

    def create_results_tab(self):
        """Create the results viewing tab."""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="  Results  ")

        # Title
        title_frame = ttk.Frame(results_frame)
        title_frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(title_frame, text="Scan Results",
                 style='Title.TLabel').pack(side='left')

        # Export buttons
        ttk.Button(title_frame, text="Export JSON",
                  command=lambda: self.export_results('json')).pack(side='right', padx=2)
        ttk.Button(title_frame, text="Export CSV",
                  command=lambda: self.export_results('csv')).pack(side='right', padx=2)
        ttk.Button(title_frame, text="Export XML",
                  command=lambda: self.export_results('xml')).pack(side='right', padx=2)

        # Results tree
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_frame)
        tree_scroll_y.pack(side='right', fill='y')
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient='horizontal')
        tree_scroll_x.pack(side='bottom', fill='x')

        # Treeview
        self.results_tree = ttk.Treeview(tree_frame,
                                         columns=('IP', 'MAC', 'Hostname', 'Status', 'Services'),
                                         show='tree headings',
                                         yscrollcommand=tree_scroll_y.set,
                                         xscrollcommand=tree_scroll_x.set)

        tree_scroll_y.config(command=self.results_tree.yview)
        tree_scroll_x.config(command=self.results_tree.xview)

        # Configure columns
        self.results_tree.heading('#0', text='#')
        self.results_tree.heading('IP', text='IP Address')
        self.results_tree.heading('MAC', text='MAC Address')
        self.results_tree.heading('Hostname', text='Hostname')
        self.results_tree.heading('Status', text='Status')
        self.results_tree.heading('Services', text='Open Ports')

        self.results_tree.column('#0', width=50)
        self.results_tree.column('IP', width=150)
        self.results_tree.column('MAC', width=180)
        self.results_tree.column('Hostname', width=200)
        self.results_tree.column('Status', width=100)
        self.results_tree.column('Services', width=300)

        self.results_tree.pack(fill='both', expand=True)

        # Bind double-click to show details
        self.results_tree.bind('<Double-1>', self.show_host_details)

        # Details frame
        details_frame = ttk.LabelFrame(results_frame, text="Host Details", padding=10)
        details_frame.pack(fill='x', padx=10, pady=5)

        self.details_text = scrolledtext.ScrolledText(details_frame, height=8,
                                                       wrap=tk.WORD, state='disabled')
        self.details_text.pack(fill='both', expand=True)

    def create_topology_tab(self):
        """Create the network topology visualization tab."""
        topology_frame = ttk.Frame(self.notebook)
        self.notebook.add(topology_frame, text="  Topology  ")

        # Title
        title_frame = ttk.Frame(topology_frame)
        title_frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(title_frame, text="Network Topology",
                 style='Title.TLabel').pack(side='left')

        ttk.Button(title_frame, text="Refresh Topology",
                  command=self.refresh_topology).pack(side='right')

        # Canvas for matplotlib
        self.topology_frame = ttk.Frame(topology_frame)
        self.topology_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Placeholder message
        self.topology_label = ttk.Label(self.topology_frame,
                                        text="Run a scan to visualize network topology",
                                        font=('Arial', 12))
        self.topology_label.pack(expand=True)

    def create_settings_tab(self):
        """Create the settings tab."""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="  Settings  ")

        # Title
        title_frame = ttk.Frame(settings_frame)
        title_frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(title_frame, text="Settings",
                 style='Title.TLabel').pack(anchor='w')

        # Scan profiles section
        profiles_frame = ttk.LabelFrame(settings_frame, text="Scan Profiles", padding=10)
        profiles_frame.pack(fill='x', padx=10, pady=5)

        for profile_name, profile_settings in self.scan_profiles.items():
            profile_info = ttk.Frame(profiles_frame)
            profile_info.pack(fill='x', pady=2)
            ttk.Label(profile_info, text=f"{profile_name}:",
                     font=('Arial', 10, 'bold')).pack(side='left')
            ttk.Label(profile_info,
                     text=f"Workers: {profile_settings['workers']}, "
                          f"Timeout: {profile_settings['timeout']}s").pack(side='left', padx=10)

        # Appearance section
        appearance_frame = ttk.LabelFrame(settings_frame, text="Appearance", padding=10)
        appearance_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(appearance_frame, text="Theme:").pack(side='left', padx=5)
        self.theme_var = tk.StringVar(value=self.current_theme)
        theme_combo = ttk.Combobox(appearance_frame, textvariable=self.theme_var,
                                   values=['light', 'dark'], state='readonly', width=15)
        theme_combo.pack(side='left', padx=5)
        theme_combo.bind('<<ComboboxSelected>>', lambda e: self.apply_theme())

        # About section
        about_frame = ttk.LabelFrame(settings_frame, text="About NetScan", padding=10)
        about_frame.pack(fill='both', expand=True, padx=10, pady=5)

        about_text = """
NetScan - Advanced Network Scanner
Version: 2.0.0

A comprehensive network scanning tool with GUI interface.

Features:
• Host discovery with ARP scanning
• Service detection and OS fingerprinting
• Network topology visualization
• Multiple export formats (JSON, CSV, XML)
• Scan profiles (Quick, Normal, Deep)
• Real-time scan progress monitoring
• Scan history tracking

Created with Python, Tkinter, Scapy, and NetworkX
        """

        about_label = tk.Text(about_frame, wrap=tk.WORD, height=15,
                             relief='flat', bg=self.themes[self.current_theme]['bg'])
        about_label.insert(1.0, about_text.strip())
        about_label.config(state='disabled')
        about_label.pack(fill='both', expand=True)

    def auto_detect_network(self):
        """Auto-detect the current network."""
        self.log_message("Detecting network...")
        self.update_status("Detecting network...")
        try:
            network = getipaddr.get_wifi_ip()
            if network:
                self.network_var.set(str(network))
                self.log_message(f"Network detected: {network}")
                self.update_status(f"Network detected: {network}")
                messagebox.showinfo("Success", f"Network detected: {network}")
            else:
                messagebox.showwarning("Warning",
                                      "Could not detect network. Please enter manually.")
                self.log_message("Network detection failed")
                self.update_status("Network detection failed")
        except Exception as e:
            messagebox.showerror("Error", f"Error detecting network: {str(e)}")
            self.log_message(f"Error: {str(e)}")
            self.update_status("Error detecting network")

    def start_scan(self):
        """Start the network scan."""
        network = self.network_var.get().strip()
        if not network:
            messagebox.showwarning("Warning", "Please enter a network to scan")
            return

        self.scan_running = True
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress_var.set(0)
        self.status_var.set("Starting scan...")

        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.run_scan, args=(network,))
        scan_thread.daemon = True
        scan_thread.start()

    def run_scan(self, network):
        """
        Run the network scan asynchronously.

        Args:
            network (str): Network to scan in CIDR notation
        """
        try:
            self.log_message(f"Starting scan of {network}...")
            self.progress_var.set(10)

            # Discover hosts
            self.status_var.set("Discovering hosts...")
            active_hosts = discoverhosts.DiscoverHosts.discover_hosts(network)
            self.log_message(f"Found {len(active_hosts)} active hosts")
            self.progress_var.set(30)

            if not active_hosts:
                self.log_message("No hosts found")
                self.scan_complete()
                return

            # Scan each host
            self.scan_results = []
            total_hosts = len(active_hosts)

            for i, (ip, mac) in enumerate(active_hosts):
                if not self.scan_running:
                    self.log_message("Scan stopped by user")
                    break

                self.status_var.set(f"Scanning host {i+1}/{total_hosts}: {ip}")
                self.log_message(f"Scanning {ip}...")

                # Scan the host
                result = discoverhosts.DiscoverHosts.scan_host(ip, mac)
                self.scan_results.append(result)

                # Update progress
                progress = 30 + (60 * (i + 1) / total_hosts)
                self.progress_var.set(progress)

                # Add to results tree
                self.root.after(0, self.add_result_to_tree, result, i+1)

            # Save results
            self.progress_var.set(95)
            self.status_var.set("Saving results...")

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"

            with open(filename, "w") as file:
                json.dump(self.scan_results, file, indent=4)

            self.log_message(f"Results saved to {filename}")

            # Add to scan history
            self.scan_history.append({
                'timestamp': datetime.now().isoformat(),
                'network': network,
                'hosts_found': len(active_hosts),
                'filename': filename
            })
            self.save_scan_history()

            self.scan_complete()

        except Exception as e:
            self.log_message(f"Error during scan: {str(e)}")
            messagebox.showerror("Scan Error", f"An error occurred: {str(e)}")
            self.scan_complete()

    def scan_complete(self):
        """Handle scan completion."""
        self.scan_running = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.progress_var.set(100)
        self.status_var.set("Scan complete")
        self.log_message("Scan complete!")
        self.update_status(f"Scan complete - Found {len(self.scan_results)} hosts")

        # Auto-switch to results tab
        self.notebook.select(self.RESULTS_TAB)

        # Refresh topology
        self.refresh_topology()

    def stop_scan(self):
        """Stop the current scan."""
        if not self.scan_running:
            return  # No scan to stop

        if messagebox.askyesno("Confirm", "Are you sure you want to stop the scan?"):
            self.scan_running = False
            self.log_message("Stopping scan...")
            self.update_status("Scan stopped by user")

    def add_result_to_tree(self, result, index):
        """
        Add a scan result to the results tree.

        Args:
            result (dict): Scan result dictionary
            index (int): Index number for the result
        """
        ip = result['ip']
        mac = result['mac']

        # Extract hostname and status
        hostname = "Unknown"
        status = "Unknown"
        services = []

        if ip in result.get('services', {}):
            service_data = result['services'][ip]
            hostname = service_data.get('hostname', 'Unknown')
            status = service_data.get('state', 'Unknown')

            # Extract open ports
            protocols = service_data.get('protocols', {})
            for protocol, ports in protocols.items():
                for port, port_data in ports.items():
                    if isinstance(port_data, dict) and port_data.get('state') == 'open':
                        services.append(f"{port}/{protocol}")

        services_str = ", ".join(services) if services else "None detected"

        self.results_tree.insert('', 'end', text=str(index),
                                values=(ip, mac, hostname, status, services_str))

    def show_host_details(self, event):
        """
        Show detailed information for a selected host.

        Args:
            event: The event that triggered this method
        """
        selection = self.results_tree.selection()
        if not selection:
            return

        item = self.results_tree.item(selection[0])
        ip = item['values'][0]

        # Find the full result
        result = next((r for r in self.scan_results if r['ip'] == ip), None)
        if not result:
            return

        # Format details
        details = f"Host Details for {ip}\n"
        details += "=" * 60 + "\n\n"
        details += f"IP Address: {result['ip']}\n"
        details += f"MAC Address: {result['mac']}\n\n"

        # Services
        if ip in result.get('services', {}):
            service_data = result['services'][ip]
            details += f"Hostname: {service_data.get('hostname', 'Unknown')}\n"
            details += f"Status: {service_data.get('state', 'Unknown')}\n\n"

            protocols = service_data.get('protocols', {})
            if protocols:
                details += "Services:\n"
                for protocol, ports in protocols.items():
                    for port, port_data in ports.items():
                        if isinstance(port_data, dict):
                            state = port_data.get('state', 'unknown')
                            name = port_data.get('name', 'unknown')
                            details += f"  {port}/{protocol}: {state} ({name})\n"

        # OS
        if result.get('os'):
            details += "\nOperating System:\n"
            for os_match in result['os'][:3]:  # Show top 3 matches
                if isinstance(os_match, dict):
                    name = os_match.get('name', 'Unknown')
                    accuracy = os_match.get('accuracy', 'N/A')
                    details += f"  {name} (Accuracy: {accuracy}%)\n"

        # Traceroute
        if result.get('traceroute'):
            details += "\nTraceroute:\n"
            for hop in result['traceroute'][:10]:  # Show first 10 hops
                if isinstance(hop, dict):
                    hop_num = hop.get('hop', '?')
                    ip_addr = hop.get('ip', 'N/A')
                    rtt = hop.get('rtt', 'N/A')
                    details += f"  {hop_num}. {ip_addr} ({rtt}ms)\n"

        # Update details text
        self.details_text.config(state='normal')
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(1.0, details)
        self.details_text.config(state='disabled')

    def refresh_topology(self):
        """Refresh the network topology visualization."""
        if not self.scan_results:
            return

        # Clear existing widgets
        for widget in self.topology_frame.winfo_children():
            widget.destroy()

        try:
            # Create network graph
            G = nx.Graph()

            # Add router (first device)
            if self.scan_results:
                router = self.scan_results[0]
                router_ip = router['ip']
                router_hostname = router.get('services', {}).get(router_ip, {}).get('hostname', 'Router')
                router_label = f"{router_hostname}\n{router_ip}"

                G.add_node(router_ip, label=router_label, color='red')

                # Add other devices
                for device in self.scan_results[1:]:
                    device_ip = device['ip']
                    device_hostname = device.get('services', {}).get(device_ip, {}).get('hostname', 'Device')
                    device_label = f"{device_hostname}\n{device_ip}"

                    G.add_node(device_ip, label=device_label, color='lightblue')
                    G.add_edge(router_ip, device_ip)

            # Create matplotlib figure
            fig = plt.Figure(figsize=(8, 6), dpi=100)
            ax = fig.add_subplot(111)

            pos = nx.spring_layout(G, k=1, iterations=50)
            labels = nx.get_node_attributes(G, 'label')
            colors = [G.nodes[node]['color'] for node in G.nodes]

            nx.draw(G, pos, labels=labels, node_color=colors,
                   with_labels=True, node_size=3000, font_size=8,
                   font_color='black', ax=ax, edge_color='gray')

            ax.set_title("Network Topology", fontsize=14, fontweight='bold')

            # Embed in tkinter
            canvas = FigureCanvasTkAgg(fig, master=self.topology_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True)

            self.log_message("Topology visualization updated")

        except Exception as e:
            self.log_message(f"Error creating topology: {str(e)}")
            ttk.Label(self.topology_frame,
                     text=f"Error creating topology: {str(e)}",
                     font=('Arial', 10)).pack(expand=True)

    def show_topology(self):
        """Switch to topology tab and refresh."""
        self.notebook.select(self.TOPOLOGY_TAB)
        self.refresh_topology()

    def export_results(self, format_type):
        """
        Export scan results to a file.

        Args:
            format_type (str): Export format ('json', 'csv', or 'xml')
        """
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to export")
            return

        # Ask for filename
        filetypes = {
            'json': [("JSON files", "*.json"), ("All files", "*.*")],
            'csv': [("CSV files", "*.csv"), ("All files", "*.*")],
            'xml': [("XML files", "*.xml"), ("All files", "*.*")]
        }

        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=filetypes.get(format_type, [("All files", "*.*")])
        )

        if not filename:
            return

        try:
            if format_type == 'json':
                export.export_to_json(self.scan_results, filename)
            elif format_type == 'csv':
                export.export_to_csv(self.scan_results, filename)
            elif format_type == 'xml':
                export.export_to_xml(self.scan_results, filename)

            messagebox.showinfo("Success", f"Results exported to {filename}")
            self.log_message(f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")
            self.log_message(f"Export error: {str(e)}")

    def open_results(self):
        """Open and load previously saved scan results."""
        filename = filedialog.askopenfilename(
            title="Open Scan Results",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if not filename:
            return

        try:
            with open(filename, 'r') as file:
                self.scan_results = json.load(file)

            # Clear and populate results tree
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)

            for i, result in enumerate(self.scan_results):
                self.add_result_to_tree(result, i + 1)

            messagebox.showinfo("Success", f"Loaded {len(self.scan_results)} results")
            self.log_message(f"Loaded results from {filename}")
            self.update_status(f"Loaded {len(self.scan_results)} results from file")

            # Switch to results tab
            self.notebook.select(self.RESULTS_TAB)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load results: {str(e)}")
            self.log_message(f"Error loading results: {str(e)}")
            self.update_status("Error loading results")

    def new_scan(self):
        """Start a new scan (clear current results)."""
        if messagebox.askyesno("Confirm",
                              "This will clear current results. Continue?"):
            self.scan_results = []
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            self.details_text.config(state='normal')
            self.details_text.delete(1.0, tk.END)
            self.details_text.config(state='disabled')
            self.notebook.select(self.SCAN_TAB)
            self.log_message("Ready for new scan")
            self.update_status("Ready for new scan")

    def show_scan_history(self):
        """Show scan history window."""
        history_window = tk.Toplevel(self.root)
        history_window.title("Scan History")
        history_window.geometry("800x400")

        # Create treeview
        tree = ttk.Treeview(history_window,
                           columns=('Date', 'Network', 'Hosts', 'File'),
                           show='headings')

        tree.heading('Date', text='Date & Time')
        tree.heading('Network', text='Network')
        tree.heading('Hosts', text='Hosts Found')
        tree.heading('File', text='Results File')

        tree.column('Date', width=200)
        tree.column('Network', width=150)
        tree.column('Hosts', width=100)
        tree.column('File', width=300)

        # Populate with history
        for entry in reversed(self.scan_history):
            date = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            tree.insert('', 'end', values=(
                date,
                entry['network'],
                entry['hosts_found'],
                entry['filename']
            ))

        tree.pack(fill='both', expand=True, padx=10, pady=10)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

    def load_scan_history(self):
        """Load scan history from file."""
        history_file = 'scan_history.json'
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r') as file:
                    self.scan_history = json.load(file)
            except Exception:
                self.scan_history = []
        else:
            self.scan_history = []

    def save_scan_history(self):
        """Save scan history to file."""
        history_file = 'scan_history.json'
        try:
            with open(history_file, 'w') as file:
                json.dump(self.scan_history, file, indent=4)
        except Exception as e:
            self.log_message(f"Error saving history: {str(e)}")

    def toggle_theme(self):
        """Toggle between light and dark themes."""
        self.current_theme = 'dark' if self.current_theme == 'light' else 'light'
        self.theme_var.set(self.current_theme)
        self.apply_theme()

    def apply_theme(self):
        """Apply the selected theme."""
        self.current_theme = self.theme_var.get()
        theme = self.themes[self.current_theme]

        # Update root window
        self.root.configure(bg=theme['bg'])

        # Update styles
        style = ttk.Style()
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])

        self.log_message(f"Theme changed to {self.current_theme}")

    def log_message(self, message):
        """
        Add a message to the log.

        Args:
            message (str): Message to log
        """
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"

        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def show_documentation(self):
        """Show documentation window."""
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("700x600")

        doc_text = scrolledtext.ScrolledText(doc_window, wrap=tk.WORD, padx=10, pady=10)
        doc_text.pack(fill='both', expand=True)

        docs = """
NetScan Documentation
====================

OVERVIEW
--------
NetScan is an advanced network scanning tool that helps you discover and analyze
devices on your local network. It provides detailed information about hosts,
services, operating systems, and network topology.

GETTING STARTED
--------------
1. Click "Auto-detect" to automatically find your network, or enter manually
2. Choose a scan profile (Quick, Normal, or Deep)
3. Click "Start Scan" to begin scanning
4. View results in the Results tab
5. Visualize network topology in the Topology tab

SCAN PROFILES
-------------
• Quick Scan: Fast scan with 2 workers, 2s timeout
• Normal Scan: Balanced scan with 4 workers, 5s timeout
• Deep Scan: Thorough scan with 8 workers, 10s timeout

FEATURES
--------
• Host Discovery: Finds active devices using ARP scanning
• Service Detection: Identifies running services and open ports
• OS Detection: Determines the operating system of devices
• Network Topology: Visual representation of your network
• Export Options: Save results in JSON, CSV, or XML format
• Scan History: Track all your previous scans
• Themes: Switch between light and dark themes

RESULTS VIEW
-----------
Double-click any host in the results table to see detailed information including:
• Services and open ports
• Operating system detection results
• Traceroute information

EXPORT FORMATS
-------------
• JSON: Complete data structure, best for programmatic access
• CSV: Spreadsheet-compatible format for analysis
• XML: Structured data format for integration

NETWORK REQUIREMENTS
-------------------
⚠️ Important: Only scan networks you own or have permission to scan.
• Requires administrative/root privileges for some features
• Make sure your firewall allows network scanning
• Some features may be detected by intrusion detection systems

TROUBLESHOOTING
--------------
• If auto-detect fails, manually enter your network (e.g., 192.168.1.0/24)
• Ensure you have the necessary permissions to scan
• Check that required dependencies are installed
• Review the scan log for detailed error messages

For more information, visit the project repository or README file.
        """

        doc_text.insert(1.0, docs.strip())
        doc_text.config(state='disabled')

    def show_about(self):
        """Show about dialog."""
        messagebox.showinfo(
            "About NetScan",
            "NetScan - Advanced Network Scanner\n"
            "Version 2.0.0\n\n"
            "A comprehensive network scanning tool with modern GUI.\n\n"
            "Features:\n"
            "• Host discovery and service detection\n"
            "• OS fingerprinting\n"
            "• Network topology visualization\n"
            "• Multiple export formats\n"
            "• Real-time scan monitoring\n\n"
            "Created with Python, Tkinter, Scapy, and NetworkX\n\n"
            "⚠️ Use responsibly and only on authorized networks."
        )

    def create_status_bar(self):
        """Create the status bar at the bottom of the window."""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(side='bottom', fill='x')

        # Left side - general status
        self.status_label = ttk.Label(self.status_bar, text="Ready", relief='sunken', anchor='w')
        self.status_label.pack(side='left', fill='x', expand=True, padx=2, pady=2)

        # Right side - info
        self.info_label = ttk.Label(self.status_bar, text="NetScan v2.0", relief='sunken', anchor='e')
        self.info_label.pack(side='right', padx=2, pady=2)

    def setup_keyboard_shortcuts(self):
        """Set up keyboard shortcuts for the application."""
        # Ctrl+N - New scan
        self.root.bind('<Control-n>', lambda e: self.new_scan())

        # Ctrl+O - Open results
        self.root.bind('<Control-o>', lambda e: self.open_results())

        # Ctrl+S - Start scan (when on scan tab)
        def start_scan_shortcut(event):
            if self.notebook.index('current') == self.SCAN_TAB:
                self.start_scan()

        self.root.bind('<Control-s>', start_scan_shortcut)

        # Ctrl+Q - Quit
        self.root.bind('<Control-q>', lambda e: self.root.quit())

        # Ctrl+T - Toggle theme
        self.root.bind('<Control-t>', lambda e: self.toggle_theme())

        # F1 - Help
        self.root.bind('<F1>', lambda e: self.show_documentation())

        # F5 - Refresh topology
        self.root.bind('<F5>', lambda e: self.refresh_topology())

        # Escape - Stop scan
        self.root.bind('<Escape>', lambda e: self.stop_scan())

    def show_shortcuts(self):
        """Show keyboard shortcuts dialog."""
        shortcuts_window = tk.Toplevel(self.root)
        shortcuts_window.title("Keyboard Shortcuts")
        shortcuts_window.geometry("500x400")

        # Create text widget
        shortcuts_text = scrolledtext.ScrolledText(shortcuts_window, wrap=tk.WORD, padx=10, pady=10)
        shortcuts_text.pack(fill='both', expand=True)

        shortcuts = """
Keyboard Shortcuts
==================

File Operations:
  Ctrl+N        New Scan
  Ctrl+O        Open Results
  Ctrl+Q        Quit Application

Scan Operations:
  Ctrl+S        Start Scan (on Scan tab)
  Escape        Stop Current Scan

View:
  Ctrl+T        Toggle Theme
  F5            Refresh Topology

Help:
  F1            Show Documentation

Tab Navigation:
  Ctrl+Tab      Next Tab
  Ctrl+Shift+Tab Previous Tab

General:
  Double-Click  Show detailed host information (on Results tab)
        """

        shortcuts_text.insert(1.0, shortcuts.strip())
        shortcuts_text.config(state='disabled')

        # Add close button
        close_button = ttk.Button(shortcuts_window, text="Close", command=shortcuts_window.destroy)
        close_button.pack(pady=10)

    def update_status(self, message):
        """
        Update the status bar message.

        Args:
            message (str): Status message to display
        """
        self.status_label.config(text=message)
        self.root.update_idletasks()


def main():
    """Main function to run the GUI application."""
    root = tk.Tk()
    NetScanGUI(root)  # noqa: F841
    root.mainloop()


if __name__ == "__main__":
    main()
