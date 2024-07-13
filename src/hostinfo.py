from scapy.all import ARP, Ether, srp
import nmap
import ipaddress
import bannergrabbing

class HostInfo:
    def __init__(self, ip):
        self.ip = ip
        self.hostname = None
        self.os = None
        self.services = []

    def __str__(self):
        return f"{self.ip} ({self.hostname})\n  OS: {self.os}\n  Services: {', '.join(self.services)}"
    
    def scan_services(ip):
        nm = nmap.PortScanner()
        print(f"Scanning services on {ip}...")
        nm.scan(ip, arguments='-sV')
        
        output = {}
        
        for host in nm.all_hosts():
            host_info = {}
            host_info['hostname'] = nm[host].hostname()
            host_info['state'] = nm[host].state()
            protocols = {}
            
            for proto in nm[host].all_protocols():
                protocol_info = {}
                lport = nm[host][proto].keys()
                services = []
                
                for port in lport:
                    service_info = {}
                    service_info['port'] = port
                    service_info['name'] = nm[host][proto][port]["name"]
                    service_info['version'] = nm[host][proto][port]["version"]
                    if service_info['name'].lower() != 'unknown':
                        service_info['banner'] = bannergrabbing.BannerGrabbing.banner_grabbing(host, port)
                    services.append(service_info)
                
                protocol_info['services'] = services
                protocols[proto] = protocol_info
            
            host_info['protocols'] = protocols
            output[host] = host_info
        
        return output


    def detect_os(ip):
        """
        Detects the operating system of a given IP address using nmap.

        Args:
            ip (str): The IP address to scan.

        Returns:
            List: A list containing the detected operating system information.
        """
        os_info = []
        nm = nmap.PortScanner()
        print(f"Detecting OS on {ip}...")
        nm.scan(ip, arguments='-O')
        
        for host in nm.all_hosts():
            os_data = {}
            os_data['host'] = f'{host} ({nm[host].hostname()})'
            if 'osclass' in nm[host]:
                os_classes = []
                for osclass in nm[host]['osclass']:
                    os_class = {}
                    os_class['type'] = osclass['type']
                    os_class['vendor'] = osclass['vendor']
                    os_class['osfamily'] = osclass['osfamily']
                    os_class['osgen'] = osclass['osgen']
                    os_class['accuracy'] = osclass['accuracy']
                    os_classes.append(os_class)
                os_data['os_classes'] = os_classes
            else:
                os_data['os_classes'] = []
                os_data['os_classes'].append("OS detection not available.")
            os_info.append(os_data)
        print("OS detection complete.")
        
        return os_info