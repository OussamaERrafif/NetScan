"""
Host information gathering module.

This module provides functionality to scan network hosts for service
information and operating system detection using Nmap.
"""
import nmap
import bannergrabbing


class HostInfo:
    """Class for gathering detailed host information."""

    @staticmethod
    def scan_services(ip):
        """
        Scan services running on a host.

        Args:
            ip (str): IP address of the target host

        Returns:
            dict: Dictionary containing hostname, state, and protocol information
        """
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
                        banner = bannergrabbing.BannerGrabbing.banner_grabbing(
                            host, port
                        )
                        service_info['banner'] = banner
                    services.append(service_info)

                protocol_info['services'] = services
                protocols[proto] = protocol_info

            host_info['protocols'] = protocols
            output[host] = host_info

        return output

    @staticmethod
    def detect_os(ip):
        """
        Detect the operating system of a host.

        Args:
            ip (str): IP address of the target host

        Returns:
            list: List of dictionaries containing OS detection information
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
