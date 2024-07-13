from scapy.all import ARP, Ether, srp
import hostinfo
import traceroute
import json


class DiscoverHosts:

    def discover_hosts(network):
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        try:
            result = srp(packet, timeout=2, verbose=0)[0]
            active_hosts = [(received.psrc, received.hwsrc) for sent, received in result if received.psrc != '192.168.1.1']
            return active_hosts
        except Exception as e:
            print(f"Error discovering hosts: {e}")
            return []

    def scan_network(network):
        print(f"Discovering hosts in the network {network}...\n")
        active_ips = DiscoverHosts.discover_hosts(network)
        print(f"Active IPs: {active_ips}")

        #testing
        active_ips = active_ips[:2]

        scan_results = []

        for ip ,mac in active_ips:
            print(f"\nStarting scan on {ip}...\n")
            services = hostinfo.HostInfo.scan_services(ip)
            os = hostinfo.HostInfo.detect_os(ip)
            traceroute_result = traceroute.Traceroute.traceroute(ip)
            scan_results.append({
                "ip": ip,
                "services": services,
                "os": os,
                "traceroute": traceroute_result
            })

        with open("scan_results.json", "w") as file:
            json.dump(scan_results, file)

        print("Scan results saved as scan_results.json")