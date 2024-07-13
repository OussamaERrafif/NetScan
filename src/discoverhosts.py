from scapy.all import ARP, Ether, srp
import hostinfo
import asyncio
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

    async def scan_host(ip, mac):
        services = await hostinfo.HostInfo.scan_services(ip)
        os = await hostinfo.HostInfo.detect_os(ip)
        traceroute_result = await traceroute.Traceroute.traceroute(ip)
        
        return {
            "ip": ip,
            "mac": mac,
            "services": services,
            "os": os,
            "traceroute": traceroute_result
        }

    async def scan_network(network):
        print(f"Discovering hosts in the network {network}...\n")
        active_ips = DiscoverHosts.discover_hosts(network)

        # Limiting for testing purposes
        # active_ips = active_ips[:2]

        scan_tasks = [DiscoverHosts.scan_host(ip, mac) for ip, mac in active_ips]
        scan_results = await asyncio.gather(*scan_tasks)

        with open("scan_results.json", "w") as file:
            json.dump(scan_results, file, indent=4)

        print("Scan results saved as scan_results.json")