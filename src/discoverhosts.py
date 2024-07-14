from concurrent.futures import ThreadPoolExecutor
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

    def scan_host(ip, mac):
        services =  hostinfo.HostInfo.scan_services(ip)
        os = hostinfo.HostInfo.detect_os(ip)
        traceroute_result = traceroute.Traceroute.traceroute(ip)
        
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
        print(f"Found {len(active_ips)} active hosts in the network {network}")
        print(active_ips)

        # Limiting for testing purposes
        # print("Limiting to 3 hosts for testing purposes")
        # active_ips = active_ips[:3]
        

        # Using ThreadPoolExecutor to run scan_host concurrently
        with ThreadPoolExecutor(max_workers=2) as executor:
            loop = asyncio.get_event_loop()
            # Collect coroutines to run in the executor
            tasks = [
                loop.run_in_executor(executor, DiscoverHosts.scan_host, ip, mac)
                for ip, mac in active_ips
            ]
            # Await all coroutines and gather results
            try:
                scan_results = await asyncio.gather(*tasks)
            except Exception as e:
                print(f"Error during scanning: {e}")
                return
        
        # Convert results to JSON-serializable format
        serializable_results = [dict(result) for result in scan_results]

        with open("scan_results.json", "w") as file:
            json.dump(serializable_results, file, indent=4)

        print("Scan results saved as scan_results.json")