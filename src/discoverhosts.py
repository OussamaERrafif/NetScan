"""
Host discovery and network scanning module.

This module provides functionality to discover active hosts on a network
and scan them for detailed information including services, OS, and routes.
"""
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp
import asyncio
import json
import hostinfo
import traceroute


class DiscoverHosts:
    """Class for discovering and scanning network hosts."""

    @staticmethod
    def discover_hosts(network):
        """
        Discover active hosts on a network using ARP scanning.

        Args:
            network (str): Network address in CIDR notation (e.g., '192.168.1.0/24')

        Returns:
            list: List of tuples containing (IP, MAC) for each discovered host
        """
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        try:
            result = srp(packet, timeout=2, verbose=0)[0]
            # Filter out router (adjust as needed, or make this configurable)
            active_hosts = [
                (received.psrc, received.hwsrc)
                for sent, received in result
                if received.psrc != '192.168.1.1'
            ]
            return active_hosts
        except Exception as e:
            print(f"Error discovering hosts: {e}")
            return []

    @staticmethod
    def scan_host(ip, mac):
        """
        Scan a single host for detailed information.

        Args:
            ip (str): IP address of the host
            mac (str): MAC address of the host

        Returns:
            dict: Dictionary containing host information (IP, MAC, services, OS, traceroute)
        """
        services = hostinfo.HostInfo.scan_services(ip)
        os = hostinfo.HostInfo.detect_os(ip)
        traceroute_result = traceroute.Traceroute.traceroute(ip)

        return {
            "ip": ip,
            "mac": mac,
            "services": services,
            "os": os,
            "traceroute": traceroute_result
        }

    @staticmethod
    async def scan_network(network):
        """
        Asynchronously scan all hosts on a network.

        Args:
            network (str): Network address in CIDR notation

        Saves scan results to scan_results.json file.
        """
        print(f"Discovering hosts in the network {network}...\n")
        active_ips = DiscoverHosts.discover_hosts(network)
        print(f"Found {len(active_ips)} active hosts in the network {network}")
        print(active_ips)

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
