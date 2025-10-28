"""
Traceroute functionality module.

This module provides traceroute functionality to trace the network path
to a destination host.
"""
from scapy.all import IP, ICMP, sr1


class Traceroute:
    """Class for performing traceroute operations."""

    @staticmethod
    def traceroute(ip):
        """
        Perform a traceroute to a destination IP address.

        Args:
            ip (str): Destination IP address

        Returns:
            list: List of strings describing each hop in the route
        """
        ttl = 1
        result = []
        while True:
            packet = IP(dst=ip, ttl=ttl) / ICMP()
            reply = sr1(packet, verbose=0, timeout=1)

            if reply is None:
                break

            result.append(f"{ttl}: {reply.src} ({reply.type}) {reply.time} ms  ")

            if reply.src == ip:
                break

            ttl += 1

        return result
