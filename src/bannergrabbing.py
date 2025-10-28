"""
Banner grabbing module for network service identification.

This module provides functionality to grab service banners from network hosts.
"""
import socket


class BannerGrabbing:
    """Class for performing banner grabbing operations on network services."""

    @staticmethod
    def banner_grabbing(ip, port):
        """
        Grab service banner from a specific IP and port.

        Args:
            ip (str): IP address of the target host
            port (int): Port number to connect to

        Returns:
            str: Banner information or error message
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            banner = sock.recv(1024)
            sock.close()
            return f"Banner from {ip}:{port}: {banner.decode().strip()}"
        except Exception as e:
            return f"Error grabbing banner from {ip}:{port}: {e}"
