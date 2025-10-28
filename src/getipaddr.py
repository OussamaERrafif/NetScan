"""
Network interface IP address detection module.

This module provides functionality to detect the local network IP address
and calculate the network range for scanning.
"""
import socket
import psutil


def get_all_network_interfaces():
    """
    Get all available network interfaces with their IP addresses.

    Returns:
        dict: Dictionary mapping interface names to IP addresses
    """
    interfaces = {}
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    interfaces[interface] = addr.address
    except Exception as e:
        print(f"Error getting network interfaces: {e}")
    return interfaces


def get_wifi_ip():
    """
    Get the local IP address and network range from Wi-Fi interface.

    Returns:
        str: Network address in CIDR notation (e.g., '192.168.1.0/24')
        None: If no Wi-Fi interface is found or error occurs

    Note:
        This function assumes a /24 network mask. Adjust if needed.
        It will also try to find Ethernet interfaces if Wi-Fi is not available.
    """
    try:
        # First try Wi-Fi interfaces
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    # Check for common Wi-Fi interface names
                    if any(name in interface.lower() for name in ['wi-fi', 'wlan', 'wireless']):
                        local_ip = addr.address
                        network = local_ip.rsplit('.', 1)[0] + '.0/24'
                        print(f"Found Wi-Fi interface: {interface} ({local_ip})")
                        return network

        # If no Wi-Fi found, try Ethernet or other interfaces
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    # Check for common Ethernet interface names
                    if any(name in interface.lower() for name in ['ethernet', 'eth', 'en0', 'ens']):
                        local_ip = addr.address
                        network = local_ip.rsplit('.', 1)[0] + '.0/24'
                        print(f"Found Ethernet interface: {interface} ({local_ip})")
                        return network

        # If still nothing found, use the first non-loopback interface
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    local_ip = addr.address
                    network = local_ip.rsplit('.', 1)[0] + '.0/24'
                    print(f"Using interface: {interface} ({local_ip})")
                    return network

    except Exception as e:
        print(f"Failed to get local IP address: {e}")
    return None


def get_network_from_interface(interface_name):
    """
    Get network range from a specific interface.

    Args:
        interface_name (str): Name of the network interface

    Returns:
        str: Network address in CIDR notation or None
    """
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            if interface == interface_name:
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        local_ip = addr.address
                        network = local_ip.rsplit('.', 1)[0] + '.0/24'
                        return network
    except Exception as e:
        print(f"Error getting network from interface {interface_name}: {e}")
    return None
