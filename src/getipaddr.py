import asyncio
import discoverhosts
import socket
import struct
import psutil
# import fcntl

# def get_local_ip(ifname):
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     return socket.inet_ntoa(fcntl.ioctl(
#         s.fileno(),
#         0x8915,  # SIOCGIFADDR
#         struct.pack('256s', bytes(ifname[:15], 'utf-8'))
#     )[20:24])


def get_wifi_ip():
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and 'Wi-Fi' in interface:
                    local_ip = addr.address
                    # Assuming a typical /24 network, adjust if your subnet mask is different
                    network = local_ip.rsplit('.', 1)[0] + '.0/24'
                    return network
    except Exception as e:
        print(f"Failed to get local IP address: {e}")
        return None