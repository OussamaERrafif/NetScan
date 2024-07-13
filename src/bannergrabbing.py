import socket

class BannerGrabbing:
    def banner_grabbing(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            banner = sock.recv(1024)
            print(f"Banner from {ip}:{port}: {banner.decode().strip()}")
            sock.close()
        except Exception as e:
            print(f"Error grabbing banner from {ip}:{port}: {e}")