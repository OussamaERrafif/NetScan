import socket

class BannerGrabbing:
    def banner_grabbing(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            banner = sock.recv(1024)
            sock.close()
            return f"Banner from {ip}:{port}: {banner.decode().strip()}"
        except Exception as e:
            return f"Error grabbing banner from {ip}:{port}: {e}"