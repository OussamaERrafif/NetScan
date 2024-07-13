from scapy.all import IP, ICMP, sr1


class Traceroute:
    def traceroute(ip):
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