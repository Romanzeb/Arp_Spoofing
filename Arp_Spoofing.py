from scapy.all import sniff, ARP

ip_mac_dict = {}

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in ip_mac_dict:
            if ip_mac_dict[ip] != mac:
                print(f"[Warning] Possible ARP Spoofing detected! IP: {ip}, Current MAC: {ip_mac_dict[ip]}, New MAC: {mac}")
        else:
            ip_mac_dict[ip] = mac

print("Monitoring ARP packets...")
sniff(prn=process_packet, filter="arp", store=0)
