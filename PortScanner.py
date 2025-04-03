from scapy.all import IP, TCP, sr1
print("Scapy")
def scan_port(target_ip, port):
    print("Scanning port {port}")
    packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

    response = sr1(packet, timeout = 5, verbose = 0)

    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12:
            print(f"[+] Port {port} is OPEN")
        elif response[TCP].flags == 0x14:
            print(f"[-] Port {port} is CLOSED")
        else:
            print(f"[?] Port {port} returned an unknown response")
    else:
        print(f"[?] No response from port {port}")

    target = "127.0.0.1"
    ports = [22, 80, 443, 8080]

    for port in ports:
        scan_port(target, port)
