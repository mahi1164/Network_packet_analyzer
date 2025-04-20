import socket
import struct
import sys
import os

def get_local_ip():
    """Gets the local IP address of the machine."""
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

def parse_ip_header(packet):
    """Parses the IP header from the raw packet data."""
    ip_header = packet[0:20]
    header = struct.unpack("!BBHHHBBH4s4s", ip_header)

    version_ihl = header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    src_ip = socket.inet_ntoa(header[8])
    dst_ip = socket.inet_ntoa(header[9])
    protocol = header[6]

    return {
        'version': version,
        'header_length': ihl * 4,
        'ttl': header[5],
        'protocol': protocol,
        'source_ip': src_ip,
        'destination_ip': dst_ip
    }

def main():
    local_ip = get_local_ip()

    try:
        # Create raw socket
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((local_ip, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Windows specific: enable promiscuous mode
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print(f"[+] Packet Sniffer started on {local_ip}...\n")

        while True:
            raw_data, _ = sniffer.recvfrom(65535)
            ip_info = parse_ip_header(raw_data)

            print(f"[+] Protocol: {ip_info['protocol']} | From: {ip_info['source_ip']} -> {ip_info['destination_ip']}")

    except KeyboardInterrupt:
        print("\n[-] Stopping packet sniffer...")
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

if __name__ == "__main__":
    main()
