import socket
import struct
import sys
import os

# === CONFIGURABLE FILTERS ===
FILTER_PROTOCOL = None    # Options: 'tcp', 'udp', 'icmp', or None
FILTER_PORT = None        # e.g., 80 or None
FILTER_IP = None          # e.g., "192.168.1.1" or None


def get_local_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

def parse_ip_header(packet):
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
        'ihl': ihl,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'header_length': ihl * 4
    }

def parse_tcp_header(packet):
    tcp_header = packet[0:20]
    header = struct.unpack("!HHLLBBHHH", tcp_header)

    src_port = header[0]
    dst_port = header[1]
    seq = header[2]
    ack = header[3]
    offset_reserved = header[4]
    tcp_header_length = (offset_reserved >> 4) * 4

    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq': seq,
        'ack': ack,
        'header_length': tcp_header_length
    }

def parse_udp_header(packet):
    udp_header = packet[0:8]
    header = struct.unpack("!HHHH", udp_header)

    return {
        'src_port': header[0],
        'dst_port': header[1],
        'length': header[2],
        'checksum': header[3]
    }

def main():
    local_ip = get_local_ip()

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((local_ip, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print(f"[+] Sniffer started on {local_ip}")
        print(f"[!] Filters → Protocol: {FILTER_PROTOCOL or 'Any'}, Port: {FILTER_PORT or 'Any'}, IP: {FILTER_IP or 'Any'}\n")

        while True:
            raw_data, _ = sniffer.recvfrom(65535)
            ip_info = parse_ip_header(raw_data)
            protocol = ip_info["protocol"]
            src_ip, dst_ip = ip_info["src_ip"], ip_info["dst_ip"]

            # Protocol filter
            if FILTER_PROTOCOL:
                if FILTER_PROTOCOL.lower() == "tcp" and protocol != 6:
                    continue
                if FILTER_PROTOCOL.lower() == "udp" and protocol != 17:
                    continue
                if FILTER_PROTOCOL.lower() == "icmp" and protocol != 1:
                    continue

            # IP filter
            if FILTER_IP and FILTER_IP not in [src_ip, dst_ip]:
                continue

            payload = raw_data[ip_info['header_length']:]
            matched_port = False

            if protocol == 6:  # TCP
                tcp = parse_tcp_header(payload)
                if FILTER_PORT and FILTER_PORT not in [tcp['src_port'], tcp['dst_port']]:
                    continue
                matched_port = True
                print(f"[TCP] {src_ip}:{tcp['src_port']} → {dst_ip}:{tcp['dst_port']}")
            elif protocol == 17:  # UDP
                udp = parse_udp_header(payload)
                if FILTER_PORT and FILTER_PORT not in [udp['src_port'], udp['dst_port']]:
                    continue
                matched_port = True
                print(f"[UDP] {src_ip}:{udp['src_port']} → {dst_ip}:{udp['dst_port']}")
            elif protocol == 1:  # ICMP
                print(f"[ICMP] {src_ip} → {dst_ip}")

    except KeyboardInterrupt:
        print("\n[-] Stopped.")
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()


if __name__ == "__main__":
    main()
