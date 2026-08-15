"""
UDP probe → each address in subnet
              ↓
closed UDP port
              ↓
ICMP Type 3 / Code 3
"Destination Unreachable / Port Unreachable"
              ↓
scanner receives ICMP
              ↓
verify embedded magic marker
              ↓
mark source IP as alive
"""

# icmp_host_scanner.py

import ipaddress
import os
import socket
import struct
import threading
import time


SUBNET = "192.168.1.0/24"
UDP_PORT = 65212

# Marker used to distinguish responses caused by our own probes.
MESSAGE = b"PYTHONRULES!"


# ------------------------------------------------------------
# IPv4 header parser
# ------------------------------------------------------------

class IP:
    def __init__(self, buff: bytes):

        (
            version_header_length,
            self.tos,
            self.len,
            self.id,
            self.offset,
            self.ttl,
            protocol_num,
            self.sum,
            src,
            dst,
        ) = struct.unpack(
            "!BBHHHBBH4s4s",
            buff[:20],
        )

        # Upper four bits = IPv4 version.
        self.ver = version_header_length >> 4

        # Lower four bits = header length in 32-bit words.
        self.ihl = version_header_length & 0xF

        self.protocol_num = protocol_num

        self.src_address = socket.inet_ntoa(src)
        self.dst_address = socket.inet_ntoa(dst)

        protocols = {
            socket.IPPROTO_ICMP: "ICMP",
            socket.IPPROTO_TCP: "TCP",
            socket.IPPROTO_UDP: "UDP",
        }

        self.protocol = protocols.get(
            protocol_num,
            str(protocol_num),
        )


# ------------------------------------------------------------
# ICMP header parser
# ------------------------------------------------------------

class ICMP:
    def __init__(self, buff: bytes):

        (
            self.type,
            self.code,
            self.checksum,
            self.id,
            self.seq,
        ) = struct.unpack(
            "!BBHHH",
            buff[:8],
        )


# ------------------------------------------------------------
# UDP probe sender
# ------------------------------------------------------------

def udp_sender():
    """
    Send a UDP probe to every usable host in SUBNET.

    Hosts with a closed UDP port commonly answer with an
    ICMP Destination Unreachable / Port Unreachable packet.
    """

    network = ipaddress.ip_network(
        SUBNET,
        strict=False,
    )

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    ) as sender:

        for ip in network.hosts():

            try:
                sender.sendto(
                    MESSAGE,
                    (str(ip), UDP_PORT),
                )

            except OSError:
                continue


# ------------------------------------------------------------
# Scanner
# ------------------------------------------------------------

class Scanner:

    def __init__(self, host: str):

        self.host = host

        # Windows raw sockets operate slightly differently.
        if os.name == "nt":
            protocol = socket.IPPROTO_IP
        else:
            protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            protocol,
        )

        self.socket.bind(
            (host, 0)
        )

        # Tell the OS that IP headers are included.
        self.socket.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_HDRINCL,
            1,
        )

        # Windows can enable receive-all mode.
        if os.name == "nt":
            self.socket.ioctl(
                socket.SIO_RCVALL,
                socket.RCVALL_ON,
            )

    def sniff(self):

        network = ipaddress.ip_network(
            SUBNET,
            strict=False,
        )

        hosts_up = {
            self.host
        }

        print(
            f"[*] Listening on {self.host}"
        )

        print(
            f"[*] Scanning {network}"
        )

        try:

            while True:

                # Receive an IP packet.
                raw_buffer = self.socket.recvfrom(
                    65535
                )[0]

                if len(raw_buffer) < 20:
                    continue

                # Parse IPv4 header.
                ip_header = IP(
                    raw_buffer[:20]
                )

                # We're interested in ICMP.
                if ip_header.protocol != "ICMP":
                    continue

                # Actual IPv4 header length can exceed 20 bytes
                # when IP options are present.
                offset = ip_header.ihl * 4

                if len(raw_buffer) < offset + 8:
                    continue

                # Parse ICMP header.
                icmp_header = ICMP(
                    raw_buffer[
                        offset:offset + 8
                    ]
                )

                # ICMP:
                #
                # Type 3 = Destination Unreachable
                # Code 3 = Port Unreachable
                #
                # This commonly occurs when our UDP probe reaches
                # a live system where UDP_PORT isn't listening.
                if (
                    icmp_header.type == 3
                    and icmp_header.code == 3
                ):

                    source = ipaddress.ip_address(
                        ip_header.src_address
                    )

                    # Ignore traffic outside the subnet.
                    if source not in network:
                        continue

                    # Ignore ourselves.
                    if ip_header.src_address == self.host:
                        continue

                    # The ICMP payload may contain the UDP packet
                    # that triggered the error. Look for our marker.
                    if MESSAGE not in raw_buffer:
                        continue

                    target = ip_header.src_address

                    if target not in hosts_up:

                        hosts_up.add(target)

                        print(
                            f"[+] Host up: {target}"
                        )

        except KeyboardInterrupt:

            print("\n[*] Stopping scanner")

        finally:

            if os.name == "nt":
                self.socket.ioctl(
                    socket.SIO_RCVALL,
                    socket.RCVALL_OFF,
                )

            self.socket.close()


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():

    # Change this to the IPv4 address assigned to your Mac
    # or other machine on the target LAN.
    host = "192.168.1.203"

    scanner = Scanner(host)

    # Start capturing before transmitting probes.
    thread = threading.Thread(
        target=scanner.sniff,
        daemon=True,
    )

    thread.start()

    # Give the raw socket a moment to initialize.
    time.sleep(1)

    udp_sender()

    try:
        while thread.is_alive():
            thread.join(timeout=1)

    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
