# dns_monitor.py

from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, IPv6
from datetime import datetime
import json
from pathlib import Path


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

# File used to keep a historical record of observed DNS traffic.
LOG_FILE = Path("dns_events.jsonl")

# DNS normally uses UDP/TCP port 53.
BPF_FILTER = "port 53"


# ------------------------------------------------------------
# DNS helper functions
# ------------------------------------------------------------

def decode_dns_name(raw_name) -> str:
    """
    Convert Scapy's DNS name representation into a normal string.

    Example:

        b"example.com."

    becomes:

        example.com
    """

    if isinstance(raw_name, bytes):
        return raw_name.decode(
            "utf-8",
            errors="replace"
        ).rstrip(".")

    return str(raw_name).rstrip(".")


def get_addresses(packet):
    """
    Return the source and destination IP addresses.

    Supports both IPv4 and IPv6.
    """

    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return None, None


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

def log_event(event: dict):
    """
    Append one DNS event to a JSON Lines file.

    JSONL is useful for security logs because each line is
    independently parseable JSON.
    """

    with LOG_FILE.open(
        "a",
        encoding="utf-8"
    ) as file:
        file.write(
            json.dumps(
                event,
                ensure_ascii=False
            ) + "\n"
        )


# ------------------------------------------------------------
# DNS request handler
# ------------------------------------------------------------

def handle_dns_query(packet):
    """
    Process a captured DNS request.

    DNS query packets contain the DNSQR layer.
    """

    if DNS not in packet:
        return

    dns = packet[DNS]

    # qr == 0 means this is a DNS query/request.
    if dns.qr != 0:
        return

    if DNSQR not in packet:
        return

    query = packet[DNSQR]

    domain = decode_dns_name(query.qname)

    source_ip, destination_ip = get_addresses(packet)

    event = {
        "timestamp": datetime.now().isoformat(),
        "type": "query",
        "source": source_ip,
        "destination": destination_ip,
        "domain": domain,
        "query_type": int(query.qtype),
    }

    print(
        f"[DNS QUERY] "
        f"{source_ip} -> {destination_ip} "
        f"{domain}"
    )

    log_event(event)


# ------------------------------------------------------------
# DNS response handler
# ------------------------------------------------------------

def handle_dns_response(packet):
    """
    Process DNS responses and extract returned addresses.
    """

    if DNS not in packet:
        return

    dns = packet[DNS]

    # qr == 1 means response.
    if dns.qr != 1:
        return

    source_ip, destination_ip = get_addresses(packet)

    answers = []

    # Walk through all DNS answer records.
    for index in range(dns.ancount):

        try:
            answer = dns.an[index]
        except Exception:
            continue

        if not isinstance(answer, DNSRR):
            continue

        name = decode_dns_name(answer.rrname)

        # rdata can contain an IP address, hostname,
        # byte string, or another DNS-specific value.
        value = answer.rdata

        if isinstance(value, bytes):
            value = value.decode(
                "utf-8",
                errors="replace"
            )

        answers.append({
            "name": name,
            "type": int(answer.type),
            "value": str(value),
        })

    event = {
        "timestamp": datetime.now().isoformat(),
        "type": "response",
        "source": source_ip,
        "destination": destination_ip,
        "answers": answers,
    }

    if answers:

        print(
            f"[DNS RESPONSE] "
            f"{source_ip} -> {destination_ip}"
        )

        for answer in answers:
            print(
                f"    {answer['name']} "
                f"-> {answer['value']}"
            )

    log_event(event)


# ------------------------------------------------------------
# Basic DNS-tunneling heuristic
# ------------------------------------------------------------

def check_suspicious_domain(domain: str):
    """
    Apply a few simple heuristics that can help identify domains
    worth investigating.

    IMPORTANT:
    These are indicators only. They do not prove malware or
    DNS exfiltration.
    """

    labels = domain.split(".")

    if not labels:
        return []

    alerts = []

    # Very long DNS labels can occasionally indicate encoded
    # data being transported through DNS.
    longest_label = max(
        labels,
        key=len
    )

    if len(longest_label) > 40:
        alerts.append(
            "unusually long DNS label"
        )

    # A domain with many subdomains can also be interesting
    # when investigating DNS tunneling.
    if len(labels) > 6:
        alerts.append(
            "large number of subdomains"
        )

    return alerts


# ------------------------------------------------------------
# Main packet callback
# ------------------------------------------------------------

def packet_handler(packet):
    """
    Called by Scapy for every captured DNS packet.
    """

    if DNS not in packet:
        return

    dns = packet[DNS]

    # --------------------------------------------------------
    # DNS request
    # --------------------------------------------------------

    if dns.qr == 0 and DNSQR in packet:

        domain = decode_dns_name(
            packet[DNSQR].qname
        )

        handle_dns_query(packet)

        # Run simple detection heuristics.
        alerts = check_suspicious_domain(
            domain
        )

        for alert in alerts:
            print(
                f"    [!] {alert}: {domain}"
            )

    # --------------------------------------------------------
    # DNS response
    # --------------------------------------------------------

    elif dns.qr == 1:
        handle_dns_response(packet)


# ------------------------------------------------------------
# Start monitor
# ------------------------------------------------------------

def monitor_dns(interface=None):
    """
    Passively monitor DNS requests and responses.

    On macOS, raw packet capture generally requires root
    privileges.

    Example:

        sudo python3 dns_monitor.py
    """

    print("[*] DNS monitor started")
    print(f"[*] Logging to: {LOG_FILE.resolve()}")

    if interface:
        print(f"[*] Interface: {interface}")
    else:
        print("[*] Interface: automatic")

    print("[*] Press Ctrl+C to stop\n")

    sniff(
        iface=interface,
        filter=BPF_FILTER,
        prn=packet_handler,
        store=False,
    )


# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------

if __name__ == "__main__":

    try:
        monitor_dns()

    except KeyboardInterrupt:
        print("\n[*] DNS monitor stopped")
