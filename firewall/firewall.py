from scapy.all import sniff
from scapy.layers.inet import IP
from rule_manager import load_rules
import logging
import os

LOG_FILE = 'firewall/logs/firewall.log'

# Set up logging
if not os.path.exists('firewall/logs'):
    os.makedirs('firewall/logs')

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)


def packet_callback(packet):
    """Callback function to process each packet."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Load firewall rules
        rules = load_rules()

        # Check if any rule matches this packet's source or destination IP
        for rule in rules:
            if rule['ip'] == src_ip or rule['ip'] == dst_ip:
                if rule['action'] == 'block':
                    logging.info(f"Blocked packet from {src_ip} to {dst_ip}")
                    return  # Drop the packet by not forwarding it

        # Log allowed packets
        logging.info(f"Allowed packet from {src_ip} to {dst_ip}")


if __name__ == "__main__":
    print("Firewall is running...")

    # Start sniffing packets on all interfaces (you can specify an interface like 'eth0')
    sniff(prn=packet_callback, store=0)