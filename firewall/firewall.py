from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from rule_manager import load_rules, RULES_FILE
import logging
import os
import time
from ml_detector import evaluate_packet, ML_DETECT_ENFORCE

LOG_FILE = 'firewall/logs/firewall.log'

# Set up logging
if not os.path.exists('firewall/logs'):
    os.makedirs('firewall/logs')

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)


RULES_REFRESH_INTERVAL = float(os.getenv('RULES_REFRESH_INTERVAL', '5'))
_blocked_ip_set = set()
_last_rules_mtime = None
_next_rules_check_ts = 0.0


def _maybe_refresh_rules():
    """Refresh cached rules at most every RULES_REFRESH_INTERVAL seconds.

    Uses the rules file's mtime to rebuild caches only when content changes.
    """
    global _blocked_ip_set, _last_rules_mtime, _next_rules_check_ts

    now = time.monotonic()
    if now < _next_rules_check_ts:
        return
    _next_rules_check_ts = now + RULES_REFRESH_INTERVAL

    try:
        current_mtime = os.path.getmtime(RULES_FILE)
    except FileNotFoundError:
        _blocked_ip_set = set()
        _last_rules_mtime = None
        return

    if _last_rules_mtime == current_mtime:
        return

    rules = load_rules()
    _blocked_ip_set = {r.get('ip') for r in rules if r.get('action') == 'block' and r.get('ip')}
    _last_rules_mtime = current_mtime


def packet_callback(packet):
    """Callback function to process each packet."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        _maybe_refresh_rules()

        # Fast set membership check for blocked IPs
        if src_ip in _blocked_ip_set or dst_ip in _blocked_ip_set:
            logging.info(f"Blocked packet from {src_ip} to {dst_ip}")
            return  # Drop the packet by not forwarding it

        # Optional ML-based detection (local, no API key)
        try:
            proto = 'tcp' if TCP in packet else ('udp' if UDP in packet else str(packet[IP].proto))
            src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else '')
            dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else '')
            metadata = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'proto': str(proto),
                'src_port': str(src_port),
                'dst_port': str(dst_port),
                'length': str(len(packet))
            }
            decision, reason = evaluate_packet(metadata)
            if decision == 'block' and ML_DETECT_ENFORCE:
                logging.info(f"Blocked (ML) packet from {src_ip} to {dst_ip} reason={reason}")
                return
        except Exception:
            # ML path is best-effort; ignore errors to keep fast path reliable
            pass

        # Log allowed packets
        logging.info(f"Allowed packet from {src_ip} to {dst_ip}")


if __name__ == "__main__":
    print("Firewall is running...")

    # Start sniffing packets on all interfaces (you can specify an interface like 'eth0')
    sniff(prn=packet_callback, store=0)