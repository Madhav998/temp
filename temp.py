import subprocess
import logging
import os
import time
from netfilterqueue import NetfilterQueue
import iptc
from scapy.all import IP, TCP, UDP, Raw

# Configure logging to file and console
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')
logger = logging.getLogger()
file_handler = logging.FileHandler('firewall_log.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(file_handler)

# Blocklist file paths (add full paths if needed)
BLOCKLIST_PATH = "/path/to/blocklists/"

def load_blocklist(file_name):
    try:
        with open(os.path.join(BLOCKLIST_PATH, file_name), "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"[ERROR] Blocklist file not found: {file_name}")
        return []

# Load blocklists
blocked_ips = load_blocklist("blocked_ips.txt")
blocked_ports = load_blocklist("blocked_ports.txt")
blocked_keywords = load_blocklist("blocked_keywords.txt")
blocked_sites = load_blocklist("blocked_sites.txt")

# Automated update function to refresh blocklists
def update_blocklists():
    logger.info("Checking for blocklist updates...")
    try:
        # Placeholder for actual blocklist update mechanism
        # For example, downloading from a remote server
        subprocess.run(["wget", "-q", "-O", os.path.join(BLOCKLIST_PATH, "blocked_ips.txt"), "http://example.com/blocked_ips.txt"], check=True)
        subprocess.run(["wget", "-q", "-O", os.path.join(BLOCKLIST_PATH, "blocked_ports.txt"), "http://example.com/blocked_ports.txt"], check=True)
        subprocess.run(["wget", "-q", "-O", os.path.join(BLOCKLIST_PATH, "blocked_keywords.txt"), "http://example.com/blocked_keywords.txt"], check=True)
        subprocess.run(["wget", "-q", "-O", os.path.join(BLOCKLIST_PATH, "blocked_sites.txt"), "http://example.com/blocked_sites.txt"], check=True)
        logger.info("Blocklists updated successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"[ERROR] Blocklist update failed: {e}")

# Setup iptables for blocking traffic
def setup_iptables():
    logger.info("Setting up iptables...")
    
    try:
        # Flush existing rules to avoid conflicts
        subprocess.run(["iptables", "-F"], check=True)

        # Set default policies to DROP
        subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
        subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True)
        subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)
        
        # Allow loopback and established connections
        subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)

        # Block IPs in the blocklist
        for ip in blocked_ips:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
        
        # Block ports in the blocklist
        for port in blocked_ports:
            subprocess.run(["iptables", "-A", "INPUT", "--dport", port, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "--sport", port, "-j", "DROP"], check=True)

        # Allow HTTP/S traffic on ports 80, 443
        subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", "80", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", "443", "-j", "ACCEPT"], check=True)
        
        # Block websites based on domains (basic DNS blocking)
        for site in blocked_sites:
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", site, "-j", "DROP"], check=True)
        
        logger.info("Iptables setup complete.")
    except subprocess.CalledProcessError as e:
        logger.error(f"[ERROR] Failed to setup iptables: {e}")

# Setup Fail2Ban to block brute-force attempts
def setup_fail2ban():
    logger.info("Setting up Fail2Ban...")
    try:
        # Example: Ban IP for 1 hour if too many failed login attempts
        subprocess.run(["fail2ban-client", "start"], check=True)
        logger.info("Fail2Ban setup complete.")
    except subprocess.CalledProcessError as e:
        logger.error(f"[ERROR] Failed to setup Fail2Ban: {e}")

# Packet inspection function for NetfilterQueue
def inspect_packet(pkt):
    packet = IP(pkt.get_payload())
    logger.info(f"Inspecting packet: {packet.summary()}")
    
    # Block based on IP
    if packet.src in blocked_ips or packet.dst in blocked_ips:
        logger.warning(f"Blocked packet from IP: {packet.src} -> {packet.dst}")
        pkt.drop()
        return
    
    # Block based on ports
    if packet.haslayer(TCP):
        if packet.dport in blocked_ports or packet.sport in blocked_ports:
            logger.warning(f"Blocked packet on port: {packet.dport}")
            pkt.drop()
            return
    
    # Block based on keywords in the packet payload
    if packet.haslayer(Raw):
        payload = str(packet[Raw].load)
        for keyword in blocked_keywords:
            if keyword in payload:
                logger.warning(f"Blocked packet with keyword: {keyword}")
                pkt.drop()
                return

    # Allow packet if no conditions are matched
    pkt.accept()

# Start the packet filtering process with NetfilterQueue
def start_packet_filtering():
    logger.info("Starting packet filtering...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, inspect_packet)
    try:
        nfqueue.run()
    except Exception as e:
        logger.error(f"[ERROR] NetfilterQueue failed: {e}")

# Main function to setup and run the firewall
def main():
    setup_iptables()
    setup_fail2ban()
    update_blocklists()  # Ensure blocklists are updated
    start_packet_filtering()

if __name__ == "__main__":
    main()
