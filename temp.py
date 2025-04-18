import os
import subprocess
import threading
import logging
import signal
import sys
from scapy.all import IP, TCP, Raw
from netfilterqueue import NetfilterQueue

# 🔹 Logging Setup
LOG_FILE = "/var/log/hybrid_firewall.log"

logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(message)s")
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# 🔹 Load Blocklists
def load_blocklist(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"[ERROR] Blocklist file not found: {file_path}")
        return []

def reload_blocklists():
    global BLOCKED_IPS, BLOCKED_PORTS, BLOCKED_KEYWORDS, BLOCKED_SITES
    BLOCKED_IPS = load_blocklist("blocked_ips.txt")
    BLOCKED_PORTS = [int(port) for port in load_blocklist("blocked_ports.txt") if port.isdigit()]
    BLOCKED_KEYWORDS = load_blocklist("blocked_keywords.txt")
    BLOCKED_SITES = load_blocklist("blocked_sites.txt")

# Initial load
reload_blocklists()

# 🔹 Sanity Check
def sanity_check():
    required = ['iptables', 'fail2ban-client', 'squid']
    for tool in required:
        if subprocess.run(["which", tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
            logger.warning(f"[WARNING] {tool} not found!")

# 🔹 Configure iptables Rules
def setup_iptables():
    commands = [
        ["sudo", "iptables", "-F"],
        ["sudo", "iptables", "-P", "INPUT", "DROP"],
        ["sudo", "iptables", "-P", "FORWARD", "DROP"],
        ["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"],
        ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-m", "state", "--state", "NEW", "-m", "recent", "--set"],
        ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-m", "state", "--state", "NEW", "-m", "recent", "--update", "--seconds", "60", "--hitcount", "4", "-j", "DROP"],
        ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
        ["sudo", "iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-m", "limit", "--limit", "1/s", "--limit-burst", "3", "-j", "ACCEPT"],
        ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-j", "NFQUEUE", "--queue-num", "1"],
        ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", "1"],
    ]

    for ip in BLOCKED_IPS:
        commands.append(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        commands.append(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])

    for port in BLOCKED_PORTS:
        commands.append(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])

    for cmd in commands:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"[ERROR] Failed to apply iptables rule: {' '.join(cmd)} - {e}")

    logger.info("[INFO] iptables rules finalized.")

# 🔹 Packet Inspection & Filtering
def inspect_packet(packet):
    try:
        scapy_pkt = IP(packet.get_payload())

        if scapy_pkt.src in BLOCKED_IPS or scapy_pkt.dst in BLOCKED_IPS:
            logger.warning(f"[BLOCKED] IP: {scapy_pkt.src} -> {scapy_pkt.dst}")
            packet.drop()
            return

        if scapy_pkt.haslayer(TCP) and (
            scapy_pkt[TCP].sport in BLOCKED_PORTS or scapy_pkt[TCP].dport in BLOCKED_PORTS):
            logger.warning(f"[BLOCKED] Port: {scapy_pkt.src}:{scapy_pkt[TCP].sport} -> {scapy_pkt.dst}:{scapy_pkt[TCP].dport}")
            packet.drop()
            return

        if scapy_pkt.haslayer(Raw):
            try:
                http_payload = scapy_pkt[Raw].load.decode("utf-8", errors="replace")
                for keyword in BLOCKED_KEYWORDS:
                    if keyword.lower() in http_payload.lower():
                        logger.warning(f"[BLOCKED] Keyword Detected: {keyword}")
                        packet.drop()
                        return
            except UnicodeDecodeError:
                logger.error("[ERROR] Unicode decoding failed")

        packet.accept()

    except Exception as e:
        logger.error(f"[ERROR] Packet inspection failed: {e}")
        packet.accept()

# 🔹 Fail2Ban Setup
def setup_fail2ban():
    try:
        if subprocess.run(["which", "fail2ban-server"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
            subprocess.run(["sudo", "apt-get", "install", "fail2ban", "-y"], check=True)
        subprocess.run(["sudo", "systemctl", "enable", "fail2ban"], check=True)
        subprocess.run(["sudo", "systemctl", "start", "fail2ban"], check=True)
        logger.info("[INFO] Fail2Ban is active.")
    except Exception as e:
        logger.error(f"[ERROR] Fail2Ban setup failed: {e}")

# 🔹 Squid Proxy Setup
def setup_squid_proxy():
    try:
        if subprocess.run(["which", "squid"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
            subprocess.run(["sudo", "apt-get", "install", "squid", "-y"], check=True)

        with open("/etc/squid/blocked_sites.txt", "w") as f:
            f.write("\n".join([f".{domain}" for domain in BLOCKED_SITES]))

        squid_config = """
http_port 3128
acl allowed_ips src 192.168.56.0/24
acl blocked_sites dstdomain "/etc/squid/blocked_sites.txt"
http_access deny blocked_sites
http_access allow allowed_ips
http_access deny all
"""
        with open("/etc/squid/squid.conf", "w") as f:
            f.write(squid_config)

        subprocess.run(["sudo", "systemctl", "restart", "squid"], check=True)
        logger.info("[INFO] Squid Proxy configured.")
    except Exception as e:
        logger.error(f"[ERROR] Squid Proxy setup failed: {e}")

# 🔹 Update Blocklists from GitHub URLs
def update_blocklists():
    logger.info("[INFO] Updating blocklists...")
    urls = {
        "blocked_ips.txt": r"https://github.com/Madhav998/firewall/blob/main/blocked_ips.txt",
        "blocked_ports.txt": r"https://github.com/Madhav998/firewall/blob/main/port%20list", 
        "blocked_keywords.txt": r"https://github.com/Madhav998/firewall/blob/main/blocked_keywords.txt",
        "blocked_sites.txt": r"https://github.com/Madhav998/firewall/blob/main/blocked_sites.txt"
    }

    for filename, url in urls.items():
        try:
            temp_file = filename + ".tmp"
            subprocess.run(["wget", "-O", temp_file, url], check=True)
            os.replace(temp_file, filename)
            logger.info(f"[INFO] Updated {filename}.")
        except subprocess.CalledProcessError as e:
            logger.error(
                f"[ERROR] Failed to update rules: {e}"
            )
