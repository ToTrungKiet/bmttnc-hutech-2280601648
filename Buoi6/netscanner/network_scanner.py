import requests
from scapy.all import ARP, Ether, srp

def local_network_scan(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    print(f"DEBUG: Found {len(result)} responses")

    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'vendor': "Unknown"  # Để test trước
            # 'vendor': get_vendor_by_mac(received.hwsrc)
        })
    return devices

def main():
    ip_range = "192.168.88.1/24"
    devices = local_network_scan(ip_range)
    print("Devices on the local network:")
    if not devices:
        print("No devices found.")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}")

if __name__ == "__main__":
    main()
