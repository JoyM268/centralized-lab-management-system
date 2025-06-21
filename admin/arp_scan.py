import json
from scapy.all import ARP, Ether, srp

def perform_arp_scan_and_map(subnet):
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(broadcast / arp_request, timeout=5, verbose=0)[0]

    active_devices = [{'ip': r.psrc, 'mac': r.hwsrc.lower()} for s, r in result]

    try:
        with open("user.json", "r") as f:
            mac_username_map = {k.lower(): v for k, v in json.load(f).items()}
    except (FileNotFoundError, json.JSONDecodeError):
        mac_username_map = {}

    user_ip_list = [
        {'username': mac_username_map[dev['mac']], 'ip': dev['ip']}
        for dev in active_devices if dev['mac'] in mac_username_map
    ]

    return user_ip_list
