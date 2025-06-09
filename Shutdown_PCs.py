import json
import os
import threading
import paramiko
from scapy.all import ARP, Ether, srp

# Step 1: ARP scan to discover active IP/MAC pairs
def arp_scan(ip_range):
    print(f"Scanning network: {ip_range}")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = [{'ip': received.psrc, 'mac': received.hwsrc.lower()} for sent, received in result]
    return devices

# Step 2: SSH into the machine and shut it down using sudo
def shutdown_host(hostname, port, username):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key_path = os.path.expanduser("~/.ssh/id_rsa")
        private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
        ssh.connect(hostname, port=port, username=username, pkey=private_key)

        # Use sudo to poweroff
        stdin, stdout, stderr = ssh.exec_command("sudo systemctl poweroff")

        # If sudo requires a password, this will hang — ensure passwordless sudo for this command on remote hosts!
        print(f"[{hostname}] Shutdown command sent to {username}@{hostname}")

        ssh.close()
    except Exception as e:
        print(f"[{hostname}] Error: {e}")

if __name__ == "__main__":
    subnet = input("Enter subnet (e.g., 192.168.5.0/24): ").strip()
    network_devices = arp_scan(subnet)

    try:
        with open("user.json", "r") as f:
            mac_username_map = json.load(f)
    except FileNotFoundError:
        print("Error: user.json not found in current directory.")
        exit(1)

    mac_username_map = {k.lower(): v for k, v in mac_username_map.items()}

    user_ip_list = []
    for device in network_devices:
        mac = device['mac']
        ip = device['ip']
        if mac in mac_username_map:
            username = mac_username_map[mac]
            user_ip_list.append({'username': username, 'ip': ip})

    print("\nMapped Users and IPs:")
    if not user_ip_list:
        print("  (No matches found between ARP scan and user.json)")
        exit(0)

    for entry in user_ip_list:
        print(f"  {entry['username']}: {entry['ip']}")

    confirm = input("\nAre you sure you want to SHUT DOWN these machines? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        exit(0)

    threads = []
    port = 22

    for entry in user_ip_list:
        username = entry['username']
        ip = entry['ip']
        t = threading.Thread(
            target=shutdown_host,
            args=(ip, port, username)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\nShutdown commands issued to all matched devices.")
