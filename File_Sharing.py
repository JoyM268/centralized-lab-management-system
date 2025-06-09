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

# Step 2: Send file via SSH/SFTP
def send_file(hostname, port, username, local_file_path, remote_file_path):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key_path = os.path.expanduser("~/.ssh/id_rsa")
        private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
        ssh.connect(hostname, port=port, username=username, pkey=private_key)

        sftp = ssh.open_sftp()
        sftp.put(local_file_path, remote_file_path)
        print(f"[{hostname}] File sent successfully to {username}@{hostname}:{remote_file_path}")

        sftp.close()
        ssh.close()
    except Exception as e:
        print(f"[{hostname}] Error: {e}")

if __name__ == "__main__":
    # 1) Ask for subnet and perform ARP scan
    subnet = input("Enter subnet (e.g., 192.168.5.0/24): ").strip()
    network_devices = arp_scan(subnet)

    # 2) Load MAC-to-username JSON
    try:
        with open("user.json", "r") as f:
            mac_username_map = json.load(f)
    except FileNotFoundError:
        print("Error: user.json not found in current directory.")
        exit(1)

    # Normalize MACs in JSON to lowercase
    mac_username_map = {k.lower(): v for k, v in mac_username_map.items()}

    # 3) Build full list of {username, ip} entries (allow duplicates)
    user_ip_list = []
    for device in network_devices:
        mac = device['mac']
        ip = device['ip']
        if mac in mac_username_map:
            username = mac_username_map[mac]
            user_ip_list.append({'username': username, 'ip': ip})

    # 4) Display the mapping before proceeding
    print("\nMapped Users and IPs:")
    if not user_ip_list:
        print("  (No matches found between ARP scan and user.json)")
        exit(0)

    for entry in user_ip_list:
        print(f"  {entry['username']}: {entry['ip']}")

    # 5) Ask for file paths after mapping is done
    source_path = input("\nEnter source file path to send: ").strip()
    destination_path = input("Enter destination file path on each remote machine: ").strip()

    if not os.path.isfile(source_path):
        print(f"Error: Source file '{source_path}' does not exist.")
        exit(1)

    # 6) Send file to all matching devices via threads
    threads = []
    port = 22  # Default SSH port

    for entry in user_ip_list:
        username = entry['username']
        ip = entry['ip']
        t = threading.Thread(
            target=send_file,
            args=(ip, port, username, source_path, destination_path)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\nAll file transfers completed.")