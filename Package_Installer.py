import json
import os
import threading
import paramiko
from scapy.all import ARP, Ether, srp

# ARP scan to find live devices
def arp_scan(ip_range):
    print(f"Scanning network: {ip_range}")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = [{'ip': received.psrc, 'mac': received.hwsrc.lower()} for sent, received in result]
    return devices

# Function to install package
def install_package(hostname, port, username, install_cmd):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key_path = os.path.expanduser("~/.ssh/id_rsa")
        private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
        ssh.connect(hostname, port=port, username=username, pkey=private_key)

        print(f"[{hostname}] Running: {install_cmd}")
        stdin, stdout, stderr = ssh.exec_command(install_cmd)

        output = stdout.read().decode()
        error = stderr.read().decode()
        print(f"[{hostname}] Output:\n{output}")
        if error:
            print(f"[{hostname}] Error:\n{error}")

        ssh.close()
    except Exception as e:
        print(f"[{hostname}] Exception: {e}")

if __name__ == "__main__":
    # Step 1: Scan subnet
    subnet = input("Enter subnet (e.g., 192.168.5.0/24): ").strip()
    network_devices = arp_scan(subnet)

    # Step 2: Load MAC-to-username map
    try:
        with open("user.json", "r") as f:
            mac_username_map = json.load(f)
    except FileNotFoundError:
        print("Error: user.json not found.")
        exit(1)

    mac_username_map = {k.lower(): v for k, v in mac_username_map.items()}

    # Step 3: Match devices
    user_ip_list = []
    for device in network_devices:
        mac = device['mac']
        ip = device['ip']
        if mac in mac_username_map:
            username = mac_username_map[mac]
            user_ip_list.append({'username': username, 'ip': ip})

    print("\nMapped Users and IPs:")
    if not user_ip_list:
        print("  (No matches found.)")
        exit(0)
    for entry in user_ip_list:
        print(f"  {entry['username']}: {entry['ip']}")

    # Step 4: Ask what to install
    print("\nSelect installation method:")
    print("  1. apt (e.g., sudo apt install curl)")
    print("  2. pip (e.g., pip install numpy)")
    print("  3. npm (e.g., npm install -g express)")
    method = input("Enter number (1/2/3): ").strip()

    package = input("Enter the package name to install: ").strip()

    # Build the command
    if method == "1":
        install_cmd = f"sudo apt update && sudo apt install -y {package}"
    elif method == "2":
        install_cmd = f"pip install {package}"
    elif method == "3":
        install_cmd = f"npm install -g {package}"
    else:
        print("Invalid choice.")
        exit(1)

    confirm = input(f"\nInstall '{package}' using selected method on ALL matched devices? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        exit(0)

    # Step 5: Run install command in threads
    threads = []
    port = 22

    for entry in user_ip_list:
        username = entry['username']
        ip = entry['ip']
        t = threading.Thread(
            target=install_package,
            args=(ip, port, username, install_cmd)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\nInstallation command issued on all matched devices.")
