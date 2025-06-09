import json
import os
import threading
import paramiko
from scapy.all import ARP, Ether, srp

def arp_scan(ip_range):
    print(f"Scanning network: {ip_range}")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = [{'ip': received.psrc, 'mac': received.hwsrc.lower()} for sent, received in result]
    return devices

def run_script(hostname, port, username, local_path, remote_path, exec_cmd, check_cmd, install_cmd):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key_path = os.path.expanduser("~/.ssh/id_rsa")
        private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
        ssh.connect(hostname, port=port, username=username, pkey=private_key)

        # Step 1: Check if required interpreter/compiler exists
        print(f"[{hostname}] Checking environment...")
        stdin, stdout, stderr = ssh.exec_command(check_cmd)
        result = stdout.read().decode().strip()
        if not result:
            print(f"[{hostname}] Required tool not found. Installing...")
            ssh.exec_command(f"sudo apt update && sudo apt install -y {install_cmd}")
            # Wait a bit for install to finish
            import time
            time.sleep(5)

        # Step 2: Upload script
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        print(f"[{hostname}] Script uploaded.")

        # Step 3: Execute script
        stdin, stdout, stderr = ssh.exec_command(exec_cmd)
        out = stdout.read().decode()
        err = stderr.read().decode()

        print(f"[{hostname}] Output:\n{out}")
        if err:
            print(f"[{hostname}] Error:\n{err}")

        ssh.close()
    except Exception as e:
        print(f"[{hostname}] Exception: {e}")

if __name__ == "__main__":
    subnet = input("Enter subnet (e.g., 192.168.5.0/24): ").strip()
    network_devices = arp_scan(subnet)

    try:
        with open("user.json", "r") as f:
            mac_username_map = json.load(f)
    except FileNotFoundError:
        print("Error: user.json not found.")
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
        print("  (No matches found.)")
        exit(0)
    for entry in user_ip_list:
        print(f"  {entry['username']}: {entry['ip']}")

    print("\nSelect script type:")
    print("  1. Python")
    print("  2. C (gcc)")
    print("  3. Java")
    print("  4. Bash")
    choice = input("Enter number (1/2/3/4): ").strip()

    local_path = input("Enter path to your local script file: ").strip()
    if not os.path.isfile(local_path):
        print(f"Error: file '{local_path}' does not exist.")
        exit(1)

    filename = os.path.basename(local_path)
    remote_path = f"/tmp/{filename}"

    if choice == "1":
        exec_cmd = f"python3 {remote_path}"
        check_cmd = "which python3"
        install_cmd = "python3"
    elif choice == "2":
        exe_name = filename.replace(".c", "")
        exec_cmd = f"gcc {remote_path} -o /tmp/{exe_name} && /tmp/{exe_name}"
        check_cmd = "which gcc"
        install_cmd = "gcc"
    elif choice == "3":
        class_name = filename.replace(".java", "")
        exec_cmd = f"javac {remote_path} && java -cp /tmp {class_name}"
        check_cmd = "which javac"
        install_cmd = "default-jdk"
    elif choice == "4":
        exec_cmd = f"bash {remote_path}"
        check_cmd = "which bash"
        install_cmd = "bash"
    else:
        print("Invalid choice.")
        exit(1)

    confirm = input(f"\nExecute this script on all matched devices? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        exit(0)

    threads = []
    port = 22

    for entry in user_ip_list:
        username = entry['username']
        ip = entry['ip']
        t = threading.Thread(
            target=run_script,
            args=(ip, port, username, local_path, remote_path, exec_cmd, check_cmd, install_cmd)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\nScript execution completed on all matched devices.")
