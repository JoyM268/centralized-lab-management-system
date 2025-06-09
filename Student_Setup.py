import subprocess
import os
import sys
import shutil

def run(command, check=True):
    """Run a shell command."""
    print(f"Running: {' '.join(command)}")
    subprocess.run(command, check=check)

def is_package_installed(package_name):
    """Check if a package is installed using dpkg."""
    result = subprocess.run(['dpkg', '-s', package_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0

def install_openssh_server():
    if not is_package_installed('openssh-server'):
        print("Installing OpenSSH Server...")
        run(['apt', 'update'])
        run(['apt', 'install', '-y', 'openssh-server'])
    else:
        print("OpenSSH Server is already installed.")

def configure_ssh_service():
    print("Enabling and starting SSH service...")
    run(['systemctl', 'enable', 'ssh'])
    run(['systemctl', 'start', 'ssh'])

def is_ufw_installed():
    try:
        subprocess.run(['ufw', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False
    
def install_ufw():
    print("UFW not found. Installing UFW...")
    run(['sudo', 'apt', 'update'])
    run(['sudo', 'apt', 'install', '-y', 'ufw'])

def configure_firewall():
    if not is_ufw_installed():
        install_ufw()
    else:
        print("UFW is already installed.")

    print("Configuring firewall to allow SSH...")
    run(['sudo', 'ufw', 'allow', 'ssh'])
    run(['sudo', 'ufw', 'enable'])

def add_public_key():
    pub_key_path = input("Enter the path to the public key file: ").strip()
    
    if not os.path.isfile(pub_key_path):
        print(f"Error: File '{pub_key_path}' does not exist.")
        sys.exit(1)

    with open(pub_key_path, 'r') as f:
        pub_key = f.read().strip()

    ssh_dir = os.path.expanduser("~/.ssh")
    auth_keys_path = os.path.join(ssh_dir, "authorized_keys")

    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

    if not os.path.isfile(auth_keys_path):
        print("Creating authorized_keys file...")
        with open(auth_keys_path, 'w') as f:
            f.write(pub_key + '\n')
    else:
        with open(auth_keys_path, 'r') as f:
            if pub_key in f.read():
                print("Public key already exists in authorized_keys.")
                return
        with open(auth_keys_path, 'a') as f:
            f.write(pub_key + '\n')

    os.chmod(auth_keys_path, 0o600)
    os.chown(auth_keys_path, os.getuid(), os.getgid())

    print("Public key added to authorized_keys.")

def require_root():
    if os.geteuid() != 0:
        print("This script must be run as root. Use: sudo python3 setup_ssh_server.py")
        sys.exit(1)

def main():
    require_root()
    install_openssh_server()
    configure_ssh_service()
    configure_firewall()
    add_public_key()
    print("\nSSH server configuration completed successfully.")

if __name__ == "__main__":
    main()
