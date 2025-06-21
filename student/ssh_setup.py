import subprocess
import re
import time

def install_openssh_server(capture_output=True):
    if not is_package_installed("openssh-server"):
        subprocess.run(["apt-get", "update"], check=True, capture_output=capture_output, text=True)
        subprocess.run(["apt-get", "install", "-y", "openssh-server"], check=True, capture_output=capture_output, text=True)

def is_package_installed(name):
    result = subprocess.run(["dpkg", "-s", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0

def configure_ssh_service(capture_output=True):
    subprocess.run(["systemctl", "enable", "ssh"], check=True, capture_output=capture_output, text=True)
    subprocess.run(["systemctl", "start", "ssh"], check=True, capture_output=capture_output, text=True)

def configure_firewall(capture_output=True):
    subprocess.run(["ufw", "allow", "ssh"], check=True, capture_output=capture_output, text=True)
    subprocess.run(["ufw", "enable"], input='y\n', check=True, text=True, capture_output=capture_output)

def configure_ssh_security(capture_output=True):
    sshd_config_path = "/etc/ssh/sshd_config"
    try:
        with open(sshd_config_path, 'r') as f:
            lines = f.readlines()

        new_lines = []
        password_auth_found = False
        pubkey_auth_found = False

        for line in lines:
            stripped_line = line.strip()
            if re.match(r'^\s*#?\s*PasswordAuthentication\s+', stripped_line, re.IGNORECASE):
                new_lines.append("PasswordAuthentication no\n")
                password_auth_found = True
            elif re.match(r'^\s*#?\s*PubkeyAuthentication\s+', stripped_line, re.IGNORECASE):
                new_lines.append("PubkeyAuthentication yes\n")
                pubkey_auth_found = True
            else:
                new_lines.append(line)

        if not password_auth_found:
            new_lines.append("\nPasswordAuthentication no\n")
        if not pubkey_auth_found:
            new_lines.append("PubkeyAuthentication yes\n")

        with open(sshd_config_path, 'w') as f:
            f.writelines(new_lines)
        subprocess.run(["systemctl", "restart", "ssh"], check=True, capture_output=capture_output, text=True)

    except FileNotFoundError:
        raise RuntimeError(f"SSHD config file not found at {sshd_config_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to modify SSH configuration: {e}")

def run_full_setup(update_callback=None):
    steps = [
        ("Installing OpenSSH server...", install_openssh_server),
        ("Enabling the SSH service...", configure_ssh_service),
        ("Configuring the firewall...", configure_firewall),
        ("Securing SSH configuration...", configure_ssh_security)
    ]
    for text, func in steps:
        if update_callback:
            update_callback(text)
        func()
        time.sleep(1)
