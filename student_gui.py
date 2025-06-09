import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import time
import subprocess
import os
import pwd

class SSHSetupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Setup Assistant")
        self.root.geometry("500x350")
        self.root.resizable(False, False)

        self.frame = tk.Frame(root)
        self.frame.pack(expand=True)

        self.label = tk.Label(self.frame, text="Initializing Setup...", font=("Segoe UI", 16))
        self.label.pack(pady=10)

        self.progress_label = tk.Label(self.frame, text="", font=("Segoe UI", 12))
        self.progress_label.pack(pady=5)

        self.canvas = tk.Canvas(self.frame, width=100, height=100, highlightthickness=0)
        self.canvas.pack(pady=10)
        self.arc = self.canvas.create_arc(10, 10, 90, 90, start=0, extent=60, style=tk.ARC, outline="#0078D7", width=4)
        self.angle = 0
        self.animate = True
        self.rotate_loader()

        self.root.after(100, self.run_setup_thread)

    def rotate_loader(self):
        if self.animate:
            self.angle = (self.angle + 5) % 360
            self.canvas.itemconfig(self.arc, start=self.angle)
            self.root.after(20, self.rotate_loader)

    def run_setup_thread(self):
        threading.Thread(target=self.run_setup).start()

    def run_setup(self):
        try:
            steps = [
                ("Installing OpenSSH Server...", self.install_openssh_server),
                ("Enabling SSH service...", self.configure_ssh_service),
                ("Configuring firewall...", self.configure_firewall)
            ]
            for text, func in steps:
                self.update_progress(text)
                func()
                time.sleep(1)
            self.animate = False
            self.show_key_ui()
        except Exception as e:
            self.update_progress(f"Error: {str(e)}")
            self.animate = False

    def update_progress(self, text):
        self.progress_label.config(text=text)

    def install_openssh_server(self):
        if not self.is_package_installed("openssh-server"):
            subprocess.run(["apt", "update"], check=True)
            subprocess.run(["apt", "install", "-y", "openssh-server"], check=True)

    def is_package_installed(self, name):
        result = subprocess.run(["dpkg", "-s", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0

    def configure_ssh_service(self):
        subprocess.run(["systemctl", "enable", "ssh"], check=True)
        subprocess.run(["systemctl", "start", "ssh"], check=True)

    def configure_firewall(self):
        subprocess.run(["ufw", "allow", "ssh"], check=True)
        subprocess.run(["ufw", "enable"], check=True)

    def get_target_user_home(self):
        sudo_user = os.environ.get("SUDO_USER")
        if not sudo_user:
            raise RuntimeError("This script must be run using sudo.")
        return os.path.expanduser(f"~{sudo_user}")

    def get_target_user_ids(self):
        sudo_user = os.environ.get("SUDO_USER")
        pw_record = pwd.getpwnam(sudo_user)
        return pw_record.pw_uid, pw_record.pw_gid

    def show_key_ui(self):
        self.label.config(text="Setup Complete")
        self.progress_label.config(text="Select your SSH public key to authorize:")
        self.canvas.destroy()

        self.add_key_button = tk.Button(self.frame, text="Add Public Key", command=self.add_key, font=("Segoe UI", 11))
        self.add_key_button.pack(pady=20)

    def add_key(self):
        file_path = filedialog.askopenfilename(title="Select Public Key File", filetypes=[("Public Key Files", "*.pub"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'r') as f:
                pub_key = f.read().strip()

            home_dir = self.get_target_user_home()
            uid, gid = self.get_target_user_ids()
            ssh_dir = os.path.join(home_dir, ".ssh")
            auth_keys = os.path.join(ssh_dir, "authorized_keys")
            os.makedirs(ssh_dir, exist_ok=True)
            os.chown(ssh_dir, uid, gid)
            os.chmod(ssh_dir, 0o700)

            key_exists = False
            if os.path.isfile(auth_keys):
                with open(auth_keys, 'r') as f:
                    if pub_key in f.read():
                        key_exists = True

            if key_exists:
                messagebox.showinfo("Key Already Present", "This public key is already added.")
            else:
                with open(auth_keys, 'a') as f:
                    f.write(pub_key + '\n')
                os.chown(auth_keys, uid, gid)
                os.chmod(auth_keys, 0o600)
                messagebox.showinfo("Success", "Public key has been successfully added.")

def require_root():
    if os.geteuid() != 0:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Permission Denied", "This application must be run with sudo/root privileges.")
        root.destroy()
        exit(1)

if __name__ == "__main__":
    require_root()
    root = tk.Tk()
    app = SSHSetupApp(root)
    root.mainloop()

