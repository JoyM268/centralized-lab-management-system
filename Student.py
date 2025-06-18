import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import time
import subprocess
import os
import pwd
import re

class StudentApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Student Setup Assistant")
        self.root.configure(bg="#F0F0F0")

        self.capture_subprocess_output = True

        self.content_wrapper = tk.Frame(self.root, bg="#F0F0F0")
        self.content_wrapper.pack(expand=True, fill="both", padx=10, pady=10)

        self.frame = tk.Frame(self.content_wrapper, bg="#F0F0F0")
        self.frame.place(relx=0.5, rely=0.5, anchor="center")

        self.label = tk.Label(self.frame, text="Initializing Setup...", font=("Segoe UI", 16),
                              bg="#F0F0F0", fg="black", wraplength=500, justify="center")
        self.label.pack(pady=10)

        self.progress_label = tk.Label(self.frame, text="", font=("Segoe UI", 12),
                                       bg="#F0F0F0", fg="black", wraplength=500, justify="center")
        self.progress_label.pack(pady=5)

        self.canvas = tk.Canvas(self.frame, width=100, height=100, highlightthickness=0, bg="#F0F0F0")
        self.canvas.pack(pady=10)
        self.arc = self.canvas.create_arc(10, 10, 90, 90, start=0, extent=60,
                                          style=tk.ARC, outline="#0078D7", width=4)
        self.angle = 0
        self.animate = True
        self.rotate_loader()

        self.root.after(100, self.run_setup_thread)
        self.root.bind("<Configure>", self.on_resize)

    def rotate_loader(self):
        if self.animate:
            self.angle = (self.angle - 5) % 360
            self.canvas.itemconfig(self.arc, start=self.angle)
            self.root.after(20, self.rotate_loader)

    def run_setup_thread(self):
        threading.Thread(target=self.run_setup, daemon=True).start()

    def run_setup(self):
        try:
            steps = [
                ("Installing OpenSSH server...", self.install_openssh_server),
                ("Enabling the SSH service...", self.configure_ssh_service),
                ("Configuring the firewall...", self.configure_firewall),
                ("Securing SSH configuration...", self.configure_ssh_security)
            ]
            for text, func in steps:
                self.root.after(0, self.update_progress, text)
                func()
                time.sleep(1)
            self.root.after(0, self.show_key_management_ui)
        except Exception as e:
            self.animate = False
            self.root.after(0, self.show_message, "Setup Error", f"A setup error occurred: {e}", "error")

    def update_progress(self, text):
        self.progress_label.config(text=text)

    def install_openssh_server(self):
        if not self.is_package_installed("openssh-server"):
            subprocess.run(["apt-get", "update"], check=True, capture_output=self.capture_subprocess_output, text=True)
            subprocess.run(["apt-get", "install", "-y", "openssh-server"], check=True, capture_output=self.capture_subprocess_output, text=True)

    def is_package_installed(self, name):
        result = subprocess.run(["dpkg", "-s", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0

    def configure_ssh_service(self):
        subprocess.run(["systemctl", "enable", "ssh"], check=True, capture_output=self.capture_subprocess_output, text=True)
        subprocess.run(["systemctl", "start", "ssh"], check=True, capture_output=self.capture_subprocess_output, text=True)

    def configure_firewall(self):
        subprocess.run(["ufw", "allow", "ssh"], check=True, capture_output=self.capture_subprocess_output, text=True)
        subprocess.run(["ufw", "enable"], input='y\n', check=True, text=True, capture_output=self.capture_subprocess_output)

    def configure_ssh_security(self):
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

            subprocess.run(["systemctl", "restart", "ssh"], check=True, capture_output=self.capture_subprocess_output, text=True)

        except FileNotFoundError:
            raise RuntimeError(f"SSHD config file not found at {sshd_config_path}")
        except Exception as e:
            raise RuntimeError(f"Failed to modify SSH configuration: {e}")

    def get_target_user_home(self):
        sudo_user = os.environ.get("SUDO_USER")
        if not sudo_user:
            raise RuntimeError("This script must be run using sudo to identify the target user.")
        return os.path.expanduser(f"~{sudo_user}")

    def get_target_user_ids(self):
        sudo_user = os.environ.get("SUDO_USER")
        if not sudo_user:
            raise RuntimeError("Could not determine the original user from sudo environment.")
        pw_record = pwd.getpwnam(sudo_user)
        return pw_record.pw_uid, pw_record.pw_gid

    def show_key_management_ui(self):
        self.animate = False
        self.canvas.destroy()
        self.label.config(text="Setup Complete!")
        self.progress_label.config(text="You can now manage public keys to allow remote access.")

        button_frame = tk.Frame(self.frame, bg="#F0F0F0")
        button_frame.pack(pady=20)

        common_button_options = {
            "font": ("Segoe UI", 11, "bold"), "bg": "white", "fg": "black",
            "relief": "flat", "bd": 1, "padx": 15, "pady": 8, "activebackground": "#E0E0E0"
        }

        self.add_key_button = tk.Button(button_frame, text="Add Public Key", command=self.add_key, **common_button_options)
        self.add_key_button.pack(side="left", padx=10)

        self.delete_key_button = tk.Button(button_frame, text="Delete Public Key", command=self.delete_key_dialog, **common_button_options)
        self.delete_key_button.pack(side="left", padx=10)

    def _show_dialog_and_restore(self, dialog_callback):
        self.root.withdraw()
        dialog_callback()
        self.root.deiconify()
        self.root.lift()

    def show_message(self, title, message, msg_type="info"):
        if msg_type == "info":
            messagebox.showinfo(title, message)
        elif msg_type == "error":
            messagebox.showerror(title, message)

    def add_key(self):
        def dialog_logic():
            file_path = filedialog.askopenfilename(
                title="Select Public Key File",
                filetypes=[("Public Key Files", "*.pub"), ("All Files", "*.*")]
            )
            if file_path:
                self._process_add_key(file_path)
        dialog_logic()

    def _process_add_key(self, file_path):
        try:
            with open(file_path, 'r') as f:
                pub_key = f.read().strip()
            if not any(pub_key.startswith(k_type) for k_type in ["ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp"]):
                self.show_message("Invalid Key", "The selected file does not appear to be a valid SSH public key.", "error")
                return
            home_dir = self.get_target_user_home()
            uid, gid = self.get_target_user_ids()
            ssh_dir = os.path.join(home_dir, ".ssh")
            auth_keys_path = os.path.join(ssh_dir, "authorized_keys")
            os.makedirs(ssh_dir, exist_ok=True, mode=0o700)
            os.chown(ssh_dir, uid, gid)
            os.chmod(ssh_dir, 0o700)
            key_exists = False
            if os.path.isfile(auth_keys_path):
                with open(auth_keys_path, 'r') as f:
                    if any(pub_key == line.strip() for line in f):
                        key_exists = True
            if key_exists:
                self.show_message("Key Already Exists", "The selected public key is already in the authorized_keys file.")
            else:
                with open(auth_keys_path, 'a') as f:
                    f.write(f"\n{pub_key}\n")
                os.chown(auth_keys_path, uid, gid)
                os.chmod(auth_keys_path, 0o600)
                self.show_message("Success", "The public key was added successfully.")
        except Exception as e:
            self.show_message("Error", f"An error occurred while adding the key: {e}", "error")

    def delete_key_dialog(self):
        try:
            home_dir = self.get_target_user_home()
            auth_keys_path = os.path.join(home_dir, ".ssh", "authorized_keys")
            keys = []
            if os.path.isfile(auth_keys_path):
                with open(auth_keys_path, 'r') as f:
                    keys = [line.strip() for line in f if line.strip()]
            if not keys:
                self.show_message("No Keys Found", "The authorized_keys file is empty or does not exist.")
                return
        except Exception as e:
            self.show_message("Error", f"Could not read authorized keys: {e}", "error")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Select Key to Delete")
        dialog.configure(bg="#F0F0F0")
        dialog_width, dialog_height = 700, 400
        screen_width, screen_height = dialog.winfo_screenwidth(), dialog.winfo_screenheight()
        x = int((screen_width / 2) - (dialog_width / 2))
        y = int((screen_height / 2) - (dialog_height / 2))
        dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.transient(self.root)

        main_dialog_frame = tk.Frame(dialog, bg="#F0F0F0")
        main_dialog_frame.pack(expand=True, fill="both", padx=20, pady=15)
        tk.Label(main_dialog_frame, text="Select a public key to remove:", font=("Segoe UI", 13), bg="#F0F0F0").pack(pady=(0, 10), anchor="w")
        listbox_frame = tk.Frame(main_dialog_frame, bg="white", bd=1, relief="solid")
        listbox_frame.pack(expand=True, fill="both")
        listbox = tk.Listbox(
            listbox_frame, font=("Courier", 10), bg="white", fg="black",
            selectbackground="#0078D7", selectforeground="white",
            highlightthickness=0, borderwidth=0, activestyle="none"
        )
        listbox.pack(side="left", expand=True, fill="both", padx=5, pady=5)
        scrollbar = tk.Scrollbar(listbox_frame, orient="vertical", command=listbox.yview, relief="flat")
        scrollbar.pack(side="right", fill="y")
        listbox.config(yscrollcommand=scrollbar.set)
        for key in keys:
            key_display = key if len(key) < 80 else key[:35] + "..." + key[-35:]
            listbox.insert(tk.END, key_display)

        def on_delete():
            selected_indices = listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("No Selection", "Please select a key to delete.", parent=dialog)
                return
            selected_index = selected_indices[0]
            key_to_delete = keys[selected_index]
            key_display = listbox.get(selected_index)
            if messagebox.askyesno("Confirm Deletion", "Are you sure you want to permanently delete this key?\n\n" + key_display, parent=dialog):
                try:
                    remaining_keys = [k for k in keys if k != key_to_delete]
                    uid, gid = self.get_target_user_ids()
                    with open(auth_keys_path, 'w') as f:
                        f.write("\n".join(remaining_keys) + "\n")
                    os.chown(auth_keys_path, uid, gid)
                    os.chmod(auth_keys_path, 0o600)
                    self.show_message("Success", "The selected key has been deleted.")
                    dialog.destroy()
                except Exception as e:
                    self.show_message("Error", f"Failed to delete the key: {e}", "error")

        btn_frame = tk.Frame(main_dialog_frame, bg="#F0F0F0")
        btn_frame.pack(pady=(15, 0), fill="x", side="bottom")
        cancel_btn = tk.Button(btn_frame, text="Cancel", command=dialog.destroy, font=("Segoe UI", 11), bg="#E1E1E1", fg="black", bd=0, relief="flat", padx=20, pady=8, activebackground="#CFCFCF")
        cancel_btn.pack(side="right")
        delete_btn = tk.Button(btn_frame, text="Delete Selected", command=on_delete, font=("Segoe UI", 11, "bold"), bg="#C73836", fg="white", bd=0, relief="flat", padx=20, pady=8, activebackground="#A22C2B")
        delete_btn.pack(side="right", padx=10)

        self.root.wait_window(dialog)

    def on_resize(self, event):
        self.frame.place(relx=0.5, rely=0.5, anchor="center")
        wrap = self.root.winfo_width() - 100
        self.label.config(wraplength=wrap)
        self.progress_label.config(wraplength=wrap)

def require_root():
    if os.geteuid() != 0:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Root Privileges Required",
            "This application requires administrator privileges to configure system services. Please run it again using 'sudo'."
        )
        root.destroy()
        exit(1)

if __name__ == "__main__":
    require_root()
    root = tk.Tk()
    window_width, window_height = 600, 450
    screen_width, screen_height = root.winfo_screenwidth(), root.winfo_screenheight()
    x = int((screen_width / 2) - (window_width / 2))
    y = int((screen_height / 2) - (window_height / 2))
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")
    app = StudentApp(root)
    root.mainloop()
