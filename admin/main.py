import tkinter as tk
from tkinter import messagebox, Toplevel, simpledialog, StringVar
import threading
import os
import json
from pathlib import Path
import ipaddress
from ssh_keygen import ensure_ssh_key
from arp_scan import perform_arp_scan_and_map
from export_key import export_public_key
from active_users import show_active_users
from manage_users import manage_users_dialog
from execute_command import select_user_for_command_ui
from send_files import send_file_ui

class AdminApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Admin Dashboard")
        self.root.configure(bg="#F0F0F0")

        self.subnet = None
        self.user_ip_list = []
        self.sudo_user = os.environ.get("SUDO_USER")
        if not self.sudo_user:
            raise RuntimeError("This script must be run using sudo.")

        self.status_var = StringVar()
        self.status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#F0F0F0", fg="black")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.content_wrapper = tk.Frame(self.root, bg="#F0F0F0")
        self.content_wrapper.pack(expand=True, fill="both")
        self.frame = tk.Frame(self.content_wrapper, bg="#F0F0F0")
        self.frame.place(relx=0.5, rely=0.5, anchor="center")

        self.show_loading_ui("Initializing Admin Setup...")
        self.root.after(100, self.run_initial_setup_thread)
        self.root.bind("<Configure>", self.on_resize)

    def update_status_bar(self):
        if self.subnet:
            self.status_var.set(f"Current Subnet: {self.subnet}")
        else:
            self.status_var.set("Subnet not set")

    def show_loading_ui(self, main_text):
        self.clear_frame()
        self.label = tk.Label(self.frame, text=main_text, font=("Segoe UI", 16),bg="#F0F0F0", fg="black")
        self.label.pack(pady=10)
        self.progress_label = tk.Label(self.frame, text="", font=("Segoe UI", 12), bg="#F0F0F0", fg="black")
        self.progress_label.pack(pady=5)
        self.canvas = tk.Canvas(self.frame, width=100, height=100, highlightthickness=0, bg="#F0F0F0")
        self.canvas.pack(pady=10)
        self.arc = self.canvas.create_arc(10, 10, 90, 90, start=0, extent=60, style=tk.ARC, outline="#0078D7", width=4)
        self.angle = 0
        self.animate = True
        self.rotate_loader()

    def rotate_loader(self):
        if self.animate:
            self.angle = (self.angle - 5) % 360
            self.canvas.itemconfig(self.arc, start=self.angle)
            self.root.after(50, self.rotate_loader)

    def clear_frame(self):
        for widget in self.frame.winfo_children(): widget.destroy()

    def update_progress(self, text):
        if hasattr(self, 'progress_label') and self.progress_label.winfo_exists():
            self.progress_label.config(text=text)

    def run_initial_setup_thread(self):
        threading.Thread(target=self.run_initial_setup, daemon=True).start()

    def run_initial_setup(self):
        ensure_ssh_key(self.sudo_user)
        self.ensure_user_json_exists()
        if not self.load_subnet():
            self.root.after(0, self.update_status_bar)
            self.root.after(0, lambda: self.ask_for_subnet(is_initial_setup=True))
            return
        self.root.after(0, self.update_status_bar)
        self.root.after(0, self.run_scan_and_show_menu)

    def ensure_user_json_exists(self):
        user_file = Path("user.json")
        if not user_file.exists():
            with open(user_file, 'w') as f:
                json.dump({}, f)

    def run_scan_and_show_menu(self):
        def scan_thread_target():
            self.root.after(0, self.show_loading_ui, "Scanning Network...")
            self.root.after(0, self.update_progress, f"Scanning {self.subnet} for active devices...")
            self.user_ip_list = perform_arp_scan_and_map(self.subnet)
            self.root.after(0, self.show_main_menu)
        threading.Thread(target=scan_thread_target, daemon=True).start()

    def get_sudo_user_home(self):
        return Path(os.path.expanduser(f"~{self.sudo_user}"))

    def load_subnet(self):
        try:
            with open("subnet.json", "r") as f:
                data = json.load(f)
                self.subnet = data.get("subnet")
                return self.subnet is not None
        except (FileNotFoundError, json.JSONDecodeError):
            return False

    def ask_for_subnet(self, is_initial_setup=False):
        while True:
            subnet_val = simpledialog.askstring("Network Configuration", "Please enter the network subnet to scan (e.g., 192.168.5.0/24):", parent=self.root)
            if subnet_val is None:
                if is_initial_setup: self.root.destroy()
                return
            if not subnet_val.strip():
                messagebox.showerror("Input Required", "The subnet field cannot be empty.", parent=self.root)
                continue
            try:
                ipaddress.ip_network(subnet_val.strip(), strict=False)
                self.subnet = subnet_val.strip()
                with open("subnet.json", "w") as f: json.dump({"subnet": self.subnet}, f, indent=2)
                self.update_status_bar()
                break
            except ValueError:
                messagebox.showerror("Invalid Format", "The subnet format is invalid. Please use CIDR notation (e.g., 192.168.5.0/24).", parent=self.root)
        if is_initial_setup: self.run_scan_and_show_menu()

    def change_subnet(self):
        self.ask_for_subnet()

    def show_main_menu(self):
        self.animate = False
        self.clear_frame()
        tk.Label(self.frame, text="Admin Dashboard", font=("Segoe UI", 16), bg="#F0F0F0", fg="black").pack(pady=(10, 20))

        button_frame = tk.Frame(self.frame, bg="#F0F0F0")
        button_frame.pack(pady=20, expand=True)

        opts = {"font": ("Segoe UI", 11, "bold"), "bg": "white", "fg": "black", "relief": "flat", "bd": 1, "padx": 20, "pady": 12, "width": 20, "activebackground": "#E0E0E0"}

        buttons = [
            ("Transfer File", lambda: send_file_ui(self.root, self.user_ip_list, self.get_sudo_user_home())),
            ("View Active Users", lambda: show_active_users(self.root, self.user_ip_list, self.rescan_network)),
            ("Manage Users", lambda: manage_users_dialog(self.root)),
            ("Execute Command", lambda: select_user_for_command_ui(self.root, self.user_ip_list, self.get_sudo_user_home())),
            ("Export Public Key", lambda: export_public_key(self.root, self.get_sudo_user_home())),
            ("Change Subnet", self.change_subnet)
        ]

        row, col = 0, 0
        for text, command in buttons:
            btn = tk.Button(button_frame, text=text, command=command, **opts)
            btn.grid(row=row, column=col, padx=10, pady=8)
            col += 1
            if col > 1:
                col = 0
                row += 1

    def rescan_network(self):
        self.user_ip_list = perform_arp_scan_and_map(self.subnet)
        return self.user_ip_list

    def on_resize(self, event):
        self.frame.place(relx=0.5, rely=0.5, anchor="center")

if __name__ == "__main__":
    if os.geteuid() != 0:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Root Privileges Required", "Please run with 'sudo'.")
        root.destroy()
        exit(1)

    root = tk.Tk()
    w, h = 600, 550
    ws, hs = root.winfo_screenwidth(), root.winfo_screenheight()
    x, y = int((ws/2) - (w/2)), int((hs/2) - (h/2))
    root.geometry(f'{w}x{h}+{x}+{y}')
    app = AdminApp(root)
    root.mainloop()
