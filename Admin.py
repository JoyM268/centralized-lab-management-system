import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, simpledialog, StringVar
import threading
import time
import subprocess
import os
import pwd
import json
from pathlib import Path
import shutil
from scapy.all import ARP, Ether, srp
import paramiko
import ipaddress
import re

class FileSharingApp:
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
        self.ensure_ssh_key()
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
            self.perform_arp_scan_and_map()
            self.root.after(0, self.show_main_menu)
        threading.Thread(target=scan_thread_target, daemon=True).start()

    def get_sudo_user_home(self):
        return Path(os.path.expanduser(f"~{self.sudo_user}"))

    def ensure_ssh_key(self):
        key_path = self.get_sudo_user_home() / ".ssh" / "id_rsa"
        if not key_path.exists():
            key_path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", str(key_path), "-N", ""], check=True, capture_output=True)
            pw_record = pwd.getpwnam(self.sudo_user)
            uid, gid = pw_record.pw_uid, pw_record.pw_gid
            os.chown(key_path.parent, uid, gid)
            os.chown(key_path, uid, gid)
            os.chown(key_path.with_suffix(".pub"), uid, gid)

    def load_subnet(self):
        try:
            with open("subnet.json", "r") as f: data = json.load(f); self.subnet = data.get("subnet"); return self.subnet is not None
        except (FileNotFoundError, json.JSONDecodeError): return False

    def ask_for_subnet(self, is_initial_setup=False):

        while True:
            subnet_val = simpledialog.askstring(
                "Network Configuration",
                "Please enter the network subnet to scan (e.g., 192.168.5.0/24):",
                parent=self.root
            )

            if subnet_val is None:
                if is_initial_setup:
                    self.root.destroy()
                return

            subnet_val = subnet_val.strip()
            if not subnet_val:
                messagebox.showerror(
                    "Input Required",
                    "The subnet field cannot be empty. Please enter a valid subnet.",
                    parent=self.root
                )
                continue

            try:
                ipaddress.ip_network(subnet_val, strict=False)
                self.subnet = subnet_val
                with open("subnet.json", "w") as f:
                    json.dump({"subnet": self.subnet}, f, indent=2)
                self.update_status_bar()
                break
            except ValueError:
                messagebox.showerror(
                    "Invalid Format",
                    "The subnet format is invalid. Please use CIDR notation (e.g., 192.168.5.0/24).",
                    parent=self.root
                )
                continue

        if is_initial_setup:
            pass

        self.run_scan_and_show_menu()

    def change_subnet(self):
        self.ask_for_subnet()

    def perform_arp_scan_and_map(self):
        arp_request, broadcast = ARP(pdst=self.subnet), Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(broadcast / arp_request, timeout=5, verbose=0)[0]
        active_devices = [{'ip': r.psrc, 'mac': r.hwsrc.lower()} for s, r in result]
        try:
            mac_username_map = {k.lower(): v for k, v in json.load(open("user.json", "r")).items()}
        except (FileNotFoundError, json.JSONDecodeError):
            mac_username_map = {}
        self.user_ip_list = [{'username': mac_username_map[dev['mac']], 'ip': dev['ip']} for dev in active_devices if dev['mac'] in mac_username_map]

    def show_main_menu(self):
        self.animate = False
        self.clear_frame()
        tk.Label(self.frame, text="Admin Dashboard", font=("Segoe UI", 16), bg="#F0F0F0", fg="black").pack(pady=(10, 20))

        button_frame = tk.Frame(self.frame, bg="#F0F0F0")
        button_frame.pack(pady=20, expand=True)

        opts = {"font": ("Segoe UI", 11, "bold"), "bg": "white", "fg": "black", "relief": "flat", "bd": 1, "padx": 20, "pady": 12, "width": 20, "activebackground": "#E0E0E0"}

        buttons = [
            ("Transfer File", self.send_file_ui),
            ("View Active Users", self.show_active_users),
            ("Manage Users", self.manage_users_dialog),
            ("Execute Command", self.select_user_for_command_ui),
            ("Export Public Key", self.get_public_key),
            ("Change Subnet", self.change_subnet)
        ]

        row, col = 0, 0
        for text, command in buttons:
            btn = tk.Button(button_frame, text=text, command=command, **opts)
            btn.grid(row=row, column=col, padx=10, pady=8)
            btn.bind('<Return>', lambda e: e.widget.invoke())

            col += 1
            if col > 1:
                col = 0
                row += 1

    def select_user_for_command_ui(self):
        self.root.withdraw()
        dialog = Toplevel(self.root)
        dialog.title("Select User")
        dialog.configure(bg="#F0F0F0")

        dialog.bind('<Escape>', lambda event: dialog.destroy())

        w, h = 700, 500
        ws, hs = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = int((ws / 2) - (w / 2)), int((hs / 2) - (h / 2))
        dialog.geometry(f'{w}x{h}+{x}+{y}')
        main_frame = tk.Frame(dialog, bg="#F0F0F0", padx=20, pady=15)
        main_frame.pack(expand=True, fill="both")
        tk.Label(main_frame, text="Select User to Execute Command", font=("Segoe UI", 13), bg="#F0F0F0").pack(pady=(0, 10), anchor="w")
        listbox_frame = tk.Frame(main_frame, bg="white", bd=1, relief="solid", padx=10, pady=10)
        listbox_frame.pack(expand=True, fill="both")
        listbox = tk.Listbox(listbox_frame, font=("Courier", 11), bg="white", fg="black", selectbackground="#0078D7", selectforeground="white", highlightthickness=0, bd=0)
        scrollbar = tk.Scrollbar(listbox_frame, orient="vertical", command=listbox.yview, relief="flat", bd=0)
        listbox.config(yscrollcommand=scrollbar.set)
        no_users_label = tk.Label(listbox_frame, text="No active users found on the network.", font=("Segoe UI", 11), bg="white", fg="black")

        def on_select(event=None):
            selection_indices = listbox.curselection()
            if not selection_indices or not self.user_ip_list:
                messagebox.showwarning("No Selection", "Please select a user from the list.", parent=dialog)
                return
            selected_index = selection_indices[0]
            selected_user = self.user_ip_list[selected_index]
            dialog.withdraw()
            self.execute_command_ui(selected_user)
            dialog.destroy()

        listbox.bind('<Return>', on_select)

        if not self.user_ip_list:
            no_users_label.pack(expand=True)
        else:
            scrollbar.pack(side="right", fill="y")
            listbox.pack(side="left", expand=True, fill="both")
            for user in self.user_ip_list:
                listbox.insert(tk.END, f"User: {user['username']:<30} IP: {user['ip']}")
            listbox.focus_set()

        def on_select_all():
            if not self.user_ip_list:
                messagebox.showwarning("No Users", "There are no active users to select.", parent=dialog)
                return
            dialog.withdraw()
            self.execute_command_ui(self.user_ip_list)
            dialog.destroy()

        btn_frame = tk.Frame(main_frame, bg="#F0F0F0")
        btn_frame.pack(pady=(15, 0), fill="x", side="bottom")

        close_btn = tk.Button(btn_frame, text="Close", command=dialog.destroy, font=("Segoe UI", 11), bg="#E1E1E1", fg="black", bd=0, relief="flat", padx=20, pady=8)
        close_btn.pack(side="right")
        close_btn.bind('<Return>', lambda e: e.widget.invoke())

        select_btn = tk.Button(btn_frame, text="Select", command=on_select, font=("Segoe UI", 11, "bold"), bg="#0078D7", fg="white", bd=0, relief="flat", padx=20, pady=8)
        select_btn.pack(side="right", padx=5)
        select_btn.bind('<Return>', lambda e: e.widget.invoke())

        select_all_btn = tk.Button(btn_frame, text="Select All", command=on_select_all, font=("Segoe UI", 11, "bold"), bg="#28A745", fg="white", bd=0, relief="flat", padx=10, pady=8)
        select_all_btn.pack(side="right", padx=0)
        select_all_btn.bind('<Return>', lambda e: e.widget.invoke())

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.grab_set()
        self.root.wait_window(dialog)
        self.root.deiconify()
        self.root.lift()

    def execute_command_ui(self, user_info):
        is_multiple = isinstance(user_info, list)
        dialog = Toplevel(self.root)
        if is_multiple:
            dialog.title("Execute Command on All Active Users")
        else:
            username, ip = user_info['username'], user_info['ip']
            dialog.title(f"Execute Command on {username}@{ip}")
        dialog.configure(bg="#F0F0F0")
        w, h = 800, 600
        ws, hs = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = int((ws / 2) - (w / 2)), int((hs / 2) - (h / 2))
        dialog.geometry(f'{w}x{h}+{x}+{y}')

        def go_back():
            dialog.destroy()
            self.select_user_for_command_ui()

        main_frame = tk.Frame(dialog, bg="#F0F0F0", padx=15, pady=15)
        main_frame.pack(expand=True, fill="both")
        command_frame = tk.Frame(main_frame, bg="#F0F0F0")
        command_frame.pack(fill="x", pady=(0, 10))
        tk.Label(command_frame, text="Command:", font=("Segoe UI", 11), bg="#F0F0F0").pack(side="left", padx=(0, 5))

        command_entry = tk.Entry(command_frame, font=("Courier", 9))
        command_entry.pack(side="left", expand=True, fill="x", padx=(0, 10), ipady=5)

        output_box = tk.Text(main_frame, font=("Courier", 11), state="disabled", bg="black", fg="lime", bd=1, relief="solid", highlightthickness=0, padx=10, pady=10)

        def update_output(text):
            output_box.config(state="normal")
            output_box.insert(tk.END, text)
            output_box.see(tk.END)
            output_box.config(state="disabled")

        def run_ssh_command(command, users):
            for user in users:
                header = f"\n\n{'='*20} Executing on {user['username']}@{user['ip']} {'='*20}\n"
                dialog.after(0, update_output, header)
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    pkey = paramiko.RSAKey.from_private_key_file(str(self.get_sudo_user_home() / ".ssh" / "id_rsa"))
                    ssh.connect(user['ip'], port=22, username=user['username'], pkey=pkey, timeout=10)
                    stdin, stdout, stderr = ssh.exec_command(command)
                    output, error = stdout.read().decode('utf-8'), stderr.read().decode('utf-8')
                    ssh.close()
                    full_output = output + error
                except Exception as e:
                    full_output = f"Connection or execution failed: {e}"
                dialog.after(0, update_output, full_output)
            dialog.after(0, lambda: (
                update_output(f"\n\n{'='*20} Execution finished. {'='*20}\n"),
                execute_btn.config(state="normal"),
                back_btn.config(state="normal")
            ))

        def execute_action():
            command = command_entry.get()
            if not command: return
            execute_btn.config(state="disabled")
            back_btn.config(state="disabled")
            output_box.config(state="normal")
            output_box.delete('1.0', tk.END)
            users_to_run = user_info if is_multiple else [user_info]
            if is_multiple:
                output_box.insert(tk.END, f"Executing on {len(users_to_run)} users: $ {command}\n")
            else:
                output_box.insert(tk.END, f"$ {command}\n")
            output_box.config(state="disabled")
            threading.Thread(target=run_ssh_command, args=(command, users_to_run), daemon=True).start()

        btn_style = {"font": ("Segoe UI", 11, "bold"), "bd": 0, "relief": "flat", "fg": "white", "pady": 5, "padx": 15}
        execute_btn = tk.Button(command_frame, text="Execute", command=execute_action, bg="#28A745", **btn_style)
        execute_btn.pack(side="left", padx=(0,5))
        execute_btn.bind('<Return>', lambda e: e.widget.invoke())

        back_btn = tk.Button(command_frame, text="Back", command=go_back, bg="#6C757D", **btn_style)
        back_btn.pack(side="left", padx=0)
        back_btn.bind('<Return>', lambda e: e.widget.invoke())

        output_box.pack(expand=True, fill="both", pady=(10, 0))
        command_entry.focus_set()

        command_entry.bind('<Return>', lambda event: execute_action())
        dialog.bind('<Escape>', lambda event: go_back())

        def on_close():
            dialog.destroy()

        dialog.protocol("WM_DELETE_WINDOW", on_close)
        dialog.grab_set()
        self.root.wait_window(dialog)

    def show_message(self, title, message, msg_type="info"):
        self.root.withdraw()
        if msg_type == "info": messagebox.showinfo(title, message, parent=self.root)
        elif msg_type == "error": messagebox.showerror(title, message, parent=self.root)
        self.root.deiconify()
        self.root.lift()

    def get_public_key(self):
        self.root.withdraw()
        pub_key_path = self.get_sudo_user_home() / ".ssh" / "id_rsa.pub"
        if not pub_key_path.exists():
            messagebox.showerror("Error", "Public key 'id_rsa.pub' not found.", parent=self.root)
        else:
            dest_folder = filedialog.askdirectory(title="Select a folder to save the key", parent=self.root)
            if dest_folder:
                try: shutil.copy2(pub_key_path, dest_folder); messagebox.showinfo("Success", "Public key copied.", parent=self.root)
                except Exception as e: messagebox.showerror("Error", f"Failed to copy key: {e}", parent=self.root)
        self.root.deiconify()
        self.root.lift()

    def show_active_users(self):
        self.root.withdraw()

        dialog = Toplevel(self.root)
        dialog.title("Active Users")
        dialog.configure(bg="#F0F0F0")

        w, h = 600, 400
        ws, hs = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = int((ws/2) - (w/2)), int((hs/2) - (h/2))
        dialog.geometry(f'{w}x{h}+{x}+{y}')

        main_frame = tk.Frame(dialog, bg="#F0F0F0", padx=20, pady=15)
        main_frame.pack(expand=True, fill="both")

        title_label = tk.Label(main_frame, text="Active Users on Network", font=("Segoe UI", 13), bg="#F0F0F0")
        title_label.pack(pady=(0, 10))

        listbox_frame = tk.Frame(main_frame, bg="white", bd=1, relief="solid")
        listbox_frame.pack(expand=True, fill="both")

        header = tk.Label(listbox_frame, text=f"{'Username':<30}{'IP Address':<20}", font=("Courier", 11, "bold"), bg="white")
        listbox = tk.Listbox(listbox_frame, font=("Courier", 11), bg="white", fg="black", highlightthickness=0, borderwidth=0, activestyle="none")
        scrollbar = tk.Scrollbar(listbox_frame, orient="vertical", command=listbox.yview, relief="flat")
        listbox.config(yscrollcommand=scrollbar.set)
        no_users_label = tk.Label(listbox_frame, text="No active users found on the network.", font=("Segoe UI", 11), bg="white", fg="black")

        def populate_list():
            header.pack_forget()
            listbox.pack_forget()
            scrollbar.pack_forget()
            no_users_label.pack_forget()

            listbox.delete(0, tk.END)
            if not self.user_ip_list:
                no_users_label.pack(expand=True)
            else:
                header.pack(fill="x", padx=10, pady=5)
                scrollbar.pack(side="right", fill="y")
                listbox.pack(side="left", expand=True, fill="both", padx=10, pady=5)
                for user in self.user_ip_list:
                    listbox.insert(tk.END, f"{user['username']:<30}{user['ip']:<20}")

        def refresh_action(event=None):
            if refresh_btn['state'] == 'disabled':
                return
            refresh_btn.config(state="disabled")
            title_label.config(text="Scanning network, please wait...")

            def scan_and_update_ui():
                self.perform_arp_scan_and_map()
                if dialog.winfo_exists():
                    dialog.after(0, update_gui_after_scan)

            def update_gui_after_scan():
                populate_list()
                title_label.config(text="Active Users on Network")
                refresh_btn.config(state="normal")

            threading.Thread(target=scan_and_update_ui, daemon=True).start()

        btn_frame = tk.Frame(main_frame, bg="#F0F0F0")
        btn_frame.pack(side="bottom", fill="x", pady=(15, 0))

        close_btn = tk.Button(btn_frame, text="Close", command=dialog.destroy, font=("Segoe UI", 11), bg="#E1E1E1", fg="black", bd=0, relief="flat", padx=20, pady=8)
        close_btn.pack(side="right")
        close_btn.bind('<Return>', lambda e: e.widget.invoke())

        refresh_btn = tk.Button(btn_frame, text="Refresh", command=refresh_action, font=("Segoe UI", 11, "bold"), bg="#0078D7", fg="white", bd=0, relief="flat", padx=20, pady=8)
        refresh_btn.pack(side="right", padx=5)
        refresh_btn.bind('<Return>', lambda e: e.widget.invoke())
        refresh_btn.focus_set()

        dialog.bind('<Escape>', lambda event: dialog.destroy())
        dialog.bind('<F5>', refresh_action)

        populate_list()

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.grab_set()
        self.root.wait_window(dialog)
        self.root.deiconify()
        self.root.lift()

    def manage_users_dialog(self):
        self.root.withdraw()

        dialog = Toplevel(self.root)
        dialog.title("Manage Users")
        dialog.configure(bg="#F0F0F0")

        dialog.bind('<Escape>', lambda event: dialog.destroy())

        w, h = 700, 500
        ws, hs = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = int((ws/2) - (w/2)), int((hs/2) - (h/2))
        dialog.geometry(f'{w}x{h}+{x}+{y}')

        main_frame = tk.Frame(dialog, bg="#F0F0F0", padx=20, pady=15)
        main_frame.pack(expand=True, fill="both")

        def load(): return json.load(open("user.json")) if os.path.exists("user.json") else {}
        def save(data): json.dump(data, open("user.json", 'w'), indent=2)

        def refresh():
            listbox.delete(0, tk.END)
            for m, u in sorted(load().items(), key=lambda i: i[1]):
                listbox.insert(tk.END, f"Username: {u:<20} MAC: {m}")

        tk.Label(main_frame, text="Add or Remove Users", font=("Segoe UI", 13), bg="#F0F0F0").pack(pady=(0, 10), anchor="w")

        listbox_frame = tk.Frame(main_frame, bg="white", bd=1, relief="solid", padx=10, pady=10)
        listbox_frame.pack(expand=True, fill="both")

        listbox = tk.Listbox(listbox_frame, font=("Courier", 11), bg="white", fg="black", selectbackground="#0078D7", selectforeground="white", highlightthickness=0, bd=0)
        listbox.pack(side="left", expand=True, fill="both")

        scrollbar = tk.Scrollbar(listbox_frame, orient="vertical", command=listbox.yview, relief="flat", bd=0)
        scrollbar.pack(side="right", fill="y")
        listbox.config(yscrollcommand=scrollbar.set)

        def on_add():
            add_dialog = Toplevel(dialog)
            add_dialog.title("Add New User")
            add_dialog.configure(bg="#F0F0F0")
            add_frame = tk.Frame(add_dialog, bg="#F0F0F0", padx=20, pady=15)
            add_frame.pack(expand=True, fill="both")
            tk.Label(add_frame, text="Username:", font=("Segoe UI", 11), bg="#F0F0F0").pack(pady=5)
            user_entry = tk.Entry(add_frame, font=("Segoe UI", 11), width=30)
            user_entry.pack()
            user_entry.focus_set()
            tk.Label(add_frame, text="MAC Address:", font=("Segoe UI", 11), bg="#F0F0F0").pack(pady=5)
            mac_entry = tk.Entry(add_frame, font=("Segoe UI", 11), width=30)
            mac_entry.pack()
            def perform_add():
                u, m = user_entry.get().strip(), mac_entry.get().strip().lower()
                if not u or not m:
                    messagebox.showerror("Error", "All fields are required.", parent=add_dialog)
                    return

                # Validate MAC address format
                mac_pattern = re.compile(r'^([0-9a-f]{2}[:\-]{1}){5}([0-9a-f]{2})$')
                if not mac_pattern.match(m):
                    messagebox.showerror("Invalid MAC Address", "Please use format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.", parent=add_dialog)
                    return

                data = load(); data[m] = u; save(data); add_dialog.destroy(); refresh()

            add_button = tk.Button(add_frame, text="Add User", command=perform_add, font=("Segoe UI", 11, "bold"), bg="#0078D7", fg="white", bd=0, relief="flat", padx=20, pady=8)
            add_button.pack(pady=15)
            add_button.bind('<Return>', lambda e: e.widget.invoke())

            add_dialog.bind('<Return>', lambda event: perform_add())
            add_dialog.bind('<Escape>', lambda event: add_dialog.destroy())

            add_dialog.transient(dialog)
            add_dialog.grab_set()
            dialog.wait_window(add_dialog)

        def on_delete():
            if not listbox.curselection():
                messagebox.showwarning("No User Selected", "Please select a user to delete.", parent=dialog)
                return

            entry = listbox.get(listbox.curselection()[0])
            mac_to_delete = ""
            message_body = ""

            try:
                parts = entry.split("MAC:")
                username_info = parts[0].strip()
                mac_address = parts[1].strip()
                mac_to_delete = mac_address
                message_body = f"{username_info}\nMAC: {mac_address}"
            except IndexError:
                message_body = entry
                # Fallback to original logic if split fails
                mac_to_delete = entry.split("MAC:")[1].strip()

            if messagebox.askyesno("Confirm Deletion", f"Delete this user?\n\n{message_body}", parent=dialog):
                data = {m: u for m, u in load().items() if m.lower() != mac_to_delete.lower()}
                save(data)
                refresh()

        btn_frame = tk.Frame(main_frame, bg="#F0F0F0")
        btn_frame.pack(pady=(15, 0), fill="x", side="bottom")

        close_btn = tk.Button(btn_frame, text="Close", command=dialog.destroy, font=("Segoe UI", 11), bg="#E1E1E1", fg="black", bd=0, relief="flat", padx=20, pady=8)
        close_btn.pack(side="right")
        close_btn.bind('<Return>', lambda e: e.widget.invoke())

        delete_btn = tk.Button(btn_frame, text="Delete", command=on_delete, font=("Segoe UI", 11, "bold"), bg="#C73836", fg="white", bd=0, relief="flat", padx=20, pady=8)
        delete_btn.pack(side="right", padx=5)
        delete_btn.bind('<Return>', lambda e: e.widget.invoke())

        add_btn = tk.Button(btn_frame, text="Add", command=on_add, font=("Segoe UI", 11, "bold"), bg="#28A745", fg="white", bd=0, relief="flat", padx=20, pady=8)
        add_btn.pack(side="right", padx=0)
        add_btn.bind('<Return>', lambda e: e.widget.invoke())

        refresh()

        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.grab_set()
        self.root.wait_window(dialog)
        self.root.deiconify()
        self.root.lift()

    def send_file_ui(self):
        self.root.withdraw()

        dialog = Toplevel(self.root)
        dialog.title("Transfer File")
        dialog.configure(bg="#F0F0F0")

        w, h = 600, 500
        ws, hs = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = int((ws/2) - (w/2)), int((hs/2) - (h/2))
        dialog.geometry(f'{w}x{h}+{x}+{y}')

        main_frame = tk.Frame(dialog, bg="#F0F0F0", padx=20, pady=15)
        main_frame.pack(expand=True, fill="both")

        source_path = tk.StringVar()
        def select_file():
            path = filedialog.askopenfilename(title="Select file", parent=dialog)
            if path: source_path.set(path)

        tk.Label(main_frame, text="Select Source File:", font=("Segoe UI", 12, "bold"), bg="#F0F0F0").pack(anchor="w", pady=(10,5))
        source_frame = tk.Frame(main_frame, bg="#F0F0F0")
        source_frame.pack(fill="x")

        entry = tk.Entry(source_frame, textvariable=source_path, font=("Segoe UI", 12), state="readonly")
        browse_button = tk.Button(source_frame, text="Browse...", command=select_file, font=("Segoe UI", 11))
        browse_button.pack(side="right")
        browse_button.bind('<Return>', lambda e: e.widget.invoke())
        entry.pack(side="left", expand=True, fill='both', padx=(0, 5))


        tk.Label(main_frame, text="Enter Destination Path:", font=("Segoe UI", 12, "bold"), bg="#F0F0F0").pack(anchor="w", pady=(20,5))
        dest_entry = tk.Entry(main_frame, font=("Segoe UI", 12), width=60)
        dest_entry.pack(fill="x", ipady=6)
        dest_entry.insert(0, "~/")
        tk.Label(main_frame, text="Use '~/ ' for the user's home directory.", font=("Segoe UI", 9), bg="#F0F0F0", fg="gray").pack(anchor="w")

        progress_frame = tk.Frame(main_frame, bg="#F0F0F0")
        progress_frame.pack(pady=20, expand=True, fill="both")
        progress_label = tk.Label(progress_frame, text="Waiting to start...", font=("Segoe UI", 11), bg="#F0F0F0")
        progress_label.pack(pady=5)
        results_box = tk.Text(progress_frame, height=10, width=70, font=("Courier", 9), state="disabled", bg="white", bd=1, relief="solid")
        results_box.pack(expand=True, fill="both")

        def send_action(event=None):
            local, remote = source_path.get(), dest_entry.get().strip()
            if not local or not remote: messagebox.showerror("Error", "All fields are required.", parent=dialog); return
            if not Path(local).is_file(): messagebox.showerror("Error", "Source file not found.", parent=dialog); return
            close_btn.config(state="disabled"); send_btn.config(state="disabled")
            threading.Thread(target=run_transfer, args=(local, remote), daemon=True).start()

        def run_transfer(local_file, remote_path):
            results = {"success": [], "failure": []}
            def update_ui(msg):
                if dialog.winfo_exists():
                    dialog.after(0, lambda: (results_box.config(state="normal"), results_box.insert(tk.END, msg), results_box.see(tk.END), results_box.config(state="disabled")))

            if dialog.winfo_exists():
                dialog.after(0, lambda: progress_label.config(text="Sending files..."))

            update_ui("Starting transfers...\n" + "="*40 + "\n")
            threads = []
            for entry in self.user_ip_list:
                def sftp_task(h, u, l, r):
                    try:
                        if r.startswith('~/'): r_path = f"/home/{u}/{r[2:]}"
                        else: r_path = r
                        remote_dir = str(Path(r_path).parent)
                        ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        pkey = paramiko.RSAKey.from_private_key_file(str(self.get_sudo_user_home() / ".ssh" / "id_rsa"))
                        ssh.connect(h, port=22, username=u, pkey=pkey, timeout=10)
                        stdin, stdout, stderr = ssh.exec_command(f'mkdir -p "{remote_dir}"')
                        if stdout.channel.recv_exit_status() != 0: raise Exception(f"Could not create remote directory: {stderr.read().decode()}")
                        sftp = ssh.open_sftp(); sftp.put(l, r_path); sftp.close(); ssh.close()
                        results["success"].append(h); update_ui(f"[SUCCESS] to {u}@{h}\n")
                    except Exception as e: results["failure"].append(h); update_ui(f"[FAILURE] to {u}@{h}: {e}\n")
                t = threading.Thread(target=sftp_task, args=(entry['ip'], entry['username'], local_file, remote_path)); t.start(); threads.append(t)
            for t in threads: t.join()

            if dialog.winfo_exists():
                dialog.after(0, lambda: (progress_label.config(text="Finished."), close_btn.config(state="normal"), send_btn.config(state="normal"), messagebox.showinfo("Complete", f"Success: {len(results['success'])}\nFailed: {len(results['failure'])}", parent=dialog)))

        btn_frame = tk.Frame(main_frame, bg="#F0F0F0")
        btn_frame.pack(fill="x", side="bottom", pady=(10,0))

        close_btn = tk.Button(btn_frame, text="Close", command=dialog.destroy, font=("Segoe UI", 11), bg="#E1E1E1", fg="black", bd=0, relief="flat", padx=20, pady=8)
        close_btn.pack(side="right")
        close_btn.bind('<Return>', lambda e: e.widget.invoke())

        send_btn = tk.Button(btn_frame, text="Send", command=send_action, font=("Segoe UI", 11, "bold"), bg="#0078D7", fg="white", bd=0, relief="flat", padx=20, pady=8)
        send_btn.pack(side="right", padx=10)
        send_btn.bind('<Return>', lambda e: e.widget.invoke())

        dialog.bind('<Return>', send_action)
        dialog.bind('<Escape>', lambda event: dialog.destroy())


        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.grab_set()
        self.root.wait_window(dialog)
        self.root.deiconify()
        self.root.lift()

    def on_resize(self, event): self.frame.place(relx=0.5, rely=0.5, anchor="center")

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
    app = FileSharingApp(root)
    root.mainloop()
