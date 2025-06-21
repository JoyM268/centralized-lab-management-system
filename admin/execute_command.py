import tkinter as tk
from tkinter import Toplevel, messagebox
import threading
import paramiko

def select_user_for_command_ui(root, user_ip_list, sudo_user_home):
    root.withdraw()
    dialog = Toplevel(root)
    dialog.title("Select User")
    dialog.configure(bg="#F0F0F0")
    dialog.bind('<Escape>', lambda event: dialog.destroy())

    w, h = 700, 500
    ws, hs = root.winfo_screenwidth(), root.winfo_screenheight()
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
        if not selection_indices or not user_ip_list:
            messagebox.showwarning("No Selection", "Please select a user from the list.", parent=dialog)
            return
        selected_user = user_ip_list[selection_indices[0]]
        dialog.withdraw()
        execute_command_ui(root, selected_user, sudo_user_home, lambda: select_user_for_command_ui(root, user_ip_list, sudo_user_home))
        dialog.destroy()

    listbox.bind('<Return>', on_select)

    if not user_ip_list:
        no_users_label.pack(expand=True)
    else:
        scrollbar.pack(side="right", fill="y")
        listbox.pack(side="left", expand=True, fill="both")
        for user in user_ip_list:
            listbox.insert(tk.END, f"User: {user['username']:<30} IP: {user['ip']}")
        listbox.focus_set()

    def on_select_all():
        if not user_ip_list:
            messagebox.showwarning("No Users", "There are no active users to select.", parent=dialog)
            return
        dialog.withdraw()
        execute_command_ui(root, user_ip_list, sudo_user_home, lambda: select_user_for_command_ui(root, user_ip_list, sudo_user_home))
        dialog.destroy()

    btn_frame = tk.Frame(main_frame, bg="#F0F0F0")
    btn_frame.pack(pady=(15, 0), fill="x", side="bottom")

    close_btn = tk.Button(btn_frame, text="Close", command=dialog.destroy, font=("Segoe UI", 11), bg="#E1E1E1", fg="black", bd=0, relief="flat", padx=20, pady=8)
    close_btn.pack(side="right")

    select_btn = tk.Button(btn_frame, text="Select", command=on_select, font=("Segoe UI", 11, "bold"), bg="#0078D7", fg="white", bd=0, relief="flat", padx=20, pady=8)
    select_btn.pack(side="right", padx=5)

    select_all_btn = tk.Button(btn_frame, text="Select All", command=on_select_all, font=("Segoe UI", 11, "bold"), bg="#28A745", fg="white", bd=0, relief="flat", padx=10, pady=8)
    select_all_btn.pack(side="right", padx=0)

    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.grab_set()
    root.wait_window(dialog)
    root.deiconify()
    root.lift()


def execute_command_ui(root, user_info, sudo_user_home, back_callback):
    is_multiple = isinstance(user_info, list)
    dialog = Toplevel(root)
    dialog.title("Execute Command on All Active Users" if is_multiple else f"Execute Command on {user_info['username']}@{user_info['ip']}")
    dialog.configure(bg="#F0F0F0")

    w, h = 800, 600
    ws, hs = root.winfo_screenwidth(), root.winfo_screenheight()
    x, y = int((ws / 2) - (w / 2)), int((hs / 2) - (h / 2))
    dialog.geometry(f'{w}x{h}+{x}+{y}')

    def go_back():
        dialog.destroy()
        back_callback()

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
                pkey = paramiko.RSAKey.from_private_key_file(str(sudo_user_home / ".ssh" / "id_rsa"))
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
        output_box.insert(tk.END, f"Executing on {len(users_to_run)} users: $ {command}\n" if is_multiple else f"$ {command}\n")
        output_box.config(state="disabled")
        threading.Thread(target=run_ssh_command, args=(command, users_to_run), daemon=True).start()

    btn_style = {"font": ("Segoe UI", 11, "bold"), "bd": 0, "relief": "flat", "fg": "white", "pady": 5, "padx": 15}
    execute_btn = tk.Button(command_frame, text="Execute", command=execute_action, bg="#28A745", **btn_style)
    execute_btn.pack(side="left", padx=(0,5))

    back_btn = tk.Button(command_frame, text="Back", command=go_back, bg="#6C757D", **btn_style)
    back_btn.pack(side="left", padx=0)

    output_box.pack(expand=True, fill="both", pady=(10, 0))
    command_entry.focus_set()
    command_entry.bind('<Return>', lambda event: execute_action())
    dialog.bind('<Escape>', lambda event: go_back())

    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.grab_set()
    root.wait_window(dialog)
