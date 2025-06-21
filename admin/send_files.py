import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel
import threading
from pathlib import Path
import paramiko

def send_file_ui(root, user_ip_list, sudo_user_home):
    root.withdraw()
    dialog = Toplevel(root)
    dialog.title("Transfer File")
    dialog.configure(bg="#F0F0F0")

    w, h = 600, 500
    ws, hs = root.winfo_screenwidth(), root.winfo_screenheight()
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
        if not local or not remote:
            messagebox.showerror("Error", "All fields are required.", parent=dialog)
            return
        if not Path(local).is_file():
            messagebox.showerror("Error", "Source file not found.", parent=dialog)
            return
        close_btn.config(state="disabled")
        send_btn.config(state="disabled")
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
        for entry in user_ip_list:
            def sftp_task(h, u, l, r):
                try:
                    r_path = f"/home/{u}/{r[2:]}" if r.startswith('~/') else r
                    remote_dir = str(Path(r_path).parent)
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    pkey = paramiko.RSAKey.from_private_key_file(str(sudo_user_home / ".ssh" / "id_rsa"))
                    ssh.connect(h, port=22, username=u, pkey=pkey, timeout=10)
                    stdin, stdout, stderr = ssh.exec_command(f'mkdir -p "{remote_dir}"')
                    if stdout.channel.recv_exit_status() != 0:
                        raise Exception(f"Could not create remote directory: {stderr.read().decode()}")
                    sftp = ssh.open_sftp()
                    sftp.put(l, r_path)
                    sftp.close()
                    ssh.close()
                    results["success"].append(h)
                    update_ui(f"[SUCCESS] to {u}@{h}\n")
                except Exception as e:
                    results["failure"].append(h)
                    update_ui(f"[FAILURE] to {u}@{h}: {e}\n")

            t = threading.Thread(target=sftp_task, args=(entry['ip'], entry['username'], local_file, remote_path))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        if dialog.winfo_exists():
            dialog.after(0, lambda: (
                progress_label.config(text="Finished."),
                close_btn.config(state="normal"),
                send_btn.config(state="normal"),
                messagebox.showinfo("Complete", f"Success: {len(results['success'])}\nFailed: {len(results['failure'])}", parent=dialog)
            ))

    btn_frame = tk.Frame(main_frame, bg="#F0F0F0")
    btn_frame.pack(fill="x", side="bottom", pady=(10,0))

    close_btn = tk.Button(btn_frame, text="Close", command=dialog.destroy, font=("Segoe UI", 11), bg="#E1E1E1", fg="black", bd=0, relief="flat", padx=20, pady=8)
    close_btn.pack(side="right")

    send_btn = tk.Button(btn_frame, text="Send", command=send_action, font=("Segoe UI", 11, "bold"), bg="#0078D7", fg="white", bd=0, relief="flat", padx=20, pady=8)
    send_btn.pack(side="right", padx=10)

    dialog.bind('<Return>', send_action)
    dialog.bind('<Escape>', lambda event: dialog.destroy())
    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.grab_set()
    root.wait_window(dialog)
    root.deiconify()
    root.lift()
