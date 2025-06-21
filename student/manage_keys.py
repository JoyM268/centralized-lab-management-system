import tkinter as tk
from tkinter import filedialog, messagebox
import os
import pwd

def get_target_user_home():
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        raise RuntimeError("This script must be run using sudo to identify the target user.")
    return os.path.expanduser(f"~{sudo_user}")

def get_target_user_ids():
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        raise RuntimeError("Could not determine the original user from sudo environment.")
    pw_record = pwd.getpwnam(sudo_user)
    return pw_record.pw_uid, pw_record.pw_gid

def add_key(parent):
    file_path = filedialog.askopenfilename(
        parent=parent,
        title="Select Public Key File",
        filetypes=[("Public Key Files", "*.pub"), ("All Files", "*.*")]
    )
    if not file_path:
        return

    try:
        with open(file_path, 'r') as f:
            pub_key = f.read().strip()

        if not any(pub_key.startswith(k_type) for k_type in ["ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp"]):
            messagebox.showerror("Invalid Key", "The selected file does not appear to be a valid SSH public key.", parent=parent)
            return

        home_dir = get_target_user_home()
        uid, gid = get_target_user_ids()
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
            messagebox.showinfo("Key Already Exists", "The selected public key is already in the authorized_keys file.", parent=parent)
        else:
            with open(auth_keys_path, 'a') as f:
                f.write(f"\n{pub_key}\n")
            os.chown(auth_keys_path, uid, gid)
            os.chmod(auth_keys_path, 0o600)
            messagebox.showinfo("Success", "The public key was added successfully.", parent=parent)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while adding the key: {e}", parent=parent)

def delete_key_dialog(parent):
    try:
        home_dir = get_target_user_home()
        auth_keys_path = os.path.join(home_dir, ".ssh", "authorized_keys")
        keys = []
        if os.path.isfile(auth_keys_path):
            with open(auth_keys_path, 'r') as f:
                keys = [line.strip() for line in f if line.strip()]
        if not keys:
            messagebox.showinfo("No Keys Found", "The authorized_keys file is empty or does not exist.", parent=parent)
            return
    except Exception as e:
        messagebox.showerror("Error", f"Could not read authorized keys: {e}", parent=parent)
        return

    dialog = tk.Toplevel(parent)
    dialog.title("Select Key to Delete")
    dialog.configure(bg="#F0F0F0")
    dialog_width, dialog_height = 700, 400
    x = int((parent.winfo_screenwidth() / 2) - (dialog_width / 2))
    y = int((parent.winfo_screenheight() / 2) - (dialog_height / 2))
    dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
    dialog.resizable(False, False)
    dialog.grab_set()
    dialog.transient(parent)

    tk.Label(dialog, text="Select a public key to remove:", font=("Segoe UI", 13), bg="#F0F0F0").pack(pady=10, padx=20, anchor="w")

    listbox = tk.Listbox(dialog, font=("Courier", 10), selectbackground="#0078D7", bd=1, relief="solid")
    listbox.pack(expand=True, fill="both", padx=20, pady=5)

    for key in keys:
        key_display = key if len(key) < 80 else f"{key[:35]}...{key[-35:]}"
        listbox.insert(tk.END, key_display)

    def on_delete():
        selected_indices = listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No Selection", "Please select a key to delete.", parent=dialog)
            return

        selected_key = keys[selected_indices[0]]
        key_display = listbox.get(selected_indices[0])

        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete this key?\n\n{key_display}", parent=dialog):
            try:
                remaining_keys = [k for k in keys if k != selected_key]
                uid, gid = get_target_user_ids()
                with open(auth_keys_path, 'w') as f:
                    f.write("\n".join(remaining_keys) + "\n")
                os.chown(auth_keys_path, uid, gid)
                os.chmod(auth_keys_path, 0o600)
                messagebox.showinfo("Success", "The selected key has been deleted.", parent=parent)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete the key: {e}", parent=dialog)

    btn_frame = tk.Frame(dialog, bg="#F0F0F0")
    btn_frame.pack(pady=15, padx=20, fill="x")

    delete_btn = tk.Button(btn_frame, text="Delete", command=on_delete, font=("Segoe UI", 11, "bold"), bg="#C73836", fg="white", bd=0, relief="flat", padx=15, pady=8)
    delete_btn.pack(side="right")

    cancel_btn = tk.Button(btn_frame, text="Cancel", command=dialog.destroy, font=("Segoe UI", 11), padx=15, pady=8)
    cancel_btn.pack(side="right", padx=10)

    parent.wait_window(dialog)
