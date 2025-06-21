import tkinter as tk
from tkinter import filedialog, messagebox
import shutil
from pathlib import Path

def export_public_key(root, sudo_user_home):
    root.withdraw()
    pub_key_path = sudo_user_home / ".ssh" / "id_rsa.pub"

    if not pub_key_path.exists():
        messagebox.showerror("Error", "Public key 'id_rsa.pub' not found.", parent=root)
    else:
        dest_folder = filedialog.askdirectory(title="Select a folder to save the key", parent=root)
        if dest_folder:
            try:
                shutil.copy2(pub_key_path, dest_folder)
                messagebox.showinfo("Success", "Public key copied.", parent=root)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy key: {e}", parent=root)

    root.deiconify()
    root.lift()
