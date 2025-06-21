import tkinter as tk
from tkinter import Toplevel, messagebox
import json
import os
import re

def manage_users_dialog(root):
    root.withdraw()

    dialog = Toplevel(root)
    dialog.title("Manage Users")
    dialog.configure(bg="#F0F0F0")
    dialog.bind('<Escape>', lambda event: dialog.destroy())

    w, h = 700, 500
    ws, hs = root.winfo_screenwidth(), root.winfo_screenheight()
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

            mac_pattern = re.compile(r'^([0-9a-f]{2}[:\-]{1}){5}([0-9a-f]{2})$')
            if not mac_pattern.match(m):
                messagebox.showerror("Invalid MAC Address", "Please use format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.", parent=add_dialog)
                return

            data = load()
            data[m] = u
            save(data)
            add_dialog.destroy()
            refresh()

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
        mac_to_delete = entry.split("MAC:")[1].strip()

        if messagebox.askyesno("Confirm Deletion", f"Delete this user?\n\n{entry}", parent=dialog):
            data = {m: u for m, u in load().items() if m.lower() != mac_to_delete.lower()}
            save(data)
            refresh()

    btn_frame = tk.Frame(main_frame, bg="#F0F0F0")
    btn_frame.pack(pady=(15, 0), fill="x", side="bottom")

    close_btn = tk.Button(btn_frame, text="Close", command=dialog.destroy, font=("Segoe UI", 11), bg="#E1E1E1", fg="black", bd=0, relief="flat", padx=20, pady=8)
    close_btn.pack(side="right")

    delete_btn = tk.Button(btn_frame, text="Delete", command=on_delete, font=("Segoe UI", 11, "bold"), bg="#C73836", fg="white", bd=0, relief="flat", padx=20, pady=8)
    delete_btn.pack(side="right", padx=5)

    add_btn = tk.Button(btn_frame, text="Add", command=on_add, font=("Segoe UI", 11, "bold"), bg="#28A745", fg="white", bd=0, relief="flat", padx=20, pady=8)
    add_btn.pack(side="right", padx=0)

    refresh()

    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.grab_set()
    root.wait_window(dialog)
    root.deiconify()
    root.lift()
