import tkinter as tk
from tkinter import Toplevel
import threading

def show_active_users(root, user_ip_list, scan_function):
    root.withdraw()

    dialog = Toplevel(root)
    dialog.title("Active Users")
    dialog.configure(bg="#F0F0F0")

    w, h = 600, 400
    ws, hs = root.winfo_screenwidth(), root.winfo_screenheight()
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

    def populate_list(users):
        header.pack_forget()
        listbox.pack_forget()
        scrollbar.pack_forget()
        no_users_label.pack_forget()

        listbox.delete(0, tk.END)
        if not users:
            no_users_label.pack(expand=True)
        else:
            header.pack(fill="x", padx=10, pady=5)
            scrollbar.pack(side="right", fill="y")
            listbox.pack(side="left", expand=True, fill="both", padx=10, pady=5)
            for user in users:
                listbox.insert(tk.END, f"{user['username']:<30}{user['ip']:<20}")

    def refresh_action(event=None):
        if refresh_btn['state'] == 'disabled':
            return
        refresh_btn.config(state="disabled")
        title_label.config(text="Scanning network, please wait...")

        def scan_and_update_ui():
            updated_users = scan_function()
            if dialog.winfo_exists():
                dialog.after(0, lambda: update_gui_after_scan(updated_users))

        def update_gui_after_scan(users):
            populate_list(users)
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

    populate_list(user_ip_list)

    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.grab_set()
    root.wait_window(dialog)
    root.deiconify()
    root.lift()
