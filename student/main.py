import tkinter as tk
from tkinter import messagebox
import threading
import os
import ssh_setup
import manage_keys

class StudentApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Student Setup Assistant")
        self.root.configure(bg="#F0F0F0")

        self.frame = tk.Frame(self.root, bg="#F0F0F0")
        self.frame.pack(expand=True)

        self.label = tk.Label(self.frame, text="Initializing Setup...", font=("Segoe UI", 16), bg="#F0F0F0")
        self.label.pack(pady=10)

        self.progress_label = tk.Label(self.frame, text="", font=("Segoe UI", 12), bg="#F0F0F0")
        self.progress_label.pack(pady=5)
        self.canvas = tk.Canvas(self.frame, width=100, height=100, highlightthickness=0, bg="#F0F0F0")
        self.canvas.pack(pady=10)
        self.arc = self.canvas.create_arc(10, 10, 90, 90, start=0, extent=60, style=tk.ARC, outline="#0078D7", width=4)
        self.angle = 0
        self.animate = True
        self.rotate_loader()

        self.root.after(100, self.run_setup_thread)

    def rotate_loader(self):
        if self.animate:
            self.angle = (self.angle - 5) % 360
            self.canvas.itemconfig(self.arc, start=self.angle)
            self.root.after(20, self.rotate_loader)

    def run_setup_thread(self):
        threading.Thread(target=self.run_setup, daemon=True).start()

    def run_setup(self):
        try:
            ssh_setup.run_full_setup(update_callback=self.update_progress_from_thread)
            self.root.after(0, self.show_key_management_ui)
        except Exception as e:
            self.animate = False
            self.root.after(0, lambda: messagebox.showerror("Setup Error", f"A setup error occurred: {e}"))

    def update_progress_from_thread(self, text):
        self.root.after(0, lambda: self.progress_label.config(text=text))

    def show_key_management_ui(self):
        self.animate = False
        self.canvas.destroy()
        self.label.config(text="Setup Complete!")
        self.progress_label.config(text="You can now manage public keys to allow remote access.")

        button_frame = tk.Frame(self.frame, bg="#F0F0F0")
        button_frame.pack(pady=20)

        common_opts = {"font": ("Segoe UI", 11, "bold"), "relief": "flat", "padx": 15, "pady": 8}

        add_button = tk.Button(
            button_frame, text="Add Public Key",
            command=lambda: manage_keys.add_key(self.root),
            **common_opts
        )
        add_button.pack(side="left", padx=10)

        delete_button = tk.Button(
            button_frame, text="Delete Public Key",
            command=lambda: manage_keys.delete_key_dialog(self.root),
            **common_opts
        )
        delete_button.pack(side="left", padx=10)

def require_root():
    if os.geteuid() != 0:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Root Privileges Required",
            "This application needs administrator privileges. Please run it with 'sudo'."
        )
        root.destroy()
        exit(1)

if __name__ == "__main__":
    require_root()
    root = tk.Tk()
    window_width, window_height = 600, 450
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = int((screen_width / 2) - (window_width / 2))
    y = int((screen_height / 2) - (window_height / 2))
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")

    app = StudentApp(root)
    root.mainloop()
