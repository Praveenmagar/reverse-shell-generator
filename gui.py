import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os

from payloads import python, bash, php
from encoders.encoder import (
    B64_WRAPPERS, HEX_WRAPPERS, ROT13_WRAPPERS, XOR_WRAPPERS, OBFUSCATOR_WRAPPERS
)
from host_payload import serve_directory

# ---- Settings ----
PAYLOAD_MAP = {
    "Python": ("python", python.generate, "reverse_shell.py"),
    "Bash": ("bash", bash.generate, "reverse_shell.sh"),
    "PHP": ("php", php.generate, "reverse_shell.php"),
}

ENCODER_OPTIONS = {
    "python": ["None", "Base64", "Hex", "ROT13", "XOR", "Obfuscate"],
    "bash": ["None", "Base64"],
    "php": ["None", "Base64"]
}

BG = "#16181D"
CARD_BG = "#232530"
FG = "#F8F8F2"
HEADER = "#BD93F9"
BTN = "#50FA7B"
ENTRY_BG = "#282A36"

# ---- Main App ----

class ReverseShellGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Reverse-Shell Generator")
        self.geometry("580x570")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.build_ui()

    def build_ui(self):
        # --- Header ---
        header = tk.Label(
            self, text="Reverse-Shell Generator",
            font=("Segoe UI", 20, "bold"), fg=HEADER, bg=BG
        )
        header.pack(pady=(16, 0))

        subtitle = tk.Label(
            self, text="Craft payloads with encoding/obfuscation for Python, Bash, PHP",
            font=("Segoe UI", 11), fg="#bbbbbb", bg=BG
        )
        subtitle.pack(pady=(2, 15))

        # --- Main Card ---
        card = tk.Frame(self, bg=CARD_BG, bd=2, relief="ridge")
        card.pack(padx=24, pady=4, fill="both", expand=False)

        # --- Input Section ---
        label_opts = {"bg": CARD_BG, "fg": FG, "font": ("Segoe UI", 11, "bold")}

        ttk.Style().configure("TEntry", padding=4)

        # Payload type
        tk.Label(card, text="Payload Type", **label_opts).grid(row=0, column=0, sticky="e", pady=10, padx=8)
        self.payload_var = tk.StringVar(value="Python")
        payload_combo = ttk.Combobox(card, textvariable=self.payload_var, values=list(PAYLOAD_MAP.keys()), state="readonly", font=("Segoe UI", 10))
        payload_combo.grid(row=0, column=1, pady=10, padx=8)
        self.payload_var.trace("w", self.update_encoders)

        # LHOST
        tk.Label(card, text="LHOST", **label_opts).grid(row=1, column=0, sticky="e", pady=10, padx=8)
        self.lhost_var = tk.StringVar()
        lhost_entry = tk.Entry(card, textvariable=self.lhost_var, font=("Segoe UI", 10), bg=ENTRY_BG, fg=FG, insertbackground=FG)
        lhost_entry.grid(row=1, column=1, pady=10, padx=8)

        # LPORT
        tk.Label(card, text="LPORT", **label_opts).grid(row=2, column=0, sticky="e", pady=10, padx=8)
        self.lport_var = tk.StringVar()
        lport_entry = tk.Entry(card, textvariable=self.lport_var, font=("Segoe UI", 10), bg=ENTRY_BG, fg=FG, insertbackground=FG)
        lport_entry.grid(row=2, column=1, pady=10, padx=8)

        # Encoder
        tk.Label(card, text="Encoder", **label_opts).grid(row=3, column=0, sticky="e", pady=10, padx=8)
        self.encoder_var = tk.StringVar(value="None")
        self.encoder_combo = ttk.Combobox(card, textvariable=self.encoder_var, values=ENCODER_OPTIONS["python"], state="readonly", font=("Segoe UI", 10))
        self.encoder_combo.grid(row=3, column=1, pady=10, padx=8)

        # Output filename
        tk.Label(card, text="Output Filename", **label_opts).grid(row=4, column=0, sticky="e", pady=10, padx=8)
        self.filename_var = tk.StringVar()
        filename_entry = tk.Entry(card, textvariable=self.filename_var, font=("Segoe UI", 10), bg=ENTRY_BG, fg=FG, insertbackground=FG)
        filename_entry.grid(row=4, column=1, pady=10, padx=8)

        # --- Generate/Save/Host Buttons ---
        btns = tk.Frame(self, bg=BG)
        btns.pack(pady=(8, 6))

        self.gen_btn = tk.Button(btns, text="Generate & Preview", font=("Segoe UI", 12, "bold"), bg=BTN, fg="#222", width=16, command=self.generate_and_preview)
        self.gen_btn.grid(row=0, column=0, padx=10)

        self.save_btn = tk.Button(btns, text="Save Payload", font=("Segoe UI", 12), state="disabled", bg=BTN, fg="#222", width=13, command=self.save_payload)
        self.save_btn.grid(row=0, column=1, padx=10)

        self.host_btn = tk.Button(btns, text="Host via HTTP", font=("Segoe UI", 12), state="disabled", bg=BTN, fg="#222", width=13, command=self.host_payload)
        self.host_btn.grid(row=0, column=2, padx=10)

        # --- Payload Preview ---
        preview_frame = tk.LabelFrame(self, text="Generated Payload Preview", font=("Segoe UI", 11, "bold"), fg=HEADER, bg=BG, bd=2)
        preview_frame.pack(padx=20, pady=(8, 0), fill="both", expand=True)
        self.payload_preview = scrolledtext.ScrolledText(preview_frame, font=("Consolas", 11), bg=ENTRY_BG, fg=FG, insertbackground=FG, wrap="word", height=12)
        self.payload_preview.pack(fill="both", expand=True, padx=6, pady=4)

        # --- Footer ---
        footer = tk.Label(self, text="Author: Praveen Magar | Ethical Hacking Tool | 2025", fg="#888", bg=BG, font=("Segoe UI", 9))
        footer.pack(side="bottom", pady=4)

    def update_encoders(self, *args):
        payload_type = self.payload_var.get()
        lang, _, _ = PAYLOAD_MAP[payload_type]
        self.encoder_combo['values'] = ENCODER_OPTIONS[lang]
        self.encoder_var.set(ENCODER_OPTIONS[lang][0])

    def generate_and_preview(self):
        payload_type = self.payload_var.get()
        lang, gen_fn, default_name = PAYLOAD_MAP[payload_type]
        lhost = self.lhost_var.get().strip()
        lport = self.lport_var.get().strip()
        encoder = self.encoder_var.get()
        fname = self.filename_var.get().strip() or default_name

        if not lhost or not lport:
            messagebox.showerror("Missing Input", "LHOST and LPORT must be specified.")
            return

        try:
            raw_code = gen_fn(lhost, lport)
        except Exception as e:
            messagebox.showerror("Error", f"Error generating payload:\n{e}")
            return

        encoder_map = {
            "None": ("", lambda code: code),
            "Base64": (".b64", lambda code: B64_WRAPPERS[lang](code)),
            "Hex": (".hex", lambda code: HEX_WRAPPERS["python"](code) if lang == "python" else code),
            "ROT13": (".rot13", lambda code: ROT13_WRAPPERS["python"](code) if lang == "python" else code),
            "XOR": (".xor", lambda code: XOR_WRAPPERS["python"](code) if lang == "python" else code),
            "Obfuscate": (".obf", lambda code: OBFUSCATOR_WRAPPERS["python"](code) if lang == "python" else code)
        }

        if encoder not in encoder_map:
            messagebox.showerror("Error", f"Encoder '{encoder}' not supported for {payload_type}.")
            return

        enc_ext, encoder_fn = encoder_map[encoder]
        if lang != "python" and encoder not in ["None", "Base64"]:
            messagebox.showerror("Error", f"{encoder} encoding only supported for Python.")
            return

        try:
            self.final_code = encoder_fn(raw_code)
            self.save_ext = enc_ext
        except Exception as e:
            messagebox.showerror("Error", f"Encoder error:\n{e}")
            return

        self.payload_preview.delete("1.0", "end")
        self.payload_preview.insert("1.0", self.final_code)
        self.save_btn.config(state="normal")
        self.host_btn.config(state="disabled")

    def save_payload(self):
        fname = self.filename_var.get().strip() or PAYLOAD_MAP[self.payload_var.get()][2]
        output_folder = os.path.join(os.path.dirname(__file__), "output")
        os.makedirs(output_folder, exist_ok=True)
        save_path = os.path.join(output_folder, fname + getattr(self, 'save_ext', ''))

        try:
            with open(save_path, "w") as f:
                f.write(self.final_code)
            messagebox.showinfo("Success", f"Payload saved as {save_path}")
            self.host_btn.config(state="normal")
            self.saved_path = save_path
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file:\n{e}")

    def host_payload(self):
        try:
            port_input = simple_input_dialog(self, "Enter port to use for hosting (default 8080):", "8080")
            serve_port = int(port_input) if port_input else 8080
            serve_directory(os.path.join(os.path.dirname(__file__), "output"), serve_port)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to host payload:\n{e}")

def simple_input_dialog(parent, prompt, default=''):
    top = tk.Toplevel(parent)
    top.title("Input")
    top.geometry("320x100")
    top.configure(bg=BG)
    tk.Label(top, text=prompt, bg=BG, fg=FG, font=("Segoe UI", 11)).pack(padx=10, pady=8)
    var = tk.StringVar(value=default)
    entry = tk.Entry(top, textvariable=var, font=("Segoe UI", 11), bg=ENTRY_BG, fg=FG, insertbackground=FG)
    entry.pack(padx=10, pady=3)
    entry.focus_set()
    result = []

    def ok():
        result.append(var.get())
        top.destroy()
    tk.Button(top, text="OK", font=("Segoe UI", 10, "bold"), bg=BTN, fg="#111", command=ok).pack(pady=4)
    parent.wait_window(top)
    return result[0] if result else default

if __name__ == "__main__":
    app = ReverseShellGUI()
    app.mainloop()
