# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
Tkinter GUI for PQC Folder Encryptor.

Preserves the original dark-themed TTPSEC visual design while using
the refactored modular backend.
"""
from __future__ import annotations

import re
import threading
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from . import encrypt_folder, decrypt_folder, __version__
from .exceptions import PQCError

# Color palette
C = {
    "bg": "#080b12",
    "panel": "#0d1219",
    "border": "#1a2535",
    "accent": "#00e676",
    "accent2": "#00b0ff",
    "danger": "#ff5252",
    "text": "#c8d6e5",
    "dim": "#4a5568",
    "input_bg": "#0a0f18",
}


class PQCApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title(f"TTPSEC \u2014 PQC Folder Encryptor v{__version__}")
        self.root.geometry("880x750")
        self.root.configure(bg=C["bg"])
        self.root.resizable(True, True)
        self.running = False
        self._build_styles()
        self._build_ui()

    # ---------------------------------------------------------------
    # Styles
    # ---------------------------------------------------------------
    def _build_styles(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["text"],
                    fieldbackground=C["input_bg"], borderwidth=0,
                    font=("Segoe UI", 10))
        s.configure("TFrame", background=C["bg"])
        s.configure("TLabel", background=C["bg"], foreground=C["text"])
        s.configure("Accent.TButton", background=C["accent"], foreground="#000000",
                    font=("Segoe UI", 12, "bold"), padding=(20, 12))
        s.map("Accent.TButton",
              background=[("active", "#00c864"), ("disabled", C["border"])],
              foreground=[("disabled", C["dim"])])
        s.configure("green.Horizontal.TProgressbar",
                    troughcolor=C["panel"], background=C["accent"],
                    borderwidth=0, thickness=6)

    # ---------------------------------------------------------------
    # UI construction
    # ---------------------------------------------------------------
    def _build_ui(self) -> None:
        root = self.root
        main = tk.Frame(root, bg=C["bg"])
        main.pack(fill="both", expand=True, padx=0, pady=0)

        # Header
        hdr = tk.Frame(main, bg=C["bg"], pady=15)
        hdr.pack(fill="x", padx=30)
        text_frame = tk.Frame(hdr, bg=C["bg"])
        text_frame.pack(side="left")
        tk.Label(text_frame, text="TTPSEC", font=("Consolas", 24, "bold"),
                 bg=C["bg"], fg="#ffffff").pack(anchor="w")
        tk.Label(text_frame, text="Post-Quantum Folder Encryptor",
                 font=("Segoe UI", 10), bg=C["bg"], fg=C["dim"]).pack(anchor="w")

        badge_frame = tk.Frame(hdr, bg=C["bg"])
        badge_frame.pack(side="right")
        for txt, color in [("ML-KEM-768", C["accent"]),
                           ("AES-256-GCM", C["accent2"]),
                           ("ML-DSA-65", "#ff9800")]:
            tk.Label(badge_frame, text=f" {txt} ", font=("Consolas", 8, "bold"),
                     bg=C["bg"], fg=color,
                     highlightbackground=color, highlightthickness=1,
                     padx=6, pady=1).pack(side="left", padx=2)

        tk.Frame(main, bg=C["border"], height=1).pack(fill="x", padx=30, pady=(0, 15))

        content = tk.Frame(main, bg=C["bg"])
        content.pack(fill="both", expand=True, padx=30)

        # Mode
        self._section(content, "MODO DE OPERACION")
        mode_f = tk.Frame(content, bg=C["bg"])
        mode_f.pack(fill="x", pady=(0, 12))
        self.mode = tk.StringVar(value="encrypt")
        for val, label in [("encrypt", "Cifrar Carpeta"), ("decrypt", "Descifrar .pqc")]:
            tk.Radiobutton(
                mode_f, text=f"  {label}", variable=self.mode, value=val,
                font=("Segoe UI", 11), bg=C["bg"], fg=C["text"],
                selectcolor=C["panel"], activebackground=C["bg"],
                activeforeground=C["accent"], indicatoron=0,
                borderwidth=1, relief="solid", padx=20, pady=8,
                highlightbackground=C["border"], highlightthickness=1,
            ).pack(side="left", padx=(0, 8))

        # Paths
        self._section(content, "ARCHIVOS")
        self.src_var = tk.StringVar()
        self.dst_var = tk.StringVar()
        self._path_row(content, "Origen", self.src_var, self._browse_src)
        self._path_row(content, "Destino", self.dst_var, self._browse_dst)
        self.info_var = tk.StringVar()
        tk.Label(content, textvariable=self.info_var, font=("Consolas", 9),
                 bg=C["bg"], fg=C["dim"]).pack(anchor="w", pady=(0, 8))

        # Passphrase
        self._section(content, "PASSPHRASE  \u2014  Argon2id (64 MB, 3 iter)")
        self.pw_var = tk.StringVar()
        self.pw2_var = tk.StringVar()
        pw_frame = tk.Frame(content, bg=C["bg"])
        pw_frame.pack(fill="x", pady=(0, 4))
        tk.Label(pw_frame, text="Clave:", font=("Segoe UI", 9),
                 bg=C["bg"], fg=C["dim"], width=10, anchor="w").pack(side="left")
        self.pw_entry = tk.Entry(
            pw_frame, textvariable=self.pw_var, show="*",
            font=("Consolas", 11), bg=C["input_bg"], fg=C["text"],
            insertbackground=C["accent"], relief="solid", bd=1,
            highlightbackground=C["border"], highlightthickness=1)
        self.pw_entry.pack(side="left", fill="x", expand=True, padx=5, ipady=4)
        self.show_pw = tk.BooleanVar()
        tk.Checkbutton(pw_frame, text="Show", variable=self.show_pw,
                       command=self._toggle_pw, font=("Segoe UI", 10),
                       bg=C["bg"], fg=C["dim"], selectcolor=C["bg"],
                       activebackground=C["bg"]).pack(side="left")

        pw2_frame = tk.Frame(content, bg=C["bg"])
        pw2_frame.pack(fill="x", pady=(0, 12))
        tk.Label(pw2_frame, text="Confirmar:", font=("Segoe UI", 9),
                 bg=C["bg"], fg=C["dim"], width=10, anchor="w").pack(side="left")
        self.pw2_entry = tk.Entry(
            pw2_frame, textvariable=self.pw2_var, show="*",
            font=("Consolas", 11), bg=C["input_bg"], fg=C["text"],
            insertbackground=C["accent"], relief="solid", bd=1,
            highlightbackground=C["border"], highlightthickness=1)
        self.pw2_entry.pack(side="left", fill="x", expand=True, padx=5, ipady=4)

        # Strength bar
        self.strength_frame = tk.Frame(content, bg=C["bg"])
        self.strength_frame.pack(fill="x", pady=(0, 12))
        self.strength_bar = tk.Canvas(self.strength_frame, height=3, bg=C["panel"],
                                      highlightthickness=0)
        self.strength_bar.pack(fill="x")
        self.strength_label = tk.Label(self.strength_frame, text="",
                                        font=("Consolas", 8), bg=C["bg"], fg=C["dim"])
        self.strength_label.pack(anchor="e")
        self.pw_var.trace_add("write", self._update_strength)

        # Progress
        self._section(content, "PROGRESO")
        self.prog_var = tk.DoubleVar()
        ttk.Progressbar(content, variable=self.prog_var, maximum=100,
                        style="green.Horizontal.TProgressbar").pack(fill="x", pady=(0, 4), ipady=1)
        self.status_var = tk.StringVar(value="Esperando configuracion...")
        tk.Label(content, textvariable=self.status_var, font=("Consolas", 9),
                 bg=C["bg"], fg=C["accent"]).pack(anchor="w", pady=(0, 8))

        # Log
        self._section(content, "LOG DE OPERACIONES")
        log_frame = tk.Frame(content, bg=C["border"], bd=1, relief="solid")
        log_frame.pack(fill="both", expand=True, pady=(0, 12))
        self.log = scrolledtext.ScrolledText(
            log_frame, font=("Consolas", 9), height=6,
            bg="#060a10", fg="#6b7d8e", insertbackground=C["accent"],
            relief="flat", bd=8, selectbackground="#1a2535")
        self.log.pack(fill="both", expand=True)

        # Action button
        ttk.Button(content, text="EJECUTAR", style="Accent.TButton",
                   command=self._execute).pack(fill="x", pady=(0, 8), ipady=4)

        # Footer
        tk.Frame(main, bg=C["border"], height=1).pack(fill="x", padx=30, pady=(0, 8))
        foot = tk.Frame(main, bg=C["bg"])
        foot.pack(fill="x", padx=30, pady=(0, 10))
        tk.Label(foot, text="TTPSEC SpA  \u2014  Ciberseguridad OT/ICS",
                 font=("Consolas", 8), bg=C["bg"], fg="#2a3545").pack(side="left")
        tk.Label(foot, text="FIPS 203 \u2022 FIPS 204 \u2022 Post-Quantum Security",
                 font=("Consolas", 8), bg=C["bg"], fg="#2a3545").pack(side="right")

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------
    def _section(self, parent: tk.Widget, text: str) -> None:
        f = tk.Frame(parent, bg=C["bg"])
        f.pack(fill="x", pady=(8, 4))
        tk.Label(f, text=text, font=("Consolas", 8, "bold"),
                 bg=C["bg"], fg=C["accent2"]).pack(side="left")
        tk.Frame(f, bg=C["border"], height=1).pack(
            side="left", fill="x", expand=True, padx=(10, 0), pady=1)

    def _path_row(self, parent: tk.Widget, label: str,
                  var: tk.StringVar, cmd: object) -> None:
        f = tk.Frame(parent, bg=C["bg"])
        f.pack(fill="x", pady=2)
        tk.Label(f, text=f"{label}:", font=("Segoe UI", 9),
                 bg=C["bg"], fg=C["dim"], width=10, anchor="w").pack(side="left")
        tk.Entry(f, textvariable=var, font=("Consolas", 10),
                 bg=C["input_bg"], fg=C["text"], insertbackground=C["accent"],
                 relief="solid", bd=1,
                 highlightbackground=C["border"], highlightthickness=1
                 ).pack(side="left", fill="x", expand=True, padx=5, ipady=3)
        tk.Button(f, text="Browse", command=cmd, font=("Segoe UI", 10),
                  bg=C["panel"], fg=C["text"], relief="flat",
                  activebackground=C["border"], bd=0, padx=8).pack(side="left")

    def _browse_src(self) -> None:
        if self.mode.get() == "encrypt":
            p = filedialog.askdirectory(title="Carpeta a cifrar")
        else:
            p = filedialog.askopenfilename(
                title="Archivo .pqc", filetypes=[("PQC", "*.pqc"), ("All", "*.*")])
        if p:
            self.src_var.set(p)
            if not self.dst_var.get():
                self.dst_var.set(
                    p + ".pqc" if self.mode.get() == "encrypt"
                    else str(Path(p).parent))
            if self.mode.get() == "encrypt" and Path(p).is_dir():
                n = sum(1 for f in Path(p).rglob("*") if f.is_file())
                sz = sum(f.stat().st_size for f in Path(p).rglob("*") if f.is_file())
                self.info_var.set(f"{n} archivos \u2014 {sz:,} bytes")

    def _browse_dst(self) -> None:
        if self.mode.get() == "encrypt":
            p = filedialog.asksaveasfilename(
                defaultextension=".pqc", filetypes=[("PQC", "*.pqc")])
        else:
            p = filedialog.askdirectory(title="Destino")
        if p:
            self.dst_var.set(p)

    def _toggle_pw(self) -> None:
        ch = "" if self.show_pw.get() else "*"
        self.pw_entry.configure(show=ch)
        self.pw2_entry.configure(show=ch)

    def _update_strength(self, *_: object) -> None:
        p = self.pw_var.get()
        if not p:
            self.strength_bar.delete("all")
            self.strength_label.configure(text="")
            return
        s = 0
        if len(p) >= 8: s += 1
        if len(p) >= 14: s += 1
        if len(p) >= 20: s += 1
        if re.search(r"[A-Z]", p) and re.search(r"[a-z]", p): s += 1
        if re.search(r"\d", p): s += 1
        if re.search(r"[^A-Za-z0-9]", p): s += 1
        s = min(s, 5)
        labels = ["Muy debil", "Debil", "Aceptable", "Buena", "Fuerte", "Excelente"]
        colors = ["#ff1744", "#ff5252", "#ff9800", "#ffeb3b", "#76ff03", C["accent"]]
        w = self.strength_bar.winfo_width()
        self.strength_bar.delete("all")
        bw = int(w * (s + 1) / 6)
        self.strength_bar.create_rectangle(0, 0, bw, 4, fill=colors[s], outline="")
        self.strength_label.configure(text=labels[s], fg=colors[s])

    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    def _progress(self, phase: str, detail: str, pct: float) -> None:
        self.prog_var.set(pct)
        self.status_var.set(f"[{phase}] {detail}")
        self._log(f"[{phase:>10}] {detail}")
        self.root.update_idletasks()

    def _execute(self) -> None:
        if self.running:
            return
        src = self.src_var.get().strip()
        dst = self.dst_var.get().strip()
        pw = self.pw_var.get()

        if not src or not dst:
            messagebox.showerror("TTPSEC", "Seleccione origen y destino")
            return
        if not pw:
            messagebox.showerror("TTPSEC", "Ingrese passphrase")
            return
        if self.mode.get() == "encrypt" and pw != self.pw2_var.get():
            messagebox.showerror("TTPSEC", "Las passphrases no coinciden")
            return

        self.running = True
        self.log.delete("1.0", "end")
        self.prog_var.set(0)

        def work() -> None:
            try:
                if self.mode.get() == "encrypt":
                    r = encrypt_folder(src, dst, pw, self._progress)
                    messagebox.showinfo("TTPSEC",
                        f"Cifrado exitoso\n\n"
                        f"Archivos:  {r['files']}\n"
                        f"Entrada:   {r['input_size']:,} bytes\n"
                        f"Salida:    {r['output_size']:,} bytes\n\n"
                        f"{r['output']}")
                else:
                    r = decrypt_folder(src, dst, pw, self._progress)
                    messagebox.showinfo("TTPSEC",
                        f"Descifrado exitoso\n\n"
                        f"Archivos: {r['files']}\n\n"
                        f"{r['output_dir']}")
            except PQCError as e:
                self._log(f"ERROR: {e}")
                messagebox.showerror("TTPSEC", str(e))
            except Exception as e:
                self._log(f"ERROR: {e}")
                messagebox.showerror("TTPSEC", f"Unexpected error: {e}")
            finally:
                self.running = False

        threading.Thread(target=work, daemon=True).start()

    def run(self) -> None:
        self.root.mainloop()


def run_gui() -> None:
    PQCApp().run()
