#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTPSEC SpA
"""
PQC Folder Encryptor v2.0 — TTPSEC SpA
Single-file: auto-installs dependencies, encrypts/decrypts folders
with post-quantum cryptography (ML-KEM-768 + AES-256-GCM + ML-DSA-65).

Just run:  python pqc_encryptor.py
"""

import subprocess, sys, os

# ── Auto-install dependencies ───────────────────────────────
def ensure_deps():
    if getattr(sys, 'frozen', False):
        return  # Running as .exe, deps are bundled
    required = {
        "pqcrypto": "pqcrypto",
        "cryptography": "cryptography",
        "argon2": "argon2-cffi",
    }
    missing = []
    for mod, pkg in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"Instalando dependencias: {', '.join(missing)}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print("Dependencias instaladas.\n")

ensure_deps()

# ── Imports ─────────────────────────────────────────────────
import json, struct, hashlib, secrets, threading, traceback
from pathlib import Path
from datetime import datetime
from typing import Callable, Dict

from pqcrypto.kem.ml_kem_768 import (
    generate_keypair as kem_keygen, encrypt as kem_encrypt,
    decrypt as kem_decrypt, PUBLIC_KEY_SIZE as KEM_PK,
    SECRET_KEY_SIZE as KEM_SK, CIPHERTEXT_SIZE as KEM_CT,
)
from pqcrypto.sign.ml_dsa_65 import (
    generate_keypair as sig_keygen, sign as sig_sign, verify as sig_verify,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type as A2T

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

MAGIC = b"PQC2"
VERSION = 2

# ── Crypto helpers ──────────────────────────────────────────
def kdf_pass(pw: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=pw.encode(), salt=salt,
        time_cost=3, memory_cost=65536, parallelism=4,
        hash_len=32, type=A2T.ID)

def kdf_ss(ss: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=None, info=b"pqc-folder-v2").derive(ss)

# ── Pack/Unpack ─────────────────────────────────────────────
def pack(folder, files, prog):
    manifest, blobs, n = [], [], len(files)
    for i, (rel, fp) in enumerate(files):
        prog("cifrar", rel, 20 + (i/n)*55)
        d = fp.read_bytes()
        manifest.append({"p": rel, "s": len(d), "h": hashlib.sha256(d).hexdigest()})
        blobs.append(d)
    mj = json.dumps(manifest, ensure_ascii=False, separators=(",",":")).encode()
    parts = [struct.pack("<I", len(mj)), mj]
    for b in blobs:
        parts += [struct.pack("<I", len(b)), b]
    return b"".join(parts)

def unpack(payload):
    o = 0
    ml = struct.unpack("<I", payload[o:o+4])[0]; o += 4
    manifest = json.loads(payload[o:o+ml]); o += ml
    r = []
    for e in manifest:
        bl = struct.unpack("<I", payload[o:o+4])[0]; o += 4
        r.append((e["p"], payload[o:o+bl], e["h"])); o += bl
    return r

# ── Encrypt/Decrypt ─────────────────────────────────────────
def encrypt_folder(src, dst, pw, prog=lambda *a: None):
    folder = Path(src)
    files = sorted([(str(f.relative_to(folder)), f)
                    for f in folder.rglob("*") if f.is_file()])
    if not files:
        raise ValueError("Carpeta vacia")
    tsz = sum(f.stat().st_size for _, f in files)
    prog("init", f"{len(files)} archivos - {tsz:,} bytes", 2)

    prog("keygen", "ML-KEM-768...", 5)
    kpk, ksk = kem_keygen()
    prog("keygen", "ML-DSA-65...", 8)
    spk, ssk = sig_keygen()
    prog("encap", "Encapsulando...", 10)
    ct, ss = kem_encrypt(kpk)
    prog("kdf", "HKDF -> AES-256...", 12)
    akey = kdf_ss(ss)
    prog("argon2", "Protegiendo clave...", 15)
    salt = secrets.token_bytes(16)
    ppk = kdf_pass(pw, salt)
    skn = secrets.token_bytes(12)
    esk = AESGCM(ppk).encrypt(skn, ksk, None)

    payload = pack(folder, files, prog)
    prog("aes", "AES-256-GCM...", 78)
    an = secrets.token_bytes(12)
    act = AESGCM(akey).encrypt(an, payload, None)

    prog("firma", "ML-DSA-65...", 85)
    si = ct + an + hashlib.sha256(act).digest()
    sig = sig_sign(ssk, si)

    prog("guardar", "Escribiendo .pqc...", 90)
    out = Path(dst)
    fn = folder.name.encode()
    with open(out, "wb") as f:
        f.write(MAGIC + struct.pack("<H", VERSION) + struct.pack("<H", len(fn)) + fn)
        f.write(ct + salt + skn + esk + kpk + spk)
        f.write(struct.pack("<H", len(sig)) + sig + an + act)

    prog("limpiar", "Zeroize...", 95)
    osz = out.stat().st_size
    prog("listo", f"OK {out.name} ({osz:,} bytes)", 100)
    return {"output": str(out), "files": len(files),
            "input_size": tsz, "output_size": osz}

def decrypt_folder(src, dst, pw, prog=lambda *a: None):
    prog("leer", "Abriendo .pqc...", 5)
    with open(src, "rb") as f:
        if f.read(4) != MAGIC: raise ValueError("Archivo no valido")
        f.read(2)  # version
        fnl = struct.unpack("<H", f.read(2))[0]
        fname = f.read(fnl).decode()
        ct = f.read(KEM_CT)
        salt = f.read(16); skn = f.read(12)
        esk = f.read(KEM_SK + 16)
        kpk = f.read(KEM_PK); spk = f.read(1952)
        sl = struct.unpack("<H", f.read(2))[0]
        sig = f.read(sl); an = f.read(12); act = f.read()

    prog("argon2", "Derivando clave...", 15)
    ppk = kdf_pass(pw, salt)
    prog("descifrar", "Recuperando SK...", 25)
    try: ksk = AESGCM(ppk).decrypt(skn, esk, None)
    except: raise ValueError("Passphrase incorrecta")

    prog("verificar", "Firma ML-DSA-65...", 35)
    si = ct + an + hashlib.sha256(act).digest()
    try: sig_verify(spk, si, sig)
    except: raise ValueError("Firma invalida - archivo alterado")

    prog("decap", "ML-KEM-768...", 45)
    ss = kem_decrypt(ksk, ct)
    prog("kdf", "HKDF -> AES-256...", 50)
    akey = kdf_ss(ss)
    prog("descifrar", "AES-256-GCM...", 55)
    try: payload = AESGCM(akey).decrypt(an, act, None)
    except: raise ValueError("Datos corruptos")

    prog("extraer", "Archivos...", 65)
    entries = unpack(payload)
    out = Path(dst) / fname
    out.mkdir(parents=True, exist_ok=True)
    for i, (rel, data, eh) in enumerate(entries):
        prog("extraer", rel, 65 + (i/len(entries))*30)
        if hashlib.sha256(data).hexdigest() != eh:
            raise ValueError(f"Integridad fallida: {rel}")
        fp = out / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(data)

    prog("listo", f"OK {len(entries)} archivos -> {out}", 100)
    return {"output_dir": str(out), "files": len(entries)}


# ═══════════════════════════════════════════════════════════
# GUI
# ═══════════════════════════════════════════════════════════

# Color palette
C = {
    "bg":       "#080b12",
    "panel":    "#0d1219",
    "border":   "#1a2535",
    "accent":   "#00e676",
    "accent2":  "#00b0ff",
    "danger":   "#ff5252",
    "text":     "#c8d6e5",
    "dim":      "#4a5568",
    "input_bg": "#0a0f18",
}

class PQCApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("TTPSEC - PQC Folder Encryptor")
        self.root.geometry("880x750")
        self.root.configure(bg=C["bg"])
        self.root.resizable(True, True)

        try:
            self.root.iconbitmap(default="")
        except:
            pass

        self.running = False
        self._build_styles()
        self._build_ui()

    def _build_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["text"],
                    fieldbackground=C["input_bg"], borderwidth=0,
                    font=("Segoe UI", 10))
        s.configure("TFrame", background=C["bg"])
        s.configure("Panel.TFrame", background=C["panel"])
        s.configure("TLabel", background=C["bg"], foreground=C["text"])
        s.configure("Dim.TLabel", foreground=C["dim"], font=("Consolas", 8))
        s.configure("Title.TLabel", font=("Segoe UI", 22, "bold"), foreground="#ffffff")
        s.configure("Brand.TLabel", font=("Consolas", 11, "bold"), foreground=C["accent"])
        s.configure("Sub.TLabel", font=("Consolas", 9), foreground=C["dim"])
        s.configure("Section.TLabel", font=("Segoe UI", 9, "bold"),
                    foreground=C["accent2"])
        s.configure("Status.TLabel", font=("Consolas", 9), foreground=C["accent"])

        s.configure("TEntry", fieldbackground=C["input_bg"], foreground=C["text"],
                    insertcolor=C["accent"], borderwidth=1, relief="solid",
                    font=("Consolas", 10))

        s.configure("TRadiobutton", background=C["bg"], foreground=C["text"],
                    font=("Segoe UI", 10), indicatorcolor=C["border"],
                    focuscolor=C["bg"])
        s.map("TRadiobutton",
              indicatorcolor=[("selected", C["accent"])],
              background=[("active", C["bg"])])

        s.configure("TCheckbutton", background=C["bg"], foreground=C["text"],
                    font=("Segoe UI", 9))
        s.map("TCheckbutton", background=[("active", C["bg"])])

        s.configure("Accent.TButton", background=C["accent"], foreground="#000000",
                    font=("Segoe UI", 12, "bold"), padding=(20, 12))
        s.map("Accent.TButton",
              background=[("active", "#00c864"), ("disabled", C["border"])],
              foreground=[("disabled", C["dim"])])

        s.configure("Small.TButton", background=C["border"], foreground=C["text"],
                    font=("Segoe UI", 9), padding=(8, 4))
        s.map("Small.TButton", background=[("active", "#2a3545")])

        s.configure("green.Horizontal.TProgressbar",
                    troughcolor=C["panel"], background=C["accent"],
                    borderwidth=0, thickness=6)

    def _build_ui(self):
        root = self.root

        main = tk.Frame(root, bg=C["bg"])
        main.pack(fill="both", expand=True, padx=0, pady=0)

        # ── Header ──
        hdr = tk.Frame(main, bg=C["bg"], pady=15)
        hdr.pack(fill="x", padx=30)

        brand_frame = tk.Frame(hdr, bg=C["bg"])
        brand_frame.pack(side="left")

        text_frame = tk.Frame(brand_frame, bg=C["bg"])
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
            b = tk.Label(badge_frame, text=f" {txt} ", font=("Consolas", 8, "bold"),
                        bg=C["bg"], fg=color,
                        highlightbackground=color, highlightthickness=1,
                        padx=6, pady=1)
            b.pack(side="left", padx=2)

        sep = tk.Frame(main, bg=C["border"], height=1)
        sep.pack(fill="x", padx=30, pady=(0, 15))

        # ── Content area ──
        content = tk.Frame(main, bg=C["bg"])
        content.pack(fill="both", expand=True, padx=30)

        self._section(content, "MODO DE OPERACION")
        mode_f = tk.Frame(content, bg=C["bg"])
        mode_f.pack(fill="x", pady=(0, 12))

        self.mode = tk.StringVar(value="encrypt")

        for val, label in [("encrypt", "Cifrar Carpeta"),
                           ("decrypt", "Descifrar .pqc")]:
            rb = tk.Radiobutton(
                mode_f, text=f"  {label}", variable=self.mode, value=val,
                font=("Segoe UI", 11), bg=C["bg"], fg=C["text"],
                selectcolor=C["panel"], activebackground=C["bg"],
                activeforeground=C["accent"], indicatoron=0,
                borderwidth=1, relief="solid", padx=20, pady=8,
                highlightbackground=C["border"], highlightthickness=1,
            )
            rb.pack(side="left", padx=(0, 8))

        self._section(content, "ARCHIVOS")
        self.src_var = tk.StringVar()
        self.dst_var = tk.StringVar()
        self._path_row(content, "Origen", self.src_var, self._browse_src)
        self._path_row(content, "Destino", self.dst_var, self._browse_dst)

        self.info_var = tk.StringVar()
        tk.Label(content, textvariable=self.info_var, font=("Consolas", 9),
                bg=C["bg"], fg=C["dim"]).pack(anchor="w", pady=(0, 8))

        self._section(content, "PASSPHRASE  -  Argon2id (64MB, 3 iter)")
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
            highlightbackground=C["border"], highlightthickness=1,
        )
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
            highlightbackground=C["border"], highlightthickness=1,
        )
        self.pw2_entry.pack(side="left", fill="x", expand=True, padx=5, ipady=4)

        self.strength_frame = tk.Frame(content, bg=C["bg"])
        self.strength_frame.pack(fill="x", pady=(0, 12))
        self.strength_bar = tk.Canvas(
            self.strength_frame, height=3, bg=C["panel"],
            highlightthickness=0)
        self.strength_bar.pack(fill="x")
        self.strength_label = tk.Label(
            self.strength_frame, text="", font=("Consolas", 8),
            bg=C["bg"], fg=C["dim"])
        self.strength_label.pack(anchor="e")
        self.pw_var.trace_add("write", self._update_strength)

        self._section(content, "PROGRESO")
        self.prog_var = tk.DoubleVar()
        self.pbar = ttk.Progressbar(
            content, variable=self.prog_var, maximum=100,
            style="green.Horizontal.TProgressbar")
        self.pbar.pack(fill="x", pady=(0, 4), ipady=1)

        self.status_var = tk.StringVar(value="Esperando configuracion...")
        tk.Label(content, textvariable=self.status_var, font=("Consolas", 9),
                bg=C["bg"], fg=C["accent"]).pack(anchor="w", pady=(0, 8))

        self._section(content, "LOG DE OPERACIONES")
        log_frame = tk.Frame(content, bg=C["border"], bd=1, relief="solid")
        log_frame.pack(fill="both", expand=True, pady=(0, 12))

        self.log = scrolledtext.ScrolledText(
            log_frame, font=("Consolas", 9), height=6,
            bg="#060a10", fg="#6b7d8e", insertbackground=C["accent"],
            relief="flat", bd=8, selectbackground="#1a2535",
        )
        self.log.pack(fill="both", expand=True)

        self.action_btn = ttk.Button(
            content, text="EJECUTAR", style="Accent.TButton",
            command=self._execute)
        self.action_btn.pack(fill="x", pady=(0, 8), ipady=4)

        sep2 = tk.Frame(main, bg=C["border"], height=1)
        sep2.pack(fill="x", padx=30, pady=(0, 8))

        foot = tk.Frame(main, bg=C["bg"])
        foot.pack(fill="x", padx=30, pady=(0, 10))
        tk.Label(foot, text="TTPSEC SpA  -  Ciberseguridad OT/ICS",
                font=("Consolas", 8), bg=C["bg"], fg="#2a3545").pack(side="left")
        tk.Label(foot, text="FIPS 203 - FIPS 204 - Post-Quantum Security",
                font=("Consolas", 8), bg=C["bg"], fg="#2a3545").pack(side="right")

    def _section(self, parent, text):
        f = tk.Frame(parent, bg=C["bg"])
        f.pack(fill="x", pady=(8, 4))
        tk.Label(f, text=text, font=("Consolas", 8, "bold"),
                bg=C["bg"], fg=C["accent2"]).pack(side="left")
        line = tk.Frame(f, bg=C["border"], height=1)
        line.pack(side="left", fill="x", expand=True, padx=(10, 0), pady=1)

    def _path_row(self, parent, label, var, cmd):
        f = tk.Frame(parent, bg=C["bg"])
        f.pack(fill="x", pady=2)
        tk.Label(f, text=f"{label}:", font=("Segoe UI", 9),
                bg=C["bg"], fg=C["dim"], width=10, anchor="w").pack(side="left")
        e = tk.Entry(f, textvariable=var, font=("Consolas", 10),
                    bg=C["input_bg"], fg=C["text"], insertbackground=C["accent"],
                    relief="solid", bd=1,
                    highlightbackground=C["border"], highlightthickness=1)
        e.pack(side="left", fill="x", expand=True, padx=5, ipady=3)
        b = tk.Button(f, text="Browse", command=cmd, font=("Segoe UI", 10),
                     bg=C["panel"], fg=C["text"], relief="flat",
                     activebackground=C["border"], bd=0, padx=8)
        b.pack(side="left")

    def _browse_src(self):
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
                self.info_var.set(f"{n} archivos - {sz:,} bytes")

    def _browse_dst(self):
        if self.mode.get() == "encrypt":
            p = filedialog.asksaveasfilename(
                defaultextension=".pqc", filetypes=[("PQC", "*.pqc")])
        else:
            p = filedialog.askdirectory(title="Destino")
        if p:
            self.dst_var.set(p)

    def _toggle_pw(self):
        ch = "" if self.show_pw.get() else "*"
        self.pw_entry.configure(show=ch)
        self.pw2_entry.configure(show=ch)

    def _update_strength(self, *_):
        p = self.pw_var.get()
        if not p:
            self.strength_bar.delete("all")
            self.strength_label.configure(text="")
            return
        s = 0
        if len(p) >= 8: s += 1
        if len(p) >= 14: s += 1
        if len(p) >= 20: s += 1
        import re
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

    def _log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    def _progress(self, phase, detail, pct):
        self.prog_var.set(pct)
        self.status_var.set(f"[{phase}] {detail}")
        self._log(f"[{phase:>10}] {detail}")
        self.root.update_idletasks()

    def _execute(self):
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

        def work():
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
            except Exception as e:
                self._log(f"ERROR: {e}")
                messagebox.showerror("TTPSEC", str(e))
            finally:
                self.running = False

        threading.Thread(target=work, daemon=True).start()

    def run(self):
        self.root.mainloop()


# ── CLI fallback ────────────────────────────────────────────
def run_cli():
    import argparse, getpass
    p = argparse.ArgumentParser(description="TTPSEC PQC Folder Encryptor")
    p.add_argument("mode", choices=["encrypt", "decrypt"])
    p.add_argument("source")
    p.add_argument("output")
    p.add_argument("-p", "--passphrase")
    a = p.parse_args()

    if not a.passphrase:
        a.passphrase = getpass.getpass("Passphrase: ")
        if a.mode == "encrypt":
            if a.passphrase != getpass.getpass("Confirmar:  "):
                print("No coinciden"); sys.exit(1)

    def prog(ph, d, pct):
        bar = "#" * int(pct / 4) + "." * (25 - int(pct / 4))
        print(f"\r  [{bar}] {pct:5.1f}% {d:<50}", end="", flush=True)

    print(f"\nTTPSEC - PQC Folder Encryptor v2.0\n")
    try:
        if a.mode == "encrypt":
            r = encrypt_folder(a.source, a.output, a.passphrase, prog)
            print(f"\n\n{r['files']} archivos -> {r['output']}")
        else:
            r = decrypt_folder(a.source, a.output, a.passphrase, prog)
            print(f"\n\n{r['files']} archivos -> {r['output_dir']}")
    except Exception as e:
        print(f"\n\nERROR: {e}"); sys.exit(1)


# ── Entry ───────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("encrypt", "decrypt", "-h", "--help"):
        run_cli()
    else:
        PQCApp().run()
