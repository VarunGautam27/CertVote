"""
app.py  —  CertVote PKI Voting System
======================================
Entry screen → choose role:
  ADMIN  — password protected → CA Setup + Certificates tabs
  VOTER  — Register + Vote + Tally Board tabs

Election IDs per voter: ITC_ELEC_1_2026, ITC_ELEC_2_2026, ...
Admin password: set "admin_password" in config.json
"""

import json, os, sys, threading, traceback
import tkinter as tk
from tkinter import scrolledtext, ttk

# ── IMPORTANT: import messagebox this way for Python 3.13 compatibility
from tkinter import messagebox   # noqa — must be separate import

_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(_DIR)
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from modules import ca_module, db, storage, voting_module

with open(os.path.join(_DIR, "config.json"), encoding="utf-8") as _f:
    _CFG = json.load(_f)

ELECTION_ID    = _CFG["election_id"]   # used for admin header/tally label
ADMIN_PASSWORD = _CFG.get("admin_password", "admin@ITC2026")

def voter_election_id(membership_id: str) -> str:
    """Look up the voter's unique election ID from the members CSV."""
    try:
        members = voting_module.load_members_csv()
        for m in members:
            if m["membership_id"].strip().upper() == membership_id.strip().upper():
                return m.get("election_id", "")
    except Exception:
        pass
    return ""

# ── Colours ──────────────────────────────────────────────────────────
BG   = "#1e2130"; PANEL = "#252a3d"; ACCENT = "#4a90e2"
OK   = "#27ae60"; ERR   = "#e74c3c"; TEXT   = "#ecf0f1"
SUB  = "#95a5a6"; GOLD  = "#f39c12"; HDR    = "#2c3e6b"
TREE = "#1a1f2e"; ADMIN_HDR = "#2d1a0e"; ADMIN_AC = "#e67e22"


# ── Shared helpers ───────────────────────────────────────────────────
def apply_styles(root):
    s = ttk.Style(root); s.theme_use("clam")
    s.configure("TNotebook", background=BG, borderwidth=0)
    s.configure("TNotebook.Tab", background=PANEL, foreground=SUB,
                padding=[18, 8], font=("Segoe UI", 10, "bold"))
    s.map("TNotebook.Tab",
          background=[("selected", ACCENT)], foreground=[("selected", "white")])
    s.configure("D.TFrame", background=BG)
    s.configure("D.Treeview", background=TREE, foreground=TEXT,
                fieldbackground=TREE, rowheight=24, font=("Consolas", 9))
    s.configure("D.Treeview.Heading", background=HDR, foreground=ACCENT,
                font=("Segoe UI", 9, "bold"), relief="flat")
    s.map("D.Treeview",
          background=[("selected", ACCENT)], foreground=[("selected", "white")])

def mk_log(parent, h=10):
    w = scrolledtext.ScrolledText(parent, height=h, font=("Consolas", 9),
        bg="#0d1117", fg=TEXT, insertbackground=TEXT, state="disabled", relief="flat")
    w.tag_config("ok",   foreground=OK)
    w.tag_config("err",  foreground=ERR)
    w.tag_config("warn", foreground=GOLD)
    w.tag_config("head", foreground=ACCENT)
    w.tag_config("info", foreground=TEXT)
    return w

def log_append(w, msg, tag="info"):
    w.configure(state="normal")
    w.insert(tk.END, msg + "\n", tag)
    w.see(tk.END)
    w.configure(state="disabled")

def log_clear(w):
    w.configure(state="normal"); w.delete("1.0", tk.END); w.configure(state="disabled")

def lbl(parent, text, size=10, bold=False, fg=TEXT, bg=BG):
    return tk.Label(parent, text=text,
                    font=("Segoe UI", size, "bold" if bold else "normal"),
                    bg=bg, fg=fg)

def big_btn(parent, text, cmd, bg=ACCENT, fg="white"):
    return tk.Button(parent, text=text, command=cmd,
                     font=("Segoe UI", 11, "bold"), bg=bg, fg=fg,
                     relief="flat", padx=16, pady=7, cursor="hand2")

def small_btn(parent, text, cmd, bg=PANEL, fg=TEXT):
    return tk.Button(parent, text=text, command=cmd,
                     font=("Segoe UI", 10), bg=bg, fg=fg,
                     relief="flat", padx=12, pady=5, cursor="hand2")

def fentry(parent, var, secret=False, width=28):
    return tk.Entry(parent, textvariable=var, font=("Segoe UI", 10),
                    bg="#151922", fg=TEXT, insertbackground=TEXT,
                    relief="flat", bd=4, width=width,
                    show="•" if secret else "")

def safe_warn(title, msg, parent=None):
    """Messagebox call that works even before the window is fully ready."""
    try:
        messagebox.showwarning(title, msg, parent=parent)
    except Exception:
        try: messagebox.showwarning(title, msg)
        except Exception: print(f"[WARN] {title}: {msg}")

def safe_error(title, msg, parent=None):
    try:
        messagebox.showerror(title, msg, parent=parent)
    except Exception:
        try: messagebox.showerror(title, msg)
        except Exception: print(f"[ERROR] {title}: {msg}")

def safe_info(title, msg, parent=None):
    try:
        messagebox.showinfo(title, msg, parent=parent)
    except Exception:
        try: messagebox.showinfo(title, msg)
        except Exception: print(f"[INFO] {title}: {msg}")


# ══════════════════════════════════════════════════════════════════════
#  ADMIN PORTAL
# ══════════════════════════════════════════════════════════════════════
class AdminPortal(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("CertVote — Admin / CA Portal")
        self.geometry("980x720"); self.minsize(860, 600)
        self.configure(bg=BG)
        apply_styles(self)
        self._build_header()
        self._build_tabs()
        # Defer DB check until window is fully visible
        self.after(800, self._db_check)

    def _build_header(self):
        bar = tk.Frame(self, bg=ADMIN_HDR, height=54)
        bar.pack(fill="x"); bar.pack_propagate(False)
        lbl(bar, "🔐  ADMIN / CA PORTAL", 13, True, fg="white", bg=ADMIN_HDR
            ).pack(side="left", padx=20, pady=12)
        lbl(bar, f"Election: {ELECTION_ID}   |   Certificate Authority Management",
            9, fg=SUB, bg=ADMIN_HDR).pack(side="right", padx=20)

    def _build_tabs(self):
        nb = ttk.Notebook(self); nb.pack(fill="both", expand=True)
        nb.add(self._ca_tab(nb),    text="   🛠  CA Setup   ")
        nb.add(self._certs_tab(nb), text="   📋  Certificates   ")

    # ── CA Setup tab ────────────────────────────────────────────────
    def _ca_tab(self, parent):
        f = ttk.Frame(parent, style="D.TFrame")
        lbl(f, "Certificate Authority Setup", 13, True, fg=ADMIN_AC).pack(pady=(16, 2))
        lbl(f, "Generates the CA RSA-2048 key pair and self-signed X.509 certificate.", 9, fg=SUB).pack()

        sp = tk.Frame(f, bg=PANEL, bd=1, relief="groove")
        sp.pack(padx=30, pady=10, fill="x")
        self._ca_status = lbl(sp, "CA Status: Checking...", 11, True, fg=GOLD, bg=PANEL)
        self._ca_status.pack(pady=(10, 2))
        self._ca_info = lbl(sp, "", 9, fg=TEXT, bg=PANEL)
        self._ca_info.pack(pady=(0, 10))

        bf = tk.Frame(f, bg=BG); bf.pack(pady=8)
        big_btn(bf, "🛠  Initialise CA",         self._init_ca,      ADMIN_AC).grid(row=0, column=0, padx=8)
        small_btn(bf, "📄  View CA Certificate",  self._view_ca_cert).grid(row=0, column=1, padx=8)
        small_btn(bf, "📋  Load Members CSV",     self._load_csv    ).grid(row=0, column=2, padx=8)

        self._mem_lbl = lbl(f, "Active Members: —", 10, fg=TEXT)
        self._mem_lbl.pack(pady=4)

        lf = tk.LabelFrame(f, text="  CA Activity Log  ",
                           font=("Segoe UI", 9, "bold"), bg=BG, fg=ADMIN_AC, bd=1, relief="groove")
        lf.pack(fill="both", expand=True, padx=30, pady=(4, 14))
        self._ca_log = mk_log(lf)
        self._ca_log.pack(fill="both", expand=True, padx=4, pady=4)

        self._refresh_ca_status()
        return f

    # ── Certificates tab ────────────────────────────────────────────
    def _certs_tab(self, parent):
        f = ttk.Frame(parent, style="D.TFrame")
        lbl(f, "Issued Voter Certificates", 13, True, fg=ADMIN_AC).pack(pady=(16, 2))
        lbl(f, "Each certificate binds a voter's RSA-2048 PUBLIC KEY to their identity, signed by the CA.",
            9, fg=SUB).pack()
        small_btn(f, "🔄  Refresh", self._refresh_certs, ADMIN_AC, "white").pack(pady=8)

        cf = tk.LabelFrame(f, text="  Issued Certificates  ",
                           font=("Segoe UI", 9, "bold"), bg=BG, fg=ADMIN_AC, bd=1, relief="groove")
        cf.pack(fill="both", expand=True, padx=30, pady=(0, 8))

        cols = ("election_id", "membership_id", "cert_serial", "issued_at")
        self._cert_tree = ttk.Treeview(cf, columns=cols, show="headings", style="D.Treeview")
        for col, w, heading in [
            ("election_id",   120, "Election ID"),
            ("membership_id",  95, "Member ID"),
            ("cert_serial",   305, "Certificate Serial (RSA-2048)"),
            ("issued_at",     155, "Issued At"),
        ]:
            self._cert_tree.heading(col, text=heading)
            self._cert_tree.column(col, width=w, anchor="center")

        sb = ttk.Scrollbar(cf, orient="vertical", command=self._cert_tree.yview)
        self._cert_tree.configure(yscrollcommand=sb.set)
        self._cert_tree.pack(side="left", fill="both", expand=True, padx=(4,0), pady=4)
        sb.pack(side="right", fill="y", pady=4)

        ib = tk.Frame(f, bg=PANEL, bd=1, relief="groove")
        ib.pack(fill="x", padx=30, pady=(0, 14))
        lbl(ib, "PUBLIC KEY is embedded in each certificate. PRIVATE KEY never leaves the voter's device.",
            9, fg=OK, bg=PANEL).pack(anchor="w", padx=12, pady=6)
        return f

    # ── Helpers ──────────────────────────────────────────────────────
    def _emit(self, msg, tag="info"):
        self.after(0, lambda: log_append(self._ca_log, msg, tag))

    def _refresh_ca_status(self):
        if ca_module.ca_exists():
            self._ca_status.config(text="CA Status:  ✅  INITIALISED", fg=OK)
            self._ca_info.config(text="ca/ca_private_key.pem   |   ca/ca_cert.pem")
        else:
            self._ca_status.config(text="CA Status:  ⚠️  NOT INITIALISED", fg=GOLD)
            self._ca_info.config(text="Click 'Initialise CA' to generate the RSA-2048 key pair.")

    def _db_check(self):
        if not db.test_connection():
            safe_warn("Database Not Connected",
                "Cannot connect to MySQL.\n\n"
                "Steps to fix:\n"
                "1. Open XAMPP → click Start next to MySQL\n"
                "2. Open config.json → set the correct password\n"
                "3. Run sql/schema.sql to create tables\n"
                "4. Restart this application",
                parent=self)

    def _init_ca(self):
        def run():
            try:
                self._emit("Initialising Certificate Authority...", "head")
                self._emit("─" * 50, "head")
                info = ca_module.initialize_ca(log_fn=self._emit)
                tag = "warn" if info["already_existed"] else "ok"
                self._emit(f"Serial  : {info['ca_serial']}", tag)
                self._emit(f"Subject : {info['ca_subject']}", tag)
                self._emit(f"Key     : RSA-{info['key_size']} bits", tag)
                self._emit("─" * 50, tag)
                self._emit("CA already existed — reloaded." if info["already_existed"]
                           else "CA initialised successfully ✅", tag)
                self.after(0, self._refresh_ca_status)
            except Exception as exc:
                self._emit(f"CA init FAILED: {exc}", "err")
        threading.Thread(target=run, daemon=True).start()

    def _view_ca_cert(self):
        if not ca_module.ca_exists():
            safe_warn("CA", "CA not initialised yet.", parent=self); return
        pem = ca_module.load_ca_cert_pem().decode()
        w = tk.Toplevel(self); w.title("CA Certificate")
        w.geometry("680x480"); w.configure(bg=BG)
        lbl(w, "CA Public Certificate (PEM)", 12, True, fg=ADMIN_AC).pack(pady=8)
        t = scrolledtext.ScrolledText(w, font=("Consolas", 9), bg="#0d1117", fg=OK)
        t.pack(fill="both", expand=True, padx=16, pady=(4, 16))
        t.insert(tk.END, pem); t.configure(state="disabled")

    def _load_csv(self):
        try:
            members = voting_module.load_members_csv()
            active  = [m for m in members if m["status"] == "ACTIVE"]
            self._mem_lbl.config(text=f"Active Members: {len(active)} / {len(members)} total")
            self._emit(f"CSV loaded — {len(active)} ACTIVE of {len(members)} total.", "ok")
            self._emit("─" * 65)
            self._emit(f"{'Election ID':<20} {'Membership ID':<14} {'Student ID':<15} {'Username':<18} Status")
            self._emit("─" * 65)
            for m in members:
                # Show election_id directly from CSV
                vid = m.get("election_id", "")
                tag = "ok" if m["status"] == "ACTIVE" else "warn"
                self._emit(f"{vid:<20} {m['membership_id']:<14} "
                           f"{m['student_id']:<15} {m['username']:<18} {m['status']}", tag)
        except Exception as exc:
            safe_error("CSV Error", str(exc), parent=self)

    def _refresh_certs(self):
        for r in self._cert_tree.get_children(): self._cert_tree.delete(r)
        try:
            rows = db.get_all_issued_certificates_all()   # all elections
            for rec in rows:
                self._cert_tree.insert("", "end", values=(
                    rec["election_id"], rec["membership_id"],
                    rec["cert_serial"], str(rec["issued_at"])))
            if not rows:
                safe_info("Certificates", "No certificates issued yet.\nRegister voters first.", parent=self)
        except RuntimeError as exc:
            safe_error("Database Error", str(exc), parent=self)


# ══════════════════════════════════════════════════════════════════════
#  VOTER PORTAL
# ══════════════════════════════════════════════════════════════════════
class VoterPortal(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("CertVote — Voter Portal")
        self.geometry("1000x780"); self.minsize(860, 650)
        self.configure(bg=BG)
        apply_styles(self)
        self._build_header()
        self._build_tabs()
        self.after(800, self._db_check)

    def _build_header(self):
        bar = tk.Frame(self, bg=HDR, height=54)
        bar.pack(fill="x"); bar.pack_propagate(False)
        lbl(bar, "🗳  IT Club President Election 2026", 13, True, fg="white", bg=HDR
            ).pack(side="left", padx=20, pady=12)
        lbl(bar, "PKI-Secured  •  Anonymous  •  Verifiable",
            9, fg=SUB, bg=HDR).pack(side="right", padx=20)

    def _build_tabs(self):
        nb = ttk.Notebook(self); nb.pack(fill="both", expand=True)
        nb.add(self._register_tab(nb), text="   📝  Register   ")
        nb.add(self._vote_tab(nb),     text="   🗳  Vote   ")
        nb.add(self._tally_tab(nb),    text="   📊  Tally Board   ")

    # ── Register tab ────────────────────────────────────────────────
    def _register_tab(self, parent):
        f = ttk.Frame(parent, style="D.TFrame")

        lbl(f, "Voter Registration", 13, True, fg=ACCENT).pack(pady=(16, 2))
        lbl(f, "Generates your RSA-2048 key pair and issues a CA-signed X.509 voter certificate.",
            9, fg=SUB).pack(pady=(0, 6))

        # Info bar: how election ID is assigned
        ib = tk.Frame(f, bg=PANEL, bd=1, relief="groove")
        ib.pack(padx=40, pady=(0, 8), fill="x")
        lbl(ib, "ℹ️  Your Election ID is unique to you — it is auto-filled when you enter your Membership ID.",
            9, fg=GOLD, bg=PANEL).pack(anchor="w", padx=12, pady=6)

        form = tk.Frame(f, bg=PANEL, bd=1, relief="groove")
        form.pack(padx=40, pady=4, fill="x")

        self._rv = {}
        fields = [
            ("Membership ID",     "mid",   "",  False),
            ("Student ID",        "sid",   "",  False),
            ("Username",          "uname", "",  False),
            ("PIN (min 4 chars)", "pin",   "",  True ),
        ]
        for i, (label, key, default, secret) in enumerate(fields):
            lbl(form, f"{label}:", bold=True, bg=PANEL, fg=TEXT
                ).grid(row=i, column=0, padx=(20, 6), pady=8, sticky="e")
            v = tk.StringVar(value=default); self._rv[key] = v
            e = fentry(form, v, secret)
            e.grid(row=i, column=1, padx=(0, 20), pady=8, sticky="w")

        # Election ID — read-only, auto-filled
        lbl(form, "Election ID:", bold=True, bg=PANEL, fg=TEXT
            ).grid(row=len(fields), column=0, padx=(20, 6), pady=8, sticky="e")
        self._rv["eid"] = tk.StringVar(value="— enter Membership ID first —")
        eid_entry = fentry(form, self._rv["eid"], width=36)
        eid_entry.config(state="readonly", readonlybackground="#1a2535", fg=GOLD)
        eid_entry.grid(row=len(fields), column=1, padx=(0, 20), pady=8, sticky="w")

        # Bind membership ID → auto-compute election ID
        self._rv["mid"].trace_add("write", self._update_reg_eid)

        self._btn_reg = big_btn(form, "🔑  Register Voter", self._on_register)
        self._btn_reg.grid(row=len(fields)+1, column=0, columnspan=2, pady=14)

        self._reg_status  = lbl(f, "", 10, True); self._reg_status.pack(pady=2)
        self._reg_cert_lbl = lbl(f, "", 9, fg=OK);  self._reg_cert_lbl.pack(pady=2)

        lf = tk.LabelFrame(f, text="  Registration Log  ",
                           font=("Segoe UI", 9, "bold"), bg=BG, fg=ACCENT, bd=1, relief="groove")
        lf.pack(fill="both", expand=True, padx=40, pady=(4, 14))
        self._reg_log = mk_log(lf)
        self._reg_log.pack(fill="both", expand=True, padx=4, pady=4)
        return f

    def _update_reg_eid(self, *_):
        mid = self._rv["mid"].get().strip()
        if mid:
            eid = voter_election_id(mid)
        else:
            eid = "— enter Membership ID first —"
        self._rv["eid"].set(eid)

    # ── Vote tab ────────────────────────────────────────────────────
    def _vote_tab(self, parent):
        f = ttk.Frame(parent, style="D.TFrame")

        lbl(f, "Cast Your Vote", 13, True, fg=ACCENT).pack(pady=(16, 2))
        lbl(f, "Your ballot is signed with your RSA-2048 PRIVATE KEY and verified with your PUBLIC KEY.",
            9, fg=SUB).pack(pady=(0, 6))

        outer = tk.Frame(f, bg=BG); outer.pack(fill="both", expand=True, padx=20, pady=8)

        # Left panel — credentials + candidates
        left = tk.Frame(outer, bg=PANEL, bd=1, relief="groove")
        left.pack(side="left", fill="y", padx=(0, 12), ipadx=10, ipady=10)

        lbl(left, "Voter Credentials", 11, True, fg=ACCENT, bg=PANEL
            ).grid(row=0, column=0, columnspan=2, pady=(10, 6))

        self._vv = {}
        vote_fields = [
            ("Membership ID", "vmid", "", False),
            ("PIN",           "vpin", "", True ),
        ]
        for i, (label, key, default, secret) in enumerate(vote_fields):
            lbl(left, f"{label}:", bold=True, bg=PANEL, fg=TEXT
                ).grid(row=i+1, column=0, padx=(14, 4), pady=6, sticky="e")
            v = tk.StringVar(value=default); self._vv[key] = v
            fentry(left, v, secret, width=20).grid(row=i+1, column=1, padx=(0, 14), pady=6, sticky="w")

        # Election ID — read-only, auto-filled from membership ID
        lbl(left, "Election ID:", bold=True, bg=PANEL, fg=TEXT
            ).grid(row=3, column=0, padx=(14, 4), pady=6, sticky="e")
        self._vv["veid"] = tk.StringVar(value="")
        veid_e = fentry(left, self._vv["veid"], width=20)
        veid_e.config(state="readonly", readonlybackground="#1a2535", fg=GOLD)
        veid_e.grid(row=3, column=1, padx=(0, 14), pady=6, sticky="w")

        self._vv["vmid"].trace_add("write", self._update_vote_eid)

        lbl(left, "Select Candidate:", 10, True, fg=TEXT, bg=PANEL
            ).grid(row=4, column=0, columnspan=2, pady=(14, 4))

        self._cvar = tk.StringVar()
        self._radio_frame = tk.Frame(left, bg=PANEL)
        self._radio_frame.grid(row=5, column=0, columnspan=2, padx=14, pady=4)
        self._load_candidates()

        self._btn_vote = big_btn(left, "🗳  Cast Vote", self._on_vote, OK)
        self._btn_vote.grid(row=6, column=0, columnspan=2, pady=12)
        small_btn(left, "🔬  Tamper Test (Demo)", self._on_tamper, GOLD, "black"
                  ).grid(row=7, column=0, columnspan=2, pady=(0, 10))

        # Right panel — receipt + log
        right = tk.Frame(outer, bg=BG); right.pack(side="left", fill="both", expand=True)

        rf = tk.LabelFrame(right, text="  Your Vote Receipt  ",
                           font=("Segoe UI", 9, "bold"), bg=BG, fg=GOLD, bd=1, relief="groove")
        rf.pack(fill="x", pady=(0, 10))
        self._rcpt_lbl = lbl(rf, "No vote cast yet.", 9, fg=SUB)
        self._rcpt_lbl.pack(pady=4)
        self._rcpt_txt = tk.Text(rf, height=5, font=("Consolas", 9),
                                  bg="#0d1117", fg=GOLD, relief="flat", state="disabled", wrap="word")
        self._rcpt_txt.pack(fill="x", padx=6, pady=(0, 6))

        lf = tk.LabelFrame(right, text="  Vote Log  ",
                           font=("Segoe UI", 9, "bold"), bg=BG, fg=ACCENT, bd=1, relief="groove")
        lf.pack(fill="both", expand=True)
        self._vote_log = mk_log(lf); self._vote_log.pack(fill="both", expand=True, padx=4, pady=4)
        return f

    def _update_vote_eid(self, *_):
        mid = self._vv["vmid"].get().strip()
        self._vv["veid"].set(voter_election_id(mid) if mid else "")

    # ── Tally tab ────────────────────────────────────────────────────
    def _tally_tab(self, parent):
        f = ttk.Frame(parent, style="D.TFrame")

        lbl(f, "Public Tally Board", 13, True, fg=ACCENT).pack(pady=(16, 2))
        lbl(f, "Anonymous vote totals only — voter identity is never stored or shown here.",
            9, fg=SUB).pack()
        lbl(f, f"Election: {ELECTION_ID}", 10, True, fg=GOLD).pack()
        small_btn(f, "🔄  Refresh Tally", self._refresh_tally, ACCENT, "white").pack(pady=8)

        tf = tk.LabelFrame(f, text="  Vote Totals  ",
                           font=("Segoe UI", 9, "bold"), bg=BG, fg=ACCENT, bd=1, relief="groove")
        tf.pack(fill="x", padx=30, pady=(0, 8))
        self._tt = ttk.Treeview(tf, columns=("c","v"), show="headings", height=4, style="D.Treeview")
        self._tt.heading("c", text="Candidate Name")
        self._tt.heading("v", text="Total Votes")
        self._tt.column("c", width=380, anchor="w")
        self._tt.column("v", width=130, anchor="center")
        self._tt.pack(fill="both", expand=True, padx=4, pady=4)

        rf = tk.LabelFrame(f, text="  Receipt Hashes (Vote Inclusion Proofs)  ",
                           font=("Segoe UI", 9, "bold"), bg=BG, fg=GOLD, bd=1, relief="groove")
        rf.pack(fill="both", expand=True, padx=30, pady=(0, 4))
        self._rt = ttk.Treeview(rf, columns=("h","t"), show="headings", height=6, style="D.Treeview")
        self._rt.heading("h", text="Receipt Hash (SHA-256)")
        self._rt.heading("t", text="Recorded At")
        self._rt.column("h", width=565, anchor="w")
        self._rt.column("t", width=175, anchor="center")
        sb = ttk.Scrollbar(rf, orient="vertical", command=self._rt.yview)
        self._rt.configure(yscrollcommand=sb.set)
        self._rt.pack(side="left", fill="both", expand=True, padx=(4,0), pady=4)
        sb.pack(side="right", fill="y", pady=4)

        vf = tk.LabelFrame(f, text="  Verify Your Vote Was Counted  ",
                           font=("Segoe UI", 9, "bold"), bg=BG, fg=SUB, bd=1, relief="groove")
        vf.pack(fill="x", padx=30, pady=(4, 14))
        vrow = tk.Frame(vf, bg=BG); vrow.pack(padx=10, pady=8, fill="x")
        lbl(vrow, "Paste your receipt hash:", bg=BG).pack(side="left")
        self._vhash = tk.StringVar()
        tk.Entry(vrow, textvariable=self._vhash, font=("Consolas", 9),
                 bg="#151922", fg=GOLD, insertbackground=TEXT,
                 relief="flat", bd=4, width=62
                 ).pack(side="left", padx=8)
        small_btn(vrow, "Verify", self._verify_receipt, ACCENT, "white").pack(side="left")
        self._vlbl = lbl(vf, "", 10, True); self._vlbl.pack(pady=(0, 6))

        # Deferred load — window must be fully built first
        self.after(600, self._refresh_tally)
        return f

    # ── Voter helpers ────────────────────────────────────────────────
    def _emit_reg(self, msg, tag="info"):
        self.after(0, lambda: log_append(self._reg_log, msg, tag))

    def _emit_vote(self, msg, tag="info"):
        self.after(0, lambda: log_append(self._vote_log, msg, tag))

    def _db_check(self):
        if not db.test_connection():
            safe_warn("Database Not Connected",
                "Cannot connect to MySQL.\n\n"
                "Steps to fix:\n"
                "1. Open XAMPP → click Start next to MySQL\n"
                "2. Open config.json → set correct password\n"
                "3. Run sql/schema.sql to create tables\n"
                "4. Restart this application",
                parent=self)

    def _load_candidates(self):
        try:
            names = voting_module.get_candidate_names()
        except Exception:
            names = ["Abhisek Sharma", "Kalpana Joshi", "Mandeep Dhungana"]
        if names: self._cvar.set(names[0])
        for w in self._radio_frame.winfo_children(): w.destroy()
        for name in names:
            tk.Radiobutton(self._radio_frame, text=name,
                variable=self._cvar, value=name,
                font=("Segoe UI", 11), bg=PANEL, fg=TEXT,
                selectcolor=ACCENT, activebackground=PANEL,
                activeforeground=TEXT, cursor="hand2"
            ).pack(anchor="w", pady=2)

    # ── Registration ─────────────────────────────────────────────────
    def _on_register(self):
        mid   = self._rv["mid"].get().strip()
        sid   = self._rv["sid"].get().strip()
        uname = self._rv["uname"].get().strip()
        pin   = self._rv["pin"].get().strip()
        eid   = self._rv["eid"].get().strip()

        if not all([mid, sid, uname, pin]):
            safe_warn("Input Error", "All fields are required.", parent=self); return
        if len(pin) < 4:
            safe_warn("PIN Error", "PIN must be at least 4 characters.", parent=self); return
        if eid.startswith("—"):
            safe_warn("Election ID", "Election ID could not be computed. Check Membership ID.", parent=self); return

        self._btn_reg.config(state="disabled")
        log_clear(self._reg_log)
        self._reg_cert_lbl.config(text="")
        self._reg_status.config(text="Registering...", fg=GOLD)

        def run():
            try:
                self._emit_reg("=" * 52, "head")
                self._emit_reg("VOTER REGISTRATION WORKFLOW", "head")
                self._emit_reg("=" * 52, "head")
                self._emit_reg(f"Election ID   : {eid}", "info")
                self._emit_reg(f"Membership ID : {mid}", "info")
                self._emit_reg("Step 1: Verifying CSV eligibility...")
                self._emit_reg("Step 2: Generating RSA-2048 key pair...")
                self._emit_reg("        PUBLIC KEY  → embedded in X.509 certificate (signed by CA)", "ok")
                self._emit_reg("        PRIVATE KEY → encrypted with your PIN (AES-256-CBC)", "warn")
                self._emit_reg("Step 3: CA signing your certificate...")

                result = voting_module.register_voter(
                    election_id=eid, membership_id=mid,
                    student_id=sid, username=uname, pin=pin,
                    log_fn=self._emit_reg)

                if result["success"]:
                    self.after(0, lambda: self._reg_status.config(
                        text="✅  Registration successful!", fg=OK))
                    ct = (f"Certificate Serial : {result['cert_serial']}\n"
                          f"Election ID        : {eid}\n"
                          f"Stored at          : {result['voter_dir']}")
                    self.after(0, lambda: self._reg_cert_lbl.config(text=ct))
                    self._emit_reg("─" * 52)
                    self._emit_reg(f"Certificate issued for Election ID: {eid}", "ok")
                    self._emit_reg("PRIVATE KEY → stored encrypted, unlocked only by your PIN", "warn")
                    self.after(0, lambda: safe_info("Registration Successful",
                        f"Registered!\n\nElection ID:\n{eid}\n\n"
                        f"Certificate Serial:\n{result['cert_serial']}\n\n"
                        "Remember your PIN — it cannot be recovered.", parent=self))
                else:
                    msg = result["message"]
                    self.after(0, lambda: self._reg_status.config(text=f"❌  {msg}", fg=ERR))
                    self._emit_reg(f"FAILED: {msg}", "err")
                    self.after(0, lambda: safe_error("Registration Failed", msg, parent=self))

            except Exception as exc:
                self._emit_reg(f"UNEXPECTED ERROR: {exc}", "err")
                self._emit_reg(traceback.format_exc(), "err")
                self.after(0, lambda: self._reg_status.config(text="❌  Error", fg=ERR))
                self.after(0, lambda: safe_error("Error", str(exc), parent=self))
            finally:
                self.after(0, lambda: self._btn_reg.config(state="normal"))

        threading.Thread(target=run, daemon=True).start()

    # ── Voting ───────────────────────────────────────────────────────
    def _on_vote(self):
        mid    = self._vv["vmid"].get().strip()
        pin    = self._vv["vpin"].get().strip()
        eid    = self._vv["veid"].get().strip()
        choice = self._cvar.get()

        if not all([mid, pin, choice]):
            safe_warn("Input Error", "All fields are required.", parent=self); return
        if not eid:
            safe_warn("Election ID", "Enter your Membership ID first.", parent=self); return

        self._btn_vote.config(state="disabled")
        log_clear(self._vote_log)

        def run():
            try:
                self._emit_vote("=" * 52, "head")
                self._emit_vote("VOTE CASTING — KEY USAGE", "head")
                self._emit_vote("=" * 52, "head")
                self._emit_vote(f"Election ID   : {eid}", "info")
                self._emit_vote(f"Membership ID : {mid}", "info")
                self._emit_vote("Step 1: Loading encrypted PRIVATE KEY from AppData...", "warn")
                self._emit_vote("Step 2: Decrypting PRIVATE KEY using your PIN...", "warn")
                self._emit_vote("Step 3: Verifying certificate (CA PUBLIC KEY binding)...", "ok")
                self._emit_vote("Step 4: Signing vote with PRIVATE KEY (RSA-PSS + SHA-256)...", "warn")
                self._emit_vote("Step 5: Verifying signature with PUBLIC KEY...", "ok")
                self._emit_vote("Step 6: Double-vote check (anonymous SHA-256 tag)...")
                self._emit_vote("Step 7: Recording anonymous vote...")

                result = voting_module.cast_vote(
                    election_id=eid, membership_id=mid,
                    pin=pin, choice=choice, log_fn=self._emit_vote)

                if result["success"]:
                    rh, vh, nc = result["receipt_hash"], result["vote_hash"], result["nonce"]
                    self._emit_vote("─" * 52, "ok")
                    self._emit_vote(f"Vote for '{choice}' recorded anonymously.", "ok")
                    self._emit_vote("PRIVATE KEY signed the vote payload (RSA-PSS)", "warn")
                    self._emit_vote("PUBLIC KEY verified the signature", "ok")
                    self.after(0, lambda: self._show_receipt(rh, vh, nc, choice))
                    self.after(0, lambda: safe_info("Vote Cast Successfully",
                        f"Your vote for '{choice}' has been recorded!\n\n"
                        f"Receipt Hash:\n{rh}\n\n"
                        "Save this hash — use it on the Tally Board to verify.", parent=self))
                else:
                    msg = result["message"]
                    self._emit_vote(f"FAILED: {msg}", "err")
                    self.after(0, lambda: safe_error("Vote Failed", msg, parent=self))

            except Exception as exc:
                self._emit_vote(f"UNEXPECTED ERROR: {exc}", "err")
                self._emit_vote(traceback.format_exc(), "err")
                self.after(0, lambda: safe_error("Error", str(exc), parent=self))
            finally:
                self.after(0, lambda: self._btn_vote.config(state="normal"))

        threading.Thread(target=run, daemon=True).start()

    def _show_receipt(self, rh, vh, nonce, choice):
        self._rcpt_txt.configure(state="normal")
        self._rcpt_txt.delete("1.0", tk.END)
        self._rcpt_txt.insert(tk.END,
            f"Candidate   : {choice}\n"
            f"Vote Hash   : {vh}\n"
            f"Receipt Hash: {rh}\n"
            f"Nonce       : {nonce}\n\n"
            "Paste Receipt Hash on Tally Board to verify your vote was counted.")
        self._rcpt_txt.configure(state="disabled")
        self._rcpt_lbl.config(text="✅  Vote recorded! Your receipt:", fg=OK)

    def _on_tamper(self):
        mid    = self._vv["vmid"].get().strip()
        pin    = self._vv["vpin"].get().strip()
        eid    = self._vv["veid"].get().strip()
        choice = self._cvar.get()
        if not all([mid, pin, eid]):
            safe_warn("Input", "Fill Membership ID and PIN first.", parent=self); return
        log_clear(self._vote_log)
        def run():
            try:
                self._emit_vote("=" * 52, "warn")
                self._emit_vote("TAMPER TEST — Security Demonstration", "warn")
                self._emit_vote("=" * 52, "warn")
                r = voting_module.tamper_test(election_id=eid, membership_id=mid,
                    pin=pin, choice=choice, log_fn=lambda m: self._emit_vote(m, "warn"))
                if r.get("success"):
                    ov = "PASS ✅" if r["original_sig_valid"] else "FAIL ❌"
                    tv = "FAIL ❌ (Expected)" if not r["tampered_sig_valid"] else "PASS ✅"
                    self._emit_vote(f"Original  '{r['original_choice']}' → Signature: {ov}", "ok")
                    self._emit_vote(f"Tampered  '{r['tampered_choice']}' → Signature: {tv}", "err")
                    if not r["tampered_sig_valid"]:
                        self._emit_vote("RESULT: MITM attack PREVENTED by digital signature ✅", "ok")
                else:
                    self._emit_vote(f"Error: {r.get('message')}", "err")
            except Exception as exc:
                self._emit_vote(f"Error: {exc}", "err")
        threading.Thread(target=run, daemon=True).start()

    # ── Tally ─────────────────────────────────────────────────────────
    def _refresh_tally(self):
        for r in self._tt.get_children(): self._tt.delete(r)
        for r in self._rt.get_children(): self._rt.delete(r)
        try:
            for row in db.get_vote_tally_all():
                self._tt.insert("", "end", values=(row["choice"], row["total_votes"]))
            for row in db.get_receipt_hashes_all():
                self._rt.insert("", "end", values=(row["receipt_hash"], str(row["created_at"])))
        except RuntimeError as exc:
            safe_error("Database Error", str(exc), parent=self)

    def _verify_receipt(self):
        h = self._vhash.get().strip()
        if not h:
            safe_warn("Input", "Paste a receipt hash to verify.", parent=self); return
        try:
            found = db.verify_receipt_exists_any(h)
            if found:
                self._vlbl.config(text="✅  Receipt FOUND — your vote is counted.", fg=OK)
            else:
                self._vlbl.config(text="❌  Receipt NOT FOUND — hash does not match any vote.", fg=ERR)
        except RuntimeError as exc:
            safe_error("Database Error", str(exc), parent=self)


# ══════════════════════════════════════════════════════════════════════
#  ADMIN LOGIN DIALOG
# ══════════════════════════════════════════════════════════════════════
class AdminLoginDialog(tk.Toplevel):
    def __init__(self, master, on_success):
        super().__init__(master)
        self.title("CertVote — Admin Login")
        self.geometry("380x230"); self.resizable(False, False)
        self.configure(bg=BG); self.grab_set()
        self._on_success = on_success
        self._build()

    def _build(self):
        bar = tk.Frame(self, bg=ADMIN_HDR, height=52)
        bar.pack(fill="x"); bar.pack_propagate(False)
        lbl(bar, "🔐  Admin Portal Login", 13, True, fg="white", bg=ADMIN_HDR
            ).pack(pady=12)

        lbl(self, "Enter Admin Password:", 10, True).pack(pady=(18, 4))
        self._pwd = tk.StringVar()
        pe = fentry(self, self._pwd, secret=True, width=28)
        pe.pack(pady=4); pe.bind("<Return>", lambda e: self._check()); pe.focus_set()

        self._err = lbl(self, "", 9, fg=ERR); self._err.pack()

        bf = tk.Frame(self, bg=BG); bf.pack(pady=10)
        big_btn(bf, "Login",  self._check,    ADMIN_AC).grid(row=0, column=0, padx=8)
        small_btn(bf,"Cancel", self.destroy          ).grid(row=0, column=1, padx=8)

    def _check(self):
        if self._pwd.get() == ADMIN_PASSWORD:
            self.destroy(); self._on_success()
        else:
            self._err.config(text="❌  Incorrect password. Try again.")
            self._pwd.set("")


# ══════════════════════════════════════════════════════════════════════
#  ENTRY SCREEN
# ══════════════════════════════════════════════════════════════════════
class EntryScreen(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CertVote — Welcome")
        self.geometry("540x400"); self.resizable(False, False)
        self.configure(bg=BG)
        self._build()

    def _build(self):
        bar = tk.Frame(self, bg=HDR, height=72)
        bar.pack(fill="x"); bar.pack_propagate(False)
        lbl(bar, "🏆  CertVote", 22, True, fg="white", bg=HDR).pack(pady=(10,2))
        lbl(bar, "PKI-Powered Electronic Voting System", 10, fg=SUB, bg=HDR).pack()

        lbl(self, "Select your role to continue:", 12, fg=TEXT).pack(pady=(28, 6))
        lbl(self, f"Election: {ELECTION_ID}", 10, fg=GOLD).pack(pady=(0, 20))

        bf = tk.Frame(self, bg=BG); bf.pack()

        af = tk.Frame(bf, bg=BG); af.grid(row=0, column=0, padx=24)
        tk.Button(af, text="🔐  ADMIN PORTAL",
            command=self._open_admin,
            font=("Segoe UI",13,"bold"), bg=ADMIN_AC, fg="white",
            relief="flat", padx=24, pady=16, cursor="hand2", width=16).pack()
        lbl(af, "CA setup &\ncertificate management", 8, fg=SUB).pack(pady=4)
        lbl(af, "Password required", 8, fg=GOLD).pack()

        vf = tk.Frame(bf, bg=BG); vf.grid(row=0, column=1, padx=24)
        tk.Button(vf, text="🗳  VOTER PORTAL",
            command=self._open_voter,
            font=("Segoe UI",13,"bold"), bg=ACCENT, fg="white",
            relief="flat", padx=24, pady=16, cursor="hand2", width=16).pack()
        lbl(vf, "Register, vote &\nview results", 8, fg=SUB).pack(pady=4)
        lbl(vf, "Open to all members", 8, fg=OK).pack()

        lbl(self, "Both portals can be open simultaneously for demonstration.",
            8, fg=SUB).pack(pady=20)

    def _open_admin(self):
        AdminLoginDialog(self, lambda: AdminPortal(self))

    def _open_voter(self):
        VoterPortal(self)


if __name__ == "__main__":
    EntryScreen().mainloop()
