"""
login.py  ──  Entry point for the RogueAP Detection System.
Run this file. It shows the login screen; on success it launches dashboard_gui.py.
"""

import customtkinter as ctk
from tkinter import messagebox
import psycopg2
import hashlib
import os
import sys
import subprocess
import threading
from datetime import datetime, timedelta

# ── appearance ────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── palette ───────────────────────────────────────────────────────────────────
BG       = "#0d1117"
BG_CARD  = "#161b22"
BG_INPUT = "#21262d"
BORDER   = "#30363d"
TEXT     = "#e6edf3"
TEXT_SEC = "#8b949e"
RED      = "#da3633"
GREEN    = "#3fb950"
BLUE     = "#58a6ff"
ORANGE   = "#e3b341"

MAX_ATTEMPTS  = 5
LOCKOUT_MINS  = 15

# ── database ──────────────────────────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(
        host     = os.environ.get("DB_HOST",     "localhost"),
        database = os.environ.get("DB_NAME",     "RogueAPDetection"),
        user     = os.environ.get("DB_USER",     "postgres"),
        password = os.environ.get("DB_PASSWORD", "admin123"),
    )

try:
    _conn   = get_conn()
    _conn.autocommit = True
    _cur    = _conn.cursor()
    DB_OK   = True
except Exception as e:
    DB_OK   = False
    _conn   = None
    _cur    = None
    print(f"DB: {e}")

def db(sql, params=()):
    if not _cur:
        return None
    try:
        _cur.execute(sql, params)
        try:    return _cur.fetchall()
        except: return []
    except Exception as e:
        print(f"DB error: {e}")
        return None

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def ensure_admin_table():
    db("""
        CREATE TABLE IF NOT EXISTS admin_users (
            user_id         SERIAL PRIMARY KEY,
            username        VARCHAR(50)  UNIQUE NOT NULL,
            password_hash   VARCHAR(256) NOT NULL,
            full_name       VARCHAR(100) DEFAULT 'Administrator',
            role            VARCHAR(20)  DEFAULT 'admin',
            is_active       BOOLEAN      DEFAULT TRUE,
            failed_attempts INT          DEFAULT 0,
            locked_until    TIMESTAMP    DEFAULT NULL,
            last_login      TIMESTAMP    DEFAULT NULL,
            created_at      TIMESTAMP    DEFAULT NOW()
        )
    """)
    rows = db("SELECT COUNT(*) FROM admin_users") or [[0]]
    if rows[0][0] == 0:
        db("INSERT INTO admin_users (username,password_hash,full_name,role) VALUES (%s,%s,%s,%s)",
           ("admin", hash_pw("Admin@1234"), "System Administrator", "superadmin"))
        print("Default admin created  →  username: admin   password: Admin@1234")

def validate(username, password):
    rows = db("""
        SELECT user_id,username,password_hash,full_name,role,
               is_active,failed_attempts,locked_until
        FROM admin_users WHERE username=%s
    """, (username,))
    if not rows:
        return False, "Invalid username or password.", None

    uid, uname, pw_hash, full_name, role, active, attempts, locked_until = rows[0]

    if not active:
        return False, "This account has been disabled.\nContact your system administrator.", None

    if locked_until and datetime.now() < locked_until:
        mins = int((locked_until - datetime.now()).total_seconds() / 60) + 1
        return False, f"Account locked. Try again in {mins} minute(s).", None

    if pw_hash != hash_pw(password):
        new_att = attempts + 1
        if new_att >= MAX_ATTEMPTS:
            lock = datetime.now() + timedelta(minutes=LOCKOUT_MINS)
            db("UPDATE admin_users SET failed_attempts=%s,locked_until=%s WHERE user_id=%s",
               (new_att, lock, uid))
            return False, f"Too many failed attempts.\nAccount locked for {LOCKOUT_MINS} minutes.", None
        db("UPDATE admin_users SET failed_attempts=%s WHERE user_id=%s", (new_att, uid))
        left = MAX_ATTEMPTS - new_att
        return False, f"Invalid username or password.\n{left} attempt(s) remaining before lockout.", None

    db("UPDATE admin_users SET failed_attempts=0,locked_until=NULL,last_login=NOW() WHERE user_id=%s", (uid,))
    return True, "Login successful.", {"user_id": uid, "username": uname,
                                       "full_name": full_name, "role": role}

# ── window ─────────────
app = ctk.CTk()
app.title("RogueAP Detection System — Admin Login")
app.geometry("460x640")
app.configure(fg_color=BG)
app.resizable(False, False)
app.update_idletasks()
sw, sh = app.winfo_screenwidth(), app.winfo_screenheight()
app.geometry(f"460x640+{(sw-460)//2}+{(sh-640)//2}")

# ── logo ──────────────────────────────────────────────────────────────────────
logo_f = ctk.CTkFrame(app, fg_color="transparent")
logo_f.pack(pady=(44, 0))
ctk.CTkLabel(logo_f, text="📡", font=("Arial", 54)).pack()
ctk.CTkLabel(logo_f, text="RogueAP Detection System",
             font=("Inter", 20, "bold"), text_color=TEXT).pack(pady=(8, 2))
ctk.CTkLabel(logo_f, text="Administrator Login",
             font=("Inter", 13), text_color=TEXT_SEC).pack()

# ── card ──────────────────────────────────────────────────────────────────────
card = ctk.CTkFrame(app, fg_color=BG_CARD, corner_radius=12,
                    border_width=1, border_color=BORDER)
card.pack(fill="x", padx=36, pady=28)
inner = ctk.CTkFrame(card, fg_color="transparent")
inner.pack(fill="x", padx=26, pady=26)

# banners
err_frame = ctk.CTkFrame(inner, fg_color="#2d1b1b", corner_radius=6,
                          border_width=1, border_color=RED)
err_lbl = ctk.CTkLabel(err_frame, text="", font=("Inter", 11),
                        text_color=RED, wraplength=340, justify="left")
err_lbl.pack(padx=12, pady=8)

ok_frame = ctk.CTkFrame(inner, fg_color="#0d2818", corner_radius=6,
                         border_width=1, border_color=GREEN)
ok_lbl = ctk.CTkLabel(ok_frame, text="", font=("Inter", 11),
                       text_color=GREEN, wraplength=340, justify="left")
ok_lbl.pack(padx=12, pady=8)

def show_err(msg):
    ok_frame.pack_forget()
    err_lbl.configure(text=f"⚠  {msg}")
    err_frame.pack(fill="x", pady=(0, 12))

def show_ok(msg):
    err_frame.pack_forget()
    ok_lbl.configure(text=f"✓  {msg}")
    ok_frame.pack(fill="x", pady=(0, 12))

def hide_banners():
    err_frame.pack_forget()
    ok_frame.pack_forget()

# username
ctk.CTkLabel(inner, text="Username", font=("Inter", 12),
             text_color=TEXT_SEC, anchor="w").pack(fill="x", pady=(0, 4))
user_entry = ctk.CTkEntry(inner, placeholder_text="Enter your username",
                           font=("Inter", 13), height=42, fg_color=BG_INPUT,
                           border_color=BORDER, text_color=TEXT, corner_radius=6)
user_entry.pack(fill="x", pady=(0, 14))

# password
ctk.CTkLabel(inner, text="Password", font=("Inter", 12),
             text_color=TEXT_SEC, anchor="w").pack(fill="x", pady=(0, 4))
pw_row = ctk.CTkFrame(inner, fg_color="transparent")
pw_row.pack(fill="x", pady=(0, 6))
pw_entry = ctk.CTkEntry(pw_row, placeholder_text="Enter your password",
                         font=("Inter", 13), height=42, fg_color=BG_INPUT,
                         border_color=BORDER, text_color=TEXT,
                         corner_radius=6, show="●")
pw_entry.pack(side="left", fill="x", expand=True)

show_var = ctk.BooleanVar(value=False)
def toggle_pw():
    pw_entry.configure(show="" if show_var.get() else "●")

eye = ctk.CTkButton(pw_row, text="👁", width=42, height=42,
                     fg_color=BG_INPUT, hover_color="#2d333b",
                     border_width=1, border_color=BORDER,
                     text_color=TEXT_SEC, corner_radius=6,
                     command=lambda: [show_var.set(not show_var.get()), toggle_pw()])
eye.pack(side="left", padx=(6, 0))

# remember
rem_var = ctk.BooleanVar(value=False)
ctk.CTkCheckBox(inner, text="Keep me signed in for this session",
                variable=rem_var, font=("Inter", 11), text_color=TEXT_SEC,
                checkbox_height=18, checkbox_width=18).pack(anchor="w", pady=(6, 18))

# login button
def do_login():
    username = user_entry.get().strip()
    password = pw_entry.get()
    hide_banners()

    if not username:
        show_err("Please enter your username.")
        user_entry.focus(); return
    if not password:
        show_err("Please enter your password.")
        pw_entry.focus(); return

    login_btn.configure(state="disabled", text="Verifying...")

    def _check():
        success, message, user = validate(username, password)
        app.after(0, lambda: _result(success, message, user))

    def _result(success, message, user):
        login_btn.configure(state="normal", text="  Login  →")
        if success:
            show_ok(f"Welcome, {user['full_name']}! Opening dashboard...")
            app.after(900, lambda: launch(user))
        else:
            show_err(message)
            pw_entry.delete(0, "end")
            pw_entry.focus()

    threading.Thread(target=_check, daemon=True).start()

login_btn = ctk.CTkButton(inner, text="  Login  →",
                            font=("Inter", 14, "bold"),
                            fg_color=BLUE, hover_color="#3b82f6",
                            height=44, corner_radius=6, command=do_login)
login_btn.pack(fill="x")

# key bindings
app.bind("<Return>", lambda e: do_login())
user_entry.bind("<Return>", lambda e: pw_entry.focus())
pw_entry.bind("<Return>", lambda e: do_login())

# ── footer ────────────────────────────────────────────────────────────────────
ft = ctk.CTkFrame(app, fg_color="transparent")
ft.pack(fill="x", padx=36, pady=(0, 20))
ctk.CTkLabel(ft, text="Default: username = admin   password = Admin@1234",
             font=("Inter", 9), text_color=TEXT_SEC).pack()
ctk.CTkLabel(ft, text="Change your password after first login via Admin menu.",
             font=("Inter", 9), text_color=TEXT_SEC).pack()
db_txt  = "● Database connected" if DB_OK else "● Database offline — cannot login"
db_col  = GREEN if DB_OK else RED
ctk.CTkLabel(ft, text=db_txt, font=("Inter", 9), text_color=db_col).pack(pady=(8, 0))

# ── launch dashboard ──────────────────────────────────────────────────────────
def launch(user):
    os.environ["LOGGED_IN_USER"]     = user["username"]
    os.environ["LOGGED_IN_FULLNAME"] = user["full_name"]
    os.environ["LOGGED_IN_ROLE"]     = user["role"]
    app.withdraw()
    # Run dashboard in same process so env vars are inherited
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dashboard_gui",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_gui.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except SystemExit:
        pass
    finally:
        try: app.destroy()
        except: pass

#  boot
if DB_OK:
    ensure_admin_table()
else:
    show_err("Cannot reach database.\nCheck that PostgreSQL is running.")

if not DB_OK:
    login_btn.configure(state="disabled")

user_entry.focus()
app.mainloop()
