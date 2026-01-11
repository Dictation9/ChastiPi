import base64
import os
import sys
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import messagebox, simpledialog
import threading
import urllib.request
import json
import webbrowser

from audit_log import append_audit_event

from config_store import APP_DIR, DATA_FILE, load_config, save_config
from crypto_box import (
    derive_key, hash_pin,
    encrypt_data, decrypt_data,
    CryptoInvalidToken
)
from time_lock import parse_lock_until, format_remaining, validate_system_time, add_months

APP_NAME = "Chasti-Lockbox"
VERSION = "1.1.1"

GITHUB_OWNER = "Dictation9"
GITHUB_REPO = "Chasti-Lockbox"


def resource_path(rel_path: str) -> str:
    """
    Returns an absolute path to a resource file, working both:
    - when running from source, and
    - when packaged with PyInstaller (sys._MEIPASS)
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, rel_path)  # type: ignore[attr-defined]
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), rel_path)


class LockboxApp:
    def audit(self, event_type: str, **details):
        # Best-effort; never blocks UI
        append_audit_event(APP_DIR, event_type, details)

    def __init__(self, root: tk.Tk):
        self.root = root

        # Set window icon (top-left). Requires icon.ico included in build.
        try:
            self.root.iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass

        self.root.title(APP_NAME)
        self.root.geometry("700x420")

        self.cfg = load_config()
        self.salt = base64.b64decode(self.cfg["salt"])

        self.key = None
        self.data = {"items": []}

        self.is_time_locked = False
        self.override_session_active = False
        self.override_keep_lock = False

        self.countdown_label = None
        self.latest_release_url = None
        self.update_status_label = None
        self.open_updates_btn = None

        self.audit("app_started", version=VERSION)
        self.frame_login()

    # ---------------- Update checker ----------------

    def _version_tuple(self, v: str):
        v = (v or "").strip().lstrip("v").split("+")[0]
        parts = v.split(".")
        out = []
        for p in parts:
            try:
                out.append(int(p))
            except ValueError:
                out.append(0)
        while len(out) < 3:
            out.append(0)
        return tuple(out[:3])

    def fetch_latest_release(self):
        url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"{APP_NAME}/{VERSION}"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            tag = data.get("tag_name")
            html_url = data.get("html_url") or f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases"
            return tag, html_url
        except Exception:
            return None, None

    def start_update_check(self):
        if not self.update_status_label:
            return

        self.update_status_label.config(text="Checking for updates…", fg="gray")
        self.latest_release_url = None

        def worker():
            tag, url = self.fetch_latest_release()
            if not tag:
                self.root.after(0, lambda: self.update_status_label.config(
                    text="Update check failed (offline?)",
                    fg="gray"
                ))
                if self.open_updates_btn:
                    self.root.after(0, lambda: self.open_updates_btn.config(state="normal"))
                return

            current = self._version_tuple(VERSION)
            latest = self._version_tuple(tag)

            def apply():
                self.latest_release_url = url
                if latest > current:
                    self.update_status_label.config(
                        text=f"Update available: {tag} (you have v{VERSION})",
                        fg="orange"
                    )
                    if self.open_updates_btn:
                        self.open_updates_btn.config(state="normal")
                else:
                    self.update_status_label.config(
                        text=f"Up to date (v{VERSION})",
                        fg="green"
                    )
                    if self.open_updates_btn:
                        self.open_updates_btn.config(state="disabled")

            self.root.after(0, apply)

        threading.Thread(target=worker, daemon=True).start()

    def open_updates_page(self):
        url = self.latest_release_url or f"https://github.com/Dictation9/Chasti-Lockbox/releases"
        webbrowser.open(url)

    # ---------------- Audit log viewer ----------------

    def open_audit_log(self):
        path = os.path.join(APP_DIR, "audit.log.jsonl")
        if not os.path.exists(path):
            messagebox.showinfo("Audit Log", "No audit log file yet.")
            return
        try:
            os.startfile(path)  # Windows
        except Exception:
            messagebox.showerror("Audit Log", f"Could not open:\n{path}")

    # ---------------- Login Screen ----------------

    def frame_login(self):
        for w in self.root.winfo_children():
            w.destroy()

        frm = tk.Frame(self.root, padx=20, pady=20)
        frm.pack(fill="both", expand=True)

        tk.Label(frm, text=APP_NAME, font=("Segoe UI", 18, "bold")).pack(pady=(0, 10))

        self.countdown_label = tk.Label(frm, font=("Segoe UI", 11, "bold"))
        self.countdown_label.pack(anchor="w", pady=(0, 8))

        if self.cfg["pin_hash"] is None:
            tk.Label(frm, text="First run: set a PIN").pack(anchor="w")
        else:
            tk.Label(frm, text="Enter your PIN").pack(anchor="w")

        self.pin_entry = tk.Entry(frm, show="•", font=("Segoe UI", 12))
        self.pin_entry.pack(fill="x", pady=8)
        self.pin_entry.focus()

        btn_row = tk.Frame(frm)
        btn_row.pack(pady=8, fill="x")

        tk.Button(btn_row, text="Unlock", command=self.unlock).pack(
            side="left", expand=True, fill="x", padx=(0, 6)
        )
        tk.Button(btn_row, text="Override Unlock", command=self.override_unlock).pack(
            side="left", expand=True, fill="x"
        )

        # --- Update check UI ---
        update_row = tk.Frame(frm)
        update_row.pack(fill="x", pady=(8, 0))

        self.update_status_label = tk.Label(update_row, text=f"{APP_NAME} v{VERSION}", fg="gray")
        self.update_status_label.pack(side="left")

        btns = tk.Frame(update_row)
        btns.pack(side="right")

        tk.Button(btns, text="Check Updates", command=self.start_update_check).pack(side="left", padx=(0, 6))
        self.open_updates_btn = tk.Button(btns, text="Open Releases", command=self.open_updates_page, state="disabled")
        self.open_updates_btn.pack(side="left")

        # Data location
        tk.Label(frm, text=f"Data folder: {APP_DIR}", fg="gray").pack(side="bottom", anchor="w")

        self.update_time_lock_countdown()
        self.start_update_check()

    def update_time_lock_countdown(self):
        lock_until_dt = parse_lock_until(self.cfg.get("lock_until"))
        now = datetime.now()

        if lock_until_dt and now < lock_until_dt:
            self.is_time_locked = True
            remaining = lock_until_dt - now
            self.countdown_label.config(
                text=f"⏳ Time-locked for: {format_remaining(remaining)}",
                fg="red"
            )
        else:
            self.is_time_locked = False
            self.countdown_label.config(text="✅ Not time-locked", fg="green")

        self.root.after(1000, self.update_time_lock_countdown)

    # ---------------- Data I/O ----------------

    def load_data(self):
        if not os.path.exists(DATA_FILE):
            self.data = {"items": []}
            return

        with open(DATA_FILE, "rb") as f:
            blob = f.read()

        try:
            self.data = decrypt_data(self.key, blob)
            if "items" not in self.data:
                self.data = {"items": []}
        except CryptoInvalidToken:
            messagebox.showerror("Decrypt error", "Could not decrypt data. Wrong PIN or corrupted file.")
            self.data = {"items": []}
            self.audit("decrypt_failed")

    def save_data(self):
        blob = encrypt_data(self.key, self.data)
        with open(DATA_FILE, "wb") as f:
            f.write(blob)

    # ---------------- Unlock Logic ----------------

    def unlock(self):
        if not validate_system_time(self.cfg):
            self.audit("clock_tamper_detected")
            messagebox.showerror(
                "Clock Tampering Detected",
                "System time appears to have been set backwards.\n\n"
                "Time-lock duration has been preserved.\n"
                "Fix the clock to continue."
            )
            return

        pin = self.pin_entry.get().strip()
        if len(pin) < 4:
            messagebox.showerror("PIN too short", "Use at least 4 digits/characters.")
            self.audit("unlock_failed", reason="pin_too_short")
            return

        lock_until_dt = parse_lock_until(self.cfg.get("lock_until"))
        if lock_until_dt and datetime.now() < lock_until_dt:
            remaining = lock_until_dt - datetime.now()
            messagebox.showerror("Time Locked", f"This lockbox is time-locked for {format_remaining(remaining)}.")
            self.audit("unlock_blocked", reason="time_lock_active")
            return

        if self.cfg["pin_hash"] is None:
            self.cfg["pin_hash"] = hash_pin(pin, self.salt)
            save_config(self.cfg)
            messagebox.showinfo("PIN set", "PIN created. Unlocking lockbox...")
            self.audit("pin_set")
        else:
            if hash_pin(pin, self.salt) != self.cfg["pin_hash"]:
                messagebox.showerror("Wrong PIN", "That PIN is incorrect.")
                self.audit("unlock_failed", reason="wrong_pin")
                return

        self.key = derive_key(pin, self.salt)
        self.load_data()

        self.override_session_active = False
        self.override_keep_lock = False

        self.audit("unlock_success", method="pin")
        self.frame_main()

    def override_action_choice(self) -> str:
        choice = messagebox.askyesnocancel(
            "Override Used",
            "Override accepted.\n\nYES = Clear the time lock\nNO = Keep the time lock\nCANCEL = Abort"
        )
        if choice is None:
            return "cancel"
        return "clear" if choice else "keep"

    def override_unlock(self):
        if not validate_system_time(self.cfg):
            self.audit("clock_tamper_detected")
            messagebox.showerror(
                "Clock Tampering Detected",
                "System time appears to have been set backwards.\n\n"
                "Time-lock duration has been preserved.\n"
                "Fix the clock to continue."
            )
            return

        lock_until_dt = parse_lock_until(self.cfg.get("lock_until"))
        if not lock_until_dt or datetime.now() >= lock_until_dt:
            messagebox.showinfo("Not time-locked", "No active time lock right now.")
            self.audit("override_failed", reason="no_time_lock_active")
            return

        if not self.cfg.get("override_pin_hash"):
            messagebox.showerror("No Override PIN", "No override PIN has been set yet.")
            self.audit("override_failed", reason="no_override_pin_set")
            return

        override_pin = self.pin_entry.get().strip()
        if len(override_pin) < 4:
            messagebox.showerror("PIN too short", "Use at least 4 digits/characters.")
            self.audit("override_failed", reason="override_pin_too_short")
            return

        if hash_pin(override_pin, self.salt) != self.cfg["override_pin_hash"]:
            messagebox.showerror("Wrong Override PIN", "That override PIN is incorrect.")
            self.audit("override_failed", reason="wrong_override_pin")
            return

        action = self.override_action_choice()
        if action == "cancel":
            self.audit("override_cancelled")
            return

        real_pin = simpledialog.askstring(
            "Real PIN Required",
            "Enter your normal PIN to open the lockbox:",
            show="•"
        )
        if not real_pin:
            self.audit("override_failed", reason="real_pin_missing")
            return
        if self.cfg["pin_hash"] is None or hash_pin(real_pin, self.salt) != self.cfg["pin_hash"]:
            messagebox.showerror("Wrong PIN", "Normal PIN is incorrect.")
            self.audit("override_failed", reason="wrong_real_pin")
            return

        if action == "clear":
            self.cfg["lock_until"] = None
            save_config(self.cfg)
            self.audit("time_lock_cleared", via="override")

        self.key = derive_key(real_pin, self.salt)
        self.load_data()

        self.override_session_active = True
        self.override_keep_lock = (action == "keep")

        self.audit("override_success", action=action)
        self.frame_main()

    # ---------------- Main Screen ----------------

    def frame_main(self):
        for w in self.root.winfo_children():
            w.destroy()

        top = tk.Frame(self.root, padx=12, pady=10)
        top.pack(fill="x")

        tk.Label(top, text="Lockbox Items", font=("Segoe UI", 14, "bold")).pack(side="left")
        tk.Button(top, text="Lock", command=self.relock_now).pack(side="right")

        mid = tk.Frame(self.root, padx=12, pady=8)
        mid.pack(fill="both", expand=True)

        self.listbox = tk.Listbox(mid, font=("Segoe UI", 11))
        self.listbox.pack(side="left", fill="both", expand=True)

        scroll = tk.Scrollbar(mid, command=self.listbox.yview)
        scroll.pack(side="right", fill="y")
        self.listbox.config(yscrollcommand=scroll.set)

        bottom = tk.Frame(self.root, padx=12, pady=10)
        bottom.pack(fill="x")

        tk.Button(bottom, text="Add", command=self.add_item, width=10).pack(side="left")
        tk.Button(bottom, text="View", command=self.view_item, width=10).pack(side="left", padx=6)
        tk.Button(bottom, text="Delete", command=self.delete_item, width=10).pack(side="left")
        tk.Button(bottom, text="View Audit Log", command=self.open_audit_log, width=14).pack(side="left", padx=6)

        tk.Button(bottom, text="Set Time Lock", command=self.set_time_lock).pack(side="right")
        tk.Button(bottom, text="Set/Change Override PIN", command=self.set_override_pin).pack(side="right", padx=6)
        tk.Button(bottom, text="Change PIN", command=self.change_pin).pack(side="right", padx=6)

        if self.override_session_active and self.override_keep_lock:
            relock_bar = tk.Frame(self.root, padx=12, pady=10)
            relock_bar.pack(fill="x")
            tk.Button(
                relock_bar,
                text="RELOCK (keep time lock)",
                command=self.relock_now,
                font=("Segoe UI", 12, "bold")
            ).pack(fill="x")

        self.refresh_list()

    def relock_now(self):
        self.audit("relock")
        self.key = None
        self.data = {"items": []}
        self.override_session_active = False
        self.override_keep_lock = False
        self.frame_login()

    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        for it in self.data["items"]:
            self.listbox.insert(tk.END, it.get("title", ""))

    # ---------------- Item Operations ----------------

    def add_item(self):
        title = simpledialog.askstring("Title/Date", "Entry title/Date:")
        if not title:
            return

        secret = simpledialog.askstring("Lockbox code", "Enter your lockbox code (stored encrypted):", show=None)
        if secret is None:
            return

        self.data["items"].append({"title": title.strip(), "secret": secret})
        self.save_data()
        self.refresh_list()

        self.audit("item_added", title=title.strip())

    def view_item(self):
        idx = self.listbox.curselection()
        if not idx:
            messagebox.showinfo("Select one", "Pick an item first.")
            return

        item = self.data["items"][idx[0]]
        title = item.get("title", "Item")
        val = item.get("secret") or item.get("Lockbox code") or ""
        messagebox.showinfo(title, val)

        self.audit("item_viewed", title=title)

    def delete_item(self):
        idx = self.listbox.curselection()
        if not idx:
            messagebox.showinfo("Select one", "Pick an item first.")
            return
        item = self.data["items"][idx[0]]
        title = item.get("title", "")
        if messagebox.askyesno("Delete", f"Delete '{title or 'Item'}'?"):
            self.data["items"].pop(idx[0])
            self.save_data()
            self.refresh_list()
            self.audit("item_deleted", title=title)

    # ---------------- PIN Management ----------------

    def change_pin(self):
        old_pin = simpledialog.askstring("Change PIN", "Enter current PIN:", show="•")
        if old_pin is None:
            return
        if self.cfg["pin_hash"] is None or hash_pin(old_pin, self.salt) != self.cfg["pin_hash"]:
            messagebox.showerror("Wrong PIN", "Current PIN is incorrect.")
            self.audit("pin_change_failed", reason="wrong_current_pin")
            return

        new_pin = simpledialog.askstring("Change PIN", "Enter new PIN:", show="•")
        if not new_pin or len(new_pin) < 4:
            messagebox.showerror("Bad PIN", "New PIN must be at least 4 characters.")
            self.audit("pin_change_failed", reason="new_pin_invalid")
            return

        confirm = simpledialog.askstring("Change PIN", "Confirm new PIN:", show="•")
        if new_pin != confirm:
            messagebox.showerror("Mismatch", "New PIN entries did not match.")
            self.audit("pin_change_failed", reason="confirm_mismatch")
            return

        old_key = derive_key(old_pin, self.salt)
        new_key = derive_key(new_pin, self.salt)

        try:
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, "rb") as f:
                    blob = f.read()
                data = decrypt_data(old_key, blob)
            else:
                data = {"items": []}
        except CryptoInvalidToken:
            messagebox.showerror("Error", "Could not decrypt current vault with old PIN.")
            self.audit("pin_change_failed", reason="decrypt_failed")
            return

        with open(DATA_FILE, "wb") as f:
            f.write(encrypt_data(new_key, data))

        self.cfg["pin_hash"] = hash_pin(new_pin, self.salt)
        save_config(self.cfg)

        self.key = new_key
        self.data = data
        self.refresh_list()
        messagebox.showinfo("Success", "PIN updated.")
        self.audit("pin_changed")

    def set_override_pin(self):
        cur = simpledialog.askstring("Override PIN", "Enter your normal PIN first:", show="•")
        if not cur:
            return
        if self.cfg["pin_hash"] is None or hash_pin(cur, self.salt) != self.cfg["pin_hash"]:
            messagebox.showerror("Wrong PIN", "Normal PIN is incorrect.")
            self.audit("override_pin_set_failed", reason="wrong_normal_pin")
            return

        new_pin = simpledialog.askstring("Override PIN", "Enter NEW override PIN:", show="•")
        if not new_pin or len(new_pin) < 4:
            messagebox.showerror("Bad PIN", "Override PIN must be at least 4 characters.")
            self.audit("override_pin_set_failed", reason="override_pin_invalid")
            return

        confirm = simpledialog.askstring("Override PIN", "Confirm override PIN:", show="•")
        if new_pin != confirm:
            messagebox.showerror("Mismatch", "Override PIN entries did not match.")
            self.audit("override_pin_set_failed", reason="confirm_mismatch")
            return

        self.cfg["override_pin_hash"] = hash_pin(new_pin, self.salt)
        save_config(self.cfg)
        messagebox.showinfo("Saved", "Override PIN set/updated.")
        self.audit("override_pin_set")

    # ---------------- Time Lock ----------------

    def ask_duration_components(self):
        """Modal popup with 5 boxes: Months, Weeks, Days, Hours, Minutes."""
        win = tk.Toplevel(self.root)
        win.title("Set Time Lock")
        win.resizable(False, False)
        win.grab_set()

        frm = tk.Frame(win, padx=14, pady=14)
        frm.pack(fill="both", expand=True)

        tk.Label(frm, text="Enter duration (leave blank for 0):", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10)
        )

        labels = ["Months", "Weeks", "Days", "Hours", "Minutes"]
        entries = {}

        for i, lab in enumerate(labels, start=1):
            tk.Label(frm, text=lab + ":").grid(row=i, column=0, sticky="e", padx=(0, 10), pady=4)
            e = tk.Entry(frm, width=10)
            e.grid(row=i, column=1, sticky="w", pady=4)
            entries[lab.lower()] = e

        result = {"value": None}

        def parse_int(s: str) -> int:
            s = (s or "").strip()
            if s == "":
                return 0
            if not s.isdigit():
                raise ValueError
            return int(s)

        def on_ok():
            try:
                months = parse_int(entries["months"].get())
                weeks = parse_int(entries["weeks"].get())
                days = parse_int(entries["days"].get())
                hours = parse_int(entries["hours"].get())
                minutes = parse_int(entries["minutes"].get())

                if months == weeks == days == hours == minutes == 0:
                    messagebox.showerror("Invalid duration", "Please enter at least one non-zero value.", parent=win)
                    return

                if minutes > 59 or hours > 23:
                    messagebox.showerror(
                        "Out of range",
                        "Please keep Minutes (0–59) and Hours (0–23).\nUse Days/Weeks/Months for larger amounts.",
                        parent=win
                    )
                    return

                result["value"] = (months, weeks, days, hours, minutes)
                win.destroy()
            except ValueError:
                messagebox.showerror("Invalid input", "Please enter whole numbers only (or leave blank).", parent=win)

        def on_cancel():
            result["value"] = None
            win.destroy()

        btns = tk.Frame(frm)
        btns.grid(row=7, column=0, columnspan=2, sticky="e", pady=(12, 0))

        tk.Button(btns, text="Cancel", command=on_cancel).pack(side="right")
        tk.Button(btns, text="OK", command=on_ok).pack(side="right", padx=(0, 8))

        win.bind("<Return>", lambda _e: on_ok())
        win.bind("<Escape>", lambda _e: on_cancel())

        entries["months"].focus()

        win.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (win.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (win.winfo_height() // 2)
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")

        self.root.wait_window(win)
        return result["value"]

    def set_time_lock(self):
        if not validate_system_time(self.cfg):
            self.audit("clock_tamper_detected")
            messagebox.showerror(
                "Clock Tampering Detected",
                "System time appears to have been set backwards.\n\n"
                "Fix the clock to set a time lock."
            )
            return

        picked = self.ask_duration_components()
        if picked is None:
            return

        months, weeks, days, hours, minutes = picked
        now = datetime.now()
        lock_until_dt = add_months(now, months) + timedelta(
            weeks=weeks, days=days, hours=hours, minutes=minutes
        )

        self.cfg["lock_until"] = lock_until_dt.isoformat(timespec="seconds")
        save_config(self.cfg)

        self.audit(
            "time_lock_set",
            lock_until=self.cfg.get("lock_until"),
            months=months, weeks=weeks, days=days, hours=hours, minutes=minutes
        )

        messagebox.showinfo(
            "Time Lock Set",
            f"Locked until {lock_until_dt.strftime('%Y-%m-%d %H:%M:%S')}."
        )


def run_app():
    root = tk.Tk()
    LockboxApp(root)
    root.mainloop()
