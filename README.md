# Chasti Lockbox (Windows)

A secure, offline lockbox application for Windows with PIN protection, encrypted storage, and optional time-based locking.

This project is designed to be **simple, transparent, and self-contained**, with no accounts, no cloud services, and no telemetry.

---

## ✨ Features

- 🔐 **PIN-protected vault**
- 🔒 **Encrypted storage** (AES via Fernet)
- ⏳ **Time-based lock**
  - Blocks access even with the correct PIN
  - Live countdown on unlock screen
- 🧷 **Override PIN**
  - Only usable while a time-lock is active
  - Choose to **clear** the lock or **temporarily bypass** it
- 🔁 **Relock button**
  - When keeping the time-lock after override
- 🛡️ **Clock-tamper protection**
  - Detects system clock rollback
  - Prevents shortening time-locks by changing the date/time
- 📁 **Offline-first**
  - All data stored locally in `%APPDATA%\SimpleLockbox`
- 🪟 **Native Windows UI**
  - Built with Python + Tkinter
  - Can be packaged as a standalone `.exe`

---

## 📂 Project Structure

```text
simple-lockbox/
├─ lockbox.py          # Entry point
├─ app_ui.py           # Tkinter UI and app logic
├─ config_store.py     # Config and file paths
├─ crypto_box.py       # Encryption and PIN hashing
├─ time_lock.py        # Time-lock and anti-clock-tamper logic
├─ requirements.txt
└─ README.md
