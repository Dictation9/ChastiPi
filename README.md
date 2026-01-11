# Chasti Lockbox (Windows)

A secure, offline lockbox application for Windows with PIN protection, encrypted storage, and optional time-based locking.

This project is designed to be **simple, transparent, and self-contained**, with no accounts, no cloud services, and no telemetry.

This project is currently a WIP and feedback is greatly welcome

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
  - All data stored locally in `%APPDATA%\Chasti-Lockbox`
- 🪟 **Native Windows UI**
  - Built with Python + Tkinter
  - Can be packaged as a standalone `.exe`

---

## 📸 Screenshots

### First Startup
![First Startup](Screenshots/Setup%20pin%20screen.png)

### Login Screen
![Login Screen](Screenshots/Login%20screen%20with%20time%20remaining.png)

### Main Vault View
![Main Vault](Screenshots/Lockbox%20dashboard.png)

### Adding lockbox codes
![Adding lockbox codes](Screenshots/Adding%20lockbox%201of2.png)
![Adding lockbox codes](Screenshots/Adding%20lockbox%20code%202of2.png)

### Time Lock Setup
![Time Lock](Screenshots/Adding%20time%20limit%201of2.png)
![Time Lock](Screenshots/Adding%20time%20limit%202of2.png)

---

🛠️ Setup & Installation
Option 1: Installer (Recommended)

1. Download Chasti-Lockbox-Setup.exe from the Releases page

2. Run the installer

3. Follow the on-screen steps

4. Launch Chasti-Lockbox from the Start Menu or desktop shortcut

All data will be stored securely in your user AppData folder.

---

Option 2: Portable Version (USB / No Install)

1. Download Chasti-Lockbox-Portable.zip

2. Extract the ZIP anywhere (USB drive, external drive, Desktop, etc.)

3. Run Chasti-Lockbox.exe

📌 Portable mode notes

* A file named portable.flag is included

* All vault data is stored in a local data/ folder next to the EXE

* Nothing is written to AppData or the registry

🔐 First-Time Setup

When you launch Chasti-Lockbox for the first time:

1. You will be prompted to create a PIN

2. This PIN encrypts your vault and is required to unlock it

3. Choose a PIN you will remember — it cannot be recovered if lost

Once set, the vault will open automatically.

---

⏳ Using Time Locks

Chasti-Lockbox supports time-based locking that prevents unlocking until a chosen time has passed.

Setting a Time Lock

1. Unlock the vault with your PIN

2. Click “Set Time Lock”

3. Enter a duration using any combination of:

  * Months

  * Weeks

  * Days

  * Hours

  * Minutes

4. Click OK

The vault will lock and cannot be opened again until the timer expires.

---

Countdown Display

* The login screen shows a live countdown of remaining lock time

* Example:
  ⏳ Time-locked for: 2d 4h 12m

---

Anti Clock Tampering

Chasti-Lockbox detects if the system clock is set backwards:

* The lock duration is preserved

* Unlocking is blocked until the clock is corrected

This prevents bypassing time locks by changing the system date.

---

🔓 Override PIN (Optional)

An override PIN can be set for emergency access.

Setting an Override PIN

1. Unlock the vault

2. Click “Set / Change Override PIN”

3. Enter your normal PIN

4. Choose a separate override PIN

Using the Override PIN

1. On the login screen, enter the override PIN and click Override Unlock

2. You will be asked whether to:

  * Clear the time lock, or

  * Keep the time lock active

  * Your normal PIN is still required to fully unlock the vault

---

🔄 Locking Again

At any time, click “Lock” in the main vault screen to:

  * Clear decrypted data from memory

  * Return to the locked login screen

If an override session is active, an additional RELOCK (keep time lock) button will appear.

---

📁 Data Storage & Security

* All vault contents are encrypted on disk

* No data is sent online

* No accounts or telemetry

* Time validation is local only (unless future features are enabled)

---

⚠️ Important Warnings

* If you forget your PIN, your data cannot be recovered

* Time locks cannot be bypassed without:

  * The override PIN, or

  * Waiting for the timer to expire

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
