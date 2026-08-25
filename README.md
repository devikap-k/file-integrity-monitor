# Advanced Python File Integrity Monitor (FIM) & Detection Engine

A lightweight host-based intrusion detection system (HIDS) built in Python.
Offers real-time tracking, cryptographic verification, swappable hash
algorithms, tamper-evident baselines, and persistent audit logging.

## 🚀 Features
- **Real-Time Watch Mode:** Monitors directory events for modifications,
  deletions, creations, and (where supported) file-access attempts via
  `watchdog`.
- **Swappable Cryptographic Algorithms:** Configurable via `config.json`
  (`sha256`, `sha512`, etc. — invalid algorithms fall back safely to
  `sha256` rather than silently corrupting the baseline).
- **Correct Path Matching:** Baseline keys and live filesystem events are
  both normalized to absolute paths, so integrity checks compare like with
  like instead of producing false-positive violations.
- **Tamper-Evident Baseline:** `baseline.json` is locked to read-only
  (`chmod 400`) after creation, and its own hash is stored in
  `baseline.sig`. If someone edits `baseline.json` directly to hide a
  change, watch mode detects the mismatch on startup and refuses to trust
  the baseline unless you explicitly override it.
- **Persistent Audit Log:** All alerts are written to `fim.log` with
  timestamps, in addition to the console, so you have evidence after the
  terminal closes.
- **Debounced Alerts:** Duplicate events fired by editors/OS within a short
  window are collapsed instead of spamming the console.

## ⚠️ Known Limitations
Being upfront about what this tool does *not* protect against:
- An attacker with root access can still rewrite both `baseline.json` and
  `baseline.sig` together. True tamper resistance requires storing the
  baseline off-host or cryptographically signing it with a key the
  monitored host doesn't have.
- `on_opened` (access-attempt) events depend on your `watchdog` version and
  OS backend (inotify on Linux). If unsupported, the tool logs a notice and
  continues without them rather than failing silently.
- Watching is non-recursive by default; pass `-r` to `w` for recursive
  watching of subdirectories.

## 🛠️ Tech Stack
- **Language:** Python 3
- **Libraries:** `watchdog`, `hashlib`, `json`, `logging`, `os`
- **Platform:** Linux (Kali, Ubuntu, etc.) — access-event detection is
  Linux/inotify-specific; modification/creation/deletion detection is
  cross-platform.

## ⚙️ Quick Start Guide

1. **Set up the project directory** (or clone this repo):
   ```bash
   mkdir file_integrity_monitor && cd file_integrity_monitor
   ```

2. **Install dependencies:**
   ```bash
   pip install watchdog
   ```

3. **Configure monitored files** — edit `config.json`:
   ```json
   {
     "hash_algorithm": "sha256",
     "monitored_paths": ["config.txt", "secrets.txt"]
   }
   ```

4. **Create the initial files to protect** (for testing):
   ```bash
   echo "DB_USER=admin" > config.txt
   ```

5. **Generate a baseline:**
   ```bash
   python3 fim.py b
   ```
   This creates `baseline.json` (read-only) and `baseline.sig`.

6. **Launch real-time watch mode:**
   ```bash
   python3 fim.py w
   # or, to watch subdirectories too:
   python3 fim.py w -r
   ```

7. **Test live detection** — in a second terminal, in the same folder:
   ```bash
   echo "hack" >> config.txt
   ```
   You should see a `FAIL` integrity violation alert with the original and
   current hashes, both in the console and appended to `fim.log`.

8. **Test tamper detection** — stop watch mode, hand-edit `baseline.json`
   to change a stored hash, then run `python3 fim.py w` again. It should
   refuse to trust the baseline until you either regenerate it or
   explicitly confirm the override.

## 📁 Files Produced
| File            | Purpose                                             |
|-----------------|------------------------------------------------------|
| `baseline.json` | Stored fingerprints (read-only after creation)       |
| `baseline.sig`  | Hash of `baseline.json`, used to detect tampering     |
| `fim.log`       | Timestamped, persistent alert log                     |
