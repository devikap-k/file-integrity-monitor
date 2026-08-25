# File Integrity Monitor (FIM) & Detection Engine

A lightweight, host-based intrusion detection system (HIDS) built in Python. It offers real-time file tracking, cryptographic verification, swappable hash algorithms, tamper-evident baselines, and persistent audit logging.

---

## Table of Contents
- [Features](#-features)
- [Known Limitations](#️-known-limitations)
- [Tech Stack](#️-tech-stack)
- [Quick Start](#️-quick-start)
- [Testing](#-testing)
- [Files Produced](#-files-produced)

---

## Features

| Feature | Description |
|---|---|
| **Real-Time Watch Mode** | Monitors directory events for modifications, deletions, creations, and (where supported) file-access attempts via `watchdog`. |
| **Swappable Hash Algorithms** | Configurable via `config.json` (`sha256`, `sha512`, etc.). Invalid algorithms fall back safely to `sha256` instead of silently corrupting the baseline. |
| **Correct Path Matching** | Baseline keys and live filesystem events are both normalized to absolute paths, so integrity checks compare like with like — no false-positive violations. |
| **Tamper-Evident Baseline** | `baseline.json` is locked read-only (`chmod 400`) after creation, and its own hash is stored in `baseline.sig`. Any direct edit to hide a change is detected on the next watch startup and blocked unless explicitly overridden. |
| **Persistent Audit Log** | All alerts are written to `fim.log` with timestamps, in addition to the console — so you have evidence after the terminal closes. |
| **Debounced Alerts** | Duplicate events fired by editors/OS within a short window are collapsed instead of spamming the console. |

---

## Known Limitations

Being upfront about what this tool does **not** protect against:

- An attacker with root access can still rewrite both `baseline.json` and `baseline.sig` together. True tamper resistance requires storing the baseline off-host or cryptographically signing it with a key the monitored host doesn't have.
- `on_opened` (access-attempt) events depend on your `watchdog` version and OS backend (inotify on Linux). If unsupported, the tool logs a notice and continues without them rather than failing silently.
- Watching is **non-recursive by default**; pass `-r` to `w` for recursive watching of subdirectories.

---

## Tech Stack

- **Language:** Python 3
- **Libraries:** `watchdog`, `hashlib`, `json`, `logging`, `os`
- **Platform:** Linux (Kali, Ubuntu, etc.) — access-event detection is Linux/inotify-specific; modification/creation/deletion detection is cross-platform.

---

## Quick Start

**1. Set up the project directory** (or clone this repo)
```bash
mkdir file_integrity_monitor && cd file_integrity_monitor
```

**2. Install dependencies**
```bash
pip install watchdog
```

**3. Configure monitored files** — edit `config.json`
```json
{
  "hash_algorithm": "sha256",
  "monitored_paths": ["config.txt", "secrets.txt"]
}
```

**4. Create the initial files to protect** (for testing)
```bash
echo "DB_USER=admin" > config.txt
```

**5. Generate a baseline**
```bash
python3 fim.py b
```
Creates `baseline.json` (read-only) and `baseline.sig`.

**6. Launch real-time watch mode**
```bash
python3 fim.py w
# or, to watch subdirectories too:
python3 fim.py w -r
```

---

## Testing

| Test | Command (in a 2nd terminal) | Expected Result |
|---|---|---|
| Modification detection | `echo "hack" >> config.txt` | `FAIL` alert with original vs. current hash |
| Untracked file | `echo "test" > newfile.txt` | `New File Created` alert, no false `FAIL` on later edits |
| Deletion detection | `rm secrets.txt` | `File Deleted` alert, flagged as a baselined asset |
| Access detection | `cat config.txt` | `ACCESS` alert (platform-dependent) |
| Tamper detection | Hand-edit a hash in `baseline.json`, then re-run `python3 fim.py w` | `BASELINE TAMPERING DETECTED`, watch mode blocked until confirmed |

Check `fim.log` afterward to confirm every alert was also written there with a timestamp.

---

## Files Produced

| File | Purpose |
|---|---|
| `baseline.json` | Stored fingerprints (read-only after creation) |
| `baseline.sig` | Hash of `baseline.json`, used to detect tampering |
| `fim.log` | Timestamped, persistent alert log |
