"""
Advanced Python File Integrity Monitor (FIM) & Detection Engine
-----------------------------------------------------------------
Fixes applied over the original version:
  1. Path normalization (baseline keys vs. watchdog event paths now match)
  2. Correct hash-algorithm handling (invalid algo no longer silently
     desyncs the stored baseline)
  3. on_opened now actually works (explicit event_filter passed to
     observer.schedule, which watchdog requires for FileOpenedEvent)
  4. Basic debounce so editors that fire multiple events per save don't
     spam duplicate alerts
  5. Optional recursive watching
  6. Persistent, timestamped audit log (fim.log) in addition to console
     output, so alerts survive after the terminal closes
  7. Baseline tamper-evidence: baseline.json is chmod'd read-only (0400)
     after creation, and a hash-of-the-baseline-file is stored separately
     (baseline.sig) so tampering with baseline.json to "match" a modified
     file can itself be detected on watch startup
  8. Broader exception handling (PermissionError, OSError) so a locked
     or permission-denied file doesn't crash the watcher thread
  9. baseline.sig unlock-before-write fix: protect_baseline() now resets
     permissions on baseline.sig before overwriting it, so regenerating
     the baseline a second time no longer throws PermissionError
"""

import hashlib
import json
import logging
import os
import stat
import sys
import time
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

try:
    # Needed to explicitly opt in to open/access events (fix #3)
    from watchdog.events import FileOpenedEvent
    HAVE_OPEN_EVENTS = True
except ImportError:
    HAVE_OPEN_EVENTS = False

BASELINE_FILE = "baseline.json"
BASELINE_SIG_FILE = "baseline.sig"
CONFIG_FILE = "config.json"
LOG_FILE = "fim.log"

DEBOUNCE_SECONDS = 1.0  # collapse duplicate events per path within this window

# ---------------------------------------------------------------------------
# Logging setup: mirrors alerts to both console and a persistent logfile
# ---------------------------------------------------------------------------
logger = logging.getLogger("fim")
logger.setLevel(logging.INFO)

_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(logging.Formatter("%(message)s"))

_file_handler = logging.FileHandler(LOG_FILE)
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
)

logger.addHandler(_console_handler)
logger.addHandler(_file_handler)


def load_config():
    """Loads configuration settings from config.json."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"hash_algorithm": "sha256", "monitored_paths": ["config.txt"]}


def normalize(path):
    """Canonical form used as the single source of truth for path identity.

    Both the baseline keys and every watchdog event path are passed through
    this before comparison, which fixes the original './config.txt' vs
    'config.txt' mismatch bug.
    """
    return os.path.normpath(os.path.abspath(path))


def resolve_algorithm(requested_algo):
    """Validates a requested hash algorithm, returning a safe fallback.

    Returns (algo_to_use, was_valid) so callers can decide whether to trust
    what gets written back into the baseline metadata.
    """
    if requested_algo in hashlib.algorithms_available:
        return requested_algo, True
    logger.warning(
        "[-] Invalid hash algorithm '%s' in config; falling back to sha256.",
        requested_algo,
    )
    return "sha256", False


def calculate_hash(filepath, algo="sha256"):
    """Computes a cryptographic hash of a file, or None if unreadable."""
    algo, _ = resolve_algorithm(algo)
    try:
        hasher = hashlib.new(algo)
    except ValueError:
        hasher = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hasher.update(byte_block)
        return hasher.hexdigest()
    except FileNotFoundError:
        return None
    except (PermissionError, OSError) as e:
        logger.warning("[-] Could not read %s: %s", filepath, e)
        return None


def hash_file_contents(path, algo="sha256"):
    """Hashes an arbitrary file's contents (used to sign the baseline itself)."""
    return calculate_hash(path, algo)


def protect_baseline(algo):
    """Locks baseline.json down and records its own hash for tamper detection.

    This doesn't make tampering impossible (an attacker with root can still
    rewrite both files), but it closes the trivial "just edit baseline.json
    to match the new hash" bypass a plain read/write JSON file allows.
    """
    # baseline.sig may already exist read-only from a previous run —
    # unlock it before attempting to overwrite it.
    if os.path.exists(BASELINE_SIG_FILE):
        try:
            os.chmod(BASELINE_SIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    baseline_hash = hash_file_contents(BASELINE_FILE, algo)
    with open(BASELINE_SIG_FILE, "w") as f:
        json.dump({"algorithm": algo, "baseline_hash": baseline_hash}, f, indent=4)

    # Best-effort permission lockdown (POSIX). Owner read-only.
    try:
        os.chmod(BASELINE_FILE, stat.S_IRUSR)
        os.chmod(BASELINE_SIG_FILE, stat.S_IRUSR)
    except OSError as e:
        logger.warning("[-] Could not chmod baseline files: %s", e)


def verify_baseline_untampered():
    """Checks baseline.json against its recorded self-hash before trusting it."""
    if not os.path.exists(BASELINE_SIG_FILE):
        logger.warning(
            "[-] No baseline.sig found — baseline authenticity cannot be verified."
        )
        return True  # don't hard-fail older baselines, just warn

    with open(BASELINE_SIG_FILE, "r") as f:
        sig = json.load(f)

    current_hash = hash_file_contents(BASELINE_FILE, sig.get("algorithm", "sha256"))
    if current_hash != sig.get("baseline_hash"):
        logger.critical(
            "[!!!] BASELINE TAMPERING DETECTED — baseline.json does not match "
            "its recorded signature. Do not trust this baseline. Investigate "
            "immediately or regenerate from a known-good source."
        )
        return False

    logger.info("[✔] Baseline signature verified — baseline.json is untampered.")
    return True


def create_baseline():
    """Scans targets and saves cryptographic fingerprints using configured algorithm."""
    config = load_config()
    requested_algo = config.get("hash_algorithm", "sha256")
    algo, was_valid = resolve_algorithm(requested_algo)
    paths = config.get("monitored_paths", [])

    baseline = {}
    for path in paths:
        norm_path = normalize(path)
        if os.path.exists(path):
            baseline[norm_path] = calculate_hash(path, algo)
            logger.info("[+] Fingerprinted [%s]: %s", algo, norm_path)
        else:
            logger.info("[-] Notice: %s does not exist yet.", norm_path)

    data = {"algorithm": algo, "requested_algorithm": requested_algo, "files": baseline}

    # Baseline file must be writable while we create it; make sure it's not
    # still locked down read-only from a previous run.
    if os.path.exists(BASELINE_FILE):
        try:
            os.chmod(BASELINE_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=4)

    protect_baseline(algo)
    logger.info("[✔] Baseline generated successfully using %s!", algo)
    if not was_valid:
        logger.warning(
            "[-] Note: '%s' was invalid; baseline was actually built with sha256.",
            requested_algo,
        )


class SecurityEventHandler(FileSystemEventHandler):
    """Handles real-time file system events with debouncing and correct
    path comparison against the baseline."""

    def __init__(self, baseline_data, algo):
        self.baseline_data = baseline_data
        self.algo = algo
        self._last_event_time = {}  # path -> monotonic timestamp

    def _debounced(self, path, event_type):
        """Returns True if this (path, event_type) should be suppressed
        because an identical event fired within the debounce window."""
        key = (path, event_type)
        now = time.monotonic()
        last = self._last_event_time.get(key, 0)
        self._last_event_time[key] = now
        return (now - last) < DEBOUNCE_SECONDS

    def on_modified(self, event):
        if event.is_directory:
            return
        path = normalize(event.src_path)
        if self._debounced(path, "modified"):
            return

        logger.warning("[!] REAL-TIME ALERT: File Modified -> %s", path)
        current_hash = calculate_hash(path, self.algo)
        original_hash = self.baseline_data.get(path)

        if original_hash is None:
            logger.info(
                "    [INFO] %s is not in the baseline (untracked file).", path
            )
        elif current_hash != original_hash:
            logger.critical("    [FAIL] Integrity violation detected!")
            logger.critical("    Original: %s", original_hash)
            logger.critical("    Current:  %s", current_hash)
        else:
            logger.info("    [PASS] Contents match baseline.")

    def on_created(self, event):
        if event.is_directory:
            return
        path = normalize(event.src_path)
        if self._debounced(path, "created"):
            return
        logger.warning(
            "[+] REAL-TIME ALERT: New File Created -> %s "
            "(Potential Unauthorized Artifact)",
            path,
        )

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = normalize(event.src_path)
        if self._debounced(path, "deleted"):
            return
        logger.warning("[!] REAL-TIME ALERT: File Deleted -> %s", path)
        if path in self.baseline_data:
            logger.critical(
                "    [FAIL] A baselined file was deleted — this is a "
                "monitored asset."
            )

    def on_opened(self, event):
        if event.is_directory:
            return
        path = normalize(event.src_path)
        if self._debounced(path, "opened"):
            return
        logger.info("[*] ACCESS: Process opened/read -> %s", path)


def start_watch_mode(recursive=False):
    """Starts real-time continuous background monitoring."""
    if not os.path.exists(BASELINE_FILE):
        logger.error("[-] Error: No baseline found! Run with option 'b' first.")
        return

    if not verify_baseline_untampered():
        answer = input(
            "Baseline signature check failed. Continue anyway? (y/N): "
        ).strip().lower()
        if answer != "y":
            logger.info("[!] Aborting watch mode — baseline not trusted.")
            return

    with open(BASELINE_FILE, "r") as f:
        data = json.load(f)

    algo = data.get("algorithm", "sha256")
    # Keys stored during create_baseline() are already normalized, but
    # re-normalize defensively in case baseline.json was hand-edited.
    baseline_files = {normalize(k): v for k, v in data.get("files", {}).items()}

    logger.info(
        "[*] Starting Real-Time Watch Mode (Algorithm: %s). Press Ctrl+C to stop...",
        algo,
    )

    event_handler = SecurityEventHandler(baseline_files, algo)
    observer = Observer()

    watch_dir = "."
    if HAVE_OPEN_EVENTS:
        # Explicitly opt in to open/access events — without this,
        # on_opened silently never fires (this was bug #2 originally).
        observer.schedule(
            event_handler,
            path=watch_dir,
            recursive=recursive,
            event_filter=None,  # None = all default event types
        )
        try:
            # watchdog >= 3.0 supports enabling FileOpenedEvent explicitly
            observer.schedule(
                event_handler,
                path=watch_dir,
                recursive=recursive,
                event_filter=[FileOpenedEvent],
            )
        except TypeError:
            logger.info(
                "[-] This watchdog version/platform may not support open-event "
                "detection; access warnings may not fire."
            )
    else:
        observer.schedule(event_handler, path=watch_dir, recursive=recursive)
        logger.info(
            "[-] FileOpenedEvent not available on this watchdog install; "
            "access warnings disabled."
        )

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("[!] Watch mode stopped by user.")
    observer.join()


if __name__ == "__main__":
    logger.info("--- ADVANCED KALI LINUX FIM & DETECTION ENGINE ---")
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "b":
            create_baseline()
        elif arg == "w":
            start_watch_mode(recursive="-r" in sys.argv[2:])
        else:
            logger.error("[-] Unknown argument. Use 'b' for baseline or 'w' for watch mode.")
    else:
        choice = (
            input("Type 'b' to create baseline, or 'w' for Real-Time Watch Mode: ")
            .strip()
            .lower()
        )
        if choice == "b":
            create_baseline()
        elif choice == "w":
            start_watch_mode()
        else:
            logger.error("[-] Invalid input.")
