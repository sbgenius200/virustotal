"""
VirusTotal Hash Mutation Demo
------------------------------
Demonstrates how VirusTotal treats files with different hashes as distinct submissions,
even when the content is functionally identical.

Flow:
  1. Send current filename to Discord webhook
  2. Wait 15 seconds
  3. Read own file into memory
  4. Append one random byte (mutates hash)
  5. Save as a new file with an incremented numeric name
  6. Submit new file to VirusTotal and display scan results
"""

import os
import sys
import time
import random
import hashlib
import requests


# ─── CONFIGURATION ────────────────────────────────────────────────────────────

DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1513875044202188930/dw8gsAdUGilAB9kqqafinDfc0JozomWSYErp8HOJcEKeBfLJ5oBW6IPCZd-6NDKFiArm"
VIRUSTOTAL_API_KEY  = "ffb3340192c75b96161289491c4e4949c3ca50c0e7f19f4a4d800955cc818d7e"

VT_UPLOAD_URL   = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"

POLL_INTERVAL_SECONDS = 15   # how often to poll VT while scan is queued
MAX_POLL_ATTEMPTS     = 20   # give up after this many polls (~5 minutes)
INITIAL_WAIT_SECONDS  = 15   # pause before mutating / submitting

# ──────────────────────────────────────────────────────────────────────────────


def sha256_of_file(path: str) -> str:
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def send_discord_message(message: str) -> None:
    """Post a plain-text message to the configured Discord webhook."""
    payload = {"content": message}
    try:
        resp = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        resp.raise_for_status()
        print(f"[Discord] Message sent: {message}")
    except requests.RequestException as e:
        print(f"[Discord] Failed to send message: {e}")


def derive_next_filename(current_path: str) -> str:
    """
    Increment the numeric stem of the filename by 1.
    'scan_007.py'  →  'scan_008.py'
    'vt_demo.py'   →  'vt_demo_1.py'
    '3.py'         →  '4.py'
    """
    directory  = os.path.dirname(os.path.abspath(current_path))
    basename   = os.path.basename(current_path)
    stem, ext  = os.path.splitext(basename)

    # Try to find a trailing integer in the stem
    parts = stem.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        new_stem = f"{parts[0]}_{int(parts[1]) + 1:03d}"
    elif stem.isdigit():
        new_stem = str(int(stem) + 1)
    else:
        new_stem = f"{stem}_001"

    return os.path.join(directory, f"{new_stem}{ext}")


def mutate_and_save(source_path: str, dest_path: str) -> bytes:
    """
    Read source into memory, append one random byte, write to dest.
    Returns the mutated file bytes.
    """
    with open(source_path, "rb") as f:
        data = f.read()

    random_byte = bytes([random.randint(0, 255)])
    mutated     = data + random_byte

    with open(dest_path, "wb") as f:
        f.write(mutated)

    print(f"[Mutate] Appended byte 0x{random_byte.hex().upper()} to create '{os.path.basename(dest_path)}'")
    return mutated


def upload_to_virustotal(file_path: str) -> str | None:
    """
    Upload a file to VirusTotal.
    Returns the analysis ID if successful, else None.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
        try:
            resp = requests.post(VT_UPLOAD_URL, headers=headers, files=files, timeout=60)
            resp.raise_for_status()
            analysis_id = resp.json()["data"]["id"]
            print(f"[VirusTotal] Uploaded. Analysis ID: {analysis_id}")
            return analysis_id
        except requests.RequestException as e:
            print(f"[VirusTotal] Upload failed: {e}")
            return None


def poll_virustotal(analysis_id: str) -> dict | None:
    """
    Poll VirusTotal until the analysis is complete.
    Returns the full 'attributes' dict, or None on timeout / error.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url     = VT_ANALYSIS_URL.format(analysis_id)

    print("[VirusTotal] Waiting for scan to complete", end="", flush=True)

    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        time.sleep(POLL_INTERVAL_SECONDS)
        print(".", end="", flush=True)

        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data       = resp.json()["data"]
            attributes = data["attributes"]
            status     = attributes.get("status", "unknown")

            if status == "completed":
                print(" done.\n")
                return attributes

        except requests.RequestException as e:
            print(f"\n[VirusTotal] Polling error: {e}")
            return None

    print("\n[VirusTotal] Timed out waiting for results.")
    return None


def display_results(attributes: dict, file_path: str, file_hash: str) -> None:
    """Pretty-print the VirusTotal scan summary."""
    stats   = attributes.get("stats", {})
    results = attributes.get("results", {})

    malicious    = stats.get("malicious", 0)
    suspicious   = stats.get("suspicious", 0)
    undetected   = stats.get("undetected", 0)
    total_scans  = sum(stats.values())

    bar_len   = 40
    detected  = malicious + suspicious
    bar_fill  = int((detected / total_scans) * bar_len) if total_scans else 0
    bar       = "█" * bar_fill + "░" * (bar_len - bar_fill)

    print("=" * 60)
    print("  VirusTotal Scan Report")
    print("=" * 60)
    print(f"  File    : {os.path.basename(file_path)}")
    print(f"  SHA-256 : {file_hash}")
    print(f"  Scanned : {total_scans} engines")
    print()
    print(f"  [{bar}]")
    print(f"  Malicious  : {malicious:>4}")
    print(f"  Suspicious : {suspicious:>4}")
    print(f"  Undetected : {undetected:>4}")
    print()

    if malicious == 0 and suspicious == 0:
        print("  ✅  Result: FILE IS SAFE — no engines flagged this file.")
    elif malicious < 3:
        print("  ⚠️   Result: LOW RISK — few engines flagged this file (possible false positive).")
    else:
        print(f"  ❌  Result: DETECTED — {malicious} engine(s) flagged this file as malicious.")

    # Show which engines flagged the file (if any)
    flagged = [
        (engine, info.get("result", "?"))
        for engine, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ]
    if flagged:
        print()
        print("  Engines that flagged this file:")
        for engine, verdict in flagged:
            print(f"    • {engine:<25} {verdict}")

    print("=" * 60)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main() -> None:
    current_file = os.path.abspath(sys.argv[0])
    current_name = os.path.basename(current_file)
    current_hash = sha256_of_file(current_file)

    print(f"[Init] Running as  : {current_name}")
    print(f"[Init] SHA-256     : {current_hash}")
    print()

    # ── Step 1: Notify Discord ────────────────────────────────────────────────
    send_discord_message(
        f"🔍 **VT Demo started**\n"
        f"File: `{current_name}`\n"
        f"SHA-256: `{current_hash}`\n"
        f"Submitting mutated copy to VirusTotal in {INITIAL_WAIT_SECONDS}s…"
    )

    # ── Step 2: Wait ──────────────────────────────────────────────────────────
    print(f"[Wait] Sleeping {INITIAL_WAIT_SECONDS} seconds…")
    time.sleep(INITIAL_WAIT_SECONDS)

    # ── Step 3: Derive new filename & mutate ──────────────────────────────────
    next_file = derive_next_filename(current_file)
    mutate_and_save(current_file, next_file)
    new_hash = sha256_of_file(next_file)

    print(f"[Hash] Old hash: {current_hash}")
    print(f"[Hash] New hash: {new_hash}")
    print(f"[Hash] Hashes differ: {current_hash != new_hash}")
    print()

    # ── Step 4: Upload to VirusTotal ──────────────────────────────────────────
    analysis_id = upload_to_virustotal(next_file)
    if not analysis_id:
        print("[Error] Could not upload file. Exiting.")
        sys.exit(1)

    # ── Step 5: Poll & display results ────────────────────────────────────────
    attributes = poll_virustotal(analysis_id)
    if not attributes:
        print("[Error] Could not retrieve scan results.")
        sys.exit(1)

    display_results(attributes, next_file, new_hash)

    # ── Step 6: Notify Discord of completion ──────────────────────────────────
    stats      = attributes.get("stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values())

    status_emoji = "✅" if (malicious + suspicious) == 0 else "⚠️"
    send_discord_message(
        f"{status_emoji} **VT scan complete** for `{os.path.basename(next_file)}`\n"
        f"SHA-256: `{new_hash}`\n"
        f"Malicious: {malicious} / {total} engines"
    )


if __name__ == "__main__":
    main()
