"""
VirusTotal Hash Mutation Demo
------------------------------
Demonstrates how VirusTotal treats files with different hashes as distinct submissions.

Flow:
  1. Send current filename + hash to Discord
  2. Wait 15 seconds
  3. Read own file into memory, append one random byte
  4. Save as incremented filename
  5. Upload to VirusTotal with retries
  6. Poll for results, sending live status to Discord
  7. Display final results and send summary to Discord
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

POLL_INTERVAL_SECONDS = 15
MAX_POLL_ATTEMPTS     = 20
INITIAL_WAIT_SECONDS  = 15

RETRY_COUNT = 3
RETRY_DELAY = 10  # seconds between retries

# ──────────────────────────────────────────────────────────────────────────────


def sha256_of_file(path: str) -> str:
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ─── DISCORD ──────────────────────────────────────────────────────────────────

def send_discord_message(message: str, retries: int = RETRY_COUNT) -> bool:
    """
    Post a message to Discord webhook with retry logic.
    Returns True on success, False on failure.
    """
    payload = {"content": message}
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
            resp.raise_for_status()
            print(f"[Discord] ✅ Sent: {message[:80]}{'...' if len(message) > 80 else ''}")
            return True
        except requests.RequestException as e:
            print(f"[Discord] ❌ Attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                print(f"[Discord] Retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
    print("[Discord] ❌ All attempts failed. Continuing without Discord update.")
    return False


# ─── FILE MUTATION ────────────────────────────────────────────────────────────

def derive_next_filename(current_path: str) -> str:
    """
    Increment the numeric stem of the filename by 1.
    'vt_demo.exe'      ->  'vt_demo_001.exe'
    'vt_demo_001.exe'  ->  'vt_demo_002.exe'
    'vt_demo_999.exe'  ->  'vt_demo_1000.exe'
    '1.exe'            ->  '2.exe'
    """
    directory = os.path.dirname(os.path.abspath(current_path))
    basename  = os.path.basename(current_path)
    stem, ext = os.path.splitext(basename)

    parts = stem.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        num      = int(parts[1]) + 1
        padding  = max(3, len(str(num)))
        new_stem = f"{parts[0]}_{num:0{padding}d}"
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

    print(f"[Mutate] Appended byte 0x{random_byte.hex().upper()} -> '{os.path.basename(dest_path)}'")
    return mutated


# ─── VIRUSTOTAL ───────────────────────────────────────────────────────────────

def upload_to_virustotal(file_path: str) -> str | None:
    """
    Upload a file to VirusTotal with retry logic.
    Returns the analysis ID if successful, else None.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    for attempt in range(1, RETRY_COUNT + 1):
        print(f"[VirusTotal] Upload attempt {attempt}/{RETRY_COUNT}...")
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
                resp  = requests.post(VT_UPLOAD_URL, headers=headers, files=files, timeout=60)

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", RETRY_DELAY * attempt))
                print(f"[VirusTotal] Rate limited. Waiting {wait}s...")
                send_discord_message(
                    f"⏳ **VT rate limited.** Waiting {wait}s before retry {attempt}/{RETRY_COUNT}..."
                )
                time.sleep(wait)
                continue

            if resp.status_code == 401:
                print("[VirusTotal] ❌ Invalid API key. Aborting.")
                send_discord_message("❌ **VT upload failed:** Invalid API key.")
                return None

            resp.raise_for_status()
            analysis_id = resp.json()["data"]["id"]
            print(f"[VirusTotal] ✅ Uploaded. Analysis ID: {analysis_id}")
            send_discord_message(
                f"📤 **File uploaded to VirusTotal**\n"
                f"File: `{os.path.basename(file_path)}`\n"
                f"Analysis ID: `{analysis_id}`\n"
                f"Waiting for scan results..."
            )
            return analysis_id

        except requests.exceptions.Timeout:
            print(f"[VirusTotal] ⏱ Timeout on attempt {attempt}.")
            send_discord_message(
                f"⏱ **VT upload timed out.** Attempt {attempt}/{RETRY_COUNT}."
            )
        except requests.exceptions.ConnectionError:
            print(f"[VirusTotal] 🌐 Connection error on attempt {attempt}.")
            send_discord_message(
                f"🌐 **VT connection error.** Attempt {attempt}/{RETRY_COUNT}."
            )
        except requests.RequestException as e:
            print(f"[VirusTotal] ❌ Error on attempt {attempt}: {e}")
            send_discord_message(
                f"❌ **VT upload error** (attempt {attempt}/{RETRY_COUNT}): `{e}`"
            )

        if attempt < RETRY_COUNT:
            print(f"[VirusTotal] Retrying in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)

    send_discord_message(
        f"❌ **VT upload failed after {RETRY_COUNT} attempts.** Giving up."
    )
    return None


def poll_virustotal(analysis_id: str, filename: str) -> dict | None:
    """
    Poll VirusTotal until analysis is complete, sending status updates to Discord.
    Returns the full 'attributes' dict, or None on timeout/error.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url     = VT_ANALYSIS_URL.format(analysis_id)

    print("[VirusTotal] Polling for results", end="", flush=True)

    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        time.sleep(POLL_INTERVAL_SECONDS)
        print(".", end="", flush=True)

        try:
            resp = requests.get(url, headers=headers, timeout=30)

            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", RETRY_DELAY))
                print(f"\n[VirusTotal] Rate limited during poll. Waiting {wait}s...")
                send_discord_message(
                    f"⏳ **VT polling rate limited.** Waiting {wait}s... "
                    f"(poll {attempt}/{MAX_POLL_ATTEMPTS})"
                )
                time.sleep(wait)
                continue

            resp.raise_for_status()
            data       = resp.json()["data"]
            attributes = data["attributes"]
            status     = attributes.get("status", "unknown")

            # Send periodic Discord update every 5 polls
            if attempt % 5 == 0:
                send_discord_message(
                    f"🔄 **Scan still in progress** for `{filename}`\n"
                    f"Poll: {attempt}/{MAX_POLL_ATTEMPTS} — Status: `{status}`\n"
                    f"Elapsed: ~{attempt * POLL_INTERVAL_SECONDS}s"
                )

            if status == "completed":
                print(" done.\n")
                return attributes

            print(f"[{status}]", end="", flush=True)

        except requests.exceptions.Timeout:
            print(f"\n[VirusTotal] ⏱ Timeout on poll {attempt}.")
            send_discord_message(
                f"⏱ **VT poll timed out** on attempt {attempt}/{MAX_POLL_ATTEMPTS}. Retrying..."
            )
        except requests.RequestException as e:
            print(f"\n[VirusTotal] ❌ Poll error: {e}")
            send_discord_message(
                f"❌ **VT poll error** (attempt {attempt}): `{e}`"
            )

    print("\n[VirusTotal] ⏱ Timed out waiting for results.")
    send_discord_message(
        f"⏱ **VT scan timed out** for `{filename}`\n"
        f"Gave up after {MAX_POLL_ATTEMPTS} polls "
        f"({MAX_POLL_ATTEMPTS * POLL_INTERVAL_SECONDS}s total)."
    )
    return None


# ─── RESULTS ──────────────────────────────────────────────────────────────────

def display_and_report_results(attributes: dict, file_path: str, file_hash: str) -> None:
    """Pretty-print scan results to console and send full summary to Discord."""
    stats   = attributes.get("stats", {})
    results = attributes.get("results", {})

    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    undetected  = stats.get("undetected", 0)
    total_scans = sum(stats.values())

    bar_len  = 40
    detected = malicious + suspicious
    bar_fill = int((detected / total_scans) * bar_len) if total_scans else 0
    bar      = "█" * bar_fill + "░" * (bar_len - bar_fill)

    filename = os.path.basename(file_path)

    # ── Console output ────────────────────────────────────────────────────────
    print("=" * 60)
    print("  VirusTotal Scan Report")
    print("=" * 60)
    print(f"  File    : {filename}")
    print(f"  SHA-256 : {file_hash}")
    print(f"  Scanned : {total_scans} engines")
    print()
    print(f"  [{bar}]")
    print(f"  Malicious  : {malicious:>4}")
    print(f"  Suspicious : {suspicious:>4}")
    print(f"  Undetected : {undetected:>4}")
    print()

    if malicious == 0 and suspicious == 0:
        verdict_console = "✅  Result: FILE IS SAFE — no engines flagged this file."
        verdict_discord = "✅ **SAFE** — No engines flagged this file."
    elif malicious < 3:
        verdict_console = (
            f"⚠️   Result: LOW RISK — {malicious} engine(s) flagged "
            f"(possible false positive)."
        )
        verdict_discord = (
            f"⚠️ **LOW RISK** — {malicious} engine(s) flagged "
            f"(possible false positive)."
        )
    else:
        verdict_console = (
            f"❌  Result: DETECTED — {malicious} engine(s) flagged this file as malicious."
        )
        verdict_discord = (
            f"❌ **DETECTED** — {malicious} engine(s) flagged this file as malicious."
        )

    print(f"  {verdict_console}")

    flagged = [
        (engine, info.get("result", "?"))
        for engine, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    ]

    if flagged:
        print()
        print("  Engines that flagged this file:")
        for engine, v in flagged:
            print(f"    • {engine:<25} {v}")

    print("=" * 60)

    # ── Discord summary ───────────────────────────────────────────────────────
    flagged_list = (
        "\n".join([f"  • `{engine}` → `{v}`" for engine, v in flagged[:10]])
        if flagged else "  None"
    )

    if len(flagged) > 10:
        flagged_list += f"\n  ... and {len(flagged) - 10} more"

    send_discord_message(
        f"📊 **VirusTotal Scan Complete**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📁 File: `{filename}`\n"
        f"🔑 SHA-256: `{file_hash}`\n"
        f"🔬 Engines: {total_scans} total\n"
        f"🔴 Malicious: {malicious}  "
        f"🟡 Suspicious: {suspicious}  "
        f"🟢 Clean: {undetected}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"**Verdict:** {verdict_discord}\n"
        f"**Flagged by:**\n{flagged_list}"
    )


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main() -> None:
    current_file = os.path.abspath(sys.argv[0])
    current_name = os.path.basename(current_file)
    current_hash = sha256_of_file(current_file)

    print(f"[Init] Running as  : {current_name}")
    print(f"[Init] SHA-256     : {current_hash}")
    print()

    # ── Step 1: Notify Discord of start ───────────────────────────────────────
    send_discord_message(
        f"🚀 **VT Demo Started**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📁 File: `{current_name}`\n"
        f"🔑 SHA-256: `{current_hash}`\n"
        f"⏳ Mutating and submitting in {INITIAL_WAIT_SECONDS}s..."
    )

    # ── Step 2: Wait ──────────────────────────────────────────────────────────
    print(f"[Wait] Sleeping {INITIAL_WAIT_SECONDS} seconds...")
    time.sleep(INITIAL_WAIT_SECONDS)

    # ── Step 3: Mutate file ───────────────────────────────────────────────────
    next_file = derive_next_filename(current_file)
    mutate_and_save(current_file, next_file)
    new_hash = sha256_of_file(next_file)

    print(f"[Hash] Old: {current_hash}")
    print(f"[Hash] New: {new_hash}")
    print(f"[Hash] Different: {current_hash != new_hash}")
    print()

    send_discord_message(
        f"🧬 **File Mutated Successfully**\n"
        f"Old name: `{current_name}`\n"
        f"Old hash: `{current_hash[:24]}...`\n"
        f"New name: `{os.path.basename(next_file)}`\n"
        f"New hash: `{new_hash[:24]}...`\n"
        f"Hashes differ: `{current_hash != new_hash}`\n"
        f"📤 Uploading to VirusTotal now..."
    )

    # ── Step 4: Upload to VirusTotal ──────────────────────────────────────────
    analysis_id = upload_to_virustotal(next_file)
    if not analysis_id:
        print("[Error] Upload failed. Exiting.")
        sys.exit(1)

    # ── Step 5: Poll for results ──────────────────────────────────────────────
    attributes = poll_virustotal(analysis_id, os.path.basename(next_file))
    if not attributes:
        print("[Error] Could not retrieve scan results.")
        sys.exit(1)

    # ── Step 6: Display + report results ─────────────────────────────────────
    display_and_report_results(attributes, next_file, new_hash)


if __name__ == "__main__":
    main()
