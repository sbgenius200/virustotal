import time
import io
import socket
import sys
import os
import requests
import mss
from datetime import datetime
from PIL import Image

# ─────────────────────────────────────────────
#  CONFIGURATION  –  edit these before use
# ─────────────────────────────────────────────
WEBHOOK_URL      = "https://discord.com/api/webhooks/1513875044202188930/dw8gsAdUGilAB9kqqafinDfc0JozomWSYErp8HOJcEKeBfLJ5oBW6IPCZd-6NDKFiArm"
INTERVAL_SECONDS = 10          # how often to capture (seconds)
IMAGE_QUALITY    = 60          # JPEG quality 1-95  (lower = smaller file)
MAX_WIDTH        = 1280        # resize if wider than this (0 = no resize)
# ─────────────────────────────────────────────

# Log to file next to the exe (works even with --noconsole)
LOG_PATH = os.path.join(os.path.dirname(sys.executable if getattr(sys, "frozen", False) else __file__), "exam_monitor.log")

def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-pc"


def capture_screenshot() -> bytes:
    """Take a screenshot using mss and return compressed JPEG bytes."""
    with mss.mss() as sct:
        # Capture all monitors combined
        monitor = sct.monitors[0]
        raw = sct.grab(monitor)
        img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")

    if MAX_WIDTH and img.width > MAX_WIDTH:
        ratio = MAX_WIDTH / img.width
        new_h = int(img.height * ratio)
        img = img.resize((MAX_WIDTH, new_h), Image.LANCZOS)

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=IMAGE_QUALITY, optimize=True)
    return buf.getvalue()


def send_to_discord(image_bytes: bytes, hostname: str, timestamp: str) -> bool:
    """Upload screenshot to the Discord webhook. Returns True on success."""
    # Replace colons in timestamp for safe filename
    safe_ts  = timestamp.replace(":", "-")
    filename = f"{hostname}_{safe_ts}.jpg"
    content  = f"🖥️ **{hostname}** — {timestamp}"

    try:
        resp = requests.post(
            WEBHOOK_URL,
            data    = {"content": content},
            files   = {"file": (filename, image_bytes, "image/jpeg")},
            timeout = 15,
        )
        if resp.status_code in (200, 204):
            return True
        else:
            log(f"Discord returned HTTP {resp.status_code}: {resp.text[:200]}")
            return False
    except requests.RequestException as exc:
        log(f"Request error: {exc}")
        return False


def monitor_loop():
    hostname = get_hostname()
    log(f"Exam Monitor started on '{hostname}' — interval={INTERVAL_SECONDS}s")
    log(f"Webhook URL: {WEBHOOK_URL[:60]}...")

    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            log("Capturing screenshot...")
            image_bytes = capture_screenshot()
            log(f"Screenshot size: {len(image_bytes)} bytes — sending to Discord...")
            success = send_to_discord(image_bytes, hostname, timestamp)
            log("✓ Sent successfully" if success else "✗ Send failed")
        except Exception as exc:
            log(f"Unexpected error: {exc}")

        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        monitor_loop()
    except KeyboardInterrupt:
        log("Stopped by user.")
