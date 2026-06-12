import time
import io
import socket
import threading
import requests
import pyautogui
from datetime import datetime
from PIL import Image

# ─────────────────────────────────────────────
#  CONFIGURATION  –  edit these before use
# ─────────────────────────────────────────────
WEBHOOK_URL      = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL_HERE"
INTERVAL_SECONDS = 10          # how often to capture (seconds)
IMAGE_QUALITY    = 60          # JPEG quality 1-95  (lower = smaller file)
MAX_WIDTH        = 1280        # resize if wider than this (0 = no resize)
# ─────────────────────────────────────────────

def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-pc"


def capture_screenshot() -> bytes:
    """Take a screenshot and return compressed JPEG bytes."""
    screenshot = pyautogui.screenshot()

    if MAX_WIDTH and screenshot.width > MAX_WIDTH:
        ratio  = MAX_WIDTH / screenshot.width
        new_h  = int(screenshot.height * ratio)
        screenshot = screenshot.resize((MAX_WIDTH, new_h), Image.LANCZOS)

    buf = io.BytesIO()
    screenshot.save(buf, format="JPEG", quality=IMAGE_QUALITY, optimize=True)
    return buf.getvalue()


def send_to_discord(image_bytes: bytes, hostname: str, timestamp: str) -> bool:
    """Upload screenshot to the Discord webhook. Returns True on success."""
    filename = f"{hostname}_{timestamp}.jpg"
    content  = f"🖥️ **{hostname}** — {timestamp}"

    try:
        resp = requests.post(
            WEBHOOK_URL,
            data    = {"content": content},
            files   = {"file": (filename, image_bytes, "image/jpeg")},
            timeout = 15,
        )
        return resp.status_code in (200, 204)
    except requests.RequestException as exc:
        print(f"[ERROR] Could not send screenshot: {exc}")
        return False


def monitor_loop():
    hostname = get_hostname()
    print(f"[INFO] Exam Monitor started on '{hostname}' — sending every {INTERVAL_SECONDS}s")

    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            image_bytes = capture_screenshot()
            success     = send_to_discord(image_bytes, hostname, timestamp)
            status      = "✓ sent" if success else "✗ failed"
            print(f"[{timestamp}] {status}")
        except Exception as exc:
            print(f"[{timestamp}] Unexpected error: {exc}")

        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    # Run in a daemon thread so Ctrl+C exits cleanly
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Exam Monitor stopped.")
