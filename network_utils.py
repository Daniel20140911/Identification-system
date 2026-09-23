"""區域網路與防火牆工具。"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import sys
import os
import threading
import time
import ipaddress
import urllib.parse
import urllib.request
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Callable

from pathlib import Path

from app_paths import data_dir, ensure_data_files, tools_dir

BASE_DIR = data_dir()
TOOLS_DIR = tools_dir()
CLOUDFLARED = TOOLS_DIR / "cloudflared.exe"
CLOUDFLARED_LOG = TOOLS_DIR / "cloudflared.log"
BORE = TOOLS_DIR / "bore.exe"
NGROK = TOOLS_DIR / "ngrok.exe"
NGROK_API = "http://127.0.0.1:4040/api/tunnels"
CLOUDFLARED_URL = (
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
)
BORE_URL = (
    "https://github.com/ekzhang/bore/releases/download/v0.6.0/bore-v0.6.0-x86_64-pc-windows-msvc.zip"
)
NGROK_URL = (
    "https://bin.equinox.io/a/cJk8dzafvmN/ngrok-v3-3.3.1-windows-amd64.zip"
)

FIREWALL_RULE = "物品辨識8080"
CF_URL_PATTERN = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com/?", re.I)
LOG_TIME_PATTERN = re.compile(r'"time":"([^"]+)"')
BORE_URL_PATTERN = re.compile(r"listening at bore\.pub:(\d+)", re.I)
NGROK_URL_PATTERN = re.compile(
    r"https://[a-z0-9-]+\.(?:ngrok-free\.(?:app|dev)|ngrok(?:-free)?\.(?:io|app|dev))/?",
    re.I,
)
TUNNEL_WAIT_TIMEOUT = 60.0
TUNNEL_STARTUP_TIMEOUT = 45.0
TUNNEL_DOMAIN_TIMEOUT = 25.0
TUNNEL_QUICK_RETRY = 25.0
TUNNEL_MAX_OPTIONAL_ATTEMPTS = 6
TUNNEL_BORE_DELAY = 15.0

_verify_cache: dict[str, tuple[bool, float]] = {}
_sticky_valid_until: dict[str, float] = {}
_dns_cache: dict[str, tuple[bool, float]] = {}
_cache_lock = threading.Lock()
VERIFY_CACHE_TTL_OK = 60.0
VERIFY_CACHE_TTL_FAIL = 5.0
DNS_CACHE_TTL = 90.0
DNS_CACHE_TTL_FAIL = 15.0
PING_TIMEOUT_FAST = 0.8
PING_TIMEOUT_FIXED = 1.5
STICKY_VALID_SECONDS = 50.0

_ensure_tunnel_lock = threading.Lock()
_last_tunnel_restart_at = 0.0
_rate_limit_until = 0.0
_last_rate_limit_notice_at = 0.0
TUNNEL_RESTART_COOLDOWN = 45.0
TUNNEL_RATE_LIMIT_COOLDOWN = 300.0

_tunnel_url: str | None = None
_last_known_tunnel_url: str | None = None
_tunnel_url_pinned: bool = False
_tunnel_procs: list[subprocess.Popen] = []
_tunnel_starting = False
_tunnel_lock = threading.Lock()
_on_tunnel_dead: Callable[[], None] | None = None


def set_tunnel_dead_callback(callback: Callable[[], None] | None) -> None:
    global _on_tunnel_dead
    _on_tunnel_dead = callback


def get_tunnel_url() -> str | None:
    with _tunnel_lock:
        return _tunnel_url


def get_last_known_tunnel_url() -> str | None:
    with _tunnel_lock:
        return _last_known_tunnel_url


def local_server_ready(port: int | None = None, timeout: float = 0.8) -> bool:
    port = int(port or _read_config().get("port") or 8080)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/ping",
            headers={"User-Agent": "hardware-recognizer/1.0", "Connection": "close"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def is_tunnel_process_running() -> bool:
    with _tunnel_lock:
        procs = list(_tunnel_procs)
    if any(p.poll() is None for p in procs):
        return True
    mode = tunnel_mode()
    if mode == "ngrok":
        return _ngrok_process_running()
    if mode in ("fixed", "cloudflare"):
        return _cloudflared_process_running()
    return _cloudflared_process_running() and tunnel_connection_registered()


def is_tunnel_alive() -> bool:
    port = int(_read_config().get("port") or 8080)
    if not local_server_ready(port):
        return False
    return is_tunnel_process_running()


def cloudflared_running() -> bool:
    return _cloudflared_process_running()


def _cloudflared_process_count() -> int:
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq cloudflared.exe", "/NH"],
                encoding="utf-8",
                errors="ignore",
                timeout=8,
            )
            return sum(1 for line in out.splitlines() if "cloudflared.exe" in line.lower())
        except (OSError, subprocess.SubprocessError):
            return 0
    try:
        out = subprocess.check_output(["pgrep", "-x", "cloudflared"], encoding="utf-8", errors="ignore", timeout=5)
        return len([ln for ln in out.splitlines() if ln.strip()])
    except (OSError, subprocess.SubprocessError, FileNotFoundError):
        return 0


def ensure_single_cloudflared(port: int, cfg: dict | None = None) -> None:
    """只保留一個 cloudflared；網址以 cloudflared 日誌為準，不因不符而重建。"""
    global _tunnel_procs
    cfg = cfg or _read_config()
    count = _cloudflared_process_count()
    if count == 0:
        return
    pinned = fixed_external_url(cfg)
    live = read_trycloudflare_url_from_log()
    if count > 1:
        stop_tunnel(fast=True)
        kill_all_cloudflared()
        with _tunnel_lock:
            _tunnel_procs = []
        time.sleep(0.2)
        return
    if pinned and live and pinned.rstrip("/") != live.rstrip("/"):
        reconcile_pinned_trycloudflare_url(cfg)
        live = read_trycloudflare_url_from_log() or live
    use = (live or pinned or "").strip().rstrip("/")
    if use:
        _pin_tunnel_url(use)
        _set_tunnel_url(use, force=True)


def _cloudflared_process_running() -> bool:
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq cloudflared.exe", "/NH"],
                encoding="utf-8",
                errors="ignore",
                timeout=8,
            )
            return "cloudflared.exe" in out.lower()
        except (OSError, subprocess.SubprocessError):
            return False
    try:
        out = subprocess.check_output(["pgrep", "-x", "cloudflared"], encoding="utf-8", errors="ignore", timeout=5)
        return bool(out.strip())
    except (OSError, subprocess.SubprocessError, FileNotFoundError):
        return False


def is_tunnel_starting() -> bool:
    with _tunnel_lock:
        return _tunnel_starting


def _mark_tunnel_not_starting() -> None:
    global _tunnel_starting
    with _tunnel_lock:
        _tunnel_starting = False


def _last_429_timestamp(text: str) -> float | None:
    from datetime import datetime

    last_ts: float | None = None
    for line in text.splitlines()[-400:]:
        if "429 Too Many Requests" not in line and "error code: 1015" not in line:
            continue
        match = LOG_TIME_PATTERN.search(line)
        if not match:
            continue
        try:
            ts = match.group(1).replace("Z", "+00:00")
            last_ts = datetime.fromisoformat(ts).timestamp()
        except ValueError:
            continue
    return last_ts


def _refresh_rate_limit_from_log(text: str | None = None) -> None:
    global _rate_limit_until
    if text is None:
        if not CLOUDFLARED_LOG.exists():
            _rate_limit_until = 0.0
            return
        try:
            text = CLOUDFLARED_LOG.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
    last_429 = _last_429_timestamp(text or "")
    if last_429 is None:
        _rate_limit_until = 0.0
        return
    age = time.time() - last_429
    if age > TUNNEL_RATE_LIMIT_COOLDOWN:
        _rate_limit_until = 0.0
        return
    _rate_limit_until = last_429 + TUNNEL_RATE_LIMIT_COOLDOWN


def is_tunnel_rate_limited() -> bool:
    _refresh_rate_limit_from_log()
    return time.time() < _rate_limit_until


def tunnel_rate_limit_remaining() -> int:
    _refresh_rate_limit_from_log()
    return max(0, int(_rate_limit_until - time.time()))


def _print_rate_limit_notice() -> None:
    global _last_rate_limit_notice_at
    now = time.time()
    if now - _last_rate_limit_notice_at < 30.0:
        return
    _last_rate_limit_notice_at = now
    remaining = tunnel_rate_limit_remaining()
    mins = max(1, (remaining + 59) // 60)
    print("!" * 44)
    print("Cloudflare 暫時限制 trycloudflare 請求（請求過於頻繁）")
    print(f"請等待約 {mins} 分鐘，期間請勿按「快速換外網」")
    print("WiFi 連線仍可正常使用")
    print("!" * 44)


def is_external_url_pinned(cfg: dict | None = None) -> bool:
    """外網網址一旦鎖定，不再自動換域（auto／fixed 皆適用）。"""
    cfg = cfg or _read_config()
    if cfg.get("external_url_pinned") is False:
        return False
    url = (cfg.get("external_url") or "").strip().rstrip("/")
    if not url:
        return False
    mode = tunnel_mode(cfg)
    if mode == "fixed":
        return True
    return bool(cfg.get("external_url_pinned"))


def pinned_external_url(cfg: dict | None = None) -> str:
    if is_external_url_pinned(cfg):
        return fixed_external_url(cfg)
    return ""


def _maybe_persist_tunnel_url(url: str) -> None:
    """cloudflared 一回報網址就寫入 config（首次或重建完成後）。"""
    url = (url or "").strip().rstrip("/")
    if not url or "trycloudflare.com" not in url:
        return
    if is_external_url_pinned():
        return
    cfg_file = BASE_DIR / "config.json"
    try:
        import json

        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        current = (data.get("external_url") or "").strip().rstrip("/")
        if not current:
            _sticky_save_external_url(url)
            return
        if is_tunnel_starting():
            return
        if current != url:
            _sticky_save_external_url(url)
    except (OSError, json.JSONDecodeError, TypeError):
        pass


def _pin_tunnel_url(url: str) -> None:
    """鎖定外網網址，避免 log / stdout 互相覆寫造成換域。"""
    global _tunnel_url, _last_known_tunnel_url, _tunnel_url_pinned
    url = (url or "").strip().rstrip("/")
    if not url:
        return
    with _tunnel_lock:
        _tunnel_url = url
        _last_known_tunnel_url = url
        _tunnel_url_pinned = True


def _unpin_if_dead() -> None:
    """若鎖定的網址 DNS 已失效，解除鎖定以便 cloudflared 回報新網址。"""
    global _tunnel_url_pinned, _tunnel_url
    if is_external_url_pinned():
        pinned = pinned_external_url()
        if pinned:
            _pin_tunnel_url(pinned)
        return
    with _tunnel_lock:
        if not _tunnel_url_pinned:
            return
        current = (_tunnel_url or "").strip().rstrip("/")
        if current and not dns_resolves(current):
            _tunnel_url_pinned = False
            _tunnel_url = None
            _clear_verify_cache()


def _set_tunnel_url(url: str | None, *, force: bool = False) -> None:
    global _tunnel_url, _last_known_tunnel_url, _tunnel_url_pinned
    saved_url: str | None = None
    cfg = _read_config()
    pinned = pinned_external_url(cfg)
    _unpin_if_dead()
    with _tunnel_lock:
        if not url:
            return
        if pinned and not force:
            url = pinned
        url = url.rstrip("/")
        _last_known_tunnel_url = url
        if pinned:
            _tunnel_url = url
            _tunnel_url_pinned = True
            return
        if _tunnel_url_pinned and not force:
            current = (_tunnel_url or "").rstrip("/")
            if current and dns_resolves(current):
                return
            _tunnel_url_pinned = False
        if not _tunnel_url:
            _tunnel_url = url
            saved_url = url
        else:
            current = _tunnel_url.rstrip("/")
            if current == url:
                return
            new_cf = "trycloudflare.com" in url
            old_cf = "trycloudflare.com" in current
            if new_cf and old_cf and not force:
                return
            if new_cf and (not old_cf or url != current):
                _tunnel_url = url
                _clear_verify_cache()
                saved_url = url
            elif url.startswith("https://") and current.startswith("http://"):
                _tunnel_url = url
                _clear_verify_cache()
                saved_url = url
            elif url != current:
                _tunnel_url = url
                _clear_verify_cache()
                saved_url = url
    if saved_url and not is_external_url_pinned(cfg):
        threading.Thread(target=_maybe_persist_tunnel_url, args=(saved_url,), daemon=True).start()


def _register_proc(proc: subprocess.Popen) -> None:
    with _tunnel_lock:
        _tunnel_procs.append(proc)


def is_well_formed_external_url(url: str) -> bool:
    if not url or url.count("://") != 1:
        return False
    parsed = urllib.parse.urlparse(url.strip())
    host = (parsed.hostname or "").strip()
    if not host or not parsed.scheme.startswith("http"):
        return False
    if re.search(r"https?://", host, re.I):
        return False
    if any(c in url for c in (" ", "\n", "\t")):
        return False
    return True


def is_public_external_url(url: str) -> bool:
    """外網必須是公開網址，不可為區域 IP 或 localhost。"""
    if not is_well_formed_external_url(url):
        return False
    parsed = urllib.parse.urlparse(url.strip())
    host = (parsed.hostname or "").lower().strip(".")
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    except ValueError:
        if host.endswith(".local") or host.endswith(".lan"):
            return False
    return True


def external_url_reject_reason(url: str) -> str | None:
    if not url:
        return None
    if is_public_external_url(url):
        return None
    return (
        "外網不可使用區域 IP（如 10.44.60.47、192.168.x）或 localhost。"
        "請改用 trycloudflare、ngrok 等工具的公開 HTTPS 網址。"
    )


def _clear_verify_cache() -> None:
    with _cache_lock:
        _verify_cache.clear()
        _dns_cache.clear()
        _sticky_valid_until.clear()


def tunnel_connection_registered() -> bool:
    """cloudflared 日誌已出現 Registered tunnel connection（本機 ping 常失敗但隧道仍可用）。"""
    if not CLOUDFLARED_LOG.exists():
        return False
    try:
        tail = CLOUDFLARED_LOG.read_text(encoding="utf-8", errors="replace")[-8000:]
    except OSError:
        return False
    return "Registered tunnel connection" in tail


def auto_tunnel_is_connected(url: str) -> bool:
    """auto 模式：cloudflared 在跑、網址一致，且已在 Cloudflare 註冊（避免 Error 1033）。"""
    url = (url or "").strip().rstrip("/")
    if not url or not is_tunnel_alive():
        return False
    current = (get_reported_tunnel_url() or get_tunnel_url() or "").strip().rstrip("/")
    if not current or url != current:
        return False
    return tunnel_connection_registered()


def is_tunnel_ready_for_use(url: str) -> bool:
    """外網可用：cloudflared 在跑，且為本次回報的網址。"""
    url = (url or "").strip().rstrip("/")
    if not url or not is_tunnel_alive():
        return False
    live = (get_tunnel_url() or "").strip().rstrip("/")
    if live and url != live:
        return False
    return True


def get_reported_tunnel_url(cfg: dict | None = None) -> str | None:
    """cloudflared 本次回報的網址（不要求 DNS）。"""
    _unpin_if_dead()
    url = get_tunnel_url()
    if url:
        return url.rstrip("/")
    synced = _sync_tunnel_url_from_log()
    if synced:
        return synced.rstrip("/")
    return None


def ping_tunnel_reliable(url: str, timeout: float = PING_TIMEOUT_FAST) -> bool:
    if ping_tunnel_once(url, timeout):
        return True
    time.sleep(0.12)
    return ping_tunnel_once(url, timeout)


def dns_resolves(url: str) -> bool:
    host = urllib.parse.urlparse(url).hostname
    port = urllib.parse.urlparse(url).port or (443 if url.startswith("https") else 80)
    if not host:
        return False
    now = time.time()
    with _cache_lock:
        cached = _dns_cache.get(host)
        if cached and now - cached[1] < DNS_CACHE_TTL:
            return cached[0]
    try:
        socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ok = True
    except OSError:
        ok = False
    ttl = DNS_CACHE_TTL if ok else DNS_CACHE_TTL_FAIL
    with _cache_lock:
        _dns_cache[host] = (ok, now)
    return ok


def external_url_is_dead(url: str) -> bool:
    if not url:
        return True
    return not dns_resolves(url)


def ping_tunnel_once(url: str, timeout: float = PING_TIMEOUT_FAST) -> bool:
    target = f"{url.rstrip('/')}/api/ping"
    try:
        req = urllib.request.Request(
            target,
            headers={"User-Agent": "hardware-recognizer/1.0", "Connection": "close"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def verify_tunnel_url(url: str, timeout: float = 5.0, quick: bool = False) -> bool:
    if quick:
        return ping_tunnel_once(url, min(timeout, PING_TIMEOUT_FAST))
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ping_tunnel_once(url, PING_TIMEOUT_FAST):
            return True
        time.sleep(0.25)
    return False


def _is_tunnel_url_live_uncached(url: str, mode: str) -> bool:
    if not url:
        return False
    url = url.rstrip("/")
    mode = mode.lower()
    port = int(_read_config().get("port") or 8080)
    if not local_server_ready(port):
        return False
    if not dns_resolves(url):
        return False
    if mode == "fixed":
        if "trycloudflare.com" in url and is_external_url_pinned():
            if not is_tunnel_alive():
                return False
            live = read_trycloudflare_url_from_log()
            if live and url.rstrip("/") != live.rstrip("/"):
                return False
            return ping_tunnel_reliable(url, PING_TIMEOUT_FIXED)
        return ping_tunnel_reliable(url, PING_TIMEOUT_FIXED)
    if mode == "cloudflare":
        if not is_tunnel_alive():
            return False
        expected = fixed_external_url().rstrip("/")
        if expected and url.rstrip("/") != expected:
            return False
        if ping_tunnel_reliable(url, PING_TIMEOUT_FAST):
            return True
        return tunnel_connection_registered()
    if mode == "ngrok":
        if not _ngrok_process_running():
            return False
        live = read_ngrok_public_url()
        return bool(live and url.rstrip("/") == live.rstrip("/"))
    # auto：須 cloudflared 在跑、DNS 可解析，且外網 ping 成功
    if not dns_resolves(url):
        return False
    if not auto_tunnel_is_connected(url):
        return False
    return ping_tunnel_once(url, PING_TIMEOUT_FAST)


def _sticky_valid_active(url: str, mode: str) -> bool:
    url_key = url.rstrip("/")
    now = time.time()
    with _cache_lock:
        until = _sticky_valid_until.get(url_key, 0)
    if until <= now:
        return False
    if mode != "fixed" and not is_tunnel_alive():
        with _cache_lock:
            _sticky_valid_until.pop(url_key, None)
        return False
    if mode == "auto" and not auto_tunnel_is_connected(url_key):
        with _cache_lock:
            _sticky_valid_until.pop(url_key, None)
        return False
    if not dns_resolves(url):
        with _cache_lock:
            _sticky_valid_until.pop(url_key, None)
        return False
    return True


def is_tunnel_url_live(url: str, mode: str | None = None) -> bool:
    if not url:
        return False
    mode = (mode or tunnel_mode()).lower()
    url_key = url.rstrip("/")
    key = f"{mode}:{url_key}"
    now = time.time()

    if _sticky_valid_active(url_key, mode):
        return True

    with _cache_lock:
        cached = _verify_cache.get(key)
        if cached:
            ttl = VERIFY_CACHE_TTL_OK if cached[0] else VERIFY_CACHE_TTL_FAIL
            if now - cached[1] < ttl:
                return cached[0]

    ok = _is_tunnel_url_live_uncached(url, mode)
    with _cache_lock:
        _verify_cache[key] = (ok, now)
        if ok:
            _sticky_valid_until[url_key] = now + STICKY_VALID_SECONDS
    return ok


def kill_all_cloudflared() -> None:
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "cloudflared.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            pass


def kill_all_bore() -> None:
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "bore.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            pass


def kill_all_ngrok() -> None:
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "ngrok.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            pass


def _ngrok_process_running() -> bool:
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq ngrok.exe", "/NH"],
                encoding="utf-8",
                errors="ignore",
                timeout=8,
            )
            return "ngrok.exe" in out.lower()
        except (OSError, subprocess.SubprocessError):
            return False
    try:
        out = subprocess.check_output(["pgrep", "-x", "ngrok"], encoding="utf-8", errors="ignore", timeout=5)
        return bool(out.strip())
    except (OSError, subprocess.SubprocessError, FileNotFoundError):
        return False


def stop_tunnel(fast: bool = False) -> None:
    global _tunnel_procs, _tunnel_starting, _tunnel_url_pinned
    _clear_verify_cache()
    with _tunnel_lock:
        procs = list(_tunnel_procs)
        _tunnel_procs = []
        _tunnel_url = None
        _tunnel_starting = False
        _tunnel_url_pinned = False
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=0.8 if fast else 2)
            except subprocess.TimeoutExpired:
                proc.kill()
    if not fast:
        kill_all_cloudflared()
        kill_all_bore()
        kill_all_ngrok()


def shutdown_tunnel() -> None:
    stop_tunnel()


_firewall_cache: dict[int, tuple[bool, float]] = {}
FIREWALL_CACHE_TTL = 120.0


def firewall_rule_exists(port: int = 8080) -> bool:
    now = time.time()
    cached = _firewall_cache.get(port)
    if cached and now - cached[1] < FIREWALL_CACHE_TTL:
        return cached[0]
    try:
        out = subprocess.check_output(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={FIREWALL_RULE}"],
            encoding="utf-8",
            errors="ignore",
        )
    except (OSError, subprocess.SubprocessError):
        _firewall_cache[port] = (False, now)
        return False
    if "No rules match" in out:
        _firewall_cache[port] = (False, now)
        return False
    ok = str(port) in out
    _firewall_cache[port] = (ok, now)
    return ok


def add_firewall_rule(port: int = 8080) -> bool:
    try:
        subprocess.check_call(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={FIREWALL_RULE}", "dir=in", "action=allow",
                "protocol=TCP", f"localport={port}", "profile=any", "enable=yes",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def ensure_firewall(port: int = 8080) -> dict:
    if firewall_rule_exists(port):
        return {"ok": True, "message": "防火牆已開放"}
    if add_firewall_rule(port):
        return {"ok": True, "message": "已自動開放防火牆"}
    return {"ok": False, "message": "防火牆未開放，請以系統管理員執行「開啟防火牆.bat」"}


def _download(url: str, dest: Path, label: str) -> Path | None:
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        print(f"下載 {label}（僅首次）...")
        urllib.request.urlretrieve(url, dest)
        return dest
    except Exception as e:
        print(f"{label} 下載失敗: {e}")
        return None


def ensure_cloudflared() -> Path | None:
    return _download(CLOUDFLARED_URL, CLOUDFLARED, "cloudflared")


def ensure_bore() -> Path | None:
    if BORE.exists():
        return BORE
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        print("下載 bore（僅首次）...")
        data = urllib.request.urlopen(BORE_URL, timeout=60).read()
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for name in zf.namelist():
                if Path(name).name.lower() != "bore.exe":
                    continue
                target = TOOLS_DIR / "bore.exe"
                with zf.open(name) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                return target
    except Exception as e:
        print(f"bore 下載失敗: {e}")
    return None


def _find_ngrok_exe() -> Path | None:
    if NGROK.exists():
        return NGROK
    winget = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links" / "ngrok.exe"
    if winget.exists():
        return winget
    found = shutil.which("ngrok")
    return Path(found) if found else None


def ensure_ngrok() -> Path | None:
    found = _find_ngrok_exe()
    if not found:
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            print("下載 ngrok（僅首次）...")
            data = urllib.request.urlopen(NGROK_URL, timeout=90).read()
            with zipfile.ZipFile(BytesIO(data)) as zf:
                for name in zf.namelist():
                    if Path(name).name.lower() != "ngrok.exe":
                        continue
                    with zf.open(name) as src, open(NGROK, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    return NGROK
        except Exception as e:
            print(f"ngrok 下載失敗: {e}")
            return None
    if found != NGROK:
        try:
            TOOLS_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(found, NGROK)
            return NGROK
        except OSError:
            return found
    return found


def read_ngrok_public_url() -> str | None:
    import json

    try:
        with urllib.request.urlopen(NGROK_API, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        for tunnel in data.get("tunnels") or []:
            url = (tunnel.get("public_url") or "").strip().rstrip("/")
            if url.startswith("https://") and is_ngrok_public_url(url):
                return url
    except Exception:
        return None
    return None


def _on_ngrok_output_line(line: str) -> None:
    match = NGROK_URL_PATTERN.search(line)
    if match:
        _set_tunnel_url(match.group(0).rstrip("/"))


def _start_ngrok(port: int, exe: Path, authtoken: str) -> None:
    kill_all_ngrok()
    kill_all_cloudflared()
    kill_all_bore()
    try:
        CLOUDFLARED_LOG.parent.mkdir(parents=True, exist_ok=True)
        CLOUDFLARED_LOG.write_text("", encoding="utf-8")
    except OSError:
        pass
    time.sleep(0.15)
    env = os.environ.copy()
    env["NGROK_AUTHTOKEN"] = authtoken
    try:
        proc = subprocess.Popen(
            [
                str(exe),
                "http",
                str(port),
                "--log=stdout",
                "--region=ap",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError:
        return
    _register_proc(proc)
    threading.Thread(target=_drain_output, args=(proc.stdout, _on_ngrok_output_line), daemon=True).start()


def wait_for_ngrok_url(timeout: float = 20.0) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        url = read_ngrok_public_url()
        if url:
            _set_tunnel_url(url.rstrip("/"))
            return url.rstrip("/")
        mem = get_tunnel_url()
        if mem and is_ngrok_public_url(mem):
            return mem.rstrip("/")
        if not _ngrok_process_running():
            break
        time.sleep(0.12)
    return None


def _drain_output(stream, on_line) -> None:
    if not stream:
        return
    try:
        for raw in stream:
            if isinstance(raw, bytes):
                line = raw.decode("utf-8", errors="replace")
            else:
                line = raw
            on_line(line)
    except (OSError, UnicodeError, ValueError):
        pass


def _on_output_line(line: str) -> None:
    match = CF_URL_PATTERN.search(line)
    if match:
        _set_tunnel_url(match.group(0).rstrip("/"))
        return
    if get_tunnel_url() and "trycloudflare.com" in get_tunnel_url():
        return
    bore = BORE_URL_PATTERN.search(line)
    if bore:
        _set_tunnel_url(f"http://bore.pub:{bore.group(1)}")


def _start_cloudflared(port: int, exe: Path) -> None:
    try:
        CLOUDFLARED_LOG.parent.mkdir(parents=True, exist_ok=True)
        CLOUDFLARED_LOG.write_text("", encoding="utf-8")
    except OSError:
        pass
    try:
        proc = subprocess.Popen(
            [
                str(exe),
                "tunnel",
                "--url",
                f"http://127.0.0.1:{port}",
                "--no-autoupdate",
                "--logfile",
                str(CLOUDFLARED_LOG),
                "--loglevel",
                "info",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError:
        return
    _register_proc(proc)
    threading.Thread(target=_drain_output, args=(proc.stdout, _on_output_line), daemon=True).start()


def _start_bore(port: int, exe: Path) -> None:
    try:
        proc = subprocess.Popen(
            [str(exe), "local", str(port), "--to", "bore.pub"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError:
        return
    _register_proc(proc)
    threading.Thread(target=_drain_output, args=(proc.stdout, _on_output_line), daemon=True).start()


def _read_config() -> dict:
    import json

    path = BASE_DIR / "config.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def tunnel_mode(cfg: dict | None = None) -> str:
    cfg = cfg or _read_config()
    return (cfg.get("tunnel_mode") or "auto").strip().lower()


def fixed_external_url(cfg: dict | None = None) -> str:
    cfg = cfg or _read_config()
    url = (cfg.get("external_url") or "").strip().rstrip("/")
    if url:
        return url
    if tunnel_mode(cfg) != "cloudflare":
        return ""
    domain = (cfg.get("custom_domain") or "").strip().replace("_", "-")
    return f"https://{domain}".rstrip("/") if domain else ""


def cloudflare_token_looks_valid(token: str, cfg: dict | None = None) -> bool:
    token = (token or "").strip()
    if len(token) < 50:
        return False
    cfg = cfg or _read_config()
    pwd = (cfg.get("access_password") or "").strip()
    if pwd and token == pwd:
        return False
    if " " in token or "\n" in token:
        return False
    if token.startswith("eyJ") and token.count(".") >= 2:
        return True
    return len(token) >= 80


def ngrok_authtoken_looks_valid(token: str) -> bool:
    token = (token or "").strip()
    if len(token) < 20 or len(token) > 120:
        return False
    if " " in token or "\n" in token:
        return False
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", token):
        return False
    lower = token.lower()
    if "ngrok" in lower or "authtoken" in lower or "失敗" in token or "請確認" in token:
        return False
    return True


def is_ngrok_public_url(url: str) -> bool:
    host = (urllib.parse.urlparse((url or "").strip()).hostname or "").lower()
    if not host:
        return False
    return host.endswith((
        ".ngrok-free.app",
        ".ngrok-free.dev",
        ".ngrok.io",
        ".ngrok.app",
        ".ngrok.dev",
    ))


def prepare_tunnel_tools() -> bool:
    """預先下載 cloudflared，縮短啟動等待。"""
    return ensure_cloudflared() is not None


def _start_cloudflared_token(token: str) -> None:
    exe = ensure_cloudflared()
    if not exe:
        return
    try:
        CLOUDFLARED_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(CLOUDFLARED_LOG, "a", encoding="utf-8"):
            pass
    except OSError:
        pass
    try:
        proc = subprocess.Popen(
            [
                str(exe),
                "tunnel",
                "run",
                "--token",
                token,
                "--no-autoupdate",
                "--logfile",
                str(CLOUDFLARED_LOG),
                "--loglevel",
                "info",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError:
        return
    _register_proc(proc)
    threading.Thread(target=_drain_output, args=(proc.stdout, _on_output_line), daemon=True).start()


def is_permanent_tunnel_mode(cfg: dict | None = None) -> bool:
    mode = tunnel_mode(cfg)
    return mode in ("fixed", "cloudflare")


_permanent_watchdog_started = False
_ngrok_fail_logged = False
_ngrok_last_fail_at = 0.0
NGROK_FAIL_COOLDOWN = 300.0


def start_permanent_tunnel_watchdog(port: int) -> None:
    """固定／永久外網：cloudflared 斷線或與本機伺服器脫鉤時自動重連。"""
    global _permanent_watchdog_started
    if _permanent_watchdog_started:
        return
    _permanent_watchdog_started = True

    def _loop() -> None:
        while True:
            try:
                cfg = _read_config()
                mode = tunnel_mode(cfg)
                if mode not in ("fixed", "cloudflare", "ngrok"):
                    time.sleep(25)
                    continue
                if not local_server_ready(port):
                    time.sleep(15)
                    continue
                if mode == "ngrok":
                    token = (cfg.get("ngrok_authtoken") or "").strip()
                    if not ngrok_authtoken_looks_valid(token):
                        time.sleep(25)
                        continue
                    if time.time() - _ngrok_last_fail_at < NGROK_FAIL_COOLDOWN:
                        time.sleep(25)
                        continue
                    if not _ngrok_process_running():
                        start_tunnel(port, bore_fallback=False, cfg=cfg)
                    else:
                        url = read_ngrok_public_url()
                        if url:
                            _set_tunnel_url(url)
                            if not is_external_url_pinned(cfg):
                                _sticky_save_external_url(url)
                    continue
                if mode == "auto" and is_external_url_pinned(cfg):
                    url = fixed_external_url(cfg)
                    if not url:
                        time.sleep(25)
                        continue
                    ensure_single_cloudflared(port, cfg)
                    if not is_tunnel_process_running():
                        start_tunnel(port, bore_fallback=False, cfg=cfg)
                    elif "trycloudflare.com" in url:
                        reconcile_pinned_trycloudflare_url(cfg)
                        if not is_tunnel_process_running():
                            start_tunnel(port, bore_fallback=False, cfg=cfg)
                    continue
                url = fixed_external_url(cfg)
                if mode == "cloudflare":
                    token = (cfg.get("cloudflare_tunnel_token") or "").strip()
                    if not token or not url:
                        time.sleep(25)
                        continue
                elif not url:
                    time.sleep(25)
                    continue
                ensure_single_cloudflared(port, cfg)
                if not is_tunnel_process_running():
                    start_tunnel(port, bore_fallback=False, cfg=cfg)
                elif mode == "fixed" and url and "trycloudflare.com" in url:
                    if external_url_is_dead(url) or not ping_tunnel_reliable(url, PING_TIMEOUT_FIXED):
                        reconcile_fixed_trycloudflare_url(cfg)
            except Exception:
                pass
            time.sleep(20)

    threading.Thread(target=_loop, name="tunnel-watchdog", daemon=True).start()


def start_tunnel(port: int, bore_fallback: bool = False, cfg: dict | None = None) -> threading.Thread | None:
    global _tunnel_starting
    cfg = cfg or _read_config()
    mode = tunnel_mode(cfg)

    if mode == "fixed":
        url = fixed_external_url(cfg)
        if url:
            _pin_tunnel_url(url)
            _set_tunnel_url(url, force=True)
        if url and "trycloudflare.com" in url and not is_tunnel_process_running():
            if is_tunnel_rate_limited():
                with _tunnel_lock:
                    _tunnel_starting = False
                return None
            cf = ensure_cloudflared()
            if cf:
                with _tunnel_lock:
                    _tunnel_starting = True
                _start_cloudflared(port, cf)
            else:
                with _tunnel_lock:
                    _tunnel_starting = False
                return None
        else:
            with _tunnel_lock:
                _tunnel_starting = False
        return None

    if mode == "auto":
        saved = fixed_external_url(cfg)
        if is_external_url_pinned(cfg) and saved:
            _pin_tunnel_url(saved)
            _set_tunnel_url(saved, force=True)
            if "trycloudflare.com" in saved and not is_tunnel_process_running():
                if is_tunnel_rate_limited():
                    with _tunnel_lock:
                        _tunnel_starting = False
                    return None
                cf = ensure_cloudflared()
                if cf:
                    with _tunnel_lock:
                        _tunnel_starting = True
                    _start_cloudflared(port, cf)
                else:
                    with _tunnel_lock:
                        _tunnel_starting = False
                    return None
            else:
                with _tunnel_lock:
                    _tunnel_starting = False
            return None
        if is_tunnel_alive():
            live = (get_tunnel_url() or "").strip().rstrip("/")
            if live:
                _pin_tunnel_url(live)
            elif saved:
                _pin_tunnel_url(saved)
            with _tunnel_lock:
                _tunnel_starting = False
            return None

    stop_tunnel()

    if mode == "ngrok":
        global _ngrok_fail_logged, _ngrok_last_fail_at
        token = (cfg.get("ngrok_authtoken") or "").strip()
        if not ngrok_authtoken_looks_valid(token):
            if not _ngrok_fail_logged:
                print("ngrok Authtoken 格式不正確，請到 dashboard.ngrok.com 重新複製")
                _ngrok_fail_logged = True
            return None
        exe = ensure_ngrok()
        if not exe:
            return None
        with _tunnel_lock:
            _tunnel_starting = True

        def _run_ngrok() -> None:
            global _tunnel_starting, _ngrok_fail_logged, _ngrok_last_fail_at
            _start_ngrok(port, exe, token)
            url = wait_for_ngrok_url(10.0)
            if not url:
                _start_ngrok(port, exe, token)
                url = wait_for_ngrok_url(6.0)
            if url and is_ngrok_public_url(url):
                _ngrok_fail_logged = False
                _ngrok_last_fail_at = 0.0
                _sticky_save_external_url(url)
                print(f"ngrok 外網: {url}")
            else:
                url = None
                _ngrok_last_fail_at = time.time()
                if not _ngrok_fail_logged:
                    print("ngrok 外網建立失敗，請確認 Authtoken 是否正確")
                    _ngrok_fail_logged = True
            with _tunnel_lock:
                _tunnel_starting = False

        thread = threading.Thread(target=_run_ngrok, name="ngrok-starter", daemon=True)
        thread.start()
        return thread

    if mode == "cloudflare":
        token = (cfg.get("cloudflare_tunnel_token") or "").strip()
        url = fixed_external_url(cfg)
        if not token or not url:
            print("Cloudflare 自訂模式：請在 config.json 設定 cloudflare_tunnel_token 與 external_url")
            return None
        _set_tunnel_url(url)
        with _tunnel_lock:
            _tunnel_starting = True
        _start_cloudflared_token(token)
        if not is_tunnel_alive():
            with _tunnel_lock:
                _tunnel_starting = False
            return None
        thread = threading.Thread(target=lambda: None, name="tunnel-starter", daemon=True)
        thread.start()
        return thread

    cf = ensure_cloudflared()
    bore = ensure_bore() if bore_fallback else None
    if not cf and not bore:
        return None

    with _tunnel_lock:
        _tunnel_starting = True

    def _run() -> None:
        global _tunnel_starting
        if cf:
            _start_cloudflared(port, cf)
            if bore_fallback and bore:
                deadline = time.time() + TUNNEL_BORE_DELAY
                while time.time() < deadline and not get_tunnel_url():
                    if not is_tunnel_alive():
                        break
                    time.sleep(0.3)
                if bore and not get_tunnel_url():
                    _start_bore(port, bore)
        elif bore:
            _start_bore(port, bore)
        if not is_tunnel_alive():
            with _tunnel_lock:
                _tunnel_starting = False

    thread = threading.Thread(target=_run, name="tunnel-starter", daemon=True)
    thread.start()
    return thread


_last_log_sync_at: float = 0.0


def read_trycloudflare_url_from_log() -> str | None:
    """從 cloudflared 日誌讀取本次連線的 trycloudflare 網址（不寫入 config）。"""
    if not CLOUDFLARED_LOG.exists():
        return None
    try:
        size = CLOUDFLARED_LOG.stat().st_size
        with open(CLOUDFLARED_LOG, "rb") as f:
            f.seek(max(0, size - 8192))
            text = f.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    for line in reversed(text.splitlines()[-120:]):
        if "429 Too Many Requests" in line or "error code: 1015" in line:
            continue
        match = CF_URL_PATTERN.search(line)
        if match:
            return match.group(0).rstrip("/")
    return None


def reconcile_pinned_trycloudflare_url(cfg: dict | None = None) -> str | None:
    """鎖定 trycloudflare：設定與 cloudflared 不符或連不上時，同步為目前連線。"""
    cfg = cfg or _read_config()
    if not is_external_url_pinned(cfg):
        return None
    mode = tunnel_mode(cfg)
    if mode not in ("auto", "fixed"):
        return None
    pinned = fixed_external_url(cfg)
    if not pinned or "trycloudflare.com" not in pinned:
        return pinned or None
    if not is_tunnel_process_running() or not local_server_ready():
        return pinned
    live = read_trycloudflare_url_from_log()
    if not live:
        return pinned
    if pinned.rstrip("/") == live.rstrip("/") and is_tunnel_url_live(pinned, mode="auto"):
        return pinned
    if pinned.rstrip("/") == live.rstrip("/"):
        return pinned
    try:
        import json

        path = BASE_DIR / "config.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["external_url"] = live
        data["external_url_pinned"] = True
        presets = [u for u in (data.get("external_url_presets") or []) if u != live]
        presets.insert(0, live)
        data["external_url_presets"] = presets[:8]
        history = [u for u in (data.get("external_url_history") or []) if u != live]
        history.insert(0, live)
        data["external_url_history"] = history[:8]
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, TypeError):
        return pinned
    _pin_tunnel_url(live)
    _set_tunnel_url(live, force=True)
    _mark_external_ready(live)
    print(f"外網網址已同步: {live}")
    return live


_last_heal_pinned_at: float = 0.0
HEAL_PINNED_COOLDOWN = 90.0


def heal_pinned_trycloudflare_tunnel(port: int, cfg: dict | None = None) -> None:
    """鎖定 trycloudflare：僅啟動或同步網址，不重建 cloudflared（重建會換網址）。"""
    cfg = cfg or _read_config()
    if not is_external_url_pinned(cfg):
        return
    url = fixed_external_url(cfg)
    if not url or "trycloudflare.com" not in url:
        return
    live = read_trycloudflare_url_from_log()
    if live and url.rstrip("/") != live.rstrip("/"):
        reconcile_pinned_trycloudflare_url(cfg)
        return
    if cloudflared_running():
        return
    start_tunnel(port, bore_fallback=False, cfg=cfg)


def reconcile_fixed_trycloudflare_url(cfg: dict | None = None) -> str | None:
    """固定 trycloudflare：設定網址與 cloudflared 不符或連不上時，同步為目前連線。"""
    return reconcile_pinned_trycloudflare_url(cfg)


def _sync_tunnel_url_from_log() -> str | None:
    """從 cloudflared 日誌補抓網址（僅在尚未有網址時）。"""
    if tunnel_mode() == "ngrok":
        return None
    if get_tunnel_url():
        return get_tunnel_url()
    global _last_log_sync_at
    now = time.time()
    if now - _last_log_sync_at < 0.4:
        return None
    _last_log_sync_at = now
    if not CLOUDFLARED_LOG.exists():
        return None
    try:
        size = CLOUDFLARED_LOG.stat().st_size
        with open(CLOUDFLARED_LOG, "rb") as f:
            f.seek(max(0, size - 8192))
            text = f.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    _refresh_rate_limit_from_log(text)
    if is_tunnel_rate_limited() and not is_tunnel_alive():
        return None
    for line in reversed(text.splitlines()[-120:]):
        if "429 Too Many Requests" in line or "error code: 1015" in line:
            continue
        match = CF_URL_PATTERN.search(line)
        if match:
            url = match.group(0).rstrip("/")
            _set_tunnel_url(url)
            return url
    return None


def _current_tunnel_candidate(cfg: dict | None = None) -> str | None:
    _unpin_if_dead()
    url = get_tunnel_url()
    if url:
        return url.rstrip("/")
    synced = _sync_tunnel_url_from_log()
    if synced:
        return synced.rstrip("/")
    cfg = cfg or _read_config()
    saved = fixed_external_url(cfg)
    if saved and not external_url_is_dead(saved):
        return saved
    return None


def clear_stale_trycloudflare_url(cfg: dict | None = None) -> bool:
    """清除 config 中 DNS 已失效的 trycloudflare 網址。"""
    cfg = cfg or _read_config()
    if is_external_url_pinned(cfg):
        return False
    current = (cfg.get("external_url") or "").strip().rstrip("/")
    if not current or "trycloudflare.com" not in current:
        return False
    if not external_url_is_dead(current):
        return False
    cfg["external_url"] = ""
    try:
        import json

        path = BASE_DIR / "config.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["external_url"] = ""
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    global _tunnel_url_pinned, _tunnel_url
    with _tunnel_lock:
        if (_tunnel_url or "").rstrip("/") == current:
            _tunnel_url = None
            _tunnel_url_pinned = False
    _clear_verify_cache()
    return True


def purge_dead_tunnel_url(cfg: dict | None = None) -> bool:
    """清除記憶體／設定中 DNS 已失效的 trycloudflare 網址。"""
    global _tunnel_url, _tunnel_url_pinned
    cfg = cfg or _read_config()
    if is_external_url_pinned(cfg):
        return False
    changed = False
    for candidate in [
        (get_tunnel_url() or "").strip().rstrip("/"),
        fixed_external_url(cfg),
    ]:
        if not candidate or "trycloudflare.com" not in candidate:
            continue
        if not external_url_is_dead(candidate):
            continue
        clear_stale_trycloudflare_url(cfg)
        with _tunnel_lock:
            if (_tunnel_url or "").rstrip("/") == candidate:
                _tunnel_url = None
                _tunnel_url_pinned = False
        _clear_verify_cache()
        changed = True
    return changed


_last_expired_restart_at: float = 0.0


def maybe_restart_expired_tunnel(port: int) -> None:
    """trycloudflare 網址失效（DNS 或 tunnel 斷線）時重建 cloudflared。"""
    global _last_expired_restart_at
    now = time.time()
    if now - _last_expired_restart_at < 90.0:
        return
    cfg = _read_config()
    if tunnel_mode(cfg) != "auto":
        return
    if is_external_url_pinned(cfg):
        url = fixed_external_url(cfg)
        if url and "trycloudflare.com" in url:
            _last_expired_restart_at = now
            heal_pinned_trycloudflare_tunnel(port, cfg)
        return
    if is_tunnel_rate_limited():
        return
    saved = fixed_external_url(cfg)
    live = (get_reported_tunnel_url(cfg) or get_tunnel_url() or "").strip().rstrip("/")
    url = live or saved
    if not url or "trycloudflare.com" not in url:
        return
    dns_dead = external_url_is_dead(url)
    disconnected = bool(
        dns_dead
        or (live and saved and live != saved)
        or (not is_tunnel_alive() and saved and not external_url_is_dead(saved))
    )
    if not disconnected:
        return
    _last_expired_restart_at = now
    purge_dead_tunnel_url(cfg)
    print(f"  外網連線異常，正在重建 trycloudflare…")
    stop_tunnel(fast=True)
    time.sleep(0.15)
    start_tunnel(port, bore_fallback=False, cfg=cfg)


def wait_for_tunnel_domain(
    timeout: float = TUNNEL_DOMAIN_TIMEOUT,
    on_ready=None,
    *,
    early_ready: bool = False,
) -> str | None:
    """等 cloudflared 回報網址，且 DNS 已生效後才接受。"""
    deadline = time.time() + timeout
    print("優先建立外網網址（等待 DNS 生效）...")
    last_progress = 0.0
    last_early: str | None = None

    while time.time() < deadline:
        candidate = _current_tunnel_candidate()
        if candidate and is_tunnel_alive():
            cand = candidate.rstrip("/")
            if early_ready and cand != last_early:
                last_early = cand
            if "trycloudflare.com" in candidate:
                if dns_resolves(candidate) and auto_tunnel_is_connected(candidate):
                    accepted = _accept_tunnel_domain(candidate, on_ready)
                    if accepted:
                        _mark_tunnel_not_starting()
                        return accepted
            elif candidate.startswith("http://") and dns_resolves(candidate):
                accepted = _accept_tunnel_domain(candidate, on_ready)
                if accepted:
                    _mark_tunnel_not_starting()
                    return accepted
        if not is_tunnel_alive() and not is_tunnel_starting():
            break
        now = time.time()
        if now - last_progress >= 5.0:
            if candidate:
                print(f"  等待 DNS: {candidate}")
            else:
                print("  外網連線建立中...")
            last_progress = now
        time.sleep(0.08)

    return None


def bootstrap_external_tunnel(port: int, on_ready=None) -> str | None:
    """啟動 cloudflared 並取得外網網址（單次嘗試）。"""
    prepare_tunnel_tools()
    start_tunnel(port, bore_fallback=False)
    url = wait_for_tunnel_domain(TUNNEL_DOMAIN_TIMEOUT, on_ready=on_ready)
    if url:
        return url
    stop_tunnel()
    start_tunnel(port, bore_fallback=True)
    return wait_for_tunnel_domain(TUNNEL_QUICK_RETRY, on_ready=on_ready)


def _mark_external_ready(url: str) -> None:
    url = (url or "").strip().rstrip("/")
    if not url:
        return
    now = time.time()
    with _cache_lock:
        _sticky_valid_until[url] = now + STICKY_VALID_SECONDS
        _verify_cache[f"auto:{url}"] = (True, now)


def bootstrap_tunnel_stable(
    port: int,
    *,
    on_ready=None,
    timeout: float = 45.0,
) -> str | None:
    """啟動時建立外網：cloudflared 回報網址且 DNS 可解析後才完成。"""
    cfg = _read_config()
    if tunnel_mode(cfg) == "fixed":
        return ensure_external_tunnel(port, on_ready=on_ready, required=False, cfg=cfg)

    if tunnel_mode(cfg) == "auto" and is_external_url_pinned(cfg):
        saved = fixed_external_url(cfg)
        if saved:
            _pin_tunnel_url(saved)
            _set_tunnel_url(saved, force=True)
            if not is_tunnel_alive():
                start_tunnel(port, bore_fallback=False, cfg=cfg)
            deadline = time.time() + timeout
            while time.time() < deadline:
                if is_tunnel_url_live(saved, mode="fixed") or auto_tunnel_is_connected(saved):
                    _mark_external_ready(saved)
                    print("=" * 44)
                    print(f"外網已就緒: {saved}")
                    print(f"  登入 → {saved}/login")
                    print(f"  辨識 → {saved}/app")
                    print("=" * 44)
                    return _accept_tunnel(saved, on_ready)
                time.sleep(0.12)
            return None

    saved = fixed_external_url(cfg)
    if saved and external_url_is_dead(saved) and not is_external_url_pinned(cfg):
        print(f"  外網網址已過期，正在建立新網址…")
        clear_stale_trycloudflare_url(cfg)
        if is_tunnel_alive():
            stop_tunnel(fast=True)
            time.sleep(0.15)

    if not is_tunnel_alive():
        start_tunnel(port, bore_fallback=False, cfg=cfg)

    deadline = time.time() + timeout
    early_notified = False
    while time.time() < deadline:
        _unpin_if_dead()
        url = get_reported_tunnel_url(cfg)
        if url and is_tunnel_alive():
            if auto_tunnel_is_connected(url):
                _mark_external_ready(url)
                print("=" * 44)
                print(f"外網已就緒: {url}")
                print(f"  登入 → {url}/login")
                print(f"  辨識 → {url}/app")
                print("=" * 44)
                return _accept_tunnel(url, on_ready)
            if not early_notified and dns_resolves(url) and auto_tunnel_is_connected(url):
                early_notified = True
                _set_tunnel_url(url, force=True)
                print(f"外網網址: {url}")
                print("  DNS 傳播中，連線驗證中…")
        if url and external_url_is_dead(url):
            purge_dead_tunnel_url(cfg)
            maybe_restart_expired_tunnel(port)
        time.sleep(0.08)

    return None


def wait_for_tunnel_url_ready(
    port: int,
    on_ready=None,
    timeout: float = 45.0,
) -> str | None:
    """啟動時等待外網可用；不重啟、不換域。"""
    return bootstrap_tunnel_stable(port, on_ready=on_ready, timeout=timeout)


def wait_for_tunnel_url_display(
    port: int,
    on_ready=None,
    timeout: float = 90.0,
) -> str | None:
    """相容舊名稱：等待外網真正可用。"""
    return wait_for_tunnel_url_ready(port, on_ready=on_ready, timeout=timeout)


def ensure_external_tunnel(
    port: int,
    on_ready=None,
    *,
    required: bool = False,
    cfg: dict | None = None,
) -> str | None:
    cfg = cfg or _read_config()
    mode = tunnel_mode(cfg)

    if mode == "fixed":
        url = fixed_external_url(cfg)
        if not url:
            return None
        if not is_tunnel_alive():
            start_tunnel(port, cfg=cfg)
        if url and "trycloudflare.com" in url and external_url_is_dead(url):
            updated = reconcile_fixed_trycloudflare_url(cfg)
            if updated and updated != url:
                url = updated
                cfg = _read_config()
        if is_tunnel_url_live(url, mode="fixed"):
            if on_ready:
                on_ready(url)
            return _accept_tunnel_domain(url, None)
        return _wait_fixed_url(url, on_ready, required)

    if mode == "ngrok":
        if not is_tunnel_process_running():
            start_tunnel(port, cfg=cfg)
        deadline = time.time() + TUNNEL_DOMAIN_TIMEOUT
        while time.time() < deadline:
            url = read_ngrok_public_url()
            if not url:
                mem = get_tunnel_url()
                if mem and is_ngrok_public_url(mem):
                    url = mem
            if url and _ngrok_process_running():
                _sticky_save_external_url(url)
                if on_ready:
                    on_ready(url)
                return _accept_tunnel_domain(url, on_ready)
            time.sleep(0.08)
        return None

    if mode == "cloudflare":
        start_tunnel(port, cfg=cfg)
        url = fixed_external_url(cfg)
        if url and is_tunnel_alive():
            deadline = time.time() + TUNNEL_DOMAIN_TIMEOUT
            while time.time() < deadline:
                if is_tunnel_url_live(url, mode="cloudflare"):
                    if on_ready:
                        on_ready(url)
                    return _accept_tunnel_domain(url, on_ready)
                time.sleep(0.5)
        if required:
            while True:
                start_tunnel(port, cfg=cfg)
                url = fixed_external_url(cfg)
                if url and is_tunnel_url_live(url, mode="cloudflare"):
                    if on_ready:
                        on_ready(url)
                    return _accept_tunnel_domain(url, on_ready)
                time.sleep(2)
        return None

    prepare_tunnel_tools()
    acquired = _ensure_tunnel_lock.acquire(blocking=False)
    if not acquired:
        return _current_tunnel_candidate()

    try:
        return _ensure_external_tunnel_auto(port, on_ready, required=required, cfg=cfg)
    finally:
        _ensure_tunnel_lock.release()


def _start_bore_only(port: int) -> bool:
    bore = ensure_bore()
    if not bore:
        return False
    stop_tunnel(fast=True)
    time.sleep(0.15)
    with _tunnel_lock:
        global _tunnel_starting
        _tunnel_starting = True
    _start_bore(port, bore)
    return is_tunnel_alive()


def _restart_tunnel_if_dead(port: int, cfg: dict, *, bore_fallback: bool = False) -> None:
    global _last_tunnel_restart_at
    if is_tunnel_rate_limited():
        if _start_bore_only(port):
            return
        _print_rate_limit_notice()
        return
    if is_tunnel_alive():
        return
    now = time.time()
    cooldown = TUNNEL_RESTART_COOLDOWN
    if now - _last_tunnel_restart_at < cooldown:
        return
    stop_tunnel()
    time.sleep(0.25)
    start_tunnel(port, bore_fallback=bore_fallback, cfg=cfg)
    _last_tunnel_restart_at = now


def _ensure_external_tunnel_auto(
    port: int,
    on_ready=None,
    *,
    required: bool = False,
    cfg: dict | None = None,
) -> str | None:
    cfg = cfg or _read_config()
    max_seconds = 600.0 if required else 90.0
    deadline = time.time() + max_seconds
    last_progress = 0.0
    restarts = 0

    if is_tunnel_rate_limited():
        _print_rate_limit_notice()
        if not is_tunnel_alive():
            _start_bore_only(port)
        # 仍繼續等待 bore / 既有網址，不要直接返回
    elif not is_tunnel_alive():
        start_tunnel(port, bore_fallback=False, cfg=cfg)
        time.sleep(0.4)

    while time.time() < deadline:
        if is_tunnel_rate_limited():
            _print_rate_limit_notice()
            time.sleep(5.0)
            continue

        _sync_tunnel_url_from_log()
        candidate = _current_tunnel_candidate()

        if candidate and is_tunnel_alive():
            if is_tunnel_ready_for_use(candidate):
                accepted = _accept_tunnel_domain(candidate, on_ready)
                if accepted:
                    return accepted
            now = time.time()
            if now - last_progress >= 8.0:
                print(f"  外網連線建立中: {candidate}")
                last_progress = now
        elif is_tunnel_alive():
            now = time.time()
            if now - last_progress >= 8.0:
                print("  外網連線建立中...")
                last_progress = now
        else:
            if restarts == 0:
                start_tunnel(port, bore_fallback=False, cfg=cfg)
            restarts += 1
            if restarts > 3:
                print("  外網建立暫停：請稍後再試，或先使用 WiFi 連線")
                return _current_tunnel_candidate()
            if restarts <= 1:
                print("  外網連線建立中...")
            elif restarts <= 2:
                print(f"  外網連線建立中...（重試 {restarts}）")

        time.sleep(0.5)

    return None


def _sticky_save_external_url(url: str) -> None:
    """換外網重建前保留上一個網址，避免 UI 選單短暫空白。"""
    url = (url or "").strip().rstrip("/")
    if not url or is_external_url_pinned():
        return
    cfg_file = BASE_DIR / "config.json"
    try:
        import json

        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        mode = (data.get("tunnel_mode") or "auto").strip().lower()
        if mode == "ngrok" and not is_ngrok_public_url(url):
            return
        data["external_url"] = url
        if mode in ("auto", "ngrok", "fixed"):
            data["external_url_pinned"] = True
        presets = [url] + [u for u in (data.get("external_url_presets") or []) if u != url]
        data["external_url_presets"] = presets[:8]
        history = [url] + [u for u in (data.get("external_url_history") or []) if u != url]
        data["external_url_history"] = history[:8]
        cfg_file.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, TypeError):
        pass


def refresh_external_tunnel(port: int, on_ready=None) -> None:
    """快速重建 trycloudflare（手動換外網）。"""
    cfg = _read_config()
    if tunnel_mode(cfg) != "auto":
        return
    if is_external_url_pinned(cfg):
        return
    if is_tunnel_rate_limited():
        _print_rate_limit_notice()
        return

    sticky = (get_tunnel_url() or cfg.get("external_url") or get_last_known_tunnel_url() or "").strip().rstrip("/")
    if sticky:
        _sticky_save_external_url(sticky)

    with _tunnel_lock:
        global _tunnel_starting
        _tunnel_starting = True

    stop_tunnel(fast=True)
    time.sleep(0.12)
    prepare_tunnel_tools()
    start_tunnel(port, bore_fallback=False, cfg=cfg)

    def _finalize() -> None:
        global _tunnel_starting
        try:
            url = wait_for_tunnel_domain(
                TUNNEL_QUICK_RETRY,
                on_ready=on_ready,
                early_ready=True,
            )
            if url:
                return
            url = wait_for_tunnel(TUNNEL_QUICK_RETRY, on_ready=on_ready, startup=True)
            if url:
                return
            stop_tunnel(fast=True)
            time.sleep(0.08)
            start_tunnel(port, bore_fallback=False, cfg=cfg)
            wait_for_tunnel_domain(TUNNEL_DOMAIN_TIMEOUT, on_ready=on_ready, early_ready=True)
        finally:
            with _tunnel_lock:
                _tunnel_starting = False

    threading.Thread(target=_finalize, name="tunnel-refresh-fast", daemon=True).start()


def _wait_fixed_url(url: str, on_ready, required: bool) -> str | None:
    deadline = time.time() + (120.0 if required else 45.0)
    while time.time() < deadline:
        cfg = _read_config()
        if url and "trycloudflare.com" in url and external_url_is_dead(url):
            updated = reconcile_fixed_trycloudflare_url(cfg)
            if updated and updated != url:
                url = updated
        if is_tunnel_url_live(url, mode="fixed"):
            if on_ready:
                on_ready(url)
            return _accept_tunnel_domain(url, None)
        if not is_tunnel_process_running() and tunnel_mode(cfg) == "fixed":
            port = int(cfg.get("port") or 8080)
            start_tunnel(port, cfg=cfg)
        time.sleep(0.35)
    if required:
        while True:
            if is_tunnel_url_live(url, mode="fixed"):
                if on_ready:
                    on_ready(url)
                return _accept_tunnel_domain(url, None)
            time.sleep(2.0)
    return None


def _accept_tunnel_domain(candidate: str, on_ready=None) -> str | None:
    candidate = (candidate or "").strip().rstrip("/")
    if not candidate or not is_tunnel_alive():
        return None
    if "trycloudflare.com" in candidate:
        cfg = _read_config()
        pinned = pinned_external_url(cfg)
        if pinned and candidate.rstrip("/") == pinned.rstrip("/"):
            if not dns_resolves(candidate) or not is_tunnel_alive():
                return None
            if ping_tunnel_reliable(candidate, PING_TIMEOUT_FIXED) or tunnel_connection_registered():
                return _accept_tunnel(candidate, on_ready)
            return None
        if not dns_resolves(candidate) or not auto_tunnel_is_connected(candidate):
            return None
    elif not dns_resolves(candidate):
        return None
    _mark_external_ready(candidate)
    return _accept_tunnel(candidate, on_ready)


def _accept_tunnel(candidate: str, on_ready=None) -> str:
    candidate = candidate.rstrip("/")
    _pin_tunnel_url(candidate)
    with _tunnel_lock:
        global _tunnel_starting
        _tunnel_starting = False
    print(f"外網連線: {candidate}")
    if on_ready:
        on_ready(candidate)
    return candidate


def wait_for_tunnel(
    timeout: float = TUNNEL_WAIT_TIMEOUT,
    on_ready=None,
    *,
    startup: bool = False,
) -> str | None:
    deadline = time.time() + timeout
    if not startup:
        print("建立外網連線...")
    last_progress = 0.0

    while time.time() < deadline:
        candidate = get_tunnel_url()
        if candidate and is_tunnel_alive():
            if ping_tunnel_reliable(candidate, PING_TIMEOUT_FAST):
                return _accept_tunnel(candidate, on_ready)
        if not is_tunnel_alive() and not is_tunnel_starting():
            break
        now = time.time()
        if startup and now - last_progress >= 5.0:
            print("  外網連線建立中...")
            last_progress = now
        time.sleep(0.08)

    candidate = get_tunnel_url()
    if candidate and is_tunnel_alive() and ping_tunnel_reliable(candidate, PING_TIMEOUT_FAST):
        accepted = _accept_tunnel_domain(candidate, on_ready)
        if accepted:
            return accepted

    if not startup:
        print("外網連線失敗")
    with _tunnel_lock:
        global _tunnel_starting
        _tunnel_starting = False
    return None


def tunnel_needs_rebuild(saved_url: str | None = None) -> bool:
    cfg = _read_config()
    mode = tunnel_mode(cfg)
    if mode == "fixed":
        url = fixed_external_url(cfg) or saved_url
        return not url or not is_tunnel_url_live(url, mode="fixed")
    url = (get_tunnel_url() or saved_url or "").strip().rstrip("/")
    if not url:
        return True
    if mode == "cloudflare":
        if not is_tunnel_alive():
            return True
        return not is_tunnel_url_live(url, mode="cloudflare")
    if not is_tunnel_alive():
        return True
    if external_url_is_dead(url):
        return True
    return False


def _load_saved_external_url() -> str | None:
    cfg_file = BASE_DIR / "config.json"
    try:
        import json

        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        return (data.get("external_url") or "").strip().rstrip("/") or None
    except (OSError, json.JSONDecodeError):
        return None
