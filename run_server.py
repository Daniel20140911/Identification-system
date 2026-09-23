"""啟動伺服器並確認可連線。"""

import json
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REQUIRED_FILES = (
    "app_paths.py",
    "app.py",
    "network_utils.py",
    "auth_webauthn.py",
    "config.json",
    "requirements.txt",
)


def _check_project_files() -> None:
    missing = [name for name in REQUIRED_FILES if not (ROOT / name).exists()]
    if missing:
        print("[錯誤] 專案檔案不完整，缺少：", ", ".join(missing))
        print("請從原電腦複製整個 hardware-recognizer 資料夾（不要只複製 bat）。")
        raise SystemExit(1)


_check_project_files()

from app_paths import data_dir, ensure_data_files, using_fallback_data_dir

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"


def load_config() -> dict:
    with open(CONFIG_FILE, encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: dict) -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def wait_for_server(port: int, timeout: float = 30.0) -> bool:
    url = f"http://127.0.0.1:{port}/api/ping"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.05)
    return False


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def main() -> int:
    try:
        return _main_impl()
    except Exception:
        import traceback

        traceback.print_exc()
        return 1


def _main_impl() -> int:
    ensure_data_files()
    global CONFIG_FILE, BASE_DIR
    BASE_DIR = data_dir()
    CONFIG_FILE = BASE_DIR / "config.json"
    if using_fallback_data_dir():
        print(f"資料目錄：{BASE_DIR}")

    cfg = load_config()
    port = int(cfg.get("port", 8080))

    if not port_available(port):
        for alt in (8081, 8082, 8888, 9000):
            if port_available(alt):
                port = alt
                cfg["port"] = alt
                save_config(cfg)
                print(f"8080 被占用，改用 port {port}")
                break
        else:
            print("找不到可用 port")
            return 1

    use_tunnel = bool(cfg.get("use_tunnel", True))

    def _save_external(url: str) -> None:
        from app import _persist_external_url

        _persist_external_url(url)

    def _tunnel_background() -> None:
        from network_utils import (
            ensure_external_tunnel,
            ensure_single_cloudflared,
            prepare_tunnel_tools,
            start_permanent_tunnel_watchdog,
            start_tunnel,
            tunnel_mode,
            wait_for_tunnel_url_ready,
        )

        cfg_now = load_config()
        mode = tunnel_mode(cfg_now)
        prepare_tunnel_tools()

        if mode == "auto":
            start_tunnel(port, bore_fallback=False, cfg=cfg_now)
            wait_for_tunnel_url_ready(port, on_ready=_save_external, timeout=15.0)
            return

        if not wait_for_server(port, timeout=3.0):
            return

        if mode != "ngrok":
            ensure_single_cloudflared(port, cfg_now)
        start_tunnel(port, bore_fallback=False, cfg=cfg_now)
        if mode in ("fixed", "cloudflare", "ngrok"):
            start_permanent_tunnel_watchdog(port)

        if mode == "fixed":
            fixed_url = (cfg_now.get("external_url") or "").strip()
            if not fixed_url:
                return
            ensure_external_tunnel(port, on_ready=_save_external, required=False, cfg=cfg_now)
            return

        if mode == "cloudflare":
            url = (cfg_now.get("external_url") or "").strip()
            token = (cfg_now.get("cloudflare_tunnel_token") or "").strip()
            if not url or not token:
                return
            ensure_external_tunnel(port, on_ready=_save_external, required=False, cfg=cfg_now)
            return

        if mode == "ngrok":
            token = (cfg_now.get("ngrok_authtoken") or "").strip()
            if not token:
                print("ngrok：請在外網設定填入 Authtoken")
                return
            ensure_external_tunnel(port, on_ready=_save_external, required=False, cfg=cfg_now)
            return

        wait_for_tunnel_url_ready(port, on_ready=_save_external, timeout=15.0)

    print("啟動辨識伺服器...")

    from app import (
        app,
        ensure_auth_config,
        ensure_default_structure,
        load_model,
        model_exists,
        preload_async,
        _server_urls,
        _url_path,
    )
    from werkzeug.serving import make_server

    threading.Thread(
        target=lambda: __import__("network_utils").ensure_firewall(port),
        name="firewall-setup",
        daemon=True,
    ).start()

    ensure_auth_config()
    ensure_default_structure()

    host = cfg.get("host", "0.0.0.0")
    server = make_server(host, port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    if use_tunnel:
        threading.Thread(
            target=lambda: __import__("network_utils").prepare_tunnel_tools(),
            name="tunnel-prewarm",
            daemon=True,
        ).start()
        threading.Thread(target=_tunnel_background, name="tunnel-bootstrap", daemon=True).start()

    preload_async()

    login_local = _url_path(f"http://localhost:{port}", "login")

    def _open_browser_when_ready() -> None:
        if wait_for_server(port, timeout=10.0):
            try:
                import subprocess

                if sys.platform == "win32":
                    subprocess.Popen(["cmd", "/c", "start", "", login_local], shell=False)
                else:
                    import webbrowser

                    webbrowser.open(login_local)
            except Exception:
                pass

    threading.Thread(target=_open_browser_when_ready, name="browser-open", daemon=True).start()

    if not wait_for_server(port, timeout=10.0):
        print("伺服器啟動失敗")
        return 1

    info = _server_urls(light=True)
    print("=" * 44)
    print(f"登入:   {login_local}")
    print(f"辨識系統: {_url_path(f'http://localhost:{port}', 'app')}")
    print(f"手機登入（WiFi）: {info.get('mobile_login_url')}")
    print(f"手機辨識（WiFi）: {info.get('mobile_app_url')}")
    if info.get("external_login_url"):
        print(f"手機登入（外網）: {info.get('external_login_url')}")
        print(f"手機辨識（外網）: {info.get('external_app_url')}")
    elif use_tunnel:
        print("外網連線建立中（約 15 秒），WiFi 已可使用。")
    pwd = (load_config().get("access_password") or "").strip()
    if pwd:
        print(f"登入密碼: {pwd}")
    print("=" * 44)

    def _load_models_background() -> None:
        if model_exists():
            print("載入辨識模型（背景）...")
            load_model()

    threading.Thread(target=_load_models_background, name="model-loader", daemon=True).start()

    try:
        while thread.is_alive():
            thread.join(timeout=1)
    except KeyboardInterrupt:
        pass
    finally:
        if use_tunnel:
            try:
                from network_utils import shutdown_tunnel

                shutdown_tunnel()
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
