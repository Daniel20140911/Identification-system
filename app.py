import json
import re
import secrets
import socket
import subprocess
import threading
import time
import uuid
from io import BytesIO
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_file, send_from_directory, session, url_for
from werkzeug.utils import secure_filename

from ml.clip_classifier import classify as ai_classify
from ml.clip_classifier import clear_cache as clear_ai_cache
from ml.clip_classifier import get_ai_info
from ml.clip_classifier import is_available as ai_available
from ml.clip_classifier import preload_async
from ml.clip_classifier import suggest_category
from ml.dataset_manager import (
    PENDING_DIR,
    UPLOADS_DIR,
    create_category,
    create_group,
    delete_image,
    ensure_default_structure,
    find_category_by_name,
    get_dataset_stats,
    list_categories,
    list_category_images,
    list_groups,
    list_pending,
    parse_label,
    rename_group,
    delete_pending,
    save_pending,
    save_to_category,
)
from ml.model_trainer import get_training_status, model_exists, train_model
from ml.predictor import load_model, predict

from app_paths import CODE_DIR, data_dir, ensure_data_files

ensure_data_files()
DATA_DIR = data_dir()
CONFIG_FILE = DATA_DIR / "config.json"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

_cfg_boot = json.loads(CONFIG_FILE.read_text(encoding="utf-8")) if CONFIG_FILE.exists() else {}
if not _cfg_boot.get("secret_key"):
    _cfg_boot["secret_key"] = secrets.token_hex(32)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(_cfg_boot, f, ensure_ascii=False, indent=2)
app.secret_key = _cfg_boot["secret_key"]

DEFAULT_ACCESS_PASSWORD = "8888"

PUBLIC_PATHS = {
    "/login",
    "/logout",
    "/api/login",
    "/api/logout",
    "/api/ping",
    "/api/server-info",
    "/api/auth/check",
    "/manifest.webmanifest",
    "/sw.js",
    "/api/webauthn/status",
    "/api/webauthn/login/options",
    "/api/webauthn/login/verify",
}
PUBLIC_PREFIXES = ("/static/",)

ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}


@app.after_request
def _cache_static_assets(response):
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=604800, immutable"
    return response

_config_cache: dict | None = None
_config_mtime: float = 0.0


def load_config() -> dict:
    global _config_cache, _config_mtime
    try:
        mtime = CONFIG_FILE.stat().st_mtime
    except OSError:
        return {}
    if _config_cache is not None and mtime == _config_mtime:
        return dict(_config_cache)
    with open(CONFIG_FILE, encoding="utf-8") as f:
        _config_cache = json.load(f)
    _config_mtime = mtime
    return dict(_config_cache)


def save_config(cfg: dict) -> None:
    global _config_cache, _config_mtime
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    _config_cache = dict(cfg)
    _config_mtime = CONFIG_FILE.stat().st_mtime


def _access_password() -> str:
    return (load_config().get("access_password") or "").strip()


def ensure_auth_config() -> None:
    """確保啟動時就需登入（若未設定密碼則使用預設值）。"""
    cfg = load_config()
    if not cfg.get("require_login", True):
        return
    if not (cfg.get("access_password") or "").strip():
        cfg["access_password"] = DEFAULT_ACCESS_PASSWORD
        save_config(cfg)


def _auth_required() -> bool:
    cfg = load_config()
    if not cfg.get("require_login", True):
        return False
    return bool(_access_password())


def _is_authenticated() -> bool:
    if not _auth_required():
        return True
    return bool(session.get("auth"))


@app.before_request
def require_login():
    if not _auth_required() or _is_authenticated():
        return None
    path = request.path
    if path in PUBLIC_PATHS or any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES):
        return None
    if path.startswith("/api/"):
        return jsonify({"ok": False, "error": "需要密碼", "auth_required": True}), 401
    nxt = request.full_path if request.query_string else request.path
    if path == "/":
        return redirect(url_for("login_page"))
    return redirect(url_for("login_page", next=nxt))


@app.after_request
def _no_cache_auth_pages(response):
    if request.path in ("/", "/login", "/app"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


ensure_auth_config()


def save_upload(file_storage) -> Path:
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    ext = Path(file_storage.filename or "img.jpg").suffix.lower()
    if ext not in ALLOWED_EXT:
        ext = ".jpg"
    name = f"{uuid.uuid4().hex}{ext}"
    path = UPLOADS_DIR / name
    file_storage.save(path)
    return path


def _resolve_group_category(data: dict) -> tuple[str, str]:
    group = data.get("group", "").strip()
    category = data.get("category", "").strip()
    label = data.get("name", "").strip() or data.get("label", "").strip()
    if label and (not group or not category):
        group, category = parse_label(label)
    return group, category


@app.route("/login")
def login_page():
    if not _auth_required():
        nxt = request.args.get("next") or "/app"
        return redirect(nxt)
    nxt = request.args.get("next")
    if _is_authenticated() and nxt:
        return redirect(nxt)
    urls = _server_urls()
    port = urls.get("port", 8080)
    return render_template(
        "login.html",
        login_url=urls.get("mobile_login_url") or f"http://localhost:{port}/login",
        app_url=urls.get("mobile_app_url") or f"http://localhost:{port}/app",
        external_login_url=urls.get("external_login_url"),
        external_app_url=urls.get("external_app_url"),
        external_url_valid=urls.get("external_url_valid"),
        external_has_url=urls.get("external_has_url"),
        tunnel_mode=urls.get("tunnel_mode", "auto"),
        tunnel_advice=urls.get("tunnel_advice") or [],
        external_url_options=urls.get("external_url_options") or [],
    )


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True) or {}
    password = (data.get("password") or "").strip()
    expected = _access_password()
    if not expected or secrets.compare_digest(password, expected):
        session["auth"] = True
        setup_fp = False
        try:
            from auth_webauthn import has_credentials, webauthn_available

            if (
                webauthn_available()
                and _webauthn_is_secure()
                and not has_credentials(_webauthn_rp_id())
            ):
                setup_fp = True
        except Exception:
            pass
        return jsonify(
            {
                "ok": True,
                "redirect": request.args.get("next") or "/app",
                "setup_fingerprint": setup_fp,
            }
        )
    return jsonify({"ok": False, "error": "密碼錯誤"}), 401


def _webauthn_rp_id() -> str:
    return request.host.split(":")[0]


def _webauthn_origin() -> str:
    return request.host_url.rstrip("/")


def _webauthn_is_secure() -> bool:
    rp_id = _webauthn_rp_id()
    return bool(request.is_secure or rp_id in ("localhost", "127.0.0.1"))


def _webauthn_hosts(cfg: dict | None = None) -> list[dict]:
    from urllib.parse import urlparse

    from auth_webauthn import has_credentials

    urls = _server_urls(cfg)
    hosts: dict[str, dict] = {}
    for url in urls.get("urls") or []:
        if "/login" not in url:
            continue
        parsed = urlparse(url)
        rp_id = parsed.hostname
        if not rp_id:
            continue
        login_url = url.split("?")[0]
        secure = parsed.scheme == "https" or rp_id in ("localhost", "127.0.0.1")
        existing = hosts.get(rp_id)
        if existing and existing.get("secure") and not secure:
            continue
        hosts[rp_id] = {
            "rp_id": rp_id,
            "login_url": login_url,
            "secure": secure,
            "has_credentials": has_credentials(rp_id),
        }
    current = _webauthn_rp_id()
    if current not in hosts:
        origin = _webauthn_origin()
        hosts[current] = {
            "rp_id": current,
            "login_url": _url_path(origin, "login"),
            "secure": _webauthn_is_secure(),
            "has_credentials": has_credentials(current),
        }
    return sorted(hosts.values(), key=lambda h: (not h["secure"], h["rp_id"]))


@app.route("/api/password/change", methods=["POST"])
def api_password_change():
    return api_auth_settings()


@app.route("/api/auth/settings", methods=["POST"])
def api_auth_settings():
    if _auth_required() and not _is_authenticated():
        return jsonify({"ok": False, "error": "未登入"}), 401
    data = request.get_json(force=True) or {}
    current = (data.get("current_password") or "").strip()
    new_pw = (data.get("new_password") or "").strip()
    require_login = data.get("require_login")

    cfg = load_config()
    expected = _access_password()
    auth_on = bool(cfg.get("require_login", True))

    if require_login is False:
        if auth_on and expected and not secrets.compare_digest(current, expected):
            return jsonify({"ok": False, "error": "目前密碼錯誤"}), 401
        cfg["require_login"] = False
        save_config(cfg)
        session["auth"] = True
        return jsonify({"ok": True, "auth_required": False, "authenticated": True, "require_login": False})

    if require_login is True or new_pw:
        if not new_pw:
            return jsonify({"ok": False, "error": "請輸入新密碼"}), 400
        if len(new_pw) < 4:
            return jsonify({"ok": False, "error": "新密碼至少 4 字元"}), 400
        if auth_on and expected and not secrets.compare_digest(current, expected):
            return jsonify({"ok": False, "error": "目前密碼錯誤"}), 401
        cfg["access_password"] = new_pw
        cfg["require_login"] = True
        save_config(cfg)
        session["auth"] = True
        return jsonify({"ok": True, "auth_required": True, "authenticated": True, "require_login": True})

    return jsonify({"ok": False, "error": "無變更"}), 400


@app.route("/logout")
def logout_page():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True, "redirect": "/login"})


@app.route("/api/webauthn/status")
def api_webauthn_status():
    from auth_webauthn import webauthn_status

    rp_id = _webauthn_rp_id()
    hosts = _webauthn_hosts()
    info = webauthn_status(rp_id, hosts)
    info["ok"] = True
    info["secure"] = _webauthn_is_secure()
    return jsonify(info)


@app.route("/api/webauthn/register/options", methods=["POST"])
def api_webauthn_register_options():
    from auth_webauthn import registration_options, webauthn_available

    if not _is_authenticated():
        return jsonify({"ok": False, "error": "未登入"}), 401
    if not webauthn_available():
        return jsonify({"ok": False, "error": "指紋功能未就緒"}), 503
    try:
        options = registration_options(_webauthn_rp_id(), "物品辨識系統")
        return jsonify({"ok": True, "options": options})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/webauthn/register/verify", methods=["POST"])
def api_webauthn_register_verify():
    from auth_webauthn import verify_registration, webauthn_available

    if not _is_authenticated():
        return jsonify({"ok": False, "error": "未登入"}), 401
    if not webauthn_available():
        return jsonify({"ok": False, "error": "指紋功能未就緒"}), 503
    data = request.get_json(force=True) or {}
    credential = data.get("credential")
    if not credential:
        return jsonify({"ok": False, "error": "缺少憑證"}), 400
    if verify_registration(credential, _webauthn_rp_id(), _webauthn_origin()):
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "指紋設定失敗"}), 400


@app.route("/api/webauthn/login/options", methods=["POST"])
def api_webauthn_login_options():
    from auth_webauthn import authentication_options, webauthn_available

    if not webauthn_available():
        return jsonify({"ok": False, "error": "指紋功能未就緒"}), 503
    try:
        options = authentication_options(_webauthn_rp_id())
        return jsonify({"ok": True, "options": options})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/webauthn/login/verify", methods=["POST"])
def api_webauthn_login_verify():
    from auth_webauthn import verify_authentication, webauthn_available

    if not webauthn_available():
        return jsonify({"ok": False, "error": "指紋功能未就緒"}), 503
    data = request.get_json(force=True) or {}
    credential = data.get("credential")
    if not credential:
        return jsonify({"ok": False, "error": "缺少憑證"}), 400
    if verify_authentication(credential, _webauthn_rp_id(), _webauthn_origin()):
        session["auth"] = True
        return jsonify({"ok": True, "redirect": request.args.get("next") or "/app"})
    return jsonify({"ok": False, "error": "指紋驗證失敗"}), 401


@app.route("/")
def root():
    return redirect(url_for("login_page"))


@app.route("/app")
def app_page():
    if _auth_required() and not _is_authenticated():
        return redirect(url_for("login_page", next="/app"))
    return render_template("index.html", initial_urls=_server_urls(light=True))


@app.route("/api/auth/check")
def api_auth_check():
    return jsonify({
        "ok": True,
        "auth_required": _auth_required(),
        "authenticated": _is_authenticated(),
        "require_login": bool(load_config().get("require_login", True)),
    })


_lan_cache: list[str] | None = None
_lan_cache_at: float = 0.0
LAN_CACHE_TTL = 300.0


def _lan_addresses() -> list[str]:
    global _lan_cache, _lan_cache_at
    now = time.time()
    if _lan_cache is not None and now - _lan_cache_at < LAN_CACHE_TTL:
        return list(_lan_cache)

    addrs: set[str] = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for target in ("8.8.8.8", "1.1.1.1", "192.168.1.1"):
                try:
                    s.connect((target, 80))
                    ip = s.getsockname()[0]
                    if ip and not ip.startswith("127."):
                        addrs.add(ip)
                    break
                except OSError:
                    continue
    except OSError:
        pass
    if not addrs:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = info[4][0]
                if ip and not ip.startswith("127."):
                    addrs.add(ip)
        except OSError:
            pass
    if not addrs:
        try:
            raw = subprocess.check_output(["ipconfig"], encoding="utf-8", errors="ignore")
            for ip in re.findall(r"IPv4[^:]*:\s*([\d.]+)", raw):
                if ip and not ip.startswith("127."):
                    addrs.add(ip)
        except (OSError, subprocess.SubprocessError):
            pass

    def _sort_key(ip: str) -> tuple:
        if ip.startswith("192.168."):
            return (0, ip)
        if ip.startswith("10."):
            return (1, ip)
        if ip.startswith("172."):
            return (2, ip)
        return (3, ip)

    result = sorted(addrs, key=_sort_key)
    _lan_cache = result
    _lan_cache_at = now
    return list(result)


def _primary_lan_ip() -> str:
    ips = _lan_addresses()
    return ips[0] if ips else "127.0.0.1"


def _mobile_base_url(cfg: dict | None = None) -> str:
    cfg = cfg or load_config()
    ip = _primary_lan_ip()
    port = cfg.get("port", 5050)
    if cfg.get("mobile_use_http", True):
        return f"http://{ip}:{port}"
    if cfg.get("use_https"):
        return f"https://{ip}:{cfg.get('https_port', 5443)}"
    return f"http://{ip}:{port}"


def _normalize_external_url(url: str) -> str:
    from urllib.parse import urlparse, urlunparse

    url = (url or "").strip().rstrip("/")
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urlparse(url)
    host = (parsed.hostname or "").replace("_", "-")
    if not host:
        return url.rstrip("/")
    port = parsed.port
    netloc = f"{host}:{port}" if port else host
    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", "")).rstrip("/")


def _url_path(base: str, path: str) -> str:
    base = (base or "").strip().rstrip("/")
    path = (path or "").strip().lstrip("/")
    if not base:
        return f"/{path}" if path else "/"
    return f"{base}/{path}" if path else base


def _device_urls(cfg: dict | None = None, subpath: str = "") -> list[str]:
    cfg = cfg or load_config()
    port = cfg.get("port", 5050)
    https_port = cfg.get("https_port", 5443)
    urls = []
    for ip in _lan_addresses():
        urls.append(_url_path(f"http://{ip}:{port}", subpath))
        if cfg.get("use_https"):
            urls.append(_url_path(f"https://{ip}:{https_port}", subpath))
    return urls


def _external_url_presets(cfg: dict) -> list[str]:
    from network_utils import is_public_external_url

    seen: set[str] = set()
    out: list[str] = []
    for raw in [cfg.get("external_url"), *(cfg.get("external_url_presets") or [])]:
        url = (raw or "").strip().rstrip("/")
        if url and url not in seen and is_public_external_url(url):
            seen.add(url)
            out.append(url)
    return out[:8]


def _persist_external_url(url: str, *, remember: bool = True, pin: bool = True) -> None:
    from network_utils import external_url_reject_reason, is_external_url_pinned

    url = (url or "").strip().rstrip("/")
    if not url or external_url_reject_reason(url):
        return
    cfg = load_config()
    saved = (cfg.get("external_url") or "").strip().rstrip("/")
    if is_external_url_pinned(cfg) and saved and saved == url:
        return
    cfg["external_url"] = url
    mode = (cfg.get("tunnel_mode") or "auto").strip().lower()
    if pin and mode in ("auto", "fixed", "ngrok"):
        cfg["external_url_pinned"] = True
    if remember:
        history = [url] + [u for u in (cfg.get("external_url_history") or []) if u != url]
        cfg["external_url_history"] = history[:8]
        presets = [url] + [u for u in (cfg.get("external_url_presets") or []) if u != url]
        cfg["external_url_presets"] = presets[:8]
    save_config(cfg)
    invalidate_server_urls_cache()


def _active_external_url(cfg: dict, external_raw: str, external_valid: bool, mode: str) -> str:
    from network_utils import external_url_is_dead, get_last_known_tunnel_url, get_tunnel_url

    saved = (cfg.get("external_url") or "").strip().rstrip("/")
    live = (get_tunnel_url() or "").strip().rstrip("/")
    last = (get_last_known_tunnel_url() or "").strip().rstrip("/")
    passed = (external_raw or "").strip().rstrip("/")
    if mode == "auto":
        if live and not external_url_is_dead(live):
            return live
        if external_valid and passed and not external_url_is_dead(passed):
            return passed
        if saved and not external_url_is_dead(saved):
            return saved
        if last and not external_url_is_dead(last):
            return last
        return ""
    return passed or saved or live or last


def _external_url_options(
    cfg: dict,
    external_raw: str,
    external_valid: bool,
    mode: str,
) -> list[dict]:
    from network_utils import (
        external_url_is_dead,
        get_last_known_tunnel_url,
        get_reported_tunnel_url,
        get_tunnel_url,
        is_public_external_url,
        is_tunnel_url_live,
    )

    live = (get_reported_tunnel_url(cfg) or get_tunnel_url() or "").strip().rstrip("/")
    active = _active_external_url(cfg, external_raw, external_valid, mode)
    options: list[dict] = []
    seen: set[str] = set()

    def add(url: str, label: str | None = None, kind: str = "preset", *, force_active: bool = False) -> None:
        url = (url or "").strip().rstrip("/")
        if not url or url in seen or not is_public_external_url(url):
            return
        if external_url_is_dead(url):
            return
        is_active = force_active or url == active
        seen.add(url)
        if mode == "fixed":
            live_ok = is_tunnel_url_live(url, mode="fixed") if is_active else False
        else:
            live_ok = bool(is_active and external_valid)
        host = url.replace("https://", "").replace("http://", "")
        pending = bool(mode == "auto" and is_active and not live_ok)
        if mode == "auto" and kind == "candidate":
            pending = True
            live_ok = False
        options.append({
            "url": url,
            "login_url": _url_path(url, "login"),
            "app_url": _url_path(url, "app"),
            "label": label or host,
            "active": is_active,
            "valid": live_ok,
            "pending": pending,
            "kind": kind,
        })

    if active:
        add(active, "目前使用", "current")
    if mode == "auto" and live and live != active and is_public_external_url(live):
        add(live, "新外網", "candidate")
    for u in _external_url_presets(cfg):
        add(u, kind="preset")
    for u in (cfg.get("external_url_history") or []):
        add(u, kind="history")
    if mode == "auto" and cfg.get("use_tunnel", True) and not options:
        last = (get_last_known_tunnel_url() or "").strip().rstrip("/")
        if last and is_public_external_url(last):
            add(last, "目前使用", "current", force_active=True)
    return options


def _sanitize_external_config(cfg: dict) -> tuple[dict, str | None]:
    """移除誤設為外網的區域 IP / localhost；trycloudflare 不因 DNS 檢查而刪除。"""
    from network_utils import (
        external_url_is_dead,
        external_url_reject_reason,
        is_public_external_url,
        is_well_formed_external_url,
    )

    rejected: str | None = None
    changed = False
    current = (cfg.get("external_url") or "").strip().rstrip("/")
    mode = (cfg.get("tunnel_mode") or "auto").strip().lower()

    def bad(url: str) -> bool:
        if not url:
            return True
        if external_url_reject_reason(url):
            return True
        if not is_well_formed_external_url(url):
            return True
        if mode in ("fixed", "cloudflare"):
            return False
        if mode == "auto" and "trycloudflare.com" in url:
            return external_url_is_dead(url)
        return external_url_is_dead(url)

    if current and bad(current):
        rejected = current
        cfg["external_url"] = ""
        changed = True
        if "trycloudflare.com" in current and mode != "fixed":
            cfg["tunnel_mode"] = "auto"

    def clean_list(key: str) -> None:
        nonlocal changed
        raw = cfg.get(key) or []
        cleaned = [
            u for u in raw
            if is_public_external_url(u)
            and is_well_formed_external_url(u)
            and (mode == "fixed" or not external_url_is_dead(u))
        ]
        if cleaned != raw:
            cfg[key] = cleaned
            changed = True

    clean_list("external_url_presets")
    clean_list("external_url_history")
    if changed:
        save_config(cfg)
    if rejected and cfg.get("tunnel_mode") == "fixed" and not (cfg.get("external_url") or "").strip():
        cfg["tunnel_mode"] = "auto"
        save_config(cfg)
    return cfg, rejected


def _tunnel_advice(cfg: dict, info: dict) -> list[dict]:
    return []
    tips: list[dict] = []
    port = int(info.get("port") or cfg.get("port") or 8080)
    mode = (info.get("tunnel_mode") or cfg.get("tunnel_mode") or "auto").strip().lower()

    if info.get("tunnel_rate_limited"):
        tips.insert(0, {
            "level": "warn",
            "text": (
                f"Cloudflare 暫時限制 trycloudflare 請求（請求過於頻繁）。"
                f"請等待約 {max(1, (info.get('tunnel_rate_limit_seconds') or 300) // 60)} 分鐘，"
                "期間請勿按「快速換外網」。WiFi 連線仍可使用。"
            ),
        })
        return tips

    if info.get("external_url_rejected"):
        tips.insert(0, {
            "level": "warn",
            "text": (
                f"已清除失效外網 {info['external_url_rejected']}（DNS 不存在或格式錯誤）。"
                "請按「快速換外網」建立新 trycloudflare 網址。"
            ),
        })

    if not cfg.get("use_tunnel", True):
        tips.append({
            "level": "info",
            "text": "外網尚未啟用。登入後到「外網設定」可開啟自動或固定外網。",
        })
        return tips

    if not info.get("firewall_ok"):
        tips.append({
            "level": "warn",
            "text": f"防火牆可能未開放 port {port}，同 WiFi 連線可能失敗。建議以系統管理員執行「開啟防火牆.bat」。",
        })

    if info.get("external_url_valid"):
        tips.append({
            "level": "ok",
            "text": "外網已就緒。不在同一 WiFi 時，請用「外網登入」連結，並在該網址各別設定指紋。",
        })
        if mode == "cloudflare":
            tips.append({
                "level": "info",
                "text": "永久外網網址固定不變；cloudflared 斷線時系統會自動重連，無需手動換網址。",
            })
        elif mode == "auto":
            tips.append({
                "level": "warn",
                "text": "自動 trycloudflare 網址會變動且可能失效。若要永久固定網址，請改「外網設定」→ 永久外網（Cloudflare Tunnel）。",
            })
        else:
            tips.append({
                "level": "info",
                "text": "固定外網網址已釘選，不會自動更換；請保持伺服器持續運行。",
            })
            if (info.get("external_saved") or "").find("trycloudflare.com") >= 0:
                tips.append({
                    "level": "warn",
                    "text": "trycloudflare 須同一 cloudflared 連線才有效；關閉或重啟 tunnel 後舊網址可能失效，但系統仍會保留您設定的網址。",
                })
        return tips

    if mode == "cloudflare":
        if not info.get("external_has_url"):
            tips.append({
                "level": "warn",
                "text": "請到「外網設定」選擇「永久外網」，填入 Cloudflare Tunnel Token 與固定 HTTPS 網址（一次設定，網址永不改變）。",
            })
        else:
            tips.append({
                "level": "warn",
                "text": f"永久外網連線中：{info.get('external_base_url') or info.get('external_saved') or '（等待 cloudflared）'}。通常 30 秒內就緒。",
            })
        tips.append({
            "level": "info",
            "text": "設定方式：Cloudflare 控制台 → Zero Trust → Networks → Tunnels → 建立 Tunnel → 公開主機名稱指向 localhost:8080 → 複製 Token 與網址貼上。",
        })
        return tips

    if mode == "fixed":
        if not info.get("external_has_url"):
            tips.append({
                "level": "warn",
                "text": f"建議：執行 `ngrok http {port}` 或 cloudflared 指向本機 {port}，再到「外網設定」貼上 HTTPS 網址。",
            })
        else:
            tips.append({
                "level": "warn",
                "text": (
                    f"固定外網尚未連上：{info.get('external_saved') or '（未設定）'}。"
                    "若為 trycloudflare 且曾重啟伺服器，舊網址可能已失效，系統會自動同步 cloudflared 目前連線。"
                ),
            })
        if info.get("external_url_presets"):
            tips.append({
                "level": "info",
                "text": "可從「常用外網」選項快速切換之前用過的網址。",
            })
        return tips

    if info.get("external_has_url"):
        tips.append({
            "level": "info",
            "text": "已取得外網網址，正在驗證 DNS，通常 10–30 秒內完成。",
        })
    elif info.get("external_pending"):
        tips.append({
            "level": "info",
            "text": "正在建立 trycloudflare 外網；若超過 1 分鐘，按「快速換外網」重試。",
        })
    else:
        tips.append({
            "level": "info",
            "text": "建議使用「自動外網」，系統會自動建立 trycloudflare；若要固定網址，改選「固定外網」。",
        })

    tips.append({
        "level": "info",
        "text": "上方「連線選項」可切換 WiFi / 外網，方便掃描對應 QR 碼。",
    })
    return tips


_server_urls_cache: dict | None = None
_server_urls_cache_at: float = 0.0
_server_urls_cache_lock = threading.Lock()
_last_stale_clear_at: float = 0.0
_last_sanitize_at: float = 0.0
SERVER_URLS_CACHE_TTL = 15.0
SERVER_URLS_LIGHT_CACHE_TTL = 25.0

_server_urls_light_cache: dict | None = None
_server_urls_light_cache_at: float = 0.0


def invalidate_server_urls_cache() -> None:
    global _server_urls_cache, _server_urls_light_cache
    with _server_urls_cache_lock:
        _server_urls_cache = None
        _server_urls_light_cache = None


def _server_urls(cfg: dict | None = None, *, light: bool = False) -> dict:
    global _last_stale_clear_at, _last_sanitize_at, _server_urls_cache, _server_urls_cache_at
    global _server_urls_light_cache, _server_urls_light_cache_at

    now = time.time()
    if light:
        with _server_urls_cache_lock:
            if _server_urls_light_cache and now - _server_urls_light_cache_at < SERVER_URLS_LIGHT_CACHE_TTL:
                return dict(_server_urls_light_cache)
    elif cfg is None:
        with _server_urls_cache_lock:
            if _server_urls_cache and now - _server_urls_cache_at < SERVER_URLS_CACHE_TTL:
                return dict(_server_urls_cache)

    from network_utils import (
        clear_stale_trycloudflare_url,
        dns_resolves,
        external_url_is_dead,
        firewall_rule_exists,
        get_last_known_tunnel_url,
        get_tunnel_url,
        is_tunnel_alive,
        is_tunnel_starting,
        is_tunnel_url_live,
        is_tunnel_rate_limited,
        tunnel_rate_limit_remaining,
        _sync_tunnel_url_from_log,
    )

    cfg = cfg or load_config()
    if not light and (cfg.get("tunnel_mode") or "auto") == "auto":
        if now - _last_stale_clear_at >= 60.0:
            clear_stale_trycloudflare_url(cfg)
            _last_stale_clear_at = now
            cfg = load_config()
    rejected_external = None
    if not light and now - _last_sanitize_at >= 120.0:
        cfg, rejected_external = _sanitize_external_config(dict(cfg))
        _last_sanitize_at = now
    elif not light:
        rejected_external = None
    mode = (cfg.get("tunnel_mode") or "auto").strip().lower()
    if mode != "ngrok":
        if not light:
            _sync_tunnel_url_from_log()
        elif not get_tunnel_url():
            _sync_tunnel_url_from_log()
    http_port = cfg.get("port", 5050)
    https_port = cfg.get("https_port", 5443)
    use_https = bool(cfg.get("use_https"))
    lan_ips = _lan_addresses()
    mobile_base = _mobile_base_url(cfg)
    mobile_login_url = _url_path(mobile_base, "login")
    mobile_app_url = _url_path(mobile_base, "app")
    cfg = cfg or load_config()
    external_raw = (get_tunnel_url() or "").strip().rstrip("/")
    saved_external = (cfg.get("external_url") or "").strip().rstrip("/")
    display_raw = ""
    if mode == "ngrok" and saved_external:
        from network_utils import is_ngrok_public_url

        if not is_ngrok_public_url(saved_external):
            cfg["external_url"] = ""
            save_config(cfg)
            saved_external = ""
    if saved_external and external_url_is_dead(saved_external) and mode == "auto":
        from network_utils import is_external_url_pinned

        if not is_external_url_pinned(cfg):
            cfg = load_config()
            cfg["external_url"] = ""
            save_config(cfg)
            saved_external = ""
    if mode == "fixed":
        if not light:
            from network_utils import reconcile_fixed_trycloudflare_url
            updated = reconcile_fixed_trycloudflare_url(cfg)
            if updated:
                cfg = load_config()
                saved_external = (cfg.get("external_url") or "").strip().rstrip("/")
        external_raw = saved_external
        external_valid = bool(external_raw and is_tunnel_url_live(external_raw, mode="fixed"))
        external_has_url = bool(external_raw)
        show = external_valid
        external_login_url = _url_path(external_raw, "login") if show else None
        external_app_url = _url_path(external_raw, "app") if show else None
        external_pending = bool(external_raw and not external_valid and cfg.get("use_tunnel", True))
        display_raw = external_raw
    elif mode == "cloudflare":
        external_raw = saved_external or external_raw or fixed_external_url(cfg)
        tunnel_up = is_tunnel_alive()
        external_valid = bool(
            external_raw and tunnel_up and is_tunnel_url_live(external_raw, mode="cloudflare")
        )
        external_has_url = bool(external_raw)
        display_raw = external_raw
        external_login_url = _url_path(display_raw, "login") if display_raw else None
        external_app_url = _url_path(display_raw, "app") if display_raw else None
        external_pending = bool(external_raw and not external_valid and cfg.get("use_tunnel", True))
    elif mode == "ngrok":
        from network_utils import read_ngrok_public_url, is_ngrok_public_url, is_tunnel_process_running

        live_raw = read_ngrok_public_url() or ""
        if not live_raw:
            candidate = (get_tunnel_url() or saved_external or "").strip().rstrip("/")
            if is_ngrok_public_url(candidate):
                live_raw = candidate
        tunnel_up = is_tunnel_process_running()
        if light:
            external_valid = bool(live_raw and tunnel_up)
        else:
            external_valid = bool(
                live_raw and tunnel_up and is_tunnel_url_live(live_raw, mode="ngrok")
            )
        external_has_url = bool(live_raw or is_tunnel_starting() or tunnel_up)
        display_raw = live_raw
        external_login_url = _url_path(display_raw, "login") if display_raw else None
        external_app_url = _url_path(display_raw, "app") if display_raw else None
        external_pending = bool(
            cfg.get("use_tunnel", True)
            and (is_tunnel_starting() or tunnel_up)
            and not external_valid
        )
    else:
        from network_utils import (
            get_reported_tunnel_url,
            maybe_restart_expired_tunnel,
            purge_dead_tunnel_url,
            cloudflared_running,
            reconcile_pinned_trycloudflare_url,
            is_external_url_pinned,
            read_trycloudflare_url_from_log,
        )

        if is_external_url_pinned(cfg):
            reconcile_pinned_trycloudflare_url(cfg)
            cfg = load_config()
            saved_external = (cfg.get("external_url") or "").strip().rstrip("/")
        if not light:
            purge_dead_tunnel_url(cfg)
        live_from_log = (read_trycloudflare_url_from_log() or "").strip().rstrip("/")
        live_raw = (live_from_log or get_reported_tunnel_url(cfg) or get_tunnel_url() or "").strip().rstrip("/")
        saved_external = (cfg.get("external_url") or "").strip().rstrip("/")
        if not light and live_raw and external_url_is_dead(live_raw) and not is_external_url_pinned(cfg):
            threading.Thread(
                target=maybe_restart_expired_tunnel,
                args=(int(cfg.get("port") or 8080),),
                name="tunnel-expired-restart",
                daemon=True,
            ).start()
            live_raw = ""
        check_raw = ""
        if live_raw and (light or not external_url_is_dead(live_raw)):
            check_raw = live_raw
        elif saved_external and (light or not external_url_is_dead(saved_external)):
            check_raw = saved_external
        external_raw = check_raw
        tunnel_up = is_tunnel_alive()
        tunnel_active = tunnel_up or is_tunnel_starting() or (bool(check_raw) and cloudflared_running())
        external_valid = bool(
            check_raw and tunnel_up and is_tunnel_url_live(check_raw, mode="auto")
        )
        display_raw = check_raw if external_valid else ""
        external_has_url = bool(external_valid or is_tunnel_starting() or (tunnel_active and check_raw))
        external_login_url = _url_path(display_raw, "login") if display_raw else None
        external_app_url = _url_path(display_raw, "app") if display_raw else None
        external_pending = bool(not external_valid and (is_tunnel_starting() or tunnel_active))
    tunnel_rebuilding = bool(
        mode == "auto"
        and (
            is_tunnel_starting()
            or (bool(_active_external_url(cfg, external_raw or saved_external, external_valid, mode)) and not external_valid)
        )
        )
    access_url = external_app_url if external_valid else mobile_app_url
    if light:
        from network_utils import cloudflare_token_looks_valid, ngrok_authtoken_looks_valid

        token = (cfg.get("cloudflare_tunnel_token") or "").strip()
        result = {
            "mobile_login_url": mobile_login_url,
            "mobile_app_url": mobile_app_url,
            "external_login_url": external_login_url,
            "external_app_url": external_app_url,
            "external_base_url": display_raw if display_raw else None,
            "external_url_valid": external_valid,
            "external_has_url": external_has_url,
            "external_pending": external_pending,
            "external_url_usable": external_valid,
            "tunnel_rebuilding": tunnel_rebuilding,
            "tunnel_mode": mode,
            "use_tunnel": cfg.get("use_tunnel", True),
            "external_url_pinned": bool(cfg.get("external_url_pinned")),
            "tunnel_rate_limited": is_tunnel_rate_limited(),
            "tunnel_rate_limit_seconds": tunnel_rate_limit_remaining(),
            "cloudflare_token_invalid": bool(
                mode == "cloudflare" and token and not cloudflare_token_looks_valid(token, cfg)
            ),
            "cloudflare_token_missing": bool(mode == "cloudflare" and not token),
            "ngrok_authtoken_missing": bool(
                mode == "ngrok"
                and not ngrok_authtoken_looks_valid((cfg.get("ngrok_authtoken") or "").strip())
            ),
        }
        with _server_urls_cache_lock:
            _server_urls_light_cache = dict(result)
            _server_urls_light_cache_at = time.time()
        return result
    urls = [
        _url_path(f"http://127.0.0.1:{http_port}", "login"),
        _url_path(f"http://127.0.0.1:{http_port}", "app"),
        _url_path(f"http://localhost:{http_port}", "login"),
        _url_path(f"http://localhost:{http_port}", "app"),
    ]
    urls.extend(_device_urls(cfg, "login"))
    urls.extend(_device_urls(cfg, "app"))
    if external_login_url:
        urls.insert(0, external_login_url)
    if external_app_url:
        urls.insert(0, external_app_url)
    result = {
        "port": http_port,
        "https_port": https_port,
        "use_https": use_https,
        "mobile_url": mobile_app_url,
        "mobile_login_url": mobile_login_url,
        "mobile_app_url": mobile_app_url,
        "external_url": external_app_url,
        "external_login_url": external_login_url,
        "external_app_url": external_app_url,
        "external_base_url": display_raw if display_raw else None,
        "external_url_valid": external_valid,
        "external_has_url": external_has_url,
        "tunnel_mode": mode,
        "external_url_pinned": bool(cfg.get("external_url_pinned")),
        "external_saved": (
            (cfg.get("external_url") or "").strip()
            or (get_last_known_tunnel_url() or "").strip()
            or None
        ),
        "external_url_presets": _external_url_presets(cfg),
        "external_url_options": _external_url_options(
            cfg, external_raw or saved_external or "", external_valid, mode
        ),
        "external_pending": external_pending,
        "external_url_usable": external_valid,
        "tunnel_rebuilding": tunnel_rebuilding,
        "tunnel_rate_limited": is_tunnel_rate_limited(),
        "tunnel_rate_limit_seconds": tunnel_rate_limit_remaining(),
        "access_url": access_url,
        "tunnel_url": external_app_url if external_valid else None,
        "firewall_ok": firewall_rule_exists(http_port),
        "device_urls": _device_urls(cfg, "app"),
        "device_login_urls": _device_urls(cfg, "login"),
        "urls": list(dict.fromkeys(urls)),
        "lan_ips": lan_ips,
        "primary_ip": _primary_lan_ip(),
        "external_url_rejected": rejected_external,
    }
    result["tunnel_advice"] = _tunnel_advice(cfg, result)
    if cfg is None:
        with _server_urls_cache_lock:
            _server_urls_cache = dict(result)
            _server_urls_cache_at = time.time()
    return result


def _ssl_cert_paths(cfg: dict) -> tuple[str, str]:
    from werkzeug.serving import make_ssl_devcert

    cert_dir = DATA_DIR / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    base = cert_dir / "mobile"
    crt = Path(f"{base}.crt")
    key = Path(f"{base}.key")
    host = (_lan_addresses() or ["localhost"])[0]
    marker = cert_dir / "mobile.host"
    if not crt.exists() or not key.exists() or marker.read_text(encoding="utf-8").strip() != host:
        make_ssl_devcert(str(base), host=host)
        marker.write_text(host, encoding="utf-8")
    return str(crt), str(key)


@app.route("/api/ping")
def api_ping():
    return jsonify({"ok": True, "server": "hardware-recognizer"})


@app.route("/api/server-info")
def api_server_info():
    light = request.args.get("light", "").lower() in ("1", "true", "yes")
    return jsonify(_server_urls(light=light))


@app.route("/api/ai-status")
def api_ai_status():
    return jsonify({
        "ai_available": ai_available(),
        "ai_info": get_ai_info(),
        "model_ready": model_exists(),
    })


@app.route("/api/tunnel/settings", methods=["POST"])
def api_tunnel_settings():
    if not _is_authenticated():
        return jsonify({"ok": False, "error": "未登入"}), 401
    from network_utils import (
        stop_tunnel,
        start_tunnel,
        tunnel_mode,
        external_url_reject_reason,
        cloudflare_token_looks_valid,
        ngrok_authtoken_looks_valid,
    )

    data = request.get_json(force=True) or {}
    mode = (data.get("tunnel_mode") or "auto").strip().lower()
    if mode not in ("auto", "fixed", "cloudflare", "ngrok"):
        return jsonify({"ok": False, "error": "無效的外網模式"}), 400

    cfg = load_config()
    old_mode = (cfg.get("tunnel_mode") or "auto").strip().lower()
    old_url = (cfg.get("external_url") or "").strip().rstrip("/")
    old_token = (cfg.get("cloudflare_tunnel_token") or "").strip()
    old_ngrok = (cfg.get("ngrok_authtoken") or "").strip()
    external_url = _normalize_external_url((data.get("external_url") or "").strip())
    if mode == "fixed":
        if not external_url:
            return jsonify({"ok": False, "error": "請輸入固定外網網址"}), 400
        reject = external_url_reject_reason(external_url)
        if reject:
            return jsonify({"ok": False, "error": reject}), 400
    elif mode == "cloudflare":
        token = (data.get("cloudflare_tunnel_token") or cfg.get("cloudflare_tunnel_token") or "").strip()
        if not external_url:
            return jsonify({"ok": False, "error": "請輸入永久外網 HTTPS 網址"}), 400
        if not token:
            return jsonify({"ok": False, "error": "請貼上 Cloudflare Tunnel Token"}), 400

        if not cloudflare_token_looks_valid(token, cfg):
            return jsonify({
                "ok": False,
                "error": "Token 格式不正確（不可使用登入密碼；請從 Cloudflare Zero Trust → Tunnels 複製完整 Token）",
            }), 400
        reject = external_url_reject_reason(external_url)
        if reject:
            return jsonify({"ok": False, "error": reject}), 400
        if "trycloudflare.com" in external_url:
            return jsonify({
                "ok": False,
                "error": "永久外網請用您自己的網域，不可使用 trycloudflare 臨時網址",
            }), 400

    elif mode == "ngrok":
        ngrok_token = (data.get("ngrok_authtoken") or cfg.get("ngrok_authtoken") or "").strip()
        if not ngrok_token:
            return jsonify({"ok": False, "error": "請貼上 ngrok Authtoken"}), 400
        if not ngrok_authtoken_looks_valid(ngrok_token):
            return jsonify({
                "ok": False,
                "error": "Authtoken 格式不正確，請從 dashboard.ngrok.com/get-started/your-authtoken 重新複製",
            }), 400

    new_token = (data.get("cloudflare_tunnel_token") or "").strip() or old_token
    new_ngrok = (data.get("ngrok_authtoken") or "").strip()
    if not new_ngrok and ngrok_authtoken_looks_valid(old_ngrok):
        new_ngrok = old_ngrok
    unchanged = (
        mode == old_mode
        and (
            mode == "auto"
            or (mode == "fixed" and external_url == old_url)
            or (mode == "cloudflare" and external_url == old_url and new_token == old_token)
            or (mode == "ngrok" and new_ngrok == old_ngrok)
        )
    )
    if unchanged:
        return jsonify({"ok": True, "unchanged": True, **_server_urls(cfg)})

    cfg["tunnel_mode"] = mode
    cfg["use_tunnel"] = True
    if mode == "fixed":
        stop_tunnel()
        cfg["external_url"] = external_url
        cfg["external_url_pinned"] = True
        if data.get("save_preset") and external_url:
            presets = [u for u in _external_url_presets(cfg) if u != external_url]
            presets.insert(0, external_url)
            cfg["external_url_presets"] = presets[:8]
    elif mode == "auto":
        if old_mode != "auto":
            cfg["external_url"] = ""
    elif mode == "ngrok":
        cfg["ngrok_authtoken"] = new_ngrok
        cfg["external_url"] = ""
        cfg["external_url_pinned"] = False
    elif mode == "cloudflare":
        from urllib.parse import urlparse

        cfg["cloudflare_tunnel_token"] = new_token
        cfg["external_url"] = external_url
        cfg["custom_domain"] = (urlparse(external_url).hostname or cfg.get("custom_domain") or "")
        if data.get("save_preset") and external_url:
            presets = [u for u in _external_url_presets(cfg) if u != external_url]
            presets.insert(0, external_url)
            cfg["external_url_presets"] = presets[:8]
    save_config(cfg)
    port = int(cfg.get("port", 8080))
    if mode == "fixed":
        start_tunnel(port, cfg=load_config())
    elif mode == "cloudflare":
        from network_utils import start_permanent_tunnel_watchdog

        stop_tunnel(fast=True)
        start_tunnel(port, cfg=load_config())
        start_permanent_tunnel_watchdog(port)
    elif mode == "ngrok":
        from network_utils import start_permanent_tunnel_watchdog

        stop_tunnel(fast=True)
        start_tunnel(port, cfg=load_config())
        start_permanent_tunnel_watchdog(port)

    restart = mode == "auto" and old_mode != "auto"
    if restart:
        def _run() -> None:
            from network_utils import refresh_external_tunnel

            port = int(load_config().get("port", 8080))

            def _save(url: str) -> None:
                _persist_external_url(url)

            refresh_external_tunnel(port, on_ready=_save)

        __import__("threading").Thread(target=_run, daemon=True).start()

    return jsonify({"ok": True, "restart_tunnel": restart, **_server_urls(cfg)})


@app.route("/api/tunnel/select", methods=["POST"])
def api_tunnel_select():
    if not _is_authenticated():
        return jsonify({"ok": False, "error": "未登入"}), 401
    from network_utils import external_url_is_dead, external_url_reject_reason, start_tunnel, stop_tunnel

    data = request.get_json(force=True) or {}
    external_url = (data.get("external_url") or "").strip().rstrip("/")
    if not external_url:
        return jsonify({"ok": False, "error": "請選擇外網域網址"}), 400
    if external_url == "__auto_refresh__":
        return api_tunnel_start()
    reject = external_url_reject_reason(external_url)
    if reject:
        return jsonify({"ok": False, "error": reject}), 400
    if not external_url.startswith(("http://", "https://")):
        external_url = f"https://{external_url}"
    if "trycloudflare.com" in external_url:
        return jsonify({
            "ok": False,
            "error": "trycloudflare 網址會過期，請用「快速換外網」建立新網址，不要選舊的 trycloudflare",
        }), 400
    if external_url_is_dead(external_url):
        return jsonify({"ok": False, "error": "此外網域已失效（DNS 不存在），請換新網址"}), 400

    cfg = load_config()
    stop_tunnel()
    _persist_external_url(external_url)
    cfg = load_config()
    cfg["tunnel_mode"] = "fixed"
    cfg["use_tunnel"] = True
    save_config(cfg)
    port = int(cfg.get("port", 8080))
    start_tunnel(port, cfg=load_config())
    return jsonify({"ok": True, **_server_urls(load_config())})


@app.route("/api/tunnel/start", methods=["POST"])
def api_tunnel_start():
    from network_utils import (
        is_tunnel_starting,
        is_tunnel_url_live,
        get_tunnel_url,
        is_tunnel_alive,
        is_tunnel_rate_limited,
        refresh_external_tunnel,
        tunnel_mode,
        tunnel_rate_limit_remaining,
    )

    cfg = load_config()
    from network_utils import is_external_url_pinned

    if is_external_url_pinned(cfg):
        return jsonify({
            "ok": False,
            "error": "外網網址已鎖定，不可換新網址。請在外網設定取消鎖定後再試。",
            **_server_urls(cfg),
        }), 400

    if tunnel_mode(cfg) == "fixed":
        return jsonify({"ok": True, "pending": False, **_server_urls(cfg)})

    if is_tunnel_rate_limited():
        secs = tunnel_rate_limit_remaining()
        return jsonify({
            "ok": False,
            "error": f"Cloudflare 暫時限制請求，請等待 {max(1, secs // 60)} 分鐘後再按「快速換外網」",
            "tunnel_rate_limited": True,
            "tunnel_rate_limit_seconds": secs,
            **_server_urls(cfg),
        }), 429

    port = int(cfg.get("port", 8080))
    if is_tunnel_starting():
        return jsonify({"ok": True, "pending": True, **_server_urls(cfg)})

    existing = (get_tunnel_url() or cfg.get("external_url") or "").strip().rstrip("/")
    force = (request.get_json(silent=True) or {}).get("force", False)
    if not force and existing and is_tunnel_alive():
        return jsonify({"ok": True, "pending": False, **_server_urls(cfg)})

    def _save_external(url: str) -> None:
        _persist_external_url(url)

    refresh_external_tunnel(port, on_ready=_save_external)
    return jsonify({"ok": True, "pending": True, "fast": True, **_server_urls(load_config())})


@app.route("/api/mobile-qr")
def api_mobile_qr():
    import qrcode

    url = request.args.get("url") or _mobile_base_url()
    img = qrcode.make(url, box_size=8, border=2)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png", max_age=60)


@app.route("/api/config")
def api_config():
    from network_utils import ngrok_authtoken_looks_valid

    cfg = load_config()
    safe = {k: v for k, v in cfg.items() if k not in ("access_password", "secret_key", "cloudflare_tunnel_token", "ngrok_authtoken")}
    minimal = request.args.get("minimal", "").lower() in ("1", "true", "yes")
    payload = {
        **safe,
        "cloudflare_tunnel_token_set": bool((cfg.get("cloudflare_tunnel_token") or "").strip()),
        "ngrok_authtoken_set": ngrok_authtoken_looks_valid((cfg.get("ngrok_authtoken") or "").strip()),
        "auth_required": _auth_required(),
        "authenticated": _is_authenticated(),
        "require_login": bool(cfg.get("require_login", True)),
        "model_ready": model_exists(),
        "ai_available": ai_available(),
        "ai_info": get_ai_info(),
    }
    if not minimal:
        payload.update(_server_urls(cfg))
    return jsonify(payload)


@app.route("/api/dataset")
def api_dataset():
    return jsonify(get_dataset_stats())


@app.route("/api/groups", methods=["GET", "POST"])
def api_groups():
    if request.method == "POST":
        data = request.get_json(force=True)
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"ok": False, "error": "請輸入大資料夾名稱"}), 400
        result = create_group(name)
        clear_ai_cache()
        return jsonify({"ok": True, **result, "groups": list_groups()})
    return jsonify({"groups": list_groups()})


@app.route("/api/groups/rename", methods=["POST"])
def api_rename_group():
    data = request.get_json(force=True)
    old_name = data.get("old_name", "").strip()
    new_name = data.get("new_name", "").strip()
    if not old_name or not new_name:
        return jsonify({"ok": False, "error": "請選擇大資料夾並輸入新名稱"}), 400
    try:
        result = rename_group(old_name, new_name)
        clear_ai_cache()
        return jsonify({"ok": True, **result, "groups": list_groups()})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/categories", methods=["GET", "POST"])
def api_categories():
    if request.method == "POST":
        data = request.get_json(force=True)
        group = data.get("group", "").strip()
        name = data.get("name", "").strip() or data.get("category", "").strip()
        if not group or not name:
            return jsonify({"ok": False, "error": "請選擇大資料夾並輸入分類名稱"}), 400
        result = create_category(group, name, data.get("description", ""))
        clear_ai_cache()
        return jsonify({"ok": True, **result, "groups": list_groups()})
    return jsonify({"categories": list_categories(), "groups": list_groups()})


@app.route("/api/upload-training", methods=["POST"])
def api_upload_training():
    group = request.form.get("group", "").strip()
    category = request.form.get("category", "").strip()
    if not group or not category:
        return jsonify({"ok": False, "error": "請選擇大資料夾與分類"}), 400
    files = request.files.getlist("images")
    if not files:
        return jsonify({"ok": False, "error": "請上傳圖片"}), 400

    saved = []
    for f in files:
        if f.filename:
            tmp = save_upload(f)
            result = save_to_category(tmp, group, category, f.filename, source="training_upload")
            saved.append(result)
            tmp.unlink(missing_ok=True)

    stats = get_dataset_stats()
    return jsonify({"ok": True, "saved": saved, "stats": stats})


@app.route("/api/train", methods=["POST"])
def api_train():
    cfg = load_config()

    def run():
        train_model(
            epochs=cfg.get("epochs", 15),
            batch_size=cfg.get("batch_size", 8),
            lr=cfg.get("learning_rate", 0.001),
        )
        load_model()

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"ok": True, "message": "訓練已開始，請查看訓練狀態"})


@app.route("/api/training-status")
def api_training_status():
    return jsonify(get_training_status())


@app.route("/api/recognize", methods=["POST"])
def api_recognize():
    cfg = load_config()
    threshold = float(request.form.get("threshold", cfg.get("confidence_threshold", 0.65)))
    recognize_method = request.form.get(
        "recognize_method",
        request.form.get("use_ai", cfg.get("default_recognize_method", "auto")),
    )
    if recognize_method in ("false", "0", "no"):
        recognize_method = "model"
    elif recognize_method in ("true", "1", "yes"):
        recognize_method = "ai"

    file = request.files.get("image")
    if not file or not file.filename:
        return jsonify({"ok": False, "error": "請上傳圖片"}), 400

    path = save_upload(file)
    result = {"image": f"/uploads/{path.name}", "recognize_method": recognize_method}

    def finish_unrecognized(extra: dict | None = None):
        from ml.clip_classifier import _ensure_loaded
        suggest = {"suggested_category": None}
        if _ensure_loaded():
            suggest = suggest_category(path, None)
        pending = save_pending(path, suggest.get("suggested_category"))
        result.update({
            "ok": True,
            "recognized": False,
            "needs_manual": True,
            "pending": pending,
            "suggested_category": suggest.get("suggested_category"),
            "suggest": suggest,
        })
        if extra:
            result.update(extra)
        return jsonify(result)

    def apply_prediction(pred: dict, method: str):
        top_conf = pred["top"]["confidence"]
        ai_threshold = float(cfg.get("ai_confidence_threshold", 0.25))
        effective_threshold = ai_threshold if method == "ai_clip" else threshold
        recognized = top_conf >= effective_threshold
        ai_label = pred["top"]["category"]
        existing = find_category_by_name(ai_label.split("/")[-1]) if method == "ai_clip" else None
        result.update({
            "ok": True,
            "recognized": recognized,
            "method": method,
            "category": ai_label,
            "confidence": top_conf,
            "threshold_used": effective_threshold,
        })
        if method == "ai_clip":
            result.update({
                "ai_label": ai_label,
                "label_in_dataset": existing["name"] if existing else None,
                "ask_add_tag": True,
                "suggested_category": existing["name"] if existing else ai_label,
            })
            return jsonify(result)
        if not recognized:
            pending = save_pending(path, ai_label)
            result["pending"] = pending
            result["needs_manual"] = True
            result["suggested_category"] = ai_label
        return jsonify(result)

    if recognize_method == "model":
        if not model_exists():
            return jsonify({
                "ok": False,
                "error": "模型尚未訓練，請先到「訓練模型」上傳圖片並訓練，或改用 AI 辨識",
            }), 400
        pred = predict(path)
        if not pred.get("ok"):
            return jsonify({"ok": False, "error": pred.get("error", "模型辨識失敗")}), 400
        result["model"] = pred
        return apply_prediction(pred, "trained_model")

    if recognize_method == "ai":
        from ml.clip_classifier import _ensure_loaded
        if not _ensure_loaded():
            err = "AI 模型尚未載入完成，請稍候再試"
            from ml.clip_classifier import get_load_error
            if get_load_error():
                err = f"AI 模型載入失敗：{get_load_error()}"
            return jsonify({"ok": False, "error": err}), 503
        ai_result = ai_classify(path, None)
        if not ai_result.get("ok"):
            return jsonify({"ok": False, "error": ai_result.get("error", "AI 辨識失敗")}), 400
        result["ai"] = ai_result
        return apply_prediction(ai_result, "ai_clip")

    if model_exists():
        pred = predict(path)
        if pred.get("ok"):
            result["model"] = pred
            if pred["top"]["confidence"] >= threshold:
                result.update({
                    "ok": True,
                    "recognized": True,
                    "method": "trained_model",
                    "category": pred["top"]["category"],
                    "confidence": pred["top"]["confidence"],
                })
                return jsonify(result)

    from ml.clip_classifier import _ensure_loaded
    if _ensure_loaded():
        ai_result = ai_classify(path, None)
        if ai_result.get("ok"):
            result["ai"] = ai_result
            return apply_prediction(ai_result, "ai_clip")

    return finish_unrecognized({"error_hint": "模型與 AI 皆無法辨識"})


@app.route("/api/save-to-dataset", methods=["POST"])
def api_save_to_dataset():
    data = request.get_json(force=True)
    group, category = _resolve_group_category(data)
    filename = data.get("filename", "").strip() or None
    pending_file = data.get("pending_file", "").strip()
    upload_file = data.get("upload_file", "").strip()

    if not group or not category:
        return jsonify({"ok": False, "error": "請選擇大資料夾與分類"}), 400

    source = None
    if pending_file:
        source = PENDING_DIR / secure_filename(pending_file)
    elif upload_file:
        source = UPLOADS_DIR / secure_filename(upload_file)
    elif "image" in request.files:
        source = save_upload(request.files["image"])
    else:
        return jsonify({"ok": False, "error": "找不到來源圖片"}), 400

    if not source.exists():
        return jsonify({"ok": False, "error": "來源圖片不存在"}), 400

    result = save_to_category(source, group, category, filename, source="manual_save")
    if pending_file:
        (PENDING_DIR / secure_filename(pending_file)).unlink(missing_ok=True)

    return jsonify({"ok": True, **result, "stats": get_dataset_stats()})


@app.route("/api/ai-classify", methods=["POST"])
def api_ai_classify():
    file = request.files.get("image")
    pending_file = request.form.get("pending_file", "")

    if file and file.filename:
        path = save_upload(file)
    elif pending_file:
        path = PENDING_DIR / secure_filename(pending_file)
    else:
        return jsonify({"ok": False, "error": "請提供圖片"}), 400

    if not path.exists():
        return jsonify({"ok": False, "error": "圖片不存在"}), 400

    result = ai_classify(path, None)
    return jsonify(result)


@app.route("/api/pending")
def api_pending():
    return jsonify({"items": list_pending()})


@app.route("/api/pending/delete", methods=["POST"])
def api_delete_pending():
    data = request.get_json(force=True)
    filename = data.get("filename", "").strip()
    if not filename:
        return jsonify({"ok": False, "error": "請指定要刪除的檔案"}), 400
    try:
        result = delete_pending(secure_filename(filename))
        return jsonify({"ok": True, **result, "items": list_pending()})
    except FileNotFoundError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/category-images/<group>/<category>")
def api_category_images(group, category):
    images = list_category_images(group, category)
    return jsonify({"group": group, "category": category, "images": images})


@app.route("/api/delete-image", methods=["POST"])
def api_delete_image():
    data = request.get_json(force=True)
    group = data.get("group", "").strip()
    category = data.get("category", "").strip()
    filename = data.get("filename", "").strip()
    if not group or not category:
        g, c = parse_label(data.get("category", "") or data.get("name", ""))
        group, category = g, c
    if not group or not category or not filename:
        return jsonify({"ok": False, "error": "請指定大資料夾、標籤與檔案"}), 400
    try:
        result = delete_image(group, category, secure_filename(filename))
        return jsonify({"ok": True, **result, "stats": get_dataset_stats()})
    except FileNotFoundError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/manifest.webmanifest")
def serve_manifest():
    return send_from_directory(CODE_DIR / "static", "manifest.webmanifest", mimetype="application/manifest+json")


@app.route("/sw.js")
def serve_sw():
    return send_from_directory(CODE_DIR / "static", "sw.js", mimetype="application/javascript")


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOADS_DIR, filename)


@app.route("/pending/<path:filename>")
def serve_pending(filename):
    return send_from_directory(PENDING_DIR, filename)


@app.route("/dataset/<path:filepath>")
def serve_dataset(filepath):
    return send_from_directory(DATA_DIR / "dataset", filepath)


if __name__ == "__main__":
    from werkzeug.serving import make_server

    cfg = load_config()
    http_port = cfg.get("port", 5050)
    https_port = cfg.get("https_port", 5443)
    host = cfg.get("host", "0.0.0.0")
    ensure_default_structure()
    if model_exists():
        load_model()
    preload_async()

    info = _server_urls(cfg)
    print("=" * 42)
    print(f"電腦: http://localhost:{http_port}")
    print(f"手機/其他裝置: {info['mobile_url']}")
    for url in info.get("device_urls", []):
        print(f"  {url}")
    print("=" * 42)

    http_server = make_server(host, http_port, app, threaded=True)

    if cfg.get("use_https"):
        try:
            cert, key = _ssl_cert_paths(cfg)
            https_server = make_server(host, https_port, app, threaded=True, ssl_context=(cert, key))
            threading.Thread(target=https_server.serve_forever, name="https-server", daemon=True).start()
            print(f"HTTPS 附加: {https_port}")
        except Exception as e:
            print(f"HTTPS 未啟動: {e}")

    print(f"監聽 {host}:{http_port}")
    http_server.serve_forever()
