"""新電腦 / 換裝置：檢查並重建 venv、安裝套件。"""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REQ = ROOT / "requirements.txt"
LOG = ROOT / "logs" / "setup.log"
VENV_LINK = ROOT / "venv_path.txt"

IMPORT_CHECK = """
import flask
import torch
import torchvision
import PIL
import numpy
import open_clip
import qrcode
import OpenSSL
import webauthn
print("imports_ok")
"""

VENV: Path
VENV_PY: Path
STAMP: Path
MACHINE_STAMP: Path


def log(msg: str) -> None:
    LOG.parent.mkdir(exist_ok=True)
    print(msg, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(msg.rstrip() + "\n")


def is_store_python(exe: Path | str) -> bool:
    text = str(exe).lower()
    return "windowsapps" in text or "pythonsoftwarefoundation" in text


def _venv_slug() -> str:
    return hashlib.sha256(str(ROOT.resolve()).encode("utf-8")).hexdigest()[:10]


def _store_python_local_base() -> Path | None:
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    for pkg in sorted(local.glob("Packages/PythonSoftwareFoundation.Python.*")):
        base = pkg / "LocalCache" / "Local" / "hardware-recognizer"
        return base
    return None


def _path_uses_onedrive(path: Path) -> bool:
    return "onedrive" in str(path).lower()


def resolve_venv_dir() -> Path:
    """OneDrive / Store Python 都改放到本機固定位置，避免鎖檔與路徑轉向。"""
    name = _venv_slug_name()
    if sys.platform == "win32":
        if is_store_python(sys.executable):
            store_base = _store_python_local_base()
            if store_base:
                return store_base / name
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "hardware-recognizer"
        return base / name
    if _path_uses_onedrive(ROOT):
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "hardware-recognizer"
        return base / name
    return ROOT / "venv"


def write_venv_link() -> None:
    if VENV_PY.exists():
        VENV_LINK.write_text(str(VENV_PY.resolve()), encoding="utf-8")


def init_paths() -> None:
    global VENV, VENV_PY, STAMP, MACHINE_STAMP
    VENV = resolve_venv_dir()
    VENV.mkdir(parents=True, exist_ok=True)
    VENV_PY = VENV / "Scripts" / "python.exe"
    STAMP = VENV / ".deps_stamp"
    MACHINE_STAMP = VENV / ".machine_stamp"


def discover_pythons() -> list[Path]:
    found: list[Path] = []
    try:
        out = subprocess.check_output(["py", "-0p"], text=True, errors="replace", timeout=15)
        for line in out.splitlines():
            if "\t" not in line:
                continue
            exe = line.split("\t", 1)[1].strip()
            if exe:
                found.append(Path(exe))
    except Exception:
        pass
    cur = Path(sys.executable).resolve()
    if cur not in found:
        found.append(cur)
    uniq: list[Path] = []
    seen: set[str] = set()
    for exe in found:
        key = str(exe).lower()
        if key not in seen:
            seen.add(key)
            uniq.append(exe)
    return uniq


def pick_best_python() -> Path:
    for exe in discover_pythons():
        if exe.exists() and not is_store_python(exe):
            return exe.resolve()
    return Path(sys.executable).resolve()


def maybe_reexec_with_better_python() -> None:
    if os.environ.get("SETUP_ENV_REEXEC") == "1":
        return
    best = pick_best_python()
    current = Path(sys.executable).resolve()
    if best != current and not is_store_python(best):
        print(f"[setup] 改用官網版 Python：{best}", flush=True)
        env = os.environ.copy()
        env["SETUP_ENV_REEXEC"] = "1"
        os.execve(str(best), [str(best), str(Path(__file__).resolve()), *sys.argv[1:]], env)


def require_usable_python() -> bool:
    """Store 版 Python 常無法建立 venv，有官網版就強制改用。"""
    if not is_store_python(sys.executable):
        return True
    best = pick_best_python()
    if not is_store_python(best):
        maybe_reexec_with_better_python()
        return True
    log("[setup] 錯誤：目前只有 Microsoft Store 版 Python。")
    print(
        "Microsoft Store 版 Python 無法可靠建立 venv。\n\n"
        "請安裝官網版：\n"
        "  https://www.python.org/downloads/\n"
        "安裝時勾選「Add python.exe to PATH」\n"
        "安裝完關閉視窗，再雙擊 start.bat",
        flush=True,
    )
    return False


def machine_id() -> str:
    return f"{platform.node()}|{Path(sys.executable).resolve()}"


def _read_pyvenv_home() -> Path | None:
    cfg = VENV / "pyvenv.cfg"
    if not cfg.exists():
        return None
    for line in cfg.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("home = "):
            return Path(line.split("=", 1)[1].strip())
    return None


def _venv_slug_name() -> str:
    return f"venv-{_venv_slug()}"


def _collect_venv_roots() -> list[Path]:
    slug = _venv_slug_name()
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roots: list[Path] = []
    seen: set[str] = set()

    def add(root: Path) -> None:
        key = str(root).lower()
        if key not in seen:
            seen.add(key)
            roots.append(root)

    add(VENV)
    add(local / "hardware-recognizer" / slug)
    store_base = _store_python_local_base()
    if store_base:
        add(store_base / slug)
    for pkg in local.glob("Packages/PythonSoftwareFoundation.Python.*"):
        add(pkg / "LocalCache" / "Local" / "hardware-recognizer" / slug)
    try:
        for py in local.rglob(f"{slug}/Scripts/python.exe"):
            add(py.parent.parent)
    except OSError:
        pass
    legacy = ROOT / "venv"
    if legacy.is_dir():
        add(legacy)
    return roots


def sync_venv_paths() -> None:
    """Store Python 建立 venv 時可能轉向到 Packages 目錄。"""
    global VENV, VENV_PY, STAMP, MACHINE_STAMP

    for root in _collect_venv_roots():
        alt_py = root / "Scripts" / "python.exe"
        alt_cfg = root / "pyvenv.cfg"
        if alt_py.exists() and alt_cfg.exists():
            VENV = root
            VENV_PY = alt_py
            STAMP = VENV / ".deps_stamp"
            MACHINE_STAMP = VENV / ".machine_stamp"
            write_venv_link()
            return

    tried = "\n  ".join(str(p) for p in _collect_venv_roots())
    raise SystemExit(
        "找不到 venv（python.exe）。\n"
        f"已搜尋：\n  {tried}\n"
        "請安裝官網版 Python：https://www.python.org/downloads/ （勾選 Add to PATH）\n"
        "然後重跑 start.bat"
    )


def runtime_python() -> str:
    init_paths()
    sync_venv_paths()
    return str(VENV_PY.resolve())


def venv_valid() -> bool:
    if not VENV_PY.exists() or not (VENV / "pyvenv.cfg").exists():
        return False
    home = _read_pyvenv_home()
    if home and not (home / "python.exe").exists():
        log(f"[setup] venv 指向不存在的 Python：{home}")
        return False
    try:
        subprocess.run(
            [str(VENV_PY), "-c", "import sys"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return True
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return False


def venv_from_other_pc() -> bool:
    if not MACHINE_STAMP.exists():
        return True
    try:
        return MACHINE_STAMP.read_text(encoding="utf-8").strip() != machine_id()
    except OSError:
        return True


def write_machine_stamp() -> None:
    MACHINE_STAMP.write_text(machine_id(), encoding="utf-8")


def imports_ok() -> bool:
    if not VENV_PY.exists():
        return False
    try:
        proc = subprocess.run(
            [str(VENV_PY), "-c", IMPORT_CHECK],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        if proc.returncode == 0 and "imports_ok" in (proc.stdout or ""):
            return True
        err = (proc.stderr or proc.stdout or "").strip()
        if err:
            log(f"[setup] 套件檢查失敗：{err.splitlines()[-1][:200]}")
        return False
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"[setup] 套件檢查錯誤：{exc}")
        return False


def remove_dir(path: Path) -> None:
    if not path.exists():
        return
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", str(path)], check=False)
    if path.exists():
        raise SystemExit(f"無法刪除資料夾：{path}")


def remove_venv_completely() -> None:
    targets = {VENV}
    slug = VENV.name
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    targets.add(local / "hardware-recognizer" / slug)
    store_base = _store_python_local_base()
    if store_base:
        targets.add(store_base / slug)
    for pkg in local.glob("Packages/PythonSoftwareFoundation.Python.*"):
        targets.add(pkg / "LocalCache" / "Local" / "hardware-recognizer" / slug)
    for path in targets:
        remove_dir(path)


def cleanup_legacy_onedrive_venv() -> None:
    legacy = ROOT / "venv"
    if not _path_uses_onedrive(ROOT) or not legacy.is_dir():
        return
    if legacy.resolve() == VENV.resolve():
        return
    log("[setup] 專案在 OneDrive：venv 改放到本機，清理 OneDrive 內舊 venv ...")
    try:
        remove_dir(legacy)
    except SystemExit:
        log("[setup] 無法刪除 OneDrive 內 venv（可能被同步鎖定）")
        log("[setup] 請暫停 OneDrive 同步後手動刪除專案內 venv 資料夾")


def recreate_venv() -> None:
    log(f"[setup] 建立 venv：{VENV}")
    VENV.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [sys.executable, "-m", "venv", str(VENV)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.stdout:
        log(proc.stdout.strip())
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "venv 建立失敗").strip()
        log(err)
        raise SystemExit(err)
    sync_venv_paths()
    write_machine_stamp()


def _pip(args: list[str], retries: int = 5) -> None:
    if not (VENV / "pyvenv.cfg").exists():
        sync_venv_paths()
    last: subprocess.CalledProcessError | None = None
    for attempt in range(retries):
        if attempt:
            wait = 3 * attempt
            log(f"[setup] pip 失敗，{wait} 秒後重試 ({attempt + 1}/{retries}) ...")
            time.sleep(wait)
            sync_venv_paths()
        try:
            subprocess.run(
                [str(VENV_PY), "-m", "pip", *args],
                check=True,
            )
            return
        except subprocess.CalledProcessError as exc:
            last = exc
    if last:
        raise last


def install_deps() -> None:
    log("[setup] 安裝套件（首次約 10~30 分鐘，請勿關閉視窗）...")
    if _path_uses_onedrive(ROOT):
        log("[setup] OneDrive 路徑：venv 已放在本機 AppData，避免同步鎖檔。")
    if is_store_python(sys.executable):
        log("[setup] 警告：Store 版 Python 可能不穩，建議改裝官網版。")
    _pip(["install", "-U", "pip", "wheel"])
    try:
        _pip(["install", "--no-cache-dir", "-r", str(REQ)])
    except subprocess.CalledProcessError:
        log("[setup] 一般安裝失敗，改試 CPU 版 PyTorch ...")
        _pip(
            [
                "install",
                "--no-cache-dir",
                "flask>=3.0.0",
                "Pillow>=10.0.0",
                "numpy>=1.24.0",
                "open-clip-torch>=2.24.0",
                "qrcode>=7.4.0",
                "pyopenssl>=23.0.0",
                "webauthn>=2.0.0",
            ]
        )
        _pip(
            [
                "install",
                "--no-cache-dir",
                "torch",
                "torchvision",
                "--index-url",
                "https://download.pytorch.org/whl/cpu",
            ]
        )
    shutil.copy2(REQ, STAMP)
    write_machine_stamp()


def ensure_environment() -> None:
    init_paths()
    cleanup_legacy_onedrive_venv()

    need_rebuild = not venv_valid() or venv_from_other_pc()
    if need_rebuild:
        if venv_from_other_pc() and venv_valid():
            log("[setup] 偵測到不同電腦或不同 Python，重建 venv ...")
        remove_venv_completely()
        recreate_venv()
    else:
        log("[setup] venv 可用")
        sync_venv_paths()
        write_machine_stamp()

    need_install = not STAMP.exists() or deps_changed() or not imports_ok()
    if need_install:
        if STAMP.exists() and not deps_changed() and not imports_ok():
            log("[setup] venv 存在但套件不完整，強制重裝 ...")
        install_deps()
    else:
        log("[setup] 套件已是最新")

    if not imports_ok():
        log("[setup] 重裝後仍失敗，最後嘗試整包重建 ...")
        remove_venv_completely()
        recreate_venv()
        install_deps()
        if not imports_ok():
            if is_store_python(sys.executable):
                raise SystemExit(
                    "Store 版 Python 無法完成安裝。\n"
                    "請安裝官網版：https://www.python.org/downloads/\n"
                    "勾選 Add to PATH 後重跑 start.bat"
                )
            raise SystemExit("套件安裝後仍無法 import，請查看 logs\\setup.log")


def deps_changed() -> bool:
    if not STAMP.exists() or not REQ.exists():
        return True
    return STAMP.read_bytes() != REQ.read_bytes()


def main() -> int:
    maybe_reexec_with_better_python()

    LOG.parent.mkdir(exist_ok=True)
    LOG.write_text("", encoding="utf-8")
    log(f"[setup] Python: {sys.executable}")
    log(f"[setup] 版本: {sys.version.split()[0]}")
    log(f"[setup] 目錄: {ROOT}")
    init_paths()
    log(f"[setup] venv 將使用：{VENV}")

    if sys.version_info < (3, 10):
        log("[setup] 錯誤：需要 Python 3.10 以上")
        return 1

    if not require_usable_python():
        return 1

    if is_store_python(sys.executable):
        log("[setup] 提示：偵測到 Microsoft Store 版 Python。")
        log("[setup] 若失敗，請改裝 https://www.python.org/downloads/ 並勾選 Add to PATH。")

    ensure_environment()
    sync_venv_paths()
    write_location_hint()
    write_launch_scripts()
    log(f"[setup] venv 資料夾：{VENV}")
    log(f"[setup] Python 執行檔：{VENV_PY}")
    log("[setup] 完成 → 請雙擊「啟動伺服器.bat」")
    return 0


def write_location_hint() -> None:
    hint = ROOT / "venv_location.txt"
    hint.write_text(
        "venv 不在專案資料夾內（OneDrive 會鎖檔，所以改放本機）。\n\n"
        f"venv 資料夾：\n{VENV}\n\n"
        f"Python 執行檔：\n{VENV_PY}\n\n"
        "啟動方式：雙擊「啟動伺服器.bat」或 start.bat\n",
        encoding="utf-8",
    )


def write_launch_scripts() -> None:
    """每次 setup 成功後寫入正確 venv 路徑的啟動檔（避免舊 start.bat 找錯位置）。"""
    py = str(VENV_PY.resolve())
    lines = [
        "@echo off",
        "chcp 65001 >nul",
        "cd /d \"%~dp0\"",
        "echo 啟動中...",
        f"\"{py}\" -u launch.py",
        "if errorlevel 1 pause",
    ]
    text = "\r\n".join(lines) + "\r\n"
    for name in ("啟動伺服器.bat", "run_server.bat"):
        (ROOT / name).write_text(text, encoding="utf-8")


def cmd_print_venv() -> int:
    maybe_reexec_with_better_python()
    try:
        print(runtime_python(), flush=True)
        return 0
    except SystemExit:
        if main() != 0:
            return 1
        print(runtime_python(), flush=True)
        return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--print-venv":
        raise SystemExit(cmd_print_venv())
    raise SystemExit(main())
