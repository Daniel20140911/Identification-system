"""應用程式路徑：程式碼目錄與可寫入資料目錄。"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parent


def _is_writable(path: Path) -> bool:
    try:
        probe = path / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def data_dir() -> Path:
    if _is_writable(CODE_DIR):
        return CODE_DIR
    root = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "hardware-recognizer"
    root.mkdir(parents=True, exist_ok=True)
    return root


def tools_dir() -> Path:
    bundled = CODE_DIR / "tools"
    if bundled.exists():
        return bundled
    dest = data_dir() / "tools"
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def ensure_data_files() -> Path:
    """若資料目錄與程式目錄不同，複製必要設定檔到可寫入位置。"""
    root = data_dir()
    if root == CODE_DIR:
        return root
    for name in (
        "config.json",
        "dataset_metadata.json",
        "webauthn_credentials.json",
    ):
        src = CODE_DIR / name
        dst = root / name
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)
    for folder in ("dataset", "pending", "uploads", "models"):
        src = CODE_DIR / folder
        dst = root / folder
        if src.exists() and not dst.exists():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            dst.mkdir(parents=True, exist_ok=True)
    return root


def using_fallback_data_dir() -> bool:
    return data_dir() != CODE_DIR
