"""一鍵：建立 venv（本機 AppData）並啟動伺服器。"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

REQUIRED_FILES = (
    "app_paths.py",
    "app.py",
    "run_server.py",
    "network_utils.py",
    "config.json",
)


def check_project_files() -> int:
    missing = [name for name in REQUIRED_FILES if not (ROOT / name).exists()]
    if not missing:
        return 0
    print("[錯誤] 專案檔案不完整，缺少：", ", ".join(missing))
    print("請從原電腦複製整個 hardware-recognizer 資料夾（不要只複製 bat）。")
    return 1


def main() -> int:
    if check_project_files():
        return 1

    import setup_env

    code = setup_env.main()
    if code != 0:
        return code

    setup_env.init_paths()
    try:
        setup_env.sync_venv_paths()
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 1

    py = setup_env.VENV_PY
    if not py.exists():
        print(
            "[錯誤] venv 未建立成功。\n"
            "請安裝官網 Python：https://www.python.org/downloads/\n"
            "安裝時勾選 Add to PATH，然後重跑 start.bat",
            file=sys.stderr,
        )
        return 1

    setup_env.write_location_hint()
    print(f"[launch] venv：{setup_env.VENV}")
    print(f"[launch] Python：{py}")
    print("[launch] 啟動伺服器...\n", flush=True)
    return subprocess.call([str(py), "-u", str(ROOT / "run_server.py")])


if __name__ == "__main__":
    raise SystemExit(main())
