"""WebAuthn 指紋 / 生物辨識登入。"""
from __future__ import annotations

import base64
import json
import secrets
import threading
from pathlib import Path

from flask import session

from app_paths import data_dir, ensure_data_files

ensure_data_files()
BASE_DIR = data_dir()
CREDENTIALS_FILE = BASE_DIR / "webauthn_credentials.json"
USER_ID = b"hardware-recognizer-admin"
_lock = threading.RLock()

try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers import bytes_to_base64url, options_to_json
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    )

    WEBAUTHN_OK = True
except ImportError:
    WEBAUTHN_OK = False


def webauthn_available() -> bool:
    return WEBAUTHN_OK


def _load_store() -> dict:
    default = {"credentials": []}
    if not CREDENTIALS_FILE.exists():
        return default
    try:
        data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
        data.setdefault("credentials", [])
        return data
    except (OSError, json.JSONDecodeError):
        return default


def _save_store(data: dict) -> None:
    CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CREDENTIALS_FILE.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(CREDENTIALS_FILE)


def has_credentials(rp_id: str | None = None) -> bool:
    creds = _load_store()["credentials"]
    if not rp_id:
        return bool(creds)
    return any(c.get("rp_id") == rp_id for c in creds)


def webauthn_status(rp_id: str, hosts: list[dict] | None = None) -> dict:
    creds = _load_store()["credentials"]
    configured = {c.get("rp_id") for c in creds if c.get("rp_id")}
    host_list = hosts or []
    return {
        "available": WEBAUTHN_OK,
        "has_credentials": has_credentials(rp_id),
        "has_credentials_any": bool(creds),
        "has_credentials_here": has_credentials(rp_id),
        "rp_id": rp_id,
        "hosts": host_list,
        "configured_rp_ids": sorted(configured),
    }


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _save_challenge(challenge: bytes, action: str) -> None:
    if WEBAUTHN_OK:
        session["webauthn_challenge"] = bytes_to_base64url(challenge)
    else:
        session["webauthn_challenge"] = base64.urlsafe_b64encode(challenge).decode().rstrip("=")
    session["webauthn_action"] = action


def _pop_challenge(action: str) -> bytes | None:
    if session.get("webauthn_action") != action:
        return None
    raw = session.pop("webauthn_challenge", None)
    session.pop("webauthn_action", None)
    if not raw:
        return None
    pad = "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw + pad)


def registration_options(rp_id: str, rp_name: str):
    if not WEBAUTHN_OK:
        raise RuntimeError("webauthn 未安裝")
    exclude = []
    for c in _load_store()["credentials"]:
        if c.get("rp_id") != rp_id:
            continue
        exclude.append(
            PublicKeyCredentialDescriptor(id=_b64url_decode(c["id"]))
        )
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=USER_ID,
        user_name="admin",
        user_display_name="管理員",
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    _save_challenge(options.challenge, "register")
    return json.loads(options_to_json(options))


def verify_registration(credential: dict, rp_id: str, origin: str) -> bool:
    if not WEBAUTHN_OK:
        return False
    challenge = _pop_challenge("register")
    if not challenge:
        return False
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
    )
    with _lock:
        store = _load_store()
        store["credentials"].append(
            {
                "id": bytes_to_base64url(verification.credential_id),
                "public_key": bytes_to_base64url(verification.credential_public_key),
                "sign_count": verification.sign_count,
                "rp_id": rp_id,
            }
        )
        _save_store(store)
    return True


def authentication_options(rp_id: str):
    if not WEBAUTHN_OK:
        raise RuntimeError("webauthn 未安裝")
    allow = []
    for c in _load_store()["credentials"]:
        if c.get("rp_id") != rp_id:
            continue
        allow.append(
            PublicKeyCredentialDescriptor(
                id=_b64url_decode(c["id"]),
            )
        )
    if not allow:
        raise RuntimeError("尚未設定指紋")
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    _save_challenge(options.challenge, "login")
    return json.loads(options_to_json(options))


def verify_authentication(credential: dict, rp_id: str, origin: str) -> bool:
    if not WEBAUTHN_OK:
        return False
    challenge = _pop_challenge("login")
    if not challenge:
        return False
    cred_id = credential.get("id") or credential.get("rawId")
    if not cred_id:
        return False
    store = _load_store()
    matched = None
    for c in store["credentials"]:
        if c.get("id") == cred_id and c.get("rp_id") == rp_id:
            matched = c
            break
    if not matched:
        return False
    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=_b64url_decode(matched["public_key"]),
        credential_current_sign_count=matched.get("sign_count", 0),
    )
    with _lock:
        store = _load_store()
        for c in store["credentials"]:
            if c.get("id") == cred_id and c.get("rp_id") == rp_id:
                c["sign_count"] = verification.new_sign_count
                break
        _save_store(store)
    return True
