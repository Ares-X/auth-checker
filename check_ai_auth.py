#!/usr/bin/env python3
"""Check Codex or Claude auth files without printing secrets.

Provider selection:
  - codex:  checks Codex auth.json, auth.json.*, authN.json files
  - claude: checks Claude credentials.json, credentials.json.*,
             credentialsN.json, and hidden .credentials variants
  - auto:   infers provider from file name and JSON shape

The script is read-only. It never prints access tokens, refresh tokens, API
keys, or OAuth token values.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Literal


Provider = Literal["auto", "codex", "claude"]

CODEX_MODELS_URL = "https://chatgpt.com/backend-api/codex/models"
CLAUDE_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_CODEX_AUTH_FILE = "~/.codex/auth.json"
DEFAULT_CLAUDE_AUTH_FILE = "~/.claude/.credentials.json"
DEFAULT_CLIENT_VERSION = "0.0.0"
DEFAULT_MIN_VALID_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 15
USABLE_STATUSES = {"valid", "locally_valid"}
COLOR_GREEN = "\033[32m"
COLOR_RED = "\033[31m"
COLOR_YELLOW = "\033[33m"
COLOR_DIM = "\033[2m"
COLOR_RESET = "\033[0m"


@dataclass(frozen=True)
class DynamicProbe:
    enabled: bool
    ok: bool | None
    status_code: int | None
    detail: str
    endpoint: str
    model_count: int | None = None


@dataclass(frozen=True)
class CodexTokenInfo:
    present: bool
    is_jwt: bool
    issued_at: int | None
    not_before: int | None
    expires_at: int | None
    seconds_left: int | None
    issuer: str | None
    audience: Any


@dataclass(frozen=True)
class ClaudeTokenInfo:
    present: bool
    expires_at: str | None
    seconds_left: int | None


@dataclass(frozen=True)
class SubscriptionInfo:
    plan: str
    source: str
    raw_type: str | None = None
    rate_limit_tier: str | None = None
    billing_type: str | None = None


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def format_utc(epoch_seconds: int | None) -> str:
    if epoch_seconds is None:
        return "missing"
    return dt.datetime.fromtimestamp(epoch_seconds, dt.timezone.utc).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("file root is not a JSON object")
    return value


def b64url_json(segment: str) -> dict[str, Any]:
    padding = "=" * ((4 - len(segment) % 4) % 4)
    raw = base64.urlsafe_b64decode(segment + padding)
    return json.loads(raw.decode("utf-8"))


def jwt_payload(token: str | None) -> dict[str, Any] | None:
    if not token or token.count(".") < 2:
        return None
    try:
        return b64url_json(token.split(".")[1])
    except Exception:
        return None


def parse_iso_datetime(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_error_detail(body: bytes) -> str | None:
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return error["message"]
    detail = payload.get("detail")
    if isinstance(detail, str):
        return detail
    return None


def is_codex_auth_name(name: str) -> bool:
    return (
        name == "auth.json"
        or name.startswith("auth.json.")
        or numbered_json_name(name, "auth")
    )


def is_claude_auth_name(name: str) -> bool:
    return (
        name == "credentials.json"
        or name.startswith("credentials.json.")
        or numbered_json_name(name, "credentials")
        or name == ".credentials.json"
        or name.startswith(".credentials.json.")
        or numbered_json_name(name, ".credentials")
    )


def numbered_json_name(name: str, stem: str) -> bool:
    if not name.startswith(stem) or not name.endswith(".json"):
        return False
    suffix = name[len(stem) : -len(".json")]
    return suffix.isdigit()


def safe_iter_dirs(path: Path) -> list[Path]:
    try:
        children = path.iterdir()
    except OSError:
        return []
    return sorted(child for child in children if child.is_dir())


def safe_iter_files(path: Path) -> list[Path]:
    try:
        children = path.iterdir()
    except OSError:
        return []
    return sorted(child for child in children if child.is_file())


def discover_auth_files(scan_dir: Path, kind: Provider) -> list[Path]:
    if not scan_dir.exists():
        raise ValueError(f"scan dir does not exist: {scan_dir}")
    if not scan_dir.is_dir():
        raise ValueError(f"scan path is not a directory: {scan_dir}")

    search_dirs = [scan_dir]
    for first_level in safe_iter_dirs(scan_dir):
        search_dirs.append(first_level)
        search_dirs.extend(safe_iter_dirs(first_level))

    candidates: list[Path] = []
    for directory in search_dirs:
        for path in safe_iter_files(directory):
            if kind == "codex" and is_codex_auth_name(path.name):
                candidates.append(path)
            elif kind == "claude" and is_claude_auth_name(path.name):
                candidates.append(path)
            elif kind == "auto" and (
                is_codex_auth_name(path.name) or is_claude_auth_name(path.name)
            ):
                candidates.append(path)
    return sorted(candidates)


def infer_provider(path: Path | str, payload: dict[str, Any], requested: Provider) -> str:
    if requested in {"codex", "claude"}:
        return requested

    name = path.name if isinstance(path, Path) else path.split("/")[-1]
    if is_claude_auth_name(name):
        return "claude"
    if is_codex_auth_name(name):
        return "codex"

    tokens = payload.get("tokens")
    if isinstance(tokens, dict) and (
        "access_token" in tokens or "refresh_token" in tokens or "id_token" in tokens
    ):
        return "codex"
    if any(key in payload for key in ("oauthToken", "claudeAiOauth", "accessToken")):
        return "claude"
    if "api_key" in payload:
        return "claude"
    raise ValueError("could not infer provider; pass --kind codex or --kind claude")


def decode_codex_jwt(token: str | None, now_epoch: int) -> CodexTokenInfo:
    if not token:
        return CodexTokenInfo(False, False, None, None, None, None, None, None)
    parts = token.split(".")
    if len(parts) < 2:
        return CodexTokenInfo(True, False, None, None, None, None, None, None)
    payload = b64url_json(parts[1])
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")
    return CodexTokenInfo(
        present=True,
        is_jwt=True,
        issued_at=iat if isinstance(iat, int) else None,
        not_before=nbf if isinstance(nbf, int) else None,
        expires_at=exp if isinstance(exp, int) else None,
        seconds_left=(exp - now_epoch) if isinstance(exp, int) else None,
        issuer=payload.get("iss") if isinstance(payload.get("iss"), str) else None,
        audience=payload.get("aud"),
    )


def codex_tokens(payload: dict[str, Any]) -> dict[str, Any]:
    tokens = payload.get("tokens")
    if not isinstance(tokens, dict):
        raise ValueError("Codex auth file is missing object field: tokens")
    return tokens


def extract_codex_account_id(tokens: dict[str, Any], access_token: str | None) -> str | None:
    direct = tokens.get("account_id")
    if isinstance(direct, str) and direct:
        return direct
    payload = jwt_payload(access_token)
    if payload is None:
        return None
    auth_claim = payload.get("https://api.openai.com/auth")
    if not isinstance(auth_claim, dict):
        return None
    account_id = auth_claim.get("chatgpt_account_id")
    return account_id if isinstance(account_id, str) and account_id else None


def extract_codex_subscription(access_token: str | None, id_token: str | None) -> SubscriptionInfo:
    for token_name, token in (("access_token", access_token), ("id_token", id_token)):
        payload = jwt_payload(token)
        if not payload:
            continue
        auth_claim = payload.get("https://api.openai.com/auth")
        if not isinstance(auth_claim, dict):
            continue
        plan = auth_claim.get("chatgpt_plan_type")
        if isinstance(plan, str) and plan:
            return SubscriptionInfo(
                plan=normalize_plan_value(plan),
                source=f"codex_{token_name}_jwt",
                raw_type=plan,
            )
    return SubscriptionInfo(plan="unknown", source="not_found")


def probe_codex(
    access_token: str,
    account_id: str | None,
    *,
    client_version: str,
    timeout: float,
) -> DynamicProbe:
    query = urllib.parse.urlencode({"client_version": client_version})
    request = urllib.request.Request(
        f"{CODEX_MODELS_URL}?{query}",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Origin": "https://chatgpt.com",
            "Referer": "https://chatgpt.com/codex",
            "User-Agent": "ai-auth-check/1.0",
            **({"chatgpt-account-id": account_id} if account_id else {}),
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(2_000_000)
            status_code = int(response.status)
    except urllib.error.HTTPError as exc:
        detail = parse_error_detail(exc.read(8192)) or exc.reason or "HTTP error"
        if exc.code in {401, 403}:
            return DynamicProbe(True, False, exc.code, f"auth rejected: {detail}", CODEX_MODELS_URL)
        return DynamicProbe(
            True, None, exc.code, f"unexpected HTTP {exc.code}: {detail}", CODEX_MODELS_URL
        )
    except TimeoutError:
        return DynamicProbe(True, None, None, "network timeout", CODEX_MODELS_URL)
    except urllib.error.URLError as exc:
        return DynamicProbe(True, None, None, f"network error: {exc.reason}", CODEX_MODELS_URL)
    except OSError as exc:
        return DynamicProbe(True, None, None, f"network error: {exc}", CODEX_MODELS_URL)

    if status_code != 200:
        return DynamicProbe(True, None, status_code, f"unexpected HTTP {status_code}", CODEX_MODELS_URL)
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return DynamicProbe(True, None, status_code, "HTTP 200 but response was not JSON", CODEX_MODELS_URL)
    models = payload.get("models")
    model_count = len(models) if isinstance(models, list) else None
    if model_count is None:
        return DynamicProbe(
            True, None, status_code, "HTTP 200 but models field was missing", CODEX_MODELS_URL
        )
    return DynamicProbe(
        True,
        True,
        status_code,
        "Codex models endpoint accepted token",
        CODEX_MODELS_URL,
        model_count,
    )


def classify_codex(info: CodexTokenInfo, probe: DynamicProbe, min_valid_seconds: int) -> tuple[str, int]:
    if not info.present:
        return "missing_access_token", 1
    if not info.is_jwt:
        return "access_token_not_jwt", 1
    if info.seconds_left is None:
        return "access_token_missing_exp", 1
    if info.seconds_left <= 0:
        return "expired", 1
    if info.seconds_left < min_valid_seconds:
        return "expiring_soon", 1
    return classify_probe(probe)


def make_codex_report(
    auth_path: Path | str,
    payload: dict[str, Any],
    *,
    min_valid_seconds: int,
    no_network: bool,
    client_version: str,
    timeout: float,
) -> tuple[dict[str, Any], int]:
    tokens = codex_tokens(payload)
    access_token = tokens.get("access_token")
    if access_token is not None and not isinstance(access_token, str):
        raise ValueError("tokens.access_token is not a string")
    id_token = tokens.get("id_token")
    if id_token is not None and not isinstance(id_token, str):
        raise ValueError("tokens.id_token is not a string")

    now_epoch = int(time.time())
    access_info = decode_codex_jwt(access_token, now_epoch)
    id_info = decode_codex_jwt(id_token, now_epoch)
    account_id = extract_codex_account_id(tokens, access_token)
    subscription = extract_codex_subscription(access_token, id_token)
    probe = (
        DynamicProbe(False, None, None, "disabled", CODEX_MODELS_URL)
        if no_network or not access_token
        else probe_codex(
            access_token,
            account_id,
            client_version=client_version,
            timeout=timeout,
        )
    )
    status, exit_code = classify_codex(access_info, probe, min_valid_seconds)
    return (
        {
            "provider": "codex",
            "status": status,
            "checked_at": utc_now().isoformat(),
            "auth_file": str(auth_path),
            "last_refresh": payload.get("last_refresh"),
            "min_valid_seconds": min_valid_seconds,
            "subscription": subscription_info_json(subscription),
            "tokens": {
                "access_token": codex_token_info_json(access_info),
                "id_token": codex_token_info_json(id_info),
                "refresh_token_present": isinstance(tokens.get("refresh_token"), str)
                and bool(tokens.get("refresh_token")),
                "account_id_present": bool(account_id),
            },
            "dynamic_probe": probe_json(probe),
        },
        exit_code,
    )


def codex_token_info_json(info: CodexTokenInfo) -> dict[str, Any]:
    return {
        "present": info.present,
        "is_jwt": info.is_jwt,
        "issued_at": format_utc(info.issued_at),
        "not_before": format_utc(info.not_before),
        "expires_at": format_utc(info.expires_at),
        "seconds_left": info.seconds_left,
        "issuer": info.issuer,
        "audience": info.audience,
    }


def extract_claude_token_info(
    payload: dict[str, Any], now_epoch: int
) -> tuple[str, str | None, ClaudeTokenInfo]:
    oauth = payload.get("oauthToken") or payload.get("claudeAiOauth")
    if isinstance(oauth, dict):
        access_token = oauth.get("accessToken")
        expires_at_raw = oauth.get("expiresAt")
        expires_at, seconds_left = parse_claude_expiry(expires_at_raw, now_epoch)
        return (
            "oauth",
            access_token if isinstance(access_token, str) else None,
            ClaudeTokenInfo(bool(access_token), expires_at, seconds_left),
        )

    api_key = payload.get("api_key")
    if isinstance(api_key, str) and api_key:
        return "api_key", api_key, ClaudeTokenInfo(True, "never", None)

    access_token = payload.get("accessToken")
    if isinstance(access_token, str) and access_token:
        expires_at, seconds_left = parse_claude_expiry(payload.get("expiresAt"), now_epoch)
        return "oauth", access_token, ClaudeTokenInfo(True, expires_at, seconds_left)

    return "", None, ClaudeTokenInfo(False, None, None)


def extract_claude_subscription(auth_path: Path | str, payload: dict[str, Any]) -> SubscriptionInfo:
    for source, container in (
        ("claude_credentials_oauthToken", payload.get("oauthToken")),
        ("claude_credentials_claudeAiOauth", payload.get("claudeAiOauth")),
        ("claude_credentials_root", payload),
    ):
        if not isinstance(container, dict):
            continue
        subscription_type = string_value(container.get("subscriptionType"))
        rate_limit_tier = string_value(container.get("rateLimitTier"))
        billing_type = string_value(container.get("billingType"))
        info = subscription_from_claude_fields(
            subscription_type=subscription_type,
            rate_limit_tier=rate_limit_tier,
            billing_type=billing_type,
            source=source,
        )
        if info.plan != "unknown":
            return info

    claude_json = find_claude_json_for_auth(auth_path)
    if claude_json is not None:
        try:
            claude_payload = load_json(claude_json)
        except Exception:
            claude_payload = {}
        oauth_account = claude_payload.get("oauthAccount")
        if isinstance(oauth_account, dict):
            subscription_type = string_value(oauth_account.get("subscriptionType"))
            rate_limit_tier = string_value(oauth_account.get("organizationRateLimitTier"))
            billing_type = string_value(oauth_account.get("billingType"))
            info = subscription_from_claude_fields(
                subscription_type=subscription_type,
                rate_limit_tier=rate_limit_tier,
                billing_type=billing_type,
                source="claude_json_oauthAccount",
            )
            if info.plan != "unknown":
                return info

    return SubscriptionInfo(plan="unknown", source="not_found")


def find_claude_json_for_auth(auth_path: Path | str) -> Path | None:
    if isinstance(auth_path, str) and (auth_path.startswith("http://") or auth_path.startswith("https://")):
        return None
    try:
        resolved = Path(auth_path).expanduser().resolve()
        parents = [resolved.parent, *resolved.parents]
        for parent in parents:
            candidate = parent / ".claude.json"
            if candidate.is_file():
                return candidate
    except Exception:
        return None
    return None


def subscription_from_claude_fields(
    *,
    subscription_type: str | None,
    rate_limit_tier: str | None,
    billing_type: str | None,
    source: str,
) -> SubscriptionInfo:
    if rate_limit_tier:
        return SubscriptionInfo(
            plan=normalize_claude_rate_limit_tier(rate_limit_tier),
            source=source,
            raw_type=subscription_type,
            rate_limit_tier=rate_limit_tier,
            billing_type=billing_type,
        )
    if subscription_type:
        return SubscriptionInfo(
            plan=normalize_plan_value(subscription_type),
            source=source,
            raw_type=subscription_type,
            billing_type=billing_type,
        )
    if billing_type:
        return SubscriptionInfo(
            plan=normalize_claude_billing_type(billing_type),
            source=source,
            billing_type=billing_type,
        )
    return SubscriptionInfo(plan="unknown", source=source)


def normalize_claude_rate_limit_tier(value: str) -> str:
    prefix = "default_claude_"
    if value.startswith(prefix):
        return normalize_plan_value(value[len(prefix) :])
    return normalize_plan_value(value)


def normalize_claude_billing_type(value: str) -> str:
    if value == "stripe_subscription":
        return "subscription"
    return normalize_plan_value(value)


def normalize_plan_value(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def string_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def parse_claude_expiry(value: Any, now_epoch: int) -> tuple[str | None, int | None]:
    expires_at_epoch: int | None = None
    expires_at_str: str | None = None
    if isinstance(value, (int, float)):
        expires_at_epoch = int(value / 1000) if value > 10_000_000_000 else int(value)
        expires_at_str = dt.datetime.fromtimestamp(expires_at_epoch, dt.timezone.utc).isoformat()
    elif isinstance(value, str):
        expires_at_str = value
        parsed = parse_iso_datetime(value)
        if parsed:
            expires_at_epoch = int(parsed.timestamp())
    seconds_left = expires_at_epoch - now_epoch if expires_at_epoch is not None else None
    return expires_at_str, seconds_left


def probe_claude(token_type: str, token_value: str, *, timeout: float) -> DynamicProbe:
    headers = {
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        "User-Agent": "ai-auth-check/1.0",
    }
    if token_type == "oauth":
        headers["Authorization"] = f"Bearer {token_value}"
    elif token_type == "api_key":
        headers["x-api-key"] = token_value
    else:
        return DynamicProbe(True, False, None, f"unknown token type: {token_type}", CLAUDE_MESSAGES_URL)

    # Invalid model request: authentication is checked, but no real generation is requested.
    body = {
        "model": "auth_test_ping",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "ping"}],
    }
    request = urllib.request.Request(
        CLAUDE_MESSAGES_URL,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return DynamicProbe(
                True, True, int(response.status), "API accepted request", CLAUDE_MESSAGES_URL
            )
    except urllib.error.HTTPError as exc:
        detail = parse_error_detail(exc.read(8192)) or exc.reason or "HTTP error"
        if exc.code in {401, 403}:
            return DynamicProbe(True, False, exc.code, f"auth rejected: {detail}", CLAUDE_MESSAGES_URL)
        if exc.code in {400, 404} and (
            "model" in detail.lower() or "auth_test_ping" in detail
        ):
            return DynamicProbe(
                True,
                True,
                exc.code,
                "auth valid; received expected invalid-model response",
                CLAUDE_MESSAGES_URL,
            )
        if exc.code == 429:
            return DynamicProbe(True, True, exc.code, "auth valid; rate limited", CLAUDE_MESSAGES_URL)
        return DynamicProbe(
            True, None, exc.code, f"unexpected HTTP {exc.code}: {detail}", CLAUDE_MESSAGES_URL
        )
    except TimeoutError:
        return DynamicProbe(True, None, None, "network timeout", CLAUDE_MESSAGES_URL)
    except urllib.error.URLError as exc:
        return DynamicProbe(True, None, None, f"network error: {exc.reason}", CLAUDE_MESSAGES_URL)
    except OSError as exc:
        return DynamicProbe(True, None, None, f"network error: {exc}", CLAUDE_MESSAGES_URL)


def classify_claude(
    info: ClaudeTokenInfo, probe: DynamicProbe, min_valid_seconds: int
) -> tuple[str, int]:
    if not info.present:
        return "missing_token", 1
    if info.seconds_left is not None:
        if info.seconds_left <= 0:
            return "expired", 1
        if info.seconds_left < min_valid_seconds:
            return "expiring_soon", 1
    return classify_probe(probe)


def make_claude_report(
    auth_path: Path | str,
    payload: dict[str, Any],
    *,
    min_valid_seconds: int,
    no_network: bool,
    timeout: float,
) -> tuple[dict[str, Any], int]:
    token_type, token_value, token_info = extract_claude_token_info(payload, int(time.time()))
    subscription = extract_claude_subscription(auth_path, payload)
    probe = (
        DynamicProbe(False, None, None, "disabled", CLAUDE_MESSAGES_URL)
        if no_network or not token_value
        else probe_claude(token_type, token_value, timeout=timeout)
    )
    status, exit_code = classify_claude(token_info, probe, min_valid_seconds)
    return (
        {
            "provider": "claude",
            "status": status,
            "checked_at": utc_now().isoformat(),
            "auth_file": str(auth_path),
            "min_valid_seconds": min_valid_seconds,
            "subscription": subscription_info_json(subscription),
            "token_type": token_type,
            "token": {
                "present": token_info.present,
                "expires_at": token_info.expires_at,
                "seconds_left": token_info.seconds_left,
            },
            "dynamic_probe": probe_json(probe),
        },
        exit_code,
    )


def classify_probe(probe: DynamicProbe) -> tuple[str, int]:
    if probe.enabled:
        if probe.ok is True:
            return "valid", 0
        if probe.ok is False:
            return "server_rejected", 1
        return "network_unknown", 3
    return "locally_valid", 0


def probe_json(probe: DynamicProbe) -> dict[str, Any]:
    return {
        "enabled": probe.enabled,
        "ok": probe.ok,
        "status_code": probe.status_code,
        "detail": probe.detail,
        "endpoint": probe.endpoint,
        "model_count": probe.model_count,
    }


def subscription_info_json(info: SubscriptionInfo) -> dict[str, Any]:
    return {
        "plan": info.plan,
        "source": info.source,
        "raw_type": info.raw_type,
        "rate_limit_tier": info.rate_limit_tier,
        "billing_type": info.billing_type,
    }


def fetch_json_from_url(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ai-auth-check/1.0",
            "Accept": "application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(2_000_000)
        value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("URL response root is not a JSON object")
    return value


def make_report(
    auth_path: Path | str,
    *,
    kind: Provider,
    min_valid_seconds: int,
    no_network: bool,
    client_version: str,
    timeout: float,
) -> tuple[dict[str, Any], int]:
    if isinstance(auth_path, str) and (auth_path.startswith("http://") or auth_path.startswith("https://")):
        payload = fetch_json_from_url(auth_path, timeout)
    else:
        payload = load_json(Path(auth_path))
    provider = infer_provider(auth_path, payload, kind)
    if provider == "codex":
        return make_codex_report(
            auth_path,
            payload,
            min_valid_seconds=min_valid_seconds,
            no_network=no_network,
            client_version=client_version,
            timeout=timeout,
        )
    if provider == "claude":
        return make_claude_report(
            auth_path,
            payload,
            min_valid_seconds=min_valid_seconds,
            no_network=no_network,
            timeout=timeout,
        )
    raise ValueError(f"unsupported provider: {provider}")


def make_error_report(auth_path: Path | str, exc: Exception, kind: Provider) -> dict[str, Any]:
    return {
        "provider": kind,
        "status": "error",
        "checked_at": utc_now().isoformat(),
        "auth_file": str(auth_path),
        "error": str(exc),
    }


def emit_result(
    on_result: Callable[[dict[str, Any]], None] | None,
    report: dict[str, Any],
    emit_lock: Any | None,
) -> None:
    if on_result is None:
        return
    if emit_lock is None:
        on_result(report)
        return
    with emit_lock:
        on_result(report)


def make_scan_report(
    scan_dir: Path,
    *,
    kind: Provider,
    min_valid_seconds: int,
    no_network: bool,
    client_version: str,
    timeout: float,
    workers: int = 1,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[dict[str, Any], int]:
    auth_files = discover_auth_files(scan_dir, kind)
    results: list[dict[str, Any]] = []
    exit_codes: list[int] = []
    emit_lock = Lock() if workers > 1 and on_result is not None else None

    def process_path(auth_path: Path) -> tuple[dict[str, Any], int]:
        try:
            report, exit_code = make_report(
                auth_path,
                kind=kind,
                min_valid_seconds=min_valid_seconds,
                no_network=no_network,
                client_version=client_version,
                timeout=timeout,
            )
        except Exception as exc:
            report = make_error_report(auth_path, exc, kind)
            exit_code = 2
        emit_result(on_result, report, emit_lock)
        return report, exit_code

    if workers > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(process_path, path): path for path in auth_files}
            for future in as_completed(futures):
                report, exit_code = future.result()
                results.append(report)
                exit_codes.append(exit_code)
    else:
        for auth_path in auth_files:
            report, exit_code = process_path(auth_path)
            results.append(report)
            exit_codes.append(exit_code)

    status_counts: dict[str, int] = {}
    usable_count = 0
    for result in results:
        status = str(result.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
        if status in USABLE_STATUSES:
            usable_count += 1

    if not auth_files:
        overall_exit = 2
    elif any(code in {1, 2} for code in exit_codes):
        overall_exit = 1 if any(code == 1 for code in exit_codes) else 2
    elif any(code == 3 for code in exit_codes):
        overall_exit = 3
    else:
        overall_exit = 0

    return (
        {
            "status": "ok" if overall_exit == 0 else "attention_required",
            "checked_at": utc_now().isoformat(),
            "provider": kind,
            "scan_dir": str(scan_dir),
            "max_depth": 2,
            "auth_file_count": len(auth_files),
            "usable_count": usable_count,
            "status_counts": status_counts,
            "auth_files": results,
        },
        overall_exit,
    )


def make_url_list_report(
    urls: list[str],
    url_list_path: Path,
    *,
    kind: Provider,
    min_valid_seconds: int,
    no_network: bool,
    client_version: str,
    timeout: float,
    workers: int = 1,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[dict[str, Any], int]:
    results: list[dict[str, Any]] = []
    exit_codes: list[int] = []
    emit_lock = Lock() if workers > 1 and on_result is not None else None

    def process_url(url: str) -> tuple[dict[str, Any], int]:
        try:
            report, exit_code = make_report(
                url,
                kind=kind,
                min_valid_seconds=min_valid_seconds,
                no_network=no_network,
                client_version=client_version,
                timeout=timeout,
            )
        except Exception as exc:
            report = make_error_report(url, exc, kind)
            exit_code = 2
        emit_result(on_result, report, emit_lock)
        return report, exit_code

    if workers > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(process_url, url): url for url in urls}
            for future in as_completed(futures):
                report, exit_code = future.result()
                results.append(report)
                exit_codes.append(exit_code)
    else:
        for url in urls:
            report, exit_code = process_url(url)
            results.append(report)
            exit_codes.append(exit_code)

    status_counts: dict[str, int] = {}
    usable_count = 0
    for result in results:
        status = str(result.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
        if status in USABLE_STATUSES:
            usable_count += 1

    if not urls:
        overall_exit = 2
    elif any(code in {1, 2} for code in exit_codes):
        overall_exit = 1 if any(code == 1 for code in exit_codes) else 2
    elif any(code == 3 for code in exit_codes):
        overall_exit = 3
    else:
        overall_exit = 0

    return (
        {
            "status": "ok" if overall_exit == 0 else "attention_required",
            "checked_at": utc_now().isoformat(),
            "provider": kind,
            "scan_dir": str(url_list_path),
            "max_depth": 1,
            "auth_file_count": len(urls),
            "usable_count": usable_count,
            "status_counts": status_counts,
            "auth_files": results,
        },
        overall_exit,
    )


def auth_report_usable(report: dict[str, Any]) -> str:
    status = str(report.get("status", "unknown"))
    if status in USABLE_STATUSES:
        return "yes"
    if status == "network_unknown":
        return "unknown"
    return "no"


def result_label(status: str) -> str:
    if status in USABLE_STATUSES:
        return "OK"
    if status == "network_unknown":
        return "UNKNOWN"
    return "FAIL"


def colorize_result(text: str, result: str, *, color_enabled: bool) -> str:
    if not color_enabled:
        return text
    if result == "OK":
        return f"{COLOR_GREEN}{text}{COLOR_RESET}"
    if result == "FAIL":
        return f"{COLOR_RED}{text}{COLOR_RESET}"
    if result == "UNKNOWN":
        return f"{COLOR_YELLOW}{text}{COLOR_RESET}"
    return text


def color_dim(text: str, *, color_enabled: bool) -> str:
    return f"{COLOR_DIM}{text}{COLOR_RESET}" if color_enabled else text


def resolve_color_enabled(args: argparse.Namespace) -> bool:
    if args.color == "always":
        return True
    if args.color == "never":
        return False
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def expiry_fields(report: dict[str, Any]) -> tuple[str, str]:
    if report.get("provider") == "codex":
        token = report.get("tokens", {}).get("access_token", {})
    else:
        token = report.get("token", {})
    seconds_left = token.get("seconds_left")
    expires_at = token.get("expires_at", "missing")
    expires_in = "unknown" if seconds_left is None else f"{seconds_left}s"
    return str(expires_in), str(expires_at)


def probe_http(report: dict[str, Any]) -> str:
    probe = report.get("dynamic_probe")
    if not isinstance(probe, dict):
        return "-"
    status_code = probe.get("status_code")
    return "-" if status_code is None else str(status_code)


def probe_detail(report: dict[str, Any]) -> str:
    probe = report.get("dynamic_probe")
    if isinstance(probe, dict) and probe.get("detail"):
        return str(probe["detail"])
    if report.get("error"):
        return str(report["error"])
    return ""


def subscription_plan(report: dict[str, Any]) -> str:
    subscription = report.get("subscription")
    if isinstance(subscription, dict):
        plan = subscription.get("plan")
        if isinstance(plan, str) and plan:
            return plan
    return "unknown"


def subscription_detail(report: dict[str, Any]) -> str:
    subscription = report.get("subscription")
    if not isinstance(subscription, dict):
        return "subscription: unknown"
    parts = [f"plan={subscription.get('plan', 'unknown')}"]
    for key in ("source", "raw_type", "rate_limit_tier", "billing_type"):
        value = subscription.get(key)
        if value:
            parts.append(f"{key}={value}")
    return "subscription: " + " ".join(parts)


def format_table_row(report: dict[str, Any], *, color_enabled: bool) -> str:
    status = str(report.get("status", "unknown"))
    result = result_label(status)
    expires_in, expires_at = expiry_fields(report)
    result_text = colorize_result(f"{result:<15}", result, color_enabled=color_enabled)
    return (
        f"{result_text} "
        f"{str(report.get('provider', 'unknown')):<8} "
        f"{subscription_plan(report):<14} "
        f"{status:<24} "
        f"{probe_http(report):<5} "
        f"{expires_in:<12} "
        f"{expires_at:<28} "
        f"{report.get('auth_file', 'unknown')}"
    )


def print_table_header(*, color_enabled: bool) -> None:
    header = (
        f"{'RESULT':<15} {'PROVIDER':<8} {'PLAN':<14} {'STATUS':<24} {'HTTP':<5} "
        f"{'EXPIRES_IN':<12} {'EXPIRES_AT':<28} PATH"
    )
    print(color_dim(header, color_enabled=color_enabled), flush=True)


def print_human(report: dict[str, Any], *, color_enabled: bool) -> None:
    probe = report["dynamic_probe"]
    print_table_header(color_enabled=color_enabled)
    print(format_table_row(report, color_enabled=color_enabled))
    print("")
    print(f"checked_at: {report['checked_at']}")
    print(subscription_detail(report))
    if report["provider"] == "codex":
        id_token = report["tokens"]["id_token"]
        print(f"last_refresh: {report['last_refresh']}")
        print(
            "id_token: "
            f"expires_at={id_token['expires_at']} seconds_left={id_token['seconds_left']}"
        )
        print(
            "refresh_token: "
            f"{'present' if report['tokens']['refresh_token_present'] else 'missing'}"
        )
    else:
        token = report["token"]
        print(f"token_type: {str(report['token_type']).upper()}")
        print(f"token: expires_at={token['expires_at']} seconds_left={token['seconds_left']}")
    print(
        "dynamic_probe: "
        f"enabled={probe['enabled']} ok={probe['ok']} "
        f"http={probe['status_code']} detail={probe['detail']}"
    )


def print_scan_item(report: dict[str, Any], *, quiet: bool, color_enabled: bool) -> None:
    provider = report.get("provider", "unknown")
    status = report.get("status", "unknown")
    path = report.get("auth_file", "unknown")
    if quiet:
        result = result_label(str(status))
        print(
            f"{colorize_result(result, result, color_enabled=color_enabled)}"
            f"\t{provider}\t{subscription_plan(report)}\t{status}\t{path}",
            flush=True,
        )
        return
    print(format_table_row(report, color_enabled=color_enabled), flush=True)
    detail = probe_detail(report)
    if detail:
        print(color_dim(f"  detail: {detail}", color_enabled=color_enabled), flush=True)


def print_scan_start(scan_dir: Path, *, kind: Provider, quiet: bool, color_enabled: bool) -> None:
    if quiet:
        return
    print(f"scan_dir: {scan_dir} provider: {kind}", flush=True)
    print_table_header(color_enabled=color_enabled)


def print_scan_summary(report: dict[str, Any], *, quiet: bool) -> None:
    if quiet:
        return
    print(
        "summary: "
        f"usable={report['usable_count']}/{report['auth_file_count']} "
        f"status={report['status']} provider={report['provider']} "
        f"scan_dir={report['scan_dir']}",
        flush=True,
    )


def print_usable_summary(
    report: dict[str, Any], *, quiet: bool, color_enabled: bool
) -> None:
    usable_items = [
        item
        for item in report.get("auth_files", [])
        if str(item.get("status", "unknown")) in USABLE_STATUSES
    ]
    print("==== usable auth files ====", flush=True)
    if not usable_items:
        print("none", flush=True)
        print("===========================", flush=True)
        return

    if not quiet:
        print_table_header(color_enabled=color_enabled)
    for item in usable_items:
        if quiet:
            provider = item.get("provider", "unknown")
            status = item.get("status", "unknown")
            path = item.get("auth_file", "unknown")
            result = result_label(str(status))
            print(
                f"{colorize_result(result, result, color_enabled=color_enabled)}"
                f"\t{provider}\t{subscription_plan(item)}\t{status}\t{path}",
                flush=True,
            )
        else:
            print(format_table_row(item, color_enabled=color_enabled), flush=True)
    print("===========================", flush=True)


def default_auth_file(kind: Provider) -> str:
    if kind == "claude":
        return DEFAULT_CLAUDE_AUTH_FILE
    return DEFAULT_CODEX_AUTH_FILE


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Codex or Claude auth files without printing secrets."
    )
    parser.add_argument(
        "-k",
        "--kind",
        choices=("auto", "codex", "claude"),
        default="auto",
        help="Auth provider to check. Default: auto.",
    )
    parser.add_argument(
        "--auth-file",
        default=None,
        help=(
            "Path to one auth file. Defaults to ~/.codex/auth.json for auto/codex "
            "and ~/.claude/.credentials.json for claude."
        ),
    )
    parser.add_argument(
        "-d",
        "--dir",
        default=None,
        help=(
            "Scan matching auth files directly under DIR and one/two-level "
            "subdirectories under DIR."
        ),
    )
    parser.add_argument(
        "-l",
        "--url-list",
        default=None,
        help="Path to a text file containing a list of URLs to verify (one URL per line).",
    )
    parser.add_argument(
        "-b",
        "--workers",
        type=int,
        default=1,
        help="Number of concurrent workers for scanning or URL checking. Default: 1.",
    )
    parser.add_argument(
        "--min-valid-seconds",
        type=int,
        default=DEFAULT_MIN_VALID_SECONDS,
        help=(
            "Return non-zero when token expires sooner than this. "
            f"Default: {DEFAULT_MIN_VALID_SECONDS}."
        ),
    )
    parser.add_argument(
        "--client-version",
        default=DEFAULT_CLIENT_VERSION,
        help=(
            "Codex client_version query value for the models probe. "
            f"Default: {DEFAULT_CLIENT_VERSION}."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Network timeout in seconds. Default: {DEFAULT_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Only check local expiry; skip backend probes.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--quiet", action="store_true", help="Print compact status output.")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Color terminal result labels. Default: auto.",
    )
    parser.add_argument(
        "--watch",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Repeat the check every SECONDS until interrupted.",
    )
    return parser.parse_args(argv)


def run_once(args: argparse.Namespace) -> int:
    kind: Provider = args.kind
    color_enabled = resolve_color_enabled(args)
    if args.url_list:
        url_list_path = Path(args.url_list).expanduser()
        if not url_list_path.exists():
            raise ValueError(f"URL list file does not exist: {url_list_path}")

        urls: list[str] = []
        with url_list_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)

        if not args.json:
            print_scan_start(
                url_list_path,
                kind=kind,
                quiet=args.quiet,
                color_enabled=color_enabled,
            )
        try:
            report, exit_code = make_url_list_report(
                urls,
                url_list_path,
                kind=kind,
                min_valid_seconds=args.min_valid_seconds,
                no_network=args.no_network,
                client_version=args.client_version,
                timeout=args.timeout,
                workers=args.workers,
                on_result=(
                    None
                    if args.json
                    else lambda item: print_scan_item(
                        item,
                        quiet=args.quiet,
                        color_enabled=color_enabled,
                    )
                ),
            )
        except Exception as exc:
            report = {
                "provider": kind,
                "status": "error",
                "checked_at": utc_now().isoformat(),
                "scan_dir": str(url_list_path),
                "error": str(exc),
            }
            if args.json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            elif args.quiet:
                print("error")
            else:
                print(f"status: error\nerror: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print_scan_summary(report, quiet=args.quiet)
            print_usable_summary(
                report,
                quiet=args.quiet,
                color_enabled=color_enabled,
            )
        return exit_code

    if args.dir:
        scan_dir = Path(args.dir).expanduser()
        if not args.json:
            print_scan_start(
                scan_dir,
                kind=kind,
                quiet=args.quiet,
                color_enabled=color_enabled,
            )
        try:
            report, exit_code = make_scan_report(
                scan_dir,
                kind=kind,
                min_valid_seconds=args.min_valid_seconds,
                no_network=args.no_network,
                client_version=args.client_version,
                timeout=args.timeout,
                workers=args.workers,
                on_result=(
                    None
                    if args.json
                    else lambda item: print_scan_item(
                        item,
                        quiet=args.quiet,
                        color_enabled=color_enabled,
                    )
                ),
            )
        except Exception as exc:
            report = {
                "provider": kind,
                "status": "error",
                "checked_at": utc_now().isoformat(),
                "scan_dir": str(scan_dir),
                "error": str(exc),
            }
            if args.json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            elif args.quiet:
                print("error")
            else:
                print(f"status: error\nerror: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print_scan_summary(report, quiet=args.quiet)
            print_usable_summary(
                report,
                quiet=args.quiet,
                color_enabled=color_enabled,
            )
        return exit_code

    auth_file = args.auth_file or default_auth_file(kind)
    try:
        report, exit_code = make_report(
            Path(auth_file).expanduser(),
            kind=kind,
            min_valid_seconds=args.min_valid_seconds,
            no_network=args.no_network,
            client_version=args.client_version,
            timeout=args.timeout,
        )
    except Exception as exc:
        report = {
            "provider": kind,
            "status": "error",
            "checked_at": utc_now().isoformat(),
            "auth_file": str(Path(auth_file).expanduser()),
            "error": str(exc),
        }
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        elif args.quiet:
            print("error")
        else:
            print(f"status: error\nerror: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.quiet:
        result = result_label(str(report["status"]))
        print(
            f"{colorize_result(result, result, color_enabled=color_enabled)}"
            f"\t{report['provider']}\t{subscription_plan(report)}"
            f"\t{report['status']}\t{report['auth_file']}"
        )
    else:
        print_human(report, color_enabled=color_enabled)
    return exit_code


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.watch is None:
        return run_once(args)
    if args.watch <= 0:
        print("--watch must be greater than 0", file=sys.stderr)
        return 2

    last_exit = 0
    try:
        while True:
            last_exit = run_once(args)
            sys.stdout.flush()
            time.sleep(args.watch)
    except KeyboardInterrupt:
        return last_exit


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
