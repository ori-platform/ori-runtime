# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Install backend-generated Ori runtime configs after signature verification.

The private APK and assisted Termux provisioning paths need one narrow runtime
primitive: accept a generated config, prove it verifies with the same loader the
runtime uses, then atomically write it as ``ori.yaml``. This module deliberately
does not create configs, provision accounts, or store long-lived secrets; those
belong to the product backend / Android shell.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ori.config import Config, ConfigValidationError

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_CONFIG_BYTES = 512 * 1024
_DEFAULT_TIMEOUT_S = 10.0
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ConfigInstallError(Exception):
    """Raised when a generated config cannot be safely installed."""


@dataclass(frozen=True)
class ConfigInstallResult:
    destination: Path
    device_id: str
    signer_id: str
    signed_at_ms: int | None
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "installed": not self.dry_run,
            "dry_run": self.dry_run,
            "destination": str(self.destination),
            "device_id": self.device_id,
            "signer_id": self.signer_id,
            "signed_at_ms": self.signed_at_ms,
        }


def install_signed_config(
    *,
    source: str,
    destination: str | Path,
    bearer_token_env: str | None = None,
    allow_insecure_loopback: bool = False,
    timeout_s: float = _DEFAULT_TIMEOUT_S,
    dry_run: bool = False,
) -> ConfigInstallResult:
    """Verify and atomically install a generated signed runtime config."""

    destination_path = Path(destination).expanduser()
    source_bytes = _read_source(
        source=source,
        bearer_token_env=bearer_token_env,
        allow_insecure_loopback=allow_insecure_loopback,
        timeout_s=timeout_s,
    )
    if not source_bytes.strip():
        raise ConfigInstallError("generated config is empty")
    if len(source_bytes) > _MAX_CONFIG_BYTES:
        raise ConfigInstallError(f"generated config exceeds {_MAX_CONFIG_BYTES} bytes")

    destination_parent = destination_path.parent
    destination_parent.mkdir(parents=True, exist_ok=True)
    result = _verify_with_runtime_loader(
        source_bytes=source_bytes,
        destination_parent=destination_parent,
    )
    if dry_run:
        return ConfigInstallResult(
            destination=destination_path,
            device_id=result.device.id,
            signer_id=str(result.security["config_signature"].get("signer_id") or ""),
            signed_at_ms=result.security["config_signature"].get("signed_at_ms"),
            dry_run=True,
        )

    _atomic_write(destination_path, source_bytes)
    return ConfigInstallResult(
        destination=destination_path,
        device_id=result.device.id,
        signer_id=str(result.security["config_signature"].get("signer_id") or ""),
        signed_at_ms=result.security["config_signature"].get("signed_at_ms"),
    )


def _verify_with_runtime_loader(
    *, source_bytes: bytes, destination_parent: Path
) -> Config:
    fd = -1
    temp_path: Path | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=".ori-config-verify-",
            suffix=".yaml",
            dir=destination_parent,
        )
        temp_path = Path(temp_name)
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(source_bytes)
            fh.flush()
            os.fsync(fh.fileno())
        config = Config.load(str(temp_path))
    except ConfigValidationError as exc:
        raise ConfigInstallError(f"generated config failed validation: {exc}") from exc
    finally:
        if fd != -1:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                # Cleanup is idempotent; another path may have already removed it.
                pass

    signature_cfg = config.security.get("config_signature") or {}
    if not isinstance(signature_cfg, dict) or signature_cfg.get("verified") is not True:
        raise ConfigInstallError(
            "generated config must carry a verified config_signature"
        )
    return config


def _read_source(
    *,
    source: str,
    bearer_token_env: str | None,
    allow_insecure_loopback: bool,
    timeout_s: float,
) -> bytes:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        return _fetch_https_source(
            source=source,
            bearer_token_env=bearer_token_env,
            allow_insecure_loopback=allow_insecure_loopback,
            timeout_s=timeout_s,
        )
    if parsed.scheme:
        raise ConfigInstallError("config source must be a local path or https URL")
    if bearer_token_env:
        raise ConfigInstallError("bearer-token-env is only valid for URL sources")
    path = Path(source).expanduser()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigInstallError(f"cannot read generated config {path}: {exc}") from exc
    if len(data) > _MAX_CONFIG_BYTES:
        raise ConfigInstallError(f"generated config exceeds {_MAX_CONFIG_BYTES} bytes")
    return data


def _fetch_https_source(
    *,
    source: str,
    bearer_token_env: str | None,
    allow_insecure_loopback: bool,
    timeout_s: float,
) -> bytes:
    parsed = urlparse(source)
    if parsed.scheme != "https" and not (
        allow_insecure_loopback
        and parsed.scheme == "http"
        and _is_loopback_host(parsed.hostname)
    ):
        raise ConfigInstallError(
            "remote generated configs must be fetched over https "
            "(http is allowed only for explicit loopback development)"
        )

    headers = {"Accept": "application/x-yaml, text/yaml, application/octet-stream"}
    if bearer_token_env:
        env_name = bearer_token_env.strip()
        if not _ENV_NAME_RE.fullmatch(env_name):
            raise ConfigInstallError("bearer-token-env must be an environment name")
        token = os.environ.get(env_name, "").strip()
        if not token:
            raise ConfigInstallError(f"bearer token env {env_name!r} is not set")
        headers["Authorization"] = f"Bearer {token}"

    request = Request(source, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=timeout_s) as response:
            final_url = response.geturl()
            final = urlparse(final_url)
            if final.scheme != "https" and not (
                allow_insecure_loopback
                and final.scheme == "http"
                and _is_loopback_host(final.hostname)
            ):
                raise ConfigInstallError(
                    "config download redirected to a non-https URL"
                )
            data = cast(bytes, response.read(_MAX_CONFIG_BYTES + 1))
    except ConfigInstallError:
        raise
    except Exception as exc:
        raise ConfigInstallError(f"cannot fetch generated config: {exc}") from exc

    if len(data) > _MAX_CONFIG_BYTES:
        raise ConfigInstallError(f"generated config exceeds {_MAX_CONFIG_BYTES} bytes")
    return data


def _atomic_write(destination: Path, data: bytes) -> None:
    destination_parent = destination.parent
    destination_parent.mkdir(parents=True, exist_ok=True)
    fd = -1
    temp_path: Path | None = None
    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination_parent,
        )
        temp_path = Path(temp_name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, destination)
        _fsync_directory(destination_parent)
    finally:
        if fd != -1:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                # os.replace() may have already moved it into destination.
                pass


def _fsync_directory(path: Path) -> None:
    try:
        dir_fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _is_loopback_host(hostname: str | None) -> bool:
    return (hostname or "").strip().lower() in _LOOPBACK_HOSTS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a backend-generated signed Ori config and atomically install it."
        )
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Local signed config path or HTTPS URL.",
    )
    parser.add_argument(
        "--destination",
        default="ori.yaml",
        help="Destination config path to replace after verification.",
    )
    parser.add_argument(
        "--bearer-token-env",
        help="Environment variable containing a bearer token for HTTPS sources.",
    )
    parser.add_argument(
        "--allow-insecure-loopback",
        action="store_true",
        help="Allow http://localhost or http://127.0.0.1 sources for development only.",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=_DEFAULT_TIMEOUT_S,
        help="HTTPS fetch timeout in seconds.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify without writing the destination file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    args = parser.parse_args(argv)

    try:
        result = install_signed_config(
            source=args.source,
            destination=args.destination,
            bearer_token_env=args.bearer_token_env,
            allow_insecure_loopback=args.allow_insecure_loopback,
            timeout_s=args.timeout_s,
            dry_run=args.dry_run,
        )
    except ConfigInstallError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"ok": True, **result.to_dict()}, sort_keys=True))
    elif result.dry_run:
        print(
            "Verified signed Ori config for "
            f"{result.device_id}; dry run did not write {result.destination}."
        )
    else:
        print(
            "Installed signed Ori config for "
            f"{result.device_id} at {result.destination}."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
