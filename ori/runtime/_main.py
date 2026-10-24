# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The command-line entry point: ``ori-runtime`` and ``python -m ori.runtime``."""

import asyncio
import logging
import os
from pathlib import Path

from ori.config import hardened_posture_declared
from ori.runtime._runtime import OriRuntime
from ori.utils.bool_utils import is_truthy
from ori.utils.path_utils import shown

logger = logging.getLogger("ori.runtime")


def _maybe_autoload_dotenv(config_path: str) -> frozenset[str] | None:
    """Load .env when explicitly enabled via ORI_AUTOLOAD_DOTENV=true.

    This is a development convenience toggle. Production remains explicit-env
    by default (no implicit .env loading).

    Returns ``None`` when no file was loaded, and otherwise the variable names
    this file actually introduced — which is not the same as the names it
    contains, because `override=False` leaves anything the environment already
    carries alone. A report that treated the file's existence as a supplied
    value degraded a device whose `.env` decided nothing.
    """
    if not is_truthy(os.environ.get("ORI_AUTOLOAD_DOTENV", "")):
        return None

    # A signature covers the document before expansion, so a file that supplies
    # what `${VAR}` fields expand to decides the value of a signed field
    # without invalidating the signature. The data directory is writable by the
    # service; the unit's EnvironmentFile is not, which is where a hardened
    # deployment's environment belongs.
    if hardened_posture_declared(config_path):
        logger.warning(
            "[runtime] ORI_AUTOLOAD_DOTENV is refused under staging or "
            "production posture: a .env beside the configuration would supply "
            "values for signed fields. Use the unit's EnvironmentFile."
        )
        return None

    try:
        from dotenv import load_dotenv
    except ImportError:
        logger.warning(
            "[runtime] ORI_AUTOLOAD_DOTENV is enabled but python-dotenv is not installed"
        )
        return None

    # Beside the configuration only. The unit works in a runtime directory
    # systemd empties on every stop, so a file found there is not this
    # installation's environment, and these values are expanded into the
    # configuration the runtime then trusts.
    candidate = Path(config_path).resolve().parent / ".env"
    if candidate.is_file():
        before = frozenset(os.environ)
        load_dotenv(dotenv_path=candidate, override=False)
        supplied = frozenset(os.environ) - before
        logger.info("[runtime] loaded environment from %s", shown(candidate))
        return supplied
    logger.info(
        "[runtime] ORI_AUTOLOAD_DOTENV enabled but no .env file beside %s",
        shown(config_path),
    )
    return None


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="ori-runtime", description="Ori Runtime")
    parser.add_argument(
        "--config",
        default="ori.yaml",
        help="Path to ori.yaml config file",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    dotenv_variables = _maybe_autoload_dotenv(args.config)

    runtime = OriRuntime(config_path=args.config, dotenv_variables=dotenv_variables)
    asyncio.run(runtime.start())
