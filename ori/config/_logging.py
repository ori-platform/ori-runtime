# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``logging`` section."""

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("ori.config")


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str = "ori.log"
    max_bytes: int = 10485760
    backup_count: int = 3
    log_action_decisions: bool = True
    log_approval_workflow: bool = True


def parse_logging(data: Any) -> LoggingConfig:
    if not isinstance(data, dict):
        if data is not None:
            logger.warning(
                "[config] 'logging' section is not a mapping. Using defaults."
            )
        return LoggingConfig()

    try:
        max_bytes = int(data.get("max_bytes", 10485760))
        backup_count = int(data.get("backup_count", 3))
    except (ValueError, TypeError):
        max_bytes = 10485760
        backup_count = 3

    return LoggingConfig(
        level=str(data.get("level", "INFO")),
        file=str(data.get("file", "ori.log")),
        max_bytes=max_bytes,
        backup_count=backup_count,
        log_action_decisions=bool(data.get("log_action_decisions", True)),
        log_approval_workflow=bool(data.get("log_approval_workflow", True)),
    )
