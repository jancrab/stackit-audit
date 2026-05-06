from pathlib import Path
from typing import Any

import yaml

from stackit_audit.config.schema import AuditConfig


def load_config(path: Path | str | None = None) -> AuditConfig:
    """Load audit-config.yaml. Returns defaults if no path provided."""
    if path is None:
        return AuditConfig()
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AuditConfig(**data)
