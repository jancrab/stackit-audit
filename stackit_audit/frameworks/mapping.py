"""Helpers for loading framework data files (EOL versions, manual controls)."""

from importlib import resources
from typing import Any

import yaml


def load_eol_versions() -> dict[str, str]:
    text = resources.files("stackit_audit.frameworks").joinpath("eol_versions.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text) or {}


def load_manual_controls() -> list[dict[str, Any]]:
    text = resources.files("stackit_audit.frameworks").joinpath("manual_controls.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text) or []
