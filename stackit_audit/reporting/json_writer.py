from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stackit_audit import __version__
from stackit_audit.models import Finding
from stackit_audit.scoring import aggregate
from stackit_audit.utils.redact import redact


def build_findings_document(
    findings: list[Finding],
    scope: dict[str, Any],
    started_at: datetime,
    finished_at: datetime | None = None,
    auth_method: str = "key_flow",
    sa_email: str = "",
) -> dict[str, Any]:
    summary = aggregate(findings)
    return {
        "schema_version": "1.0",
        "tool_version": __version__,
        "scan": {
            "started_at": started_at.isoformat(),
            "finished_at": (finished_at or datetime.now(tz=timezone.utc)).isoformat(),
            "scope": scope,
            "auth": {"method": auth_method, "service_account_email": sa_email},
        },
        "summary": summary.model_dump(),
        "findings": [redact(f.model_dump(mode="json")) for f in findings],
    }


def write_json(document: dict[str, Any], path: Path | str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")
    return p
