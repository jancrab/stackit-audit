"""CLI entry point: discover / audit / report / run subcommands."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stackit_audit.utils.exit_codes import (
    SUCCESS as EXIT_OK,
    FINDINGS_ABOVE_THRESHOLD as EXIT_FINDINGS,
    CONFIG_OR_AUTH_ERROR as EXIT_CONFIG_ERROR,
    API_ERROR_BUDGET_EXCEEDED as EXIT_API_ERROR,
    INTERNAL_ERROR as EXIT_INTERNAL_ERROR,
)
from stackit_audit.utils.logging import setup_logging

# ARCH-003: severity ordering for --fail-on threshold (>= not ==)
_SEV_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _at_or_above(finding_sev: str, threshold: str) -> bool:
    """Return True when finding_sev is at or above the threshold severity."""
    return _SEV_RANK.get(finding_sev, 9) <= _SEV_RANK.get(threshold, 9)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_json(path: str) -> dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[error] Cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(EXIT_CONFIG_ERROR)


def _parse_formats(raw: str) -> list[str]:
    return [f.strip().lower() for f in raw.split(",") if f.strip()]


# ---------------------------------------------------------------------------
# subcommand: discover
# ---------------------------------------------------------------------------

def cmd_discover(args: argparse.Namespace) -> int:
    # ARCH-001: was orchestrator.run() — method is .discover()
    # ARCH-002: was KeyFlowAuth.from_key_file() — construct via ServiceAccountKey.from_file()
    from stackit_audit.auth.key_flow import KeyFlowAuth, ServiceAccountKey
    from stackit_audit.discovery.orchestrator import DiscoveryOrchestrator

    log = logging.getLogger(__name__)
    try:
        sa_key = ServiceAccountKey.from_file(args.service_account_key)
        auth = KeyFlowAuth(sa_key)
    except Exception as exc:
        print(f"[error] Auth setup failed: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    project_ids: list[str] = args.project_id or []
    if not project_ids:
        print("[error] --project-id is required for discover", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    region = args.region or "eu01"

    workers = getattr(args, "workers", 8)

    try:
        orchestrator = DiscoveryOrchestrator(auth, region=region, workers=workers)
        inventory = orchestrator.discover(project_ids=project_ids)
    except Exception as exc:
        log.exception("Discovery failed: %s", exc)
        return EXIT_API_ERROR

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(inventory.model_dump(mode="json"), indent=2, default=str),
        encoding="utf-8",
    )
    print(f"[ok] Inventory written to {out_path} ({len(inventory.resources)} resources, "
          f"{len(inventory.errors)} errors)")
    if inventory.errors:
        for e in inventory.errors:
            log.warning("Discovery error [%s/%s]: %s", e.project_id, e.api, e.message)
    return EXIT_OK


# ---------------------------------------------------------------------------
# subcommand: audit
# ---------------------------------------------------------------------------

def cmd_audit(args: argparse.Namespace) -> int:
    from stackit_audit.checks import CheckEngine
    from stackit_audit.models import Resource
    from stackit_audit.reporting import build_findings_document, write_json

    log = logging.getLogger(__name__)
    raw = _load_json(args.inventory)

    try:
        resources = [Resource(**r) for r in raw.get("resources", [])]
    except Exception as exc:
        print(f"[error] Invalid inventory: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    include_only = [i.strip() for i in args.include_only.split(",")] if args.include_only else None
    exclude = [i.strip() for i in args.exclude.split(",")] if args.exclude else None

    try:
        engine = CheckEngine(include_only=include_only, exclude=exclude)
        findings = engine.run(resources)
    except Exception as exc:
        log.exception("Audit engine crashed: %s", exc)
        return EXIT_INTERNAL_ERROR

    scope = raw.get("scope", {})
    started = datetime.fromisoformat(raw.get("generated_at", datetime.now(tz=timezone.utc).isoformat()))
    # ARCH-004: pass the actual active check list so coverage stats are accurate
    doc = build_findings_document(
        findings=findings,
        scope=scope,
        started_at=started,
        active_checks=[type(c) for c in engine.checks],
    )

    out_path = Path(args.output)
    write_json(doc, out_path)
    fail_count = sum(1 for f in findings if f.status in ("FAIL", "PARTIAL"))
    print(f"[ok] findings.json written to {out_path} ({len(findings)} findings, {fail_count} actionable)")

    # ARCH-003: use >= severity threshold, not exact == match
    fail_on = (args.fail_on or "").lower()
    if fail_on and any(
        f for f in findings
        if f.status in ("FAIL", "PARTIAL") and _at_or_above(f.severity, fail_on)
    ):
        return EXIT_FINDINGS
    return EXIT_OK


# ---------------------------------------------------------------------------
# subcommand: report
# ---------------------------------------------------------------------------

def cmd_report(args: argparse.Namespace) -> int:
    from stackit_audit.reporting import write_markdown
    from stackit_audit.pdf_rendering import build_pdf

    doc = _load_json(args.findings)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = _parse_formats(args.formats)

    if "json" in formats:
        import shutil
        dst = out_dir / "findings.json"
        if Path(args.findings).resolve() != dst.resolve():
            shutil.copy2(args.findings, dst)
        print(f"[ok] {dst}")

    if "md" in formats:
        p = write_markdown(doc, out_dir / "report.md")
        print(f"[ok] {p}")

    if "pdf" in formats:
        try:
            p = build_pdf(doc, out_dir / "report.pdf")
            print(f"[ok] {p}")
        except Exception as exc:
            print(f"[error] PDF generation failed: {exc}", file=sys.stderr)
            return EXIT_INTERNAL_ERROR

    return EXIT_OK


# ---------------------------------------------------------------------------
# subcommand: run  (convenience pipeline)
# ---------------------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> int:
    import tempfile, os

    with tempfile.TemporaryDirectory() as tmp:
        inv_path = os.path.join(tmp, "inventory.json")
        findings_path = os.path.join(tmp, "findings.json")

        # discover
        discover_args = argparse.Namespace(
            service_account_key=args.service_account_key,
            project_id=args.project_id,
            region=getattr(args, "region", "eu01"),
            output=inv_path,
        )
        rc = cmd_discover(discover_args)
        if rc != EXIT_OK:
            return rc

        # audit
        audit_args = argparse.Namespace(
            inventory=inv_path,
            include_only=None,
            exclude=None,
            output=findings_path,
            fail_on=getattr(args, "fail_on", None),
        )
        rc = cmd_audit(audit_args)
        if rc not in (EXIT_OK, EXIT_FINDINGS):
            return rc
        audit_rc = rc

        # report
        report_args = argparse.Namespace(
            findings=findings_path,
            formats=getattr(args, "formats", "json,md,pdf"),
            output_dir=args.output_dir,
        )
        cmd_report(report_args)

    return audit_rc


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def _load_config(path: str | None):
    """ARCH-008: load audit-config.yaml if --config was supplied."""
    if not path:
        return None
    from stackit_audit.config.loader import load_config
    try:
        return load_config(path)
    except Exception as exc:
        print(f"[error] Cannot load config file '{path}': {exc}", file=sys.stderr)
        sys.exit(EXIT_CONFIG_ERROR)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stackit-audit",
        description="STACKIT Cloud Audit — CCM/C5 readiness assessment",
    )
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument(  # ARCH-008
        "--config", default=None, metavar="PATH",
        help="Path to audit-config.yaml (overrides per-subcommand defaults)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # discover
    p_disc = sub.add_parser("discover", help="Inventory STACKIT resources")
    p_disc.add_argument("--service-account-key", required=True, metavar="PATH")
    p_disc.add_argument("--project-id", action="append", metavar="ID")
    p_disc.add_argument("--region", default="eu01")
    p_disc.add_argument("--output", default="inventory.json", metavar="PATH")

    # audit
    p_audit = sub.add_parser("audit", help="Run checks over an inventory")
    p_audit.add_argument("--inventory", required=True, metavar="PATH")
    p_audit.add_argument("--output", default="findings.json", metavar="PATH")
    p_audit.add_argument("--include-only", default=None, metavar="CHECK_IDS")
    p_audit.add_argument("--exclude", default=None, metavar="CHECK_IDS")
    p_audit.add_argument("--fail-on", default=None,
                         choices=["critical", "high", "medium", "low", "info"],
                         metavar="SEVERITY")

    # report
    p_rep = sub.add_parser("report", help="Render reports from findings.json")
    p_rep.add_argument("--findings", required=True, metavar="PATH")
    p_rep.add_argument("--formats", default="json,md,pdf", metavar="LIST")
    p_rep.add_argument("--output-dir", default="out", metavar="DIR")

    # run (pipeline)
    p_run = sub.add_parser("run", help="Discover + audit + report in one step")
    p_run.add_argument("--service-account-key", required=True, metavar="PATH")
    p_run.add_argument("--project-id", action="append", metavar="ID")
    p_run.add_argument("--region", default="eu01")
    p_run.add_argument("--output-dir", default="out", metavar="DIR")
    p_run.add_argument("--formats", default="json,md,pdf", metavar="LIST")
    p_run.add_argument("--fail-on", default=None,
                       choices=["critical", "high", "medium", "low", "info"],
                       metavar="SEVERITY")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    setup_logging(args.log_level)

    # ARCH-008: apply config file as defaults before dispatching
    cfg = _load_config(getattr(args, "config", None))
    if cfg is not None:
        # Fill in CLI arg gaps from config (CLI flags always win when explicitly set)
        if not getattr(args, "service_account_key", None) and cfg.auth.service_account_key_path:
            args.service_account_key = str(cfg.auth.service_account_key_path)
        if not getattr(args, "project_id", None) and cfg.scope.project_ids:
            args.project_id = list(cfg.scope.project_ids)
        if getattr(args, "region", None) in (None, "eu01") and cfg.scope.region != "eu01":
            args.region = cfg.scope.region
        if not getattr(args, "output_dir", None) and cfg.reporting.output_dir:
            args.output_dir = str(cfg.reporting.output_dir)
        if not getattr(args, "formats", None) and cfg.reporting.formats:
            args.formats = ",".join(cfg.reporting.formats)
        if not getattr(args, "exclude", None) and cfg.checks.exclude:
            args.exclude = ",".join(cfg.checks.exclude)
        if not getattr(args, "include_only", None) and cfg.checks.include_only:
            args.include_only = ",".join(cfg.checks.include_only)
        # ARCH-005: parallelism from RuntimeConfig
        if not getattr(args, "workers", None):
            args.workers = cfg.runtime.parallelism

    dispatch = {
        "discover": cmd_discover,
        "audit": cmd_audit,
        "report": cmd_report,
        "run": cmd_run,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return EXIT_CONFIG_ERROR
    try:
        return handler(args)
    except KeyboardInterrupt:
        return EXIT_INTERNAL_ERROR
    except Exception as exc:
        logging.getLogger(__name__).exception("Unhandled error: %s", exc)
        return EXIT_INTERNAL_ERROR
