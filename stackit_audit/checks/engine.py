"""Check engine: runs the registered checks over a resource list."""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4

from stackit_audit.checks.base import CheckBase
from stackit_audit.checks.crypto_checks import CRYPTO001VolumeEncryption
from stackit_audit.checks.db_checks import (
    DB001PublicDbInstances, DB002BackupConfiguration, DB003UnsupportedDbVersion,
)
from stackit_audit.checks.iam_checks import (
    IAM001PrivilegedServiceAccounts, IAM002OldServiceAccountKeys,
    IAM003MultipleActiveKeys, IAM004MembershipsWithoutExpiry, IAM005MfaManualCheck,
)
from stackit_audit.checks.k8s_checks import (
    K8S001PublicSkeControlPlane, K8S002UnsupportedKubernetesVersion,
)
from stackit_audit.checks.logging_checks import LOG001NoAuditActivity, LOG002NoObservability
from stackit_audit.checks.manual_checks import ORG001ManualControls
from stackit_audit.checks.network_checks import (
    NET001SshOpenWorld, NET002RdpOpenWorld, NET003DbPortsOpenWorld,
    NET004ServerWithPublicIpAndPermissiveSg, NET005PublicBuckets,
    NET006LoadBalancerHttpListener,
)
from stackit_audit.checks.secret_checks import SECRET001UnusedSaKeys
from stackit_audit.models import Finding, Resource
from stackit_audit import __version__

log = logging.getLogger(__name__)

ALL_CHECKS: list[type[CheckBase]] = [
    IAM001PrivilegedServiceAccounts,
    IAM002OldServiceAccountKeys,
    IAM003MultipleActiveKeys,
    IAM004MembershipsWithoutExpiry,
    IAM005MfaManualCheck,
    NET001SshOpenWorld,
    NET002RdpOpenWorld,
    NET003DbPortsOpenWorld,
    NET004ServerWithPublicIpAndPermissiveSg,
    NET005PublicBuckets,
    NET006LoadBalancerHttpListener,
    DB001PublicDbInstances,
    DB002BackupConfiguration,
    DB003UnsupportedDbVersion,
    K8S001PublicSkeControlPlane,
    K8S002UnsupportedKubernetesVersion,
    CRYPTO001VolumeEncryption,
    LOG001NoAuditActivity,
    LOG002NoObservability,
    SECRET001UnusedSaKeys,
    ORG001ManualControls,
]


def _crash_finding(check_id: str, exc: Exception) -> Finding:
    """ARCH-007: emit a synthetic UNKNOWN finding when a check crashes.

    A crashed check must never silently disappear from the report — silence
    is indistinguishable from a clean pass to downstream consumers.
    """
    return Finding(
        finding_id=str(uuid4()),
        check_id=check_id,
        title=f"{check_id}: internal error during evaluation",
        status="UNKNOWN",
        severity="info",
        framework_refs=[],
        framework_names=[],
        domain="IAM",  # placeholder; the check's META is unavailable after a crash
        resource_type="n/a",
        resource_id="n/a",
        rationale=f"Check raised an unhandled exception: {type(exc).__name__}: {exc}",
        risk="Evaluation was incomplete; result is not a pass.",
        remediation="Report this as a bug in stackit-audit.",
        assurance_level="automated",
        manual_review_required=True,
        derived_evidence={"traceback": traceback.format_exc()},
        timestamp=datetime.now(tz=timezone.utc),
        tool_version=__version__,
    )


class CheckEngine:
    def __init__(
        self,
        check_classes: Iterable[type[CheckBase]] | None = None,
        include_only: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> None:
        check_classes = list(check_classes or ALL_CHECKS)
        if include_only:
            check_classes = [c for c in check_classes if c.META.check_id in include_only]
        if exclude:
            check_classes = [c for c in check_classes if c.META.check_id not in exclude]
        self.checks = [c() for c in check_classes]

    def run(self, resources: list[Resource]) -> list[Finding]:
        findings: list[Finding] = []
        for chk in self.checks:
            try:
                produced = chk.run(resources)
                findings.extend(produced)
            except Exception as exc:
                # ARCH-007: emit a synthetic UNKNOWN so the crash is visible in the report
                log.exception("Check %s crashed: %s", chk.META.check_id, exc)
                findings.append(_crash_finding(chk.META.check_id, exc))
        return findings
