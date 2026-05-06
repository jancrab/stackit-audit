"""Check engine: runs the registered checks over a resource list."""

from __future__ import annotations

import logging
from typing import Iterable

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
                log.exception("Check %s crashed: %s", chk.META.check_id, exc)
        return findings
