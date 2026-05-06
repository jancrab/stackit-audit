from __future__ import annotations

from stackit_audit.checks.base import CheckBase
from stackit_audit.frameworks.mapping import load_eol_versions
from stackit_audit.models import Check, Finding, Resource


def _version_lt(actual: str | None, threshold: str | None) -> bool:
    if not actual or not threshold:
        return False
    def to_tuple(v: str) -> tuple[int, ...]:
        parts = []
        for p in v.split("."):
            digits = "".join(c for c in p if c.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)
    try:
        return to_tuple(actual) < to_tuple(threshold)
    except Exception:
        return False


class DB001PublicDbInstances(CheckBase):
    META = Check(
        check_id="DB-001",
        title="DB Flex instances with public network access",
        description="Postgres/MariaDB/MongoDB Flex instances should not be reachable from the internet.",
        framework_refs=["CCM:IVS-09", "CCM:DSP-08", "C5:KOS-05"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Network",
        severity="critical",
        rationale="Public DB exposure removes the network defense layer.",
        resource_types=["dbflex.postgres", "dbflex.mariadb", "dbflex.mongodb", "dbflex.redis", "dbflex.opensearch", "dbflex.rabbitmq"],
        required_data_points=["is_public", "acl"],
        automated_assurance_level="heuristic",
        evaluation_logic="is_public == true OR acl contains 0.0.0.0/0",
        remediation="Disable public access; expose only via private network.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if not r.resource_type.startswith("dbflex."):
                continue
            pub = r.attrs.get("is_public")
            acl = r.attrs.get("acl")
            world_acl = isinstance(acl, list) and any(
                "0.0.0.0/0" in str(x) or "::/0" in str(x) for x in acl
            )
            if pub is True or world_acl:
                out.append(
                    self.make_finding(
                        r, status="FAIL",
                        rationale=f"Instance appears publicly accessible (is_public={pub}, acl={acl}).",
                        api_evidence={"is_public": pub, "acl": acl},
                    )
                )
            elif pub is None and acl is None:
                out.append(
                    self.make_finding(
                        r, status="UNKNOWN",
                        rationale="DB Flex API did not expose is_public/acl on this instance; manual review required.",
                    )
                )
        return out


class DB002BackupConfiguration(CheckBase):
    META = Check(
        check_id="DB-002",
        title="DB Flex instances without observable backup configuration",
        description="Backups are critical for recovery; STACKIT-managed backup metadata varies by service.",
        framework_refs=["CCM:BCR-08", "CCM:BCR-11", "C5:BCM-04"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Backup",
        severity="medium",
        rationale="Without recoverable backups, ransomware or operator error become catastrophic.",
        resource_types=["dbflex.postgres", "dbflex.mariadb", "dbflex.mongodb"],
        required_data_points=["backup_schedule", "backup_enabled"],
        automated_assurance_level="heuristic",
        evaluation_logic="backup_enabled is false OR neither backup_schedule nor backup_enabled is exposed",
        remediation="Verify backup configuration in the STACKIT portal; define a restore drill cadence.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if not r.resource_type.startswith("dbflex."):
                continue
            be = r.attrs.get("backup_enabled")
            bs = r.attrs.get("backup_schedule")
            if be is False:
                out.append(
                    self.make_finding(
                        r, status="FAIL",
                        rationale="Backup explicitly disabled.",
                        api_evidence={"backup_enabled": be, "backup_schedule": bs},
                    )
                )
            elif be is None and bs is None:
                out.append(
                    self.make_finding(
                        r, status="PARTIAL",
                        rationale="API does not expose backup configuration; verify in portal.",
                        api_evidence={"backup_enabled": be, "backup_schedule": bs},
                    )
                )
        return out


class DB003UnsupportedDbVersion(CheckBase):
    META = Check(
        check_id="DB-003",
        title="Database engine version below supported floor",
        description="EOL/unsupported engine versions miss security patches.",
        framework_refs=["CCM:UEM-04", "CCM:TVM-07", "C5:OPS-07"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Config",
        severity="high",
        rationale="Older engines accumulate unpatched CVEs.",
        resource_types=["dbflex.*"],
        required_data_points=["engine", "version"],
        automated_assurance_level="automated",
        evaluation_logic="version < eol_versions[engine]",
        remediation="Schedule an in-place upgrade in a maintenance window.",
    )

    def __init__(self) -> None:
        try:
            self.thresholds = load_eol_versions() or {}
        except Exception:
            self.thresholds = {}

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if not r.resource_type.startswith("dbflex."):
                continue
            engine = r.attrs.get("engine") or r.resource_type.split(".")[-1]
            version = r.attrs.get("version")
            threshold = self.thresholds.get(engine)
            if not version or not threshold:
                continue
            if _version_lt(str(version), str(threshold)):
                out.append(
                    self.make_finding(
                        r, status="FAIL",
                        rationale=f"{engine} version {version} is below supported floor {threshold}.",
                        api_evidence={"engine": engine, "version": version},
                        derived_evidence={"threshold": threshold},
                    )
                )
        return out
