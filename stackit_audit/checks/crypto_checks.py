from __future__ import annotations

from stackit_audit.checks.base import CheckBase
from stackit_audit.models import Check, Finding, Resource


class CRYPTO001VolumeEncryption(CheckBase):
    META = Check(
        check_id="CRYPTO-001",
        title="IaaS volumes without encryption indicator",
        description="STACKIT IaaS volumes may not surface encryption fields uniformly; encrypt-at-rest must be verified.",
        framework_refs=["CCM:CEK-03", "C5:KRY-01"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Crypto",
        severity="medium",
        rationale="Without explicit encryption evidence we cannot claim data-at-rest protection.",
        resource_types=["iaas.volume"],
        required_data_points=["encrypted"],
        automated_assurance_level="heuristic",
        evaluation_logic="encrypted == false → FAIL; encrypted absent → PARTIAL",
        remediation="Verify with STACKIT support or platform docs whether encryption is on by default for the chosen volume type; document the answer.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if r.resource_type != "iaas.volume":
                continue
            enc = r.attrs.get("encrypted")
            if enc is False:
                out.append(
                    self.make_finding(
                        r, status="FAIL",
                        rationale="Volume reports encrypted == false.",
                        api_evidence={"encrypted": enc},
                    )
                )
            elif enc is None:
                out.append(
                    self.make_finding(
                        r, status="PARTIAL",
                        rationale="Volume API did not surface encryption status; verify against platform default.",
                        api_evidence={"encrypted": enc},
                    )
                )
        return out
