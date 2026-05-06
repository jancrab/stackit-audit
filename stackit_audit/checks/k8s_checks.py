from __future__ import annotations

from stackit_audit.checks.base import CheckBase
from stackit_audit.checks.db_checks import _version_lt
from stackit_audit.frameworks.mapping import load_eol_versions
from stackit_audit.models import Check, Finding, Resource


class K8S001PublicSkeControlPlane(CheckBase):
    META = Check(
        check_id="K8S-001",
        title="SKE cluster control plane reachable from the internet",
        description="Cluster API endpoint should be limited via ACL to known CIDRs.",
        framework_refs=["CCM:IVS-04", "C5:KOS-04"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Network",
        severity="high",
        rationale="A public kube-apiserver invites credential brute-forcing and known CVEs.",
        resource_types=["ske.cluster"],
        required_data_points=["extensions.acl"],
        automated_assurance_level="heuristic",
        evaluation_logic="extensions.acl absent or contains 0.0.0.0/0",
        remediation="Configure SKE API ACL with restricted source CIDRs.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if r.resource_type != "ske.cluster":
                continue
            ext = r.attrs.get("extensions") or {}
            acl = (ext or {}).get("acl") if isinstance(ext, dict) else None
            allowed = None
            if isinstance(acl, dict):
                allowed = acl.get("allowedCidrs") or acl.get("allowed_cidrs") or acl.get("cidrs")
                enabled = acl.get("enabled")
                if enabled is False:
                    out.append(
                        self.make_finding(
                            r, status="FAIL",
                            rationale="SKE ACL disabled — control plane open to the internet.",
                            api_evidence={"acl": acl},
                        )
                    )
                    continue
            if allowed is None:
                out.append(
                    self.make_finding(
                        r, status="UNKNOWN",
                        rationale="ACL field not exposed for this cluster; manual review required.",
                        api_evidence={"extensions": ext},
                    )
                )
                continue
            if any("0.0.0.0/0" in str(c) or "::/0" in str(c) for c in allowed):
                out.append(
                    self.make_finding(
                        r, status="FAIL",
                        rationale=f"SKE ACL includes a world CIDR: {allowed}.",
                        api_evidence={"acl": acl},
                    )
                )
        return out


class K8S002UnsupportedKubernetesVersion(CheckBase):
    META = Check(
        check_id="K8S-002",
        title="SKE Kubernetes version below supported floor",
        description="Old Kubernetes minor versions lose security patches.",
        framework_refs=["CCM:UEM-04", "C5:OPS-07"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Config",
        severity="high",
        rationale="EOL Kubernetes versions accumulate unpatched CVEs.",
        resource_types=["ske.cluster"],
        required_data_points=["kubernetes_version"],
        automated_assurance_level="automated",
        evaluation_logic="kubernetes_version < eol_versions.kubernetes",
        remediation="Plan a controlled minor-version upgrade.",
    )

    def __init__(self) -> None:
        try:
            self.threshold = (load_eol_versions() or {}).get("kubernetes")
        except Exception:
            self.threshold = None

    def run(self, resources: list[Resource]) -> list[Finding]:
        if not self.threshold:
            return []
        out: list[Finding] = []
        for r in resources:
            if r.resource_type != "ske.cluster":
                continue
            v = r.attrs.get("kubernetes_version")
            if v and _version_lt(str(v), str(self.threshold)):
                out.append(
                    self.make_finding(
                        r, status="FAIL",
                        rationale=f"Kubernetes version {v} is below supported floor {self.threshold}.",
                        api_evidence={"kubernetes_version": v},
                        derived_evidence={"threshold": self.threshold},
                    )
                )
        return out
