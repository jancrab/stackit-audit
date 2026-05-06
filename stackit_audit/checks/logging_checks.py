from __future__ import annotations

from stackit_audit.checks.base import CheckBase
from stackit_audit.models import Check, Finding, Resource


class LOG001NoAuditActivity(CheckBase):
    META = Check(
        check_id="LOG-001",
        title="No audit log activity in the last 30 days",
        description="A project with workloads but zero audit-log entries indicates either no activity or unconfigured logging.",
        framework_refs=["CCM:LOG-02", "C5:RB-12"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Logging",
        severity="medium",
        rationale="Without audit trails, incidents cannot be investigated.",
        resource_types=["resource_manager.project"],
        required_data_points=["audit_log_entry count"],
        automated_assurance_level="heuristic",
        evaluation_logic="count(audit_log_entry where project_id = p) == 0 AND project has any workload",
        remediation="Verify Audit Log subscription and ensure entries are flowing to your SIEM.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        per_project_audit: dict[str, int] = {}
        per_project_workload: dict[str, int] = {}
        projects: dict[str, Resource] = {}
        for r in resources:
            pid = r.scope.project_id
            if r.resource_type == "audit_log.entry" and pid:
                per_project_audit[pid] = per_project_audit.get(pid, 0) + 1
            if r.resource_type == "resource_manager.project" and pid:
                projects[pid] = r
            if pid and r.resource_type in {
                "iaas.server", "ske.cluster", "object_storage.bucket",
                "load_balancer.lb",
            } or (pid and r.resource_type.startswith("dbflex.")):
                per_project_workload[pid] = per_project_workload.get(pid, 0) + 1
        for pid, proj in projects.items():
            if per_project_workload.get(pid, 0) == 0:
                continue
            if per_project_audit.get(pid, 0) == 0:
                out.append(
                    self.make_finding(
                        proj, status="PARTIAL",
                        rationale="Project has workloads but no audit-log entries observed in the last 30 days.",
                        derived_evidence={
                            "audit_entries_30d": 0,
                            "workload_count": per_project_workload.get(pid, 0),
                        },
                    )
                )
        return out


class LOG002NoObservability(CheckBase):
    META = Check(
        check_id="LOG-002",
        title="Project without Observability or LogMe instance",
        description="Production projects should ship logs/metrics to a managed observability target.",
        framework_refs=["CCM:LOG-03", "C5:RB-09"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Logging",
        severity="low",
        rationale="No central log/metric pipeline reduces the chance of detecting incidents.",
        resource_types=["resource_manager.project"],
        required_data_points=["observability or logme instance presence"],
        automated_assurance_level="heuristic",
        evaluation_logic="no observability.* or logme instance AND project has workloads",
        remediation="Provision an Observability or LogMe instance; route Compute/SKE/DB logs there.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        per_project_obs: dict[str, int] = {}
        per_project_workload: dict[str, int] = {}
        projects: dict[str, Resource] = {}
        for r in resources:
            pid = r.scope.project_id
            if pid and r.resource_type.startswith("observability."):
                per_project_obs[pid] = per_project_obs.get(pid, 0) + 1
            if r.resource_type == "resource_manager.project" and pid:
                projects[pid] = r
            if pid and r.resource_type in {
                "iaas.server", "ske.cluster", "load_balancer.lb",
            } or (pid and r.resource_type.startswith("dbflex.")):
                per_project_workload[pid] = per_project_workload.get(pid, 0) + 1
        for pid, proj in projects.items():
            if per_project_workload.get(pid, 0) == 0:
                continue
            if per_project_obs.get(pid, 0) == 0:
                out.append(
                    self.make_finding(
                        proj, status="PARTIAL",
                        rationale="Project has workloads but no Observability/LogMe instance.",
                        derived_evidence={
                            "observability_count": 0,
                            "workload_count": per_project_workload.get(pid, 0),
                        },
                    )
                )
        return out
