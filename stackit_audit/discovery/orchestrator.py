"""Coordinates calls across all STACKIT API clients and emits a normalized Inventory.

API errors are caught and recorded in `inventory.errors`; checks treat
missing resource categories as `UNKNOWN` rather than `PASS`.

ARCH-005: per-project discovery is parallelised with ThreadPoolExecutor so
that multi-project audits don't serialise 12+ API services × N projects.
The default worker count matches RuntimeConfig.parallelism (8).
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from stackit_audit.api_client.audit_log import AuditLogClient
from stackit_audit.api_client.authorization import AuthorizationClient
from stackit_audit.api_client.base import StackitApiError
from stackit_audit.api_client.dbflex import DbFlexClient, ENGINES as DBFLEX_ENGINES
from stackit_audit.api_client.dns import DnsClient
from stackit_audit.api_client.iaas import IaasClient
from stackit_audit.api_client.load_balancer import LoadBalancerClient
from stackit_audit.api_client.object_storage import ObjectStorageClient
from stackit_audit.api_client.observability import ObservabilityClient
from stackit_audit.api_client.resource_manager import ResourceManagerClient
from stackit_audit.api_client.secrets_manager import SecretsManagerClient
from stackit_audit.api_client.service_account import ServiceAccountClient
from stackit_audit.api_client.ske import SkeClient
from stackit_audit.auth.key_flow import KeyFlowAuth
from stackit_audit.models import Resource
from stackit_audit.normalization import normalize

log = logging.getLogger(__name__)


class DiscoveryError(BaseModel):
    project_id: str
    api: str
    message: str
    status_code: int | None = None


class Inventory(BaseModel):
    schema_version: str = "1.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    scope: dict[str, Any] = Field(default_factory=dict)
    resources: list[Resource] = Field(default_factory=list)
    errors: list[DiscoveryError] = Field(default_factory=list)


class DiscoveryOrchestrator:
    def __init__(self, auth: KeyFlowAuth, region: str = "eu01", workers: int = 8) -> None:
        self.auth = auth
        self.region = region
        self.workers = max(1, workers)  # ARCH-005: parallelism per RuntimeConfig
        self.rm = ResourceManagerClient(auth)
        self.authz = AuthorizationClient(auth)
        self.sa = ServiceAccountClient(auth)
        self.iaas = IaasClient(auth, region)
        self.os = ObjectStorageClient(auth, region)
        self.ske = SkeClient(auth)
        self.db = DbFlexClient(auth, region)
        self.lb = LoadBalancerClient(auth, region)
        self.dns = DnsClient(auth)
        self.sm = SecretsManagerClient(auth, region)
        self.obs = ObservabilityClient(auth, region)
        self.audit = AuditLogClient(auth, region)

    def discover(self, project_ids: list[str]) -> Inventory:
        """Discover all projects, parallelised across projects (ARCH-005).

        Each project gets its own per-project Inventory that is merged into
        the final result after all futures complete.  Resources from different
        projects are collected in separate lists to avoid lock contention.
        """
        inv = Inventory(scope={"project_ids": project_ids, "region": self.region})
        if len(project_ids) == 1:
            # Fast path: no thread overhead for single-project runs
            self._discover_project(project_ids[0], inv)
            return inv

        # ARCH-005: parallelise across projects
        sub_inventories: dict[str, Inventory] = {}
        with ThreadPoolExecutor(max_workers=min(self.workers, len(project_ids))) as pool:
            futures = {
                pool.submit(self._discover_project_isolated, pid): pid
                for pid in project_ids
            }
            for future in as_completed(futures):
                pid = futures[future]
                try:
                    sub_inv = future.result()
                    sub_inventories[pid] = sub_inv
                except Exception as exc:
                    log.exception("Unexpected error during discovery of project %s: %s", pid, exc)
                    inv.errors.append(
                        DiscoveryError(project_id=pid, api="orchestrator", message=str(exc))
                    )

        # Merge sub-inventories in deterministic project_id order
        for pid in project_ids:
            if pid in sub_inventories:
                sub = sub_inventories[pid]
                inv.resources.extend(sub.resources)
                inv.errors.extend(sub.errors)

        return inv

    def _discover_project_isolated(self, project_id: str) -> Inventory:
        """Run discovery for a single project in an isolated Inventory (thread-safe)."""
        sub = Inventory(scope={"project_ids": [project_id], "region": self.region})
        self._discover_project(project_id, sub)
        return sub

    # DEPRECATED: replaced by per-project closure inside _discover_project
    # def _safe(self, project_id, api_name, fn, *args, **kwargs):
    #     ...

    def _discover_project(self, project_id: str, inv: Inventory) -> None:
        # Local closures keep error collection per-project tidy.
        def safe(api_name: str, fn, *args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except StackitApiError as exc:
                inv.errors.append(
                    DiscoveryError(
                        project_id=project_id, api=api_name, message=str(exc),
                        status_code=exc.status_code,
                    )
                )
                return None
            except Exception as exc:
                inv.errors.append(
                    DiscoveryError(project_id=project_id, api=api_name, message=str(exc))
                )
                return None

        # Project metadata
        proj = safe("resource_manager.project", self.rm.get_project, project_id)
        if proj:
            inv.resources.append(normalize("project", proj))

        # IAM: memberships
        mems = safe("authorization.memberships", self.authz.list_memberships, f"projects/{project_id}") or []
        for m in mems:
            inv.resources.append(normalize("membership", m, project_id=project_id))

        # IAM: service accounts and keys
        sas = safe("service_account.list", self.sa.list_service_accounts, project_id) or []
        for s in sas:
            res = normalize("service_account", s, project_id=project_id)
            inv.resources.append(res)
            sa_email = res.attrs.get("email") or res.resource_id
            keys = safe("service_account.keys", self.sa.list_keys, project_id, sa_email) or []
            for k in keys:
                inv.resources.append(
                    normalize("sa_key", k, project_id=project_id, sa_email=sa_email)
                )

        # IaaS: SGs, rules, servers, volumes, public IPs
        sgs = safe("iaas.security_groups", self.iaas.list_security_groups, project_id) or []
        for sg in sgs:
            sg_res = normalize("security_group", sg, project_id=project_id, region=self.region)
            inv.resources.append(sg_res)
            rules = safe(
                "iaas.security_group_rules",
                self.iaas.list_security_group_rules,
                project_id,
                sg_res.resource_id,
            ) or []
            for r in rules:
                inv.resources.append(
                    normalize(
                        "security_group_rule",
                        r,
                        project_id=project_id,
                        region=self.region,
                        sg_id=sg_res.resource_id,
                        sg_name=sg_res.resource_name,
                    )
                )

        for srv in safe("iaas.servers", self.iaas.list_servers, project_id) or []:
            inv.resources.append(normalize("server", srv, project_id=project_id, region=self.region))
        for v in safe("iaas.volumes", self.iaas.list_volumes, project_id) or []:
            inv.resources.append(normalize("volume", v, project_id=project_id, region=self.region))
        for pip in safe("iaas.public_ips", self.iaas.list_public_ips, project_id) or []:
            inv.resources.append(normalize("public_ip", pip, project_id=project_id, region=self.region))

        # Object Storage
        for b in safe("object_storage.buckets", self.os.list_buckets, project_id) or []:
            inv.resources.append(normalize("bucket", b, project_id=project_id, region=self.region))

        # SKE
        for c in safe("ske.clusters", self.ske.list_clusters, project_id) or []:
            inv.resources.append(normalize("ske_cluster", c, project_id=project_id))

        # DB Flex (multi-engine)
        for engine in DBFLEX_ENGINES:
            for inst in safe(f"dbflex.{engine}", self.db.list_instances, engine, project_id) or []:
                inv.resources.append(
                    normalize(
                        "db_instance",
                        inst,
                        project_id=project_id,
                        region=self.region,
                        engine=engine,
                    )
                )

        # Load Balancer
        for lbo in safe("load_balancer", self.lb.list_load_balancers, project_id) or []:
            inv.resources.append(normalize("load_balancer", lbo, project_id=project_id, region=self.region))

        # DNS
        for z in safe("dns.zones", self.dns.list_zones, project_id) or []:
            inv.resources.append(normalize("dns_zone", z, project_id=project_id))

        # Secrets Manager
        for s in safe("secrets_manager", self.sm.list_instances, project_id) or []:
            inv.resources.append(
                normalize("secrets_manager_instance", s, project_id=project_id, region=self.region)
            )

        # Observability + LogMe
        for s in safe("observability", self.obs.list_observability_instances, project_id) or []:
            inv.resources.append(
                normalize(
                    "observability_instance",
                    s,
                    project_id=project_id,
                    region=self.region,
                    kind="observability",
                )
            )
        for s in safe("logme", self.obs.list_logme_instances, project_id) or []:
            inv.resources.append(
                normalize(
                    "observability_instance",
                    s,
                    project_id=project_id,
                    region=self.region,
                    kind="logme",
                )
            )

        # Audit log entries (last 30d)
        for e in safe("audit_log", self.audit.list_entries, project_id, 30) or []:
            inv.resources.append(normalize("audit_log_entry", e, project_id=project_id))


