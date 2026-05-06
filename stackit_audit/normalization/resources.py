"""Map raw STACKIT API payloads to canonical Resource objects.

Each adapter is intentionally tolerant: it picks the most likely id/name
fields and falls back to whatever is present, so a partial schema
mismatch produces a Resource with `attrs` empty rather than crashing.
The original payload is preserved in `raw` so checks can inspect it.
"""

from typing import Any
from stackit_audit.models import Resource, ResourceScope


def _pick(d: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _scope(project_id: str | None = None, region: str | None = None, organization_id: str | None = None) -> ResourceScope:
    return ResourceScope(project_id=project_id, region=region, organization_id=organization_id)


def normalize_project(raw: dict[str, Any]) -> Resource:
    pid = _pick(raw, "projectId", "id", "containerId", default="")
    return Resource(
        resource_type="resource_manager.project",
        resource_id=str(pid),
        resource_name=_pick(raw, "name"),
        scope=_scope(project_id=str(pid), organization_id=_pick(raw, "parentId")),
        attrs={"lifecycle_state": _pick(raw, "lifecycleState")},
        raw=raw,
    )


def normalize_membership(raw: dict[str, Any], project_id: str) -> Resource:
    subject = _pick(raw, "subject", default={})
    role = _pick(raw, "role", default="")
    if isinstance(subject, dict):
        subj_id = _pick(subject, "id", "email", "name", default="")
        subj_type = _pick(subject, "type", default="")
    else:
        subj_id = str(subject)
        subj_type = ""
    return Resource(
        resource_type="authorization.membership",
        resource_id=f"{project_id}:{subj_id}:{role}",
        resource_name=str(subj_id),
        scope=_scope(project_id=project_id),
        attrs={"role": role, "subject_type": subj_type, "subject_id": subj_id, "expires_at": _pick(raw, "expiresAt", "expires_at")},
        raw=raw,
    )


def normalize_service_account(raw: dict[str, Any], project_id: str) -> Resource:
    sa_id = _pick(raw, "id", "email", "name", default="")
    return Resource(
        resource_type="service_account.account",
        resource_id=str(sa_id),
        resource_name=_pick(raw, "email", "name", default=str(sa_id)),
        scope=_scope(project_id=project_id),
        attrs={"email": _pick(raw, "email"), "active": _pick(raw, "active", default=True)},
        raw=raw,
    )


def normalize_sa_key(raw: dict[str, Any], project_id: str, sa_email: str) -> Resource:
    kid = _pick(raw, "id", "keyId", default="")
    return Resource(
        resource_type="service_account.key",
        resource_id=str(kid),
        resource_name=str(kid),
        scope=_scope(project_id=project_id),
        attrs={
            "service_account_email": sa_email,
            "active": _pick(raw, "active", default=True),
            "created_at": _pick(raw, "createdAt", "created_at"),
            "valid_until": _pick(raw, "validUntil", "valid_until"),
        },
        raw=raw,
    )


def normalize_security_group(raw: dict[str, Any], project_id: str, region: str) -> Resource:
    sgid = _pick(raw, "id", default="")
    return Resource(
        resource_type="iaas.security_group",
        resource_id=str(sgid),
        resource_name=_pick(raw, "name"),
        scope=_scope(project_id=project_id, region=region),
        attrs={"description": _pick(raw, "description")},
        raw=raw,
    )


def normalize_security_group_rule(
    raw: dict[str, Any], project_id: str, region: str, sg_id: str, sg_name: str | None
) -> Resource:
    rid = _pick(raw, "id", default="")
    return Resource(
        resource_type="iaas.security_group_rule",
        resource_id=f"{sg_id}:{rid}",
        resource_name=f"{sg_name or sg_id} rule {rid}",
        scope=_scope(project_id=project_id, region=region),
        attrs={
            "security_group_id": sg_id,
            "security_group_name": sg_name,
            "direction": _pick(raw, "direction"),
            "ethertype": _pick(raw, "ethertype"),
            "protocol": _pick(raw, "protocol"),
            "port_range_min": _pick(raw, "portRangeMin", "port_range_min"),
            "port_range_max": _pick(raw, "portRangeMax", "port_range_max"),
            "remote_ip_prefix": _pick(raw, "remoteIpPrefix", "remote_ip_prefix", "ipRange"),
        },
        raw=raw,
    )


def normalize_server(raw: dict[str, Any], project_id: str, region: str) -> Resource:
    sid = _pick(raw, "id", default="")
    return Resource(
        resource_type="iaas.server",
        resource_id=str(sid),
        resource_name=_pick(raw, "name"),
        scope=_scope(project_id=project_id, region=region),
        attrs={
            "status": _pick(raw, "status"),
            "machine_type": _pick(raw, "machineType", "machine_type"),
            "security_groups": _pick(raw, "securityGroups", "security_groups", default=[]),
            "nics": _pick(raw, "nics", default=[]),
        },
        raw=raw,
    )


def normalize_volume(raw: dict[str, Any], project_id: str, region: str) -> Resource:
    vid = _pick(raw, "id", default="")
    return Resource(
        resource_type="iaas.volume",
        resource_id=str(vid),
        resource_name=_pick(raw, "name"),
        scope=_scope(project_id=project_id, region=region),
        attrs={
            "size_gb": _pick(raw, "size"),
            "encrypted": _pick(raw, "encrypted", "isEncrypted"),
            "performance_class": _pick(raw, "performanceClass"),
            "status": _pick(raw, "status"),
        },
        raw=raw,
    )


def normalize_public_ip(raw: dict[str, Any], project_id: str, region: str) -> Resource:
    pip = _pick(raw, "id", default="")
    return Resource(
        resource_type="iaas.public_ip",
        resource_id=str(pip),
        resource_name=_pick(raw, "ip"),
        scope=_scope(project_id=project_id, region=region),
        attrs={
            "ip": _pick(raw, "ip"),
            "associated_resource_id": _pick(raw, "networkInterface", "associatedResourceId"),
        },
        raw=raw,
    )


def normalize_bucket(raw: dict[str, Any], project_id: str, region: str) -> Resource:
    bid = _pick(raw, "name", "id", default="")
    return Resource(
        resource_type="object_storage.bucket",
        resource_id=str(bid),
        resource_name=str(bid),
        scope=_scope(project_id=project_id, region=region),
        attrs={
            "url_path_style": _pick(raw, "urlPathStyle"),
            "url_virtual_hosted_style": _pick(raw, "urlVirtualHostedStyle"),
            "public_access": _pick(raw, "publicAccess", "is_public", "isPublic"),
            "acl": _pick(raw, "acl"),
        },
        raw=raw,
    )


def normalize_ske_cluster(raw: dict[str, Any], project_id: str) -> Resource:
    name = _pick(raw, "name", default="")
    return Resource(
        resource_type="ske.cluster",
        resource_id=str(name),
        resource_name=str(name),
        scope=_scope(project_id=project_id),
        attrs={
            "kubernetes_version": _pick(raw, "kubernetesVersion", "kubernetes_version"),
            "status": _pick(raw, "status"),
            "extensions": _pick(raw, "extensions", default={}),
            "node_pools": _pick(raw, "nodepools", "nodePools", default=[]),
            "hibernation": _pick(raw, "hibernation"),
        },
        raw=raw,
    )


def normalize_db_instance(raw: dict[str, Any], project_id: str, region: str, engine: str) -> Resource:
    iid = _pick(raw, "id", "instanceId", default="")
    return Resource(
        resource_type=f"dbflex.{engine}",
        resource_id=str(iid),
        resource_name=_pick(raw, "name"),
        scope=_scope(project_id=project_id, region=region),
        attrs={
            "engine": engine,
            "version": _pick(raw, "version"),
            "status": _pick(raw, "status"),
            "is_public": _pick(raw, "isPublic", "is_public", "publicAccess"),
            "acl": _pick(raw, "acl"),
            "backup_schedule": _pick(raw, "backupSchedule", "backup_schedule"),
            "backup_enabled": _pick(raw, "backupEnabled", "backup_enabled"),
        },
        raw=raw,
    )


def normalize_load_balancer(raw: dict[str, Any], project_id: str, region: str) -> Resource:
    name = _pick(raw, "name", "id", default="")
    return Resource(
        resource_type="load_balancer.lb",
        resource_id=str(name),
        resource_name=str(name),
        scope=_scope(project_id=project_id, region=region),
        attrs={
            "listeners": _pick(raw, "listeners", default=[]),
            "external_address": _pick(raw, "externalAddress", "external_address"),
            "private_network_only": _pick(raw, "privateNetworkOnly", "private_network_only"),
        },
        raw=raw,
    )


def normalize_secrets_manager_instance(raw: dict[str, Any], project_id: str, region: str) -> Resource:
    iid = _pick(raw, "id", "instanceId", default="")
    return Resource(
        resource_type="secrets_manager.instance",
        resource_id=str(iid),
        resource_name=_pick(raw, "name"),
        scope=_scope(project_id=project_id, region=region),
        attrs={"status": _pick(raw, "status")},
        raw=raw,
    )


def normalize_observability_instance(raw: dict[str, Any], project_id: str, region: str, kind: str) -> Resource:
    iid = _pick(raw, "id", "instanceId", default="")
    return Resource(
        resource_type=f"observability.{kind}",
        resource_id=str(iid),
        resource_name=_pick(raw, "name"),
        scope=_scope(project_id=project_id, region=region),
        attrs={"status": _pick(raw, "status"), "plan": _pick(raw, "plan", "planName")},
        raw=raw,
    )


def normalize_dns_zone(raw: dict[str, Any], project_id: str) -> Resource:
    zid = _pick(raw, "id", default="")
    return Resource(
        resource_type="dns.zone",
        resource_id=str(zid),
        resource_name=_pick(raw, "dnsName", "name"),
        scope=_scope(project_id=project_id),
        attrs={"state": _pick(raw, "state"), "type": _pick(raw, "type")},
        raw=raw,
    )


def normalize_audit_log_entry(raw: dict[str, Any], project_id: str) -> Resource:
    eid = _pick(raw, "id", default="")
    return Resource(
        resource_type="audit_log.entry",
        resource_id=str(eid),
        resource_name=None,
        scope=_scope(project_id=project_id),
        attrs={
            "initiator": _pick(raw, "initiator", default={}),
            "action": _pick(raw, "action"),
            "timestamp": _pick(raw, "timestamp", "createdAt"),
        },
        raw=raw,
    )


def normalize(kind: str, raw: dict[str, Any], **ctx: Any) -> Resource:
    """Dispatch by kind label used in the discovery orchestrator."""
    dispatch = {
        "project": lambda: normalize_project(raw),
        "membership": lambda: normalize_membership(raw, ctx["project_id"]),
        "service_account": lambda: normalize_service_account(raw, ctx["project_id"]),
        "sa_key": lambda: normalize_sa_key(raw, ctx["project_id"], ctx["sa_email"]),
        "security_group": lambda: normalize_security_group(raw, ctx["project_id"], ctx["region"]),
        "security_group_rule": lambda: normalize_security_group_rule(
            raw, ctx["project_id"], ctx["region"], ctx["sg_id"], ctx.get("sg_name")
        ),
        "server": lambda: normalize_server(raw, ctx["project_id"], ctx["region"]),
        "volume": lambda: normalize_volume(raw, ctx["project_id"], ctx["region"]),
        "public_ip": lambda: normalize_public_ip(raw, ctx["project_id"], ctx["region"]),
        "bucket": lambda: normalize_bucket(raw, ctx["project_id"], ctx["region"]),
        "ske_cluster": lambda: normalize_ske_cluster(raw, ctx["project_id"]),
        "db_instance": lambda: normalize_db_instance(
            raw, ctx["project_id"], ctx["region"], ctx["engine"]
        ),
        "load_balancer": lambda: normalize_load_balancer(raw, ctx["project_id"], ctx["region"]),
        "secrets_manager_instance": lambda: normalize_secrets_manager_instance(
            raw, ctx["project_id"], ctx["region"]
        ),
        "observability_instance": lambda: normalize_observability_instance(
            raw, ctx["project_id"], ctx["region"], ctx.get("kind", "instance")
        ),
        "dns_zone": lambda: normalize_dns_zone(raw, ctx["project_id"]),
        "audit_log_entry": lambda: normalize_audit_log_entry(raw, ctx["project_id"]),
    }
    if kind not in dispatch:
        raise ValueError(f"Unknown normalization kind: {kind}")
    return dispatch[kind]()
