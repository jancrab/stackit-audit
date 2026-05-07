from __future__ import annotations

from typing import Iterable

from stackit_audit.checks.base import CheckBase
from stackit_audit.models import Check, Finding, Resource

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
DB_PORTS = {3306, 5432, 1433, 27017, 6379, 9200}


def _port_range(rule_attrs: dict) -> tuple[int | None, int | None]:
    return rule_attrs.get("port_range_min"), rule_attrs.get("port_range_max")


def _covers_port(rule_attrs: dict, target: int) -> bool:
    pmin, pmax = _port_range(rule_attrs)
    if pmin is None and pmax is None:
        return True  # all ports
    pmin = pmin if pmin is not None else 0
    pmax = pmax if pmax is not None else 65535
    return pmin <= target <= pmax


def _is_world_ingress_tcp(rule: Resource, port: int) -> bool:
    a = rule.attrs
    if (a.get("direction") or "").lower() != "ingress":
        return False
    proto = (a.get("protocol") or "").lower()
    if proto not in ("tcp", "any", "all", ""):
        return False
    if a.get("remote_ip_prefix") not in WORLD_CIDRS:
        return False
    return _covers_port(a, port)


def _world_open_ports(rule: Resource) -> Iterable[int]:
    a = rule.attrs
    if (a.get("direction") or "").lower() != "ingress":
        return []
    if a.get("remote_ip_prefix") not in WORLD_CIDRS:
        return []
    proto = (a.get("protocol") or "").lower()
    if proto not in ("tcp", "any", "all", ""):
        return []
    pmin, pmax = _port_range(a)
    pmin = pmin if pmin is not None else 0
    pmax = pmax if pmax is not None else 65535
    return [p for p in DB_PORTS if pmin <= p <= pmax]


class NET001SshOpenWorld(CheckBase):
    META = Check(
        check_id="NET-001",
        title="SSH (port 22) reachable from the internet",
        description="A security-group rule exposes TCP/22 to 0.0.0.0/0 or ::/0.",
        framework_refs=["CCM:IVS-04", "C5:KOS-04"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Network",
        severity="critical",
        rationale="Brute-force and exploit attempts against SSH are constant.",
        resource_types=["iaas.security_group_rule"],
        required_data_points=["direction", "protocol", "port_range_min", "port_range_max", "remote_ip_prefix"],
        automated_assurance_level="automated",
        evaluation_logic="ingress AND tcp AND 22 in port_range AND remote_ip_prefix in (0.0.0.0/0, ::/0)",
        remediation="Restrict to a bastion CIDR or VPN range; remove the world-open rule.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        return [
            self.make_finding(
                r,
                status="FAIL",
                rationale=f"Rule allows TCP/22 ingress from {r.attrs.get('remote_ip_prefix')}.",
                api_evidence={k: r.attrs.get(k) for k in ("direction", "protocol", "port_range_min", "port_range_max", "remote_ip_prefix")},
                title_override=f"SSH open to world: {r.attrs.get('security_group_name') or r.attrs.get('security_group_id')} rule {r.resource_id}",
            )
            for r in resources
            if r.resource_type == "iaas.security_group_rule" and _is_world_ingress_tcp(r, 22)
        ]


class NET002RdpOpenWorld(CheckBase):
    META = Check(
        check_id="NET-002",
        title="RDP (port 3389) reachable from the internet",
        description="A security-group rule exposes TCP/3389 to the world.",
        framework_refs=["CCM:IVS-04", "C5:KOS-04"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Network",
        severity="critical",
        rationale="RDP exposed to the internet is a top attack vector.",
        resource_types=["iaas.security_group_rule"],
        required_data_points=["direction", "protocol", "port_range_min", "port_range_max", "remote_ip_prefix"],
        automated_assurance_level="automated",
        evaluation_logic="ingress AND tcp AND 3389 in port_range AND remote_ip_prefix in world CIDRs",
        remediation="Limit RDP to corporate VPN or remove entirely.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        return [
            self.make_finding(
                r,
                status="FAIL",
                rationale=f"Rule allows TCP/3389 ingress from {r.attrs.get('remote_ip_prefix')}.",
                api_evidence={k: r.attrs.get(k) for k in ("direction", "protocol", "port_range_min", "port_range_max", "remote_ip_prefix")},
                title_override=f"RDP open to world: {r.attrs.get('security_group_name') or r.attrs.get('security_group_id')} rule {r.resource_id}",
            )
            for r in resources
            if r.resource_type == "iaas.security_group_rule" and _is_world_ingress_tcp(r, 3389)
        ]


class NET003DbPortsOpenWorld(CheckBase):
    META = Check(
        check_id="NET-003",
        title="Database default ports open to the internet",
        description="Security-group rules expose common DB ports to 0.0.0.0/0 or ::/0.",
        framework_refs=["CCM:IVS-04", "CCM:IVS-09", "C5:KOS-04"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Network",
        severity="critical",
        rationale="Direct DB exposure circumvents application-level controls.",
        resource_types=["iaas.security_group_rule"],
        required_data_points=["direction", "protocol", "port_range_min", "port_range_max", "remote_ip_prefix"],
        automated_assurance_level="automated",
        evaluation_logic="ingress, world CIDR, port_range covers any of {3306, 5432, 1433, 27017, 6379, 9200}",
        remediation="Use private networks; restrict source CIDRs to known services.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if r.resource_type != "iaas.security_group_rule":
                continue
            ports = list(_world_open_ports(r))
            if ports:
                out.append(
                    self.make_finding(
                        r,
                        status="FAIL",
                        rationale=f"Rule exposes DB-related ports {ports} to {r.attrs.get('remote_ip_prefix')}.",
                        api_evidence={k: r.attrs.get(k) for k in ("direction", "protocol", "port_range_min", "port_range_max", "remote_ip_prefix")},
                        derived_evidence={"matched_db_ports": ports},
                        title_override=f"DB ports {ports} open to world via SG rule {r.resource_id}",
                    )
                )
        return out


class NET004ServerWithPublicIpAndPermissiveSg(CheckBase):
    META = Check(
        check_id="NET-004",
        title="Public-IP-attached server behind permissive security group",
        description="Server reachable on a public IP with at least one world-open ingress on a privileged port.",
        framework_refs=["CCM:IVS-09", "C5:KOS-05"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Network",
        severity="high",
        rationale="Combines exposure (public IP) with permissive ingress.",
        resource_types=["iaas.server", "iaas.security_group_rule", "iaas.public_ip"],
        required_data_points=["server.security_groups", "server.nics"],
        automated_assurance_level="heuristic",
        evaluation_logic="server has public IP AND any attached SG has ingress 0.0.0.0/0 with port < 1024 and proto != icmp",
        remediation="Move to a load balancer in front of private compute; remove direct public IPs.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        sg_rules_by_sg: dict[str, list[Resource]] = {}
        for r in resources:
            if r.resource_type == "iaas.security_group_rule":
                sg_rules_by_sg.setdefault(r.attrs.get("security_group_id") or "", []).append(r)
        public_ips = [r for r in resources if r.resource_type == "iaas.public_ip"]
        public_ip_associated_resources = {r.attrs.get("associated_resource_id") for r in public_ips if r.attrs.get("associated_resource_id")}

        for r in resources:
            if r.resource_type != "iaas.server":
                continue
            sgs = r.attrs.get("security_groups") or []
            sg_ids: list[str] = []
            for sg in sgs:
                if isinstance(sg, dict):
                    sg_ids.append(str(sg.get("id") or sg.get("name") or ""))
                else:
                    sg_ids.append(str(sg))
            has_public_ip = r.resource_id in public_ip_associated_resources or any(
                (nic or {}).get("publicIp") for nic in r.attrs.get("nics") or []
            )
            if not has_public_ip:
                continue
            offending: list[str] = []
            for sgid in sg_ids:
                for rule in sg_rules_by_sg.get(sgid, []):
                    a = rule.attrs
                    if (a.get("direction") or "").lower() != "ingress":
                        continue
                    if a.get("remote_ip_prefix") not in WORLD_CIDRS:
                        continue
                    proto = (a.get("protocol") or "").lower()
                    if proto == "icmp":
                        continue
                    pmin = a.get("port_range_min") or 0
                    if pmin < 1024:
                        offending.append(rule.resource_id)
            if offending:
                out.append(
                    self.make_finding(
                        r,
                        status="FAIL",
                        rationale=f"Server has public reachability with permissive SG rules: {offending}.",
                        api_evidence={"security_groups": sg_ids, "offending_rule_ids": offending},
                    )
                )
        return out


class NET005PublicBuckets(CheckBase):
    META = Check(
        check_id="NET-005",
        title="Object Storage buckets with public read access",
        description="Buckets exposed publicly leak data, often without intent.",
        framework_refs=["CCM:DSP-08", "CCM:IVS-04", "C5:AM-04", "C5:KOS-04"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Network",
        severity="high",
        rationale="Public buckets are a recurrent cause of data leaks.",
        resource_types=["object_storage.bucket"],
        required_data_points=["public_access", "acl"],
        automated_assurance_level="heuristic",
        evaluation_logic="public_access == true OR acl indicates public-read",
        remediation="Set bucket ACL to private; use signed URLs for sharing.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if r.resource_type != "object_storage.bucket":
                continue
            pub = r.attrs.get("public_access")
            acl = r.attrs.get("acl")
            if pub is True or (isinstance(acl, str) and "public" in acl.lower()):
                out.append(
                    self.make_finding(
                        r, status="FAIL",
                        rationale=f"Bucket appears publicly accessible (public_access={pub}, acl={acl}).",
                        api_evidence={"public_access": pub, "acl": acl},
                    )
                )
            elif pub is None and not acl:
                out.append(
                    self.make_finding(
                        r, status="UNKNOWN",
                        rationale="Object Storage API did not expose public_access/acl on this bucket; manual review required.",
                        api_evidence={"public_access": pub, "acl": acl},
                    )
                )
        return out


class NET006LoadBalancerHttpListener(CheckBase):
    META = Check(
        check_id="NET-006",
        title="Load balancer with unencrypted HTTP listener",
        description="HTTP listeners terminate plaintext traffic; should redirect or be removed.",
        framework_refs=["CCM:CEK-19", "C5:KRY-04"],
        framework_names=["CCM v4", "BSI C5:2020"],
        domain="Network",  # ARCH-010: was incorrectly "Crypto"
        severity="high",
        rationale="Plaintext credentials and session tokens may transit the listener.",
        resource_types=["load_balancer.lb"],
        required_data_points=["listeners[].protocol"],
        automated_assurance_level="automated",
        evaluation_logic="any listener.protocol == HTTP and no companion HTTPS listener with redirect",
        remediation="Terminate TLS at the LB; force HTTP→HTTPS redirect or remove the HTTP listener.",
    )

    def run(self, resources: list[Resource]) -> list[Finding]:
        out: list[Finding] = []
        for r in resources:
            if r.resource_type != "load_balancer.lb":
                continue
            listeners = r.attrs.get("listeners") or []
            http_listeners = [l for l in listeners if isinstance(l, dict) and (l.get("protocol") or "").upper() == "HTTP"]
            if not http_listeners:
                continue
            if len(http_listeners) == len(listeners):
                out.append(
                    self.make_finding(
                        r, status="FAIL",
                        rationale="Load balancer has only HTTP listeners (no HTTPS).",
                        api_evidence={"listeners": listeners},
                    )
                )
            else:
                out.append(
                    self.make_finding(
                        r, status="PARTIAL",
                        rationale="Load balancer has both HTTP and HTTPS listeners; verify HTTP redirects to HTTPS.",
                        api_evidence={"listeners": listeners},
                    )
                )
        return out
