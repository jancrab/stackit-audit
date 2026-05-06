"""Unit tests for network checks."""
from __future__ import annotations

import pytest

from stackit_audit.checks.network_checks import (
    NET001SshOpenWorld,
    NET002RdpOpenWorld,
    NET003DbPortsOpenWorld,
    NET006LoadBalancerHttpListener,
)
from stackit_audit.models.resource import Resource, ResourceScope


def _scope():
    return ResourceScope(project_id="proj-001", region="eu01")


def _sgr(port_min: int, port_max: int, cidr: str = "0.0.0.0/0",
          direction: str = "ingress", protocol: str = "tcp") -> Resource:
    return Resource(
        resource_type="iaas.security_group_rule",
        resource_id="rule-001",
        scope=_scope(),
        attrs={
            "security_group_id": "sg-001",
            "direction": direction,
            "protocol": protocol,
            "port_range_min": port_min,
            "port_range_max": port_max,
            "remote_ip_prefix": cidr,
            "ethertype": "IPv4",
        },
    )


class TestNET001:
    def test_fail_ssh_world(self):
        check = NET001SshOpenWorld()
        assert any(f.status == "FAIL" for f in check.run([_sgr(22, 22)]))

    def test_pass_ssh_restricted(self):
        check = NET001SshOpenWorld()
        assert not any(f.status == "FAIL" for f in check.run([_sgr(22, 22, cidr="10.0.0.0/8")]))

    def test_pass_egress_ignored(self):
        check = NET001SshOpenWorld()
        assert not any(f.status == "FAIL" for f in check.run([_sgr(22, 22, direction="egress")]))

    def test_fail_port_range_includes_22(self):
        check = NET001SshOpenWorld()
        assert any(f.status == "FAIL" for f in check.run([_sgr(1, 1024)]))


class TestNET002:
    def test_fail_rdp_world(self):
        check = NET002RdpOpenWorld()
        assert any(f.status == "FAIL" for f in check.run([_sgr(3389, 3389)]))

    def test_pass_rdp_restricted(self):
        check = NET002RdpOpenWorld()
        assert not any(f.status == "FAIL" for f in check.run([_sgr(3389, 3389, cidr="192.168.0.0/16")]))


class TestNET003:
    @pytest.mark.parametrize("port", [3306, 5432, 1433, 27017, 6379, 9200])
    def test_fail_db_port_world(self, port):
        check = NET003DbPortsOpenWorld()
        assert any(f.status == "FAIL" for f in check.run([_sgr(port, port)]))

    def test_pass_db_port_restricted(self):
        check = NET003DbPortsOpenWorld()
        assert not any(f.status == "FAIL" for f in check.run([_sgr(5432, 5432, cidr="10.0.0.0/8")]))


class TestNET006:
    def _lb(self, protocols: list[str]) -> Resource:
        return Resource(
            resource_type="load_balancer.lb",
            resource_id="lb-001",
            scope=_scope(),
            attrs={
                "listeners": [{"protocol": p, "port": 80 if p == "HTTP" else 443} for p in protocols],
            },
        )

    def test_fail_http_only(self):
        check = NET006LoadBalancerHttpListener()
        assert any(f.status == "FAIL" for f in check.run([self._lb(["HTTP"])]))

    def test_pass_https_only(self):
        check = NET006LoadBalancerHttpListener()
        assert not any(f.status == "FAIL" for f in check.run([self._lb(["HTTPS"])]))

    def test_partial_http_and_https(self):
        check = NET006LoadBalancerHttpListener()
        findings = check.run([self._lb(["HTTP", "HTTPS"])])
        # HTTP alongside HTTPS is PARTIAL (redirect may be missing)
        assert any(f.status in ("PARTIAL", "FAIL") for f in findings)
