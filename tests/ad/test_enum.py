from unittest.mock import MagicMock, patch

import pytest

from qost.ad.enum import EnumResult, enum_domain


class FakeServerInfo:
    """Simulates ldap3 Server.info without network calls."""
    def __init__(self, **attrs):
        self._info_attrs = attrs
        self.raw = {}
        for k, v in attrs.items():
            self.raw[k] = v

    def __getattr__(self, name):
        return self._info_attrs.get(name, None)


class FakeServer:
    """Fake ldap3.Server that doesn't connect."""
    def __init__(self, host, get_info=True, **kwargs):
        self.host = host
        self.info = FakeServerInfo(
            defaultNamingContext=[b"DC=corp,DC=local"],
        )


class TestEnumResult:
    def test_default_construction(self):
        r = EnumResult(
            target="10.0.0.1", domain="test.local",
            dc_hostname="dc01.test.local", authenticated=False,
            root_dse={"defaultNamingContext": "DC=test,DC=local"},
        )
        assert r.target == "10.0.0.1"

    def test_groups_default_empty(self):
        r = EnumResult(target="x", domain="x", dc_hostname="x", authenticated=False, root_dse={})
        assert r.groups == []

    def test_users_default_empty(self):
        r = EnumResult(target="x", domain="x", dc_hostname="x", authenticated=False, root_dse={})
        assert r.users == []


class TestEnumDomain:
    def _mock_conn(self, entries=None, search_result=True):
        conn = MagicMock()
        conn.entries = entries or []
        conn.search.return_value = search_result
        conn.result = {"description": "success", "message": ""}
        return conn

    def test_connection_error_raises(self):
        with patch("qost.ad.enum.Server", side_effect=Exception("Connection failed")):
            with pytest.raises(Exception, match="Connection failed"):
                enum_domain("10.0.0.1", "test.local")

    def test_no_info_returns_early(self):
        server = MagicMock()
        server.info = None
        conn = self._mock_conn()

        with (
            patch("qost.ad.enum.Server", return_value=server),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "test.local")
            assert result.target == "10.0.0.1"
            conn.unbind.assert_called_once()

    def test_anonymous_enum(self):
        conn = self._mock_conn()
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "test.local")
            assert result.authenticated is False

    def test_authenticated_enum(self):
        conn = self._mock_conn()
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "test.local", "admin", "P@ssw0rd")
            assert result.authenticated is True

    def test_parses_users_from_search(self):
        user_entry = MagicMock()
        user_entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"alice"],
            "displayName": [b"Alice Smith"],
            "userPrincipalName": [b"alice@corp.local"],
            "mail": [b"alice@corp.local"],
            "adminCount": [b"1"],
            "userAccountControl": [b"66048"],
            "memberOf": [b"CN=Domain Admins,CN=Users,DC=corp,DC=local"],
            "description": [b"Regular user"],
            "whenCreated": [b"20240101000000.0Z"],
        }
        conn = self._mock_conn([user_entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.users) == 1
            assert result.users[0]["name"] == "alice"
            assert result.users[0]["admin_count"] is True
            assert len(result.admins) == 1

    def test_anonymous_restricted_detected(self):
        conn = self._mock_conn(search_result=False)
        conn.result = {"description": "insufficientAccessRights", "message": "no access"}
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local")
            assert result.anonymous_restricted is True
            assert any(f.type == "Anonymous LDAP Restricted" for f in result.findings)
            conn.unbind.assert_called_once()

    def test_enum_with_computers(self):
        comp_entry = MagicMock()
        comp_entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"WS001$"],
            "dNSHostName": [b"ws001.corp.local"],
            "operatingSystem": [b"Windows 10"],
            "operatingSystemVersion": [b"10.0.19041"],
            "userAccountControl": [b"4096"],
            "description": [b""],
        }
        conn = self._mock_conn([comp_entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.computers) == 1
            assert result.computers[0]["name"] == "WS001$"

    def test_enum_with_all_checks(self):
        user_entry = MagicMock()
        user_entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"alice"],
            "displayName": [b""],
            "userPrincipalName": [b""],
            "mail": [b""],
            "adminCount": [b"1"],
            "userAccountControl": [b"66048"],
            "memberOf": [b""],
            "description": [b""],
            "whenCreated": [b""],
        }
        conn = self._mock_conn([user_entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert result.authenticated is True

    def test_enum_spns(self):
        spn_entry = MagicMock()
        spn_entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"svc_http"],
            "servicePrincipalName": [b"HTTP/websrv.corp.local"],
            "userAccountControl": [b"66048"],
        }
        conn = self._mock_conn([spn_entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.spns) == 1
            assert result.spns[0]["spn"] == "HTTP/websrv.corp.local"

    def test_enum_asrep(self):
        asrep_entry = MagicMock()
        asrep_entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"asrep_user"],
            "userAccountControl": [b"4194304"],
        }
        conn = self._mock_conn([asrep_entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.asrep_users) == 1
            assert result.asrep_users[0]["name"] == "asrep_user"
            assert any(f.type == "AS-REP Roastable" for f in result.findings)

    def test_enum_unconstrained_delegation(self):
        ucd_entry = MagicMock()
        ucd_entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"DC01$"],
            "dNSHostName": [b"dc01.corp.local"],
            "userAccountControl": [b"524288"],
        }
        conn = self._mock_conn([ucd_entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.unconstrained) == 1
            assert result.unconstrained[0]["dns_hostname"] == "dc01.corp.local"
            assert any(f.type == "Unconstrained Delegation" for f in result.findings)

    def test_enum_groups(self):
        group_entry = MagicMock()
        group_entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"Domain Admins"],
            "description": [b"All domain admins"],
            "member": [b"CN=admin,CN=Users,DC=corp,DC=local"],
            "distinguishedName": [b"CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        }
        conn = self._mock_conn([group_entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.groups) == 1
            assert result.groups[0]["name"] == "Domain Admins"

    def test_enum_trusts(self):
        trust_entry = MagicMock()
        trust_entry.entry_attributes_as_dict = {
            "cn": [b"other.local"],
            "trustAttributes": [b"0"],
            "trustDirection": [b"3"],
            "trustType": [b"2"],
            "trustPartner": [b"other.local"],
        }
        conn = self._mock_conn([trust_entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.trusts) == 1
            assert result.trusts[0]["partner"] == "other.local"
            assert result.trusts[0]["direction"] == "Bidirectional"

    def test_enum_constrained_delegation(self):
        entry = MagicMock()
        entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"svc_account"],
            "dNSHostName": [b"svc.corp.local"],
            "msDS-AllowedToDelegateTo": [b"HTTP/websrv.corp.local", b"CIFS/filesrv.corp.local"],
            "userAccountControl": [b"66048"],
        }
        conn = self._mock_conn([entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.constrained) == 1
            assert len(result.constrained[0]["allowed_to_delegate"]) == 2
            assert any(f.type == "Constrained Delegation" for f in result.findings)

    def test_enum_rbcd(self):
        entry = MagicMock()
        entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"WS001$"],
            "dNSHostName": [b"ws001.corp.local"],
            "msDS-AllowedToActOnBehalfOfOtherIdentity": [b"some_acl_value"],
            "userAccountControl": [b"4096"],
        }
        conn = self._mock_conn([entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.rbcd) == 1
            assert any(f.type.startswith("Resource-Based") for f in result.findings)

    def test_enum_adcs_server(self):
        entry = MagicMock()
        entry.entry_attributes_as_dict = {
            "cn": [b"CA01"],
            "dNSHostName": [b"ca01.corp.local"],
            "description": [b"Enterprise CA"],
        }
        conn = self._mock_conn([entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.adcs_servers) == 1
            assert result.adcs_servers[0]["name"] == "CA01"
            assert any(f.type == "AD CS Server Detected" for f in result.findings)

    def test_enum_adcs_template_esc1(self):
        entry = MagicMock()
        entry.entry_attributes_as_dict = {
            "cn": [b"VulnTemplate"],
            "displayName": [b"Vulnerable Template"],
            "msPKI-Certificate-Name-Flag": [b"1"],
            "msPKI-Template-Schema-Version": [b"2"],
        }
        conn = self._mock_conn([entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.adcs_templates) == 1
            assert result.adcs_templates[0]["enrollee_supplies_subject"] is True
            assert any("ESC1" in f.type for f in result.findings)

    def test_enum_laps(self):
        entry = MagicMock()
        entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"WS001$"],
            "dNSHostName": [b"ws001.corp.local"],
            "ms-Mcs-AdmPwd": [b"P@ssw0rd123"],
        }
        conn = self._mock_conn([entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.laps_computers) == 1
            assert result.laps_computers[0]["name"] == "WS001$"
            assert any(f.type == "LAPS Password Readable" for f in result.findings)

    def test_enum_gmsa(self):
        entry = MagicMock()
        entry.entry_attributes_as_dict = {
            "sAMAccountName": [b"gmsa_svc$"],
            "dNSHostName": [b"gmsa-svc.corp.local"],
            "msDS-ManagedPasswordId": [b"some_id"],
        }
        conn = self._mock_conn([entry])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.gmsa_accounts) == 1
            assert result.gmsa_accounts[0]["name"] == "gmsa_svc$"
            assert any(f.type == "gMSA Accounts Detected" for f in result.findings)

    def test_enum_smb_signing(self):
        conn = self._mock_conn([])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert isinstance(result.smb_signing, str)

    def test_asrep_zero_still_adds_finding(self):
        conn = self._mock_conn([])
        with (
            patch("qost.ad.enum.Server", return_value=FakeServer("10.0.0.1")),
            patch("qost.ad.enum.Connection", return_value=conn),
        ):
            result = enum_domain("10.0.0.1", "corp.local", "admin", "P@ssw0rd")
            assert len(result.asrep_users) == 0
            matches = [f for f in result.findings if f.type == "AS-REP Roastable"]
            assert matches
            assert matches[0].severity == "INFO"
            assert "0 user" in matches[0].detail
