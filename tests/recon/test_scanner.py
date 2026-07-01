from unittest.mock import MagicMock, patch


from jusotscope.recon.scanner import query_records, resolve_all, zone_transfer, format_rdata, _clean


class TestClean:
    def test_removes_extra_whitespace(self):
        assert _clean("  hello   world  ") == "hello world"

    def test_removes_leading_trailing_whitespace(self):
        assert _clean("  hello  ") == "hello"

    def test_empty_string(self):
        assert _clean("") == ""


class TestFormatRdata:
    def test_a_record(self):
        rdata = MagicMock(spec=object, address="8.8.8.8")
        result = format_rdata(rdata, "A")
        assert result == "8.8.8.8"

    def test_aaaa_record(self):
        rdata = MagicMock(spec=object, address="::1")
        result = format_rdata(rdata, "AAAA")
        assert result == "::1"

    def test_mx_record(self):
        rdata = MagicMock(preference=10, exchange="mail.example.com")
        result = format_rdata(rdata, "MX")
        assert "mail.example.com" in result
        assert "10" in result

    def test_soa_record(self):
        rdata = MagicMock(mname="ns1.example.com", rname="admin.example.com", serial=20240101)
        result = format_rdata(rdata, "SOA")
        assert "ns1.example.com" in result
        assert "20240101" in result

    def test_srv_record(self):
        rdata = MagicMock(target="server.example.com", port=443, priority=10, weight=5)
        result = format_rdata(rdata, "SRV")
        assert "server.example.com" in result
        assert "443" in result

    def test_txt_record(self):
        rdata = MagicMock(strings=[b"v=spf1 include:_spf.google.com"])
        result = format_rdata(rdata, "TXT")
        assert "v=spf1" in result

    def test_cname_record(self):
        rdata = MagicMock(target="alias.example.com")
        result = format_rdata(rdata, "CNAME")
        assert "alias.example.com" in result

    def test_ns_record(self):
        rdata = MagicMock(target="ns1.example.com")
        result = format_rdata(rdata, "NS")
        assert "ns1.example.com" in result

    def test_unknown_type_uses_address_then_target(self):
        rdata = MagicMock(spec=object, address="10.0.0.1")
        result = format_rdata(rdata, "UNKNOWN")
        assert "10.0.0.1" in result

    def test_unknown_type_fallback_to_str(self):
        rdata = "raw data"
        result = format_rdata(rdata, "UNKNOWN")
        assert "raw data" in result


class TestQueryRecords:
    def test_successful_query(self):
        mock_answer = MagicMock()
        mock_answer.rrset = [MagicMock()]
        mock_answer.rrset[0].to_text.return_value = "8.8.8.8"

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = mock_answer

        with patch("dns.resolver.Resolver", return_value=mock_resolver):
            answers, error = query_records("example.com", "A")
            assert error is None

    def test_no_answer_triggers_fallback(self):
        """NoAnswer is caught and resolver falls through to next."""
        import dns.resolver
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer

        with (
            patch("dns.resolver.Resolver", return_value=mock_resolver),
            patch("jusotscope.recon.scanner.DEFAULT_RESOLVERS", ["1.1.1.1"]),
        ):
            answers, error = query_records("example.com", "A")
            # Since resolvers list is ["1.1.1.1"] and it raises, we get fallback msg
            assert error == "All resolvers failed"

    def test_nxdomain_triggers_fallback(self):
        import dns.resolver
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN

        with (
            patch("dns.resolver.Resolver", return_value=mock_resolver),
            patch("jusotscope.recon.scanner.DEFAULT_RESOLVERS", ["1.1.1.1"]),
        ):
            answers, error = query_records("nonexistent.invalid", "A")
            assert error == "All resolvers failed"

    def test_custom_resolvers(self):
        mock_answer = MagicMock()
        mock_answer.rrset = [MagicMock()]
        mock_answer.rrset[0].to_text.return_value = "1.1.1.1"

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = mock_answer

        with patch("dns.resolver.Resolver", return_value=mock_resolver):
            answers, error = query_records("example.com", "A", resolvers=["1.1.1.1"])
            assert error is None

    def test_is_ip_returns_directly(self):
        answers, error = query_records("8.8.8.8", "A")
        assert answers == ["8.8.8.8"]
        assert error is None

    def test_is_ip_other_type(self):
        answers, error = query_records("8.8.8.8", "MX")
        assert answers is None
        assert "IP address" in error


class TestResolveAll:
    def test_resolves_all_types(self):
        with patch("jusotscope.recon.scanner.query_records") as mock_query:
            mock_query.return_value = (["data"], None)
            result = resolve_all("example.com")
            assert "A" in result
            assert "MX" in result
            assert "NS" in result

    def test_is_ip_only_a(self):
        with patch("jusotscope.recon.scanner.query_records") as mock_query:
            mock_query.return_value = (["1.2.3.4"], None)
            result = resolve_all("8.8.8.8")
            assert "A" in result


class TestZoneTransfer:
    def test_successful_transfer(self):
        mock_zone = MagicMock()
        mock_rnode = MagicMock()
        mock_rdset = MagicMock()
        mock_rdset.rdtype = 1  # A record
        mock_rdataset_item = MagicMock()
        mock_rdataset_item.__str__.return_value = "192.168.1.1"
        mock_rdset.__iter__.return_value = [mock_rdataset_item]
        mock_rnode.rdatasets = [mock_rdset]
        mock_zone.nodes.items.return_value = [("www", mock_rnode)]

        with (
            patch("dns.query.xfr", return_value=mock_zone),
            patch("dns.zone.from_xfr", return_value=mock_zone),
            patch("dns.rdatatype.to_text", return_value="A"),
        ):
            records, error = zone_transfer("ns1.example.com", "example.com")
            assert error is None
            assert len(records) >= 0

    def test_failed_transfer(self):
        with patch("dns.query.xfr", side_effect=Exception("Transfer denied")):
            records, error = zone_transfer("ns1.example.com", "example.com")
            assert error == "Transfer denied"

    def test_is_ip(self):
        records, error = zone_transfer("ns1.example.com", "8.8.8.8")
        assert "IP address" in error
