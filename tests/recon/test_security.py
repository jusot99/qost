from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qost.recon.security import check_spf_dmarc, check_dnssec, check_takeover, Vuln


@pytest.mark.asyncio
class TestCheckSPFDMARC:
    async def test_no_spf_record(self):
        """No SPF in TXT records should flag Missing SPF."""
        with patch("qost.recon.security.query_records", new=AsyncMock(return_value=(None, None))):
            results = await check_spf_dmarc("example.com", [])
            assert any(v.type == "Missing SPF Record" for v in results)

    async def test_weak_spf_all(self):
        with patch("qost.recon.security.query_records", new=AsyncMock(return_value=(None, None))):
            results = await check_spf_dmarc("example.com", ['v=spf1 +all'])
            assert any(v.type == "Weak SPF Policy" for v in results)

    async def test_weak_spf_question(self):
        with patch("qost.recon.security.query_records", new=AsyncMock(return_value=(None, None))):
            results = await check_spf_dmarc("example.com", ['v=spf1 ?all'])
            assert any(v.type == "Neutral SPF Policy" for v in results)

    async def test_strong_spf_dmarc_dkim(self):
        mock_dmarc_answer = MagicMock()
        mock_dmarc_answer.to_text.return_value = "v=DMARC1; p=reject"
        mock_dmarc_answer.__str__.return_value = "v=DMARC1; p=reject"

        mock_dkim_answer = MagicMock()
        mock_dkim_answer.to_text.return_value = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC95"
        mock_dkim_answer.__str__.return_value = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC95"

        async def fake_query(domain, rtype):
            if "_dmarc." in domain:
                return ([mock_dmarc_answer], None)
            if "_domainkey." in domain:
                return ([mock_dkim_answer], None)
            return (None, None)

        with patch("qost.recon.security.query_records", side_effect=fake_query):
            results = await check_spf_dmarc("example.com", ['v=spf1 -all'])
            spf_missing = [v for v in results if v.type == "Missing SPF Record"]
            dmarc_missing = [v for v in results if v.type == "Missing DMARC Record"]
            assert len(spf_missing) == 0
            assert len(dmarc_missing) == 0

    async def test_dmarc_found_not_missing(self):
        mock_dmarc_answer = MagicMock()
        mock_dmarc_answer.to_text.return_value = "v=DMARC1; p=quarantine;"
        mock_dmarc_answer.__str__.return_value = "v=DMARC1; p=quarantine;"

        with patch("qost.recon.security.query_records", new=AsyncMock(return_value=([mock_dmarc_answer], None))):
            results = await check_spf_dmarc("example.com", ['v=spf1 -all'])
            dmarc_missing = [v for v in results if v.type == "Missing DMARC Record"]
            assert len(dmarc_missing) == 0

    async def test_dkim_detected(self):
        mock_dkim_answer = MagicMock()
        mock_dkim_answer.to_text.return_value = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC95"
        mock_dkim_answer.__str__.return_value = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC95"

        async def fake_query(domain, rtype):
            if "google._domainkey" in domain:
                return ([mock_dkim_answer], None)
            return (None, None)

        with patch("qost.recon.security.query_records", side_effect=fake_query):
            results = await check_spf_dmarc("example.com", ['v=spf1 -all'])
            dkim_missing = [v for v in results if v.type == "DKIM Not Detected"]
            assert len(dkim_missing) == 0

    async def test_dkim_not_detected(self):
        with patch("qost.recon.security.query_records", new=AsyncMock(return_value=(None, None))):
            results = await check_spf_dmarc("example.com", ['v=spf1 -all'])
            dkim_missing = [v for v in results if v.type == "DKIM Not Detected"]
            assert len(dkim_missing) == 1


class TestCheckDNSSEC:
    def test_dnssec_enabled(self):
        results = check_dnssec(["key1"], ["ds1"])
        enabled = [v for v in results if v.type == "DNSSEC Enabled"]
        assert len(enabled) == 1
        assert enabled[0].severity == "INFO"

    def test_dnssec_missing_keys(self):
        results = check_dnssec([], [])
        assert any(v.severity == "LOW" for v in results)


class TestCheckTakeover:
    def test_no_cname(self):
        results = check_takeover([])
        assert len(results) == 0

    def test_cname_resolves(self):
        with patch("qost.recon.security.resolve_ip", return_value="1.2.3.4"):
            results = check_takeover(["alias.example.com."])
            assert len(results) == 0

    def test_takeover_detected_for_aws(self):
        with patch("qost.recon.security.resolve_ip", return_value=None):
            results = check_takeover(["myapp.s3.amazonaws.com."])
            takovers = [v for v in results if "takeover" in v.type.lower()]
            assert len(takovers) >= 1

    def test_known_cloud_target(self):
        with patch("qost.recon.security.resolve_ip", return_value=None):
            results = check_takeover(["myapp.azurewebsites.net."])
            takovers = [v for v in results if "takeover" in v.type.lower()]
            assert len(takovers) >= 1

    def test_no_match_not_takeover(self):
        with patch("qost.recon.security.resolve_ip", return_value=None):
            results = check_takeover(["random.example.com."])
            assert len(results) == 0


class TestVulnDataclass:
    def test_vuln_creation(self):
        v = Vuln(type="test", severity="high", detail="something", fix="do something")
        assert v.type == "test"
        assert v.severity == "high"
