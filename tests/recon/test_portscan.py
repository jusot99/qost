from unittest.mock import patch


from jusotscope.recon.portscan import scan, COMMON_PORTS


class TestScan:
    def test_scan_with_open_ports(self):
        with patch("socket.socket") as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 0
            mock_socket.return_value.recv.return_value = b"SSH-2.0-OpenSSH"
            mock_socket.return_value.getpeername.return_value = ("8.8.8.8", 22)

            results = scan("8.8.8.8")
            assert len(results) > 0
            assert any(port == 22 for port, _ in results)

    def test_scan_no_open_ports(self):
        with patch("socket.socket") as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 1
            results = scan("8.8.8.8")
            assert len(results) == 0

    def test_common_ports_defined(self):
        assert len(COMMON_PORTS) > 0
        assert (22, "SSH") in COMMON_PORTS
        assert (80, "HTTP") in COMMON_PORTS
        assert (443, "HTTPS") in COMMON_PORTS
