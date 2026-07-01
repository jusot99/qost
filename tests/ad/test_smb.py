from unittest.mock import MagicMock, patch


from jusotscope.ad.smb import (
    _smb2_header,
    _ntlmssp_negotiate,
    check_null_session,
)


def _smb2_resp(status_code: int = 0, session_id: int = 0xDEADBEEF,
               dialect: int = 0x0311) -> bytes:
    import struct
    hdr = _smb2_header(command=0, message_id=0, session_id=session_id)
    hdr = hdr[:8] + struct.pack("<I", status_code) + hdr[12:]
    body = struct.pack("<H", 65) + struct.pack("<B", 2) + b"\x00" + struct.pack("<H", dialect)
    return hdr + body


def _smb2_ss_resp(status_code: int = 0, session_id: int = 0xDEADBEEF) -> bytes:
    import struct
    hdr = _smb2_header(command=0, message_id=0, session_id=session_id)
    hdr = hdr[:8] + struct.pack("<I", status_code) + hdr[12:]
    return hdr + b"\x00" * 16


def struct_pack(status_code):
    import struct
    return b"xxxx" + struct.pack("<I", status_code) + b"x" * 24


class TestCheckNullSession:
    def test_null_session_allowed(self):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            mock_sock.recv.side_effect = [
                b"x" * 64,
                struct_pack(0x00000000),
            ]
            result = check_null_session("192.168.1.1")
            assert result["vulnerable"] is True
            assert result["status"] == "vulnerable"

    def test_null_session_denied_access_denied(self):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            mock_sock.recv.side_effect = [
                b"x" * 64,
                struct_pack(0xC0000022),
            ]
            result = check_null_session("192.168.1.1")
            assert result["vulnerable"] is False
            assert result["status"] == "secure"

    def test_null_session_denied_unsuccessful(self):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            mock_sock.recv.side_effect = [
                b"x" * 64,
                struct_pack(0xC0000001),
            ]
            result = check_null_session("192.168.1.1")
            assert result["vulnerable"] is False
            assert result["status"] == "secure"

    def test_timeout(self):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            mock_sock.connect.side_effect = TimeoutError("timed out")
            result = check_null_session("192.168.1.1")
            assert result["status"] == "error"
            assert "timed out" in result["detail"]

    def test_connection_refused(self):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            mock_sock.connect.side_effect = ConnectionRefusedError("refused")
            result = check_null_session("192.168.1.1")
            assert result["status"] == "error"
            assert "not open" in result["detail"]

    def test_no_negotiate_response(self):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            mock_sock.recv.return_value = b""
            result = check_null_session("192.168.1.1")
            assert result["detail"] == "No response to SMB negotiate"

    def test_no_session_response(self):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            mock_sock.recv.side_effect = [
                b"x" * 64,
                b"",
            ]
            result = check_null_session("192.168.1.1")
            assert result["detail"] == "No response to SMB session setup"

    def test_unknown_status(self):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            mock_sock.recv.side_effect = [
                b"x" * 64,
                struct_pack(0xDEADBEEF),
            ]
            result = check_null_session("192.168.1.1")
            assert result["status"] == "unknown"
            assert "DEADBEEF" in result["detail"]

    def test_oserror(self):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            mock_sock.connect.side_effect = OSError("Some other socket error")
            result = check_null_session("192.168.1.1")
            assert result["status"] == "error"
            assert "Some other socket error" in result["detail"]


class TestSmbV2Fallback:
    def test_smbv2_negotiate_secure(self):
        mock_sock = MagicMock()
        mock_sock2 = MagicMock()
        neg_resp = _smb2_resp(status_code=0, session_id=0x2000, dialect=0x0311)
        ss_resp = _smb2_ss_resp(status_code=0xC0000022, session_id=0x2000)
        with patch("socket.socket", side_effect=[mock_sock, mock_sock2]):
            mock_sock.send.side_effect = None
            mock_sock.recv.side_effect = ConnectionResetError("reset")
            mock_sock2.send.side_effect = None
            mock_sock2.recv.side_effect = [neg_resp, ss_resp]
            result = check_null_session("192.168.1.1")
            assert result["status"] == "secure"
            assert "ACCESS_DENIED" in result["detail"]

    def test_smbv2_null_session_allowed(self):
        mock_sock = MagicMock()
        mock_sock2 = MagicMock()
        neg_resp = _smb2_resp(status_code=0, session_id=0x2000, dialect=0x0311)
        ss_resp = _smb2_ss_resp(status_code=0, session_id=0x2000)
        with patch("socket.socket", side_effect=[mock_sock, mock_sock2]):
            mock_sock.send.side_effect = None
            mock_sock.recv.side_effect = ConnectionResetError("reset")
            mock_sock2.send.side_effect = None
            mock_sock2.recv.side_effect = [neg_resp, ss_resp]
            result = check_null_session("192.168.1.1")
            assert result["status"] == "vulnerable"
            assert result["vulnerable"] is True
            assert "SMBv2" in result["detail"]

    def test_smbv2_more_processing(self):
        mock_sock = MagicMock()
        mock_sock2 = MagicMock()
        neg_resp = _smb2_resp(status_code=0, session_id=0x2000, dialect=0x0311)
        ss_resp = _smb2_ss_resp(status_code=0xC0000016, session_id=0x2000)
        with patch("socket.socket", side_effect=[mock_sock, mock_sock2]):
            mock_sock.send.side_effect = None
            mock_sock.recv.side_effect = ConnectionResetError("reset")
            mock_sock2.send.side_effect = None
            mock_sock2.recv.side_effect = [neg_resp, ss_resp]
            result = check_null_session("192.168.1.1")
            assert result["status"] == "secure"
            assert "requires NTLM" in result["detail"]

    def test_smbv2_negotiate_fails(self):
        mock_sock = MagicMock()
        mock_sock2 = MagicMock()
        neg_resp = _smb2_resp(status_code=0xC0000001, session_id=0x2000, dialect=0x0311)
        with patch("socket.socket", side_effect=[mock_sock, mock_sock2]):
            mock_sock.send.side_effect = None
            mock_sock.recv.side_effect = ConnectionResetError("reset")
            mock_sock2.send.side_effect = None
            mock_sock2.recv.return_value = neg_resp
            result = check_null_session("192.168.1.1")
            assert result["status"] == "error"

    def test_smbv2_zero_session_id(self):
        mock_sock = MagicMock()
        mock_sock2 = MagicMock()
        neg_resp = _smb2_resp(status_code=0, session_id=0, dialect=0x0311)
        with patch("socket.socket", side_effect=[mock_sock, mock_sock2]):
            mock_sock.send.side_effect = None
            mock_sock.recv.side_effect = ConnectionResetError("reset")
            mock_sock2.send.side_effect = None
            mock_sock2.recv.return_value = neg_resp
            result = check_null_session("192.168.1.1")
            assert result["status"] == "error"
            assert "zero session ID" in result["detail"]

    def test_smbv2_unexpected_response(self):
        mock_sock = MagicMock()
        mock_sock2 = MagicMock()
        with patch("socket.socket", side_effect=[mock_sock, mock_sock2]):
            mock_sock.send.side_effect = None
            mock_sock.recv.side_effect = ConnectionResetError("reset")
            mock_sock2.send.side_effect = None
            mock_sock2.recv.return_value = b"\x00\x00\x00\x00"
            result = check_null_session("192.168.1.1")
            assert result["status"] == "error"

    def test_smbv2_oserror(self):
        mock_sock = MagicMock()
        mock_sock2 = MagicMock()
        with patch("socket.socket", side_effect=[mock_sock, mock_sock2]):
            mock_sock.send.side_effect = None
            mock_sock.recv.side_effect = ConnectionResetError("reset")
            mock_sock2.connect.side_effect = OSError("v2 failed")
            result = check_null_session("192.168.1.1")
            assert result["status"] == "error"
            assert "SMBv1 disabled" in result["detail"]


class TestNtlmsspNegotiate:
    def test_starts_with_ntlmssp(self):
        buf = _ntlmssp_negotiate()
        assert buf[:8] == b"NTLMSSP\x00"

    def test_message_type_is_negotiate(self):
        import struct
        buf = _ntlmssp_negotiate()
        assert struct.unpack_from("<I", buf, 8)[0] == 1


class TestSmb2Header:
    def test_protocol_id(self):
        hdr = _smb2_header(command=0, message_id=0)
        assert hdr[:4] == b"\xfe\x53\x4d\x42"

    def test_command_field(self):
        hdr = _smb2_header(command=5, message_id=0)
        import struct
        cmd = struct.unpack_from("<H", hdr, 12)[0]
        assert cmd == 5

    def test_session_id(self):
        hdr = _smb2_header(command=0, message_id=0, session_id=0x1234)
        import struct
        sid = struct.unpack_from("<Q", hdr, 40)[0]
        assert sid == 0x1234
