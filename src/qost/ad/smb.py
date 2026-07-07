import socket
import struct
import uuid


SMB_NEGOTIATE_BODY = b"\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

SMB_SESSION_SETUP_BODY = b"\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def _frame_smb(body: bytes) -> bytes:
    """Prepend Direct TCP (port 445) length prefix (4-byte big-endian)."""
    return struct.pack(">I", len(body)) + body


def _unframe_smb(data: bytes) -> bytes:
    """Strip Direct TCP length prefix from received data.

    Real SMB responses on port 445 start with a 4-byte big-endian length.
    Return the SMB message body; if data looks unframed (< 4 bytes or
    first 4 bytes aren't a plausible length), return data as-is.
    """
    if len(data) >= 4:
        claimed = struct.unpack(">I", data[:4])[0]
        if claimed <= len(data) - 4:
            return data[4:]
    return data

def _smb2_header(command: int, message_id: int, session_id: int = 0, credit: int = 1) -> bytes:
    return (
        b"\xfe\x53\x4d\x42"
        + struct.pack("<H", 64)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + struct.pack("<H", command)
        + struct.pack("<H", credit)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", message_id)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", session_id)
        + b"\x00" * 16
    )


def _smb2_negotiate_packet() -> bytes:
    client_guid = uuid.uuid4().bytes
    body = (
        struct.pack("<HH", 36, 1)
        + struct.pack("<H", 1)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + client_guid
        + struct.pack("<H", 0x0210)
    )
    return _frame_smb(_smb2_header(command=0, message_id=0, session_id=0, credit=31) + body)


def _ntlmssp_negotiate() -> bytes:
    flags = 0x00088201
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 1)
        + struct.pack("<I", flags)
        + struct.pack("<HHI", 0, 0, 0)
        + struct.pack("<HHI", 0, 0, 0)
    )


def _smb2_session_setup_packet(session_id: int) -> bytes:
    sec_buf = _ntlmssp_negotiate()
    sec_offset = 64 + 25
    header = _smb2_header(command=1, message_id=1, session_id=session_id)
    body = (
        struct.pack("<H", 25)
        + struct.pack("<B", 0)
        + struct.pack("<B", 0)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<H", sec_offset)
        + struct.pack("<H", len(sec_buf))
        + struct.pack("<Q", 0)
    )
    return _frame_smb(header + body + sec_buf)


def _extract_session_id(resp: bytes) -> int:
    if len(resp) >= 48:
        return struct.unpack("<Q", resp[40:48])[0]
    return 0


def _smb2_parse_negotiate_response(resp: bytes) -> dict | None:
    if len(resp) < 68:
        return {"status": "error", "detail": "SMBv2 negotiate response too short", "vulnerable": False, "signing_required": False}
    status = struct.unpack("<I", resp[8:12])[0]
    if status != 0:
        return {"status": "error", "detail": f"SMBv2 negotiate failed 0x{status:08X}", "vulnerable": False, "signing_required": False}
    return None


def _smb2_parse_session_setup(resp: bytes, signing_required: bool = False) -> dict:
    if len(resp) < 12:
        return {"status": "error", "detail": "SMBv2 session setup response too short", "vulnerable": False, "signing_required": signing_required}
    status = struct.unpack("<I", resp[8:12])[0]
    session_id = _extract_session_id(resp)

    if status == 0:
        return {
            "status": "vulnerable",
            "vulnerable": True,
            "detail": "Anonymous SMB null session allowed via SMBv2",
            "session_id": session_id,
            "signing_required": signing_required,
        }
    elif status == 0xC0000022:
        return {
            "status": "secure",
            "vulnerable": False,
            "detail": "SMB null session denied via SMBv2 (STATUS_ACCESS_DENIED)",
            "signing_required": signing_required,
        }
    elif status == 0xC0000016:
        return {
            "status": "secure",
            "vulnerable": False,
            "detail": "SMBv2 requires NTLM authentication (not directly exploitable as null session)",
            "signing_required": signing_required,
        }
    elif status == 0xC0000001:
        return {
            "status": "secure",
            "vulnerable": False,
            "detail": "SMB null session denied via SMBv2 (STATUS_UNSUCCESSFUL)",
            "signing_required": signing_required,
        }
    else:
        return {
            "status": "unknown",
            "vulnerable": False,
            "detail": f"SMBv2 session setup returned status 0x{status:08X}",
            "signing_required": signing_required,
        }


def _try_smbv1(host: str, port: int, timeout: float) -> dict:
    sock = socket.create_connection((host, port), timeout=timeout)

    sock.send(_frame_smb(SMB_NEGOTIATE_BODY))
    resp = _unframe_smb(sock.recv(1024))
    if len(resp) < 4:
        sock.close()
        return {"status": "error", "detail": "No response to SMB negotiate", "vulnerable": False}

    sock.send(_frame_smb(SMB_SESSION_SETUP_BODY))
    resp = _unframe_smb(sock.recv(1024))
    sock.close()

    if len(resp) < 9:
        return {"status": "error", "detail": "No response to SMB session setup", "vulnerable": False}

    status = struct.unpack("<I", resp[4:8])[0]
    if status == 0:
        return {"status": "vulnerable", "vulnerable": True, "detail": "Anonymous SMB null session allowed on port 445", "signing_required": False}
    elif status == 0xC0000022:
        return {"status": "secure", "vulnerable": False, "detail": "SMB null session denied (STATUS_ACCESS_DENIED)", "signing_required": False}
    elif status == 0xC0000001:
        return {"status": "secure", "vulnerable": False, "detail": "SMB null session denied (STATUS_UNSUCCESSFUL)", "signing_required": False}
    else:
        return {"status": "unknown", "vulnerable": False, "detail": f"SMB returned status 0x{status:08X}", "signing_required": False}


def _try_smbv2(host: str, port: int, timeout: float) -> dict:
    sock = socket.create_connection((host, port), timeout=timeout)

    pkt = _smb2_negotiate_packet()
    sock.send(pkt)
    resp = _unframe_smb(sock.recv(4096))

    if len(resp) < 4:
        sock.close()
        return {"status": "error", "detail": "No response to SMBv2 negotiate", "vulnerable": False}

    if resp[:4] != b"\xfe\x53\x4d\x42":
        sock.close()
        if resp[:4] == b"\xff\x53\x4d\x42":
            return {"status": "secure", "detail": "Server prefers SMBv1 but SMBv2 also accepted", "vulnerable": False}
        return {"status": "error", "detail": f"Unexpected SMBv2 response: {resp[:4].hex()}", "vulnerable": False}

    signing = _parse_smb2_security_mode(resp) if len(resp) >= 72 else False
    neg_result = _smb2_parse_negotiate_response(resp)
    if neg_result is not None:
        sock.close()
        return neg_result

    session_id = _extract_session_id(resp)
    if not session_id:
        sock.close()
        return {"status": "error", "detail": "SMBv2 negotiate returned zero session ID", "vulnerable": False, "signing_required": signing}

    ss_pkt = _smb2_session_setup_packet(session_id)
    sock.send(ss_pkt)
    resp = _unframe_smb(sock.recv(4096))
    sock.close()

    return _smb2_parse_session_setup(resp, signing_required=signing)


def _parse_smb2_security_mode(resp: bytes) -> bool:
    """Check if SMB signing is required from SMBv2 negotiate response.
    
    SecurityMode is a 2-byte field at offset 70 in the SMBv2 response:
    - bit 0: signing enabled
    - bit 1: signing required
    """
    if len(resp) < 72:
        return False
    sec_mode = struct.unpack("<H", resp[70:72])[0]
    return bool(sec_mode & 0x02)


def check_null_session(host: str, port: int = 445, timeout: float = 5.0) -> dict:
    try:
        res = _try_smbv1(host, port, timeout)
        return res
    except socket.timeout:
        return {"status": "error", "detail": "SMB connection timed out", "vulnerable": False, "signing_required": False}
    except ConnectionRefusedError:
        return {"status": "error", "detail": "SMB port 445 not open", "vulnerable": False, "signing_required": False}
    except ConnectionResetError:
        pass
    except OSError as e:
        return {"status": "error", "detail": f"SMB error: {e}", "vulnerable": False, "signing_required": False}

    try:
        result = _try_smbv2(host, port, timeout)
        if result["status"] == "error":
            result["detail"] += " (SMBv1 disabled)"
        return result
    except socket.timeout:
        return {"status": "error", "detail": "SMBv2 negotiate timed out (SMBv1 disabled)", "vulnerable": False, "signing_required": False}
    except ConnectionRefusedError:
        return {"status": "error", "detail": "SMB port 445 not open", "vulnerable": False, "signing_required": False}
    except OSError as e:
        return {"status": "error", "detail": f"SMBv2 error: {e} (SMBv1 disabled)", "vulnerable": False, "signing_required": False}
