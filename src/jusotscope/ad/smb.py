import socket
import struct


SMB_NEGOTIATE = b"\x00\x00\x00\x00\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

SMB_SESSION_SETUP = b"\x00\x00\x00\x00\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def check_null_session(host: str, port: int = 445, timeout: float = 5.0) -> dict:
    result = {
        "status": "error",
        "detail": "",
        "vulnerable": False,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        sock.send(SMB_NEGOTIATE)
        resp = sock.recv(1024)
        if len(resp) < 4:
            result["detail"] = "No response to SMB negotiate"
            sock.close()
            return result

        sock.send(SMB_SESSION_SETUP)
        resp = sock.recv(1024)
        sock.close()

        if len(resp) < 9:
            result["detail"] = "No response to SMB session setup"
            return result

        status = struct.unpack("<I", resp[4:8])[0]
        if status == 0:
            result["status"] = "vulnerable"
            result["vulnerable"] = True
            result["detail"] = "Anonymous SMB null session allowed on port 445"
        elif status == 0xC0000022:
            result["status"] = "secure"
            result["vulnerable"] = False
            result["detail"] = "SMB null session denied (STATUS_ACCESS_DENIED)"
        elif status == 0xC0000001:
            result["status"] = "secure"
            result["vulnerable"] = False
            result["detail"] = "SMB null session denied (STATUS_UNSUCCESSFUL)"
        else:
            result["status"] = "unknown"
            result["vulnerable"] = False
            result["detail"] = f"SMB returned status 0x{status:08X}"
    except socket.timeout:
        result["detail"] = "SMB connection timed out"
    except ConnectionRefusedError:
        result["detail"] = "SMB port 445 not open"
    except OSError as e:
        result["detail"] = f"SMB error: {e}"
    return result
