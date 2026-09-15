import datetime as dt
import logging
import os
import socket
import ssl
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SMBProbeData:
    dialect: str | None
    smb1_supported: bool | None
    signing_supported: bool | None
    signing_required: bool | None
    identity: str | None = None
    authentication_status: str = "Not required for protocol negotiation"


@dataclass(frozen=True, slots=True)
class TLSProbeData:
    tls_version: str | None
    cipher: str | None
    subject: str | None
    issuer: str | None
    not_before: str | None
    not_after: str | None
    expired: bool | None
    not_yet_valid: bool | None
    http_status: int | None = None
    security_headers: dict[str, str] | None = None
    verification_result: str = "not performed"


class ProbeError(RuntimeError):
    """Raised when a safe network probe cannot complete."""


@contextmanager
def _quiet_smb_worker():
    # smbprotocol logs this worker exception and then re-raises it on the
    # calling thread. NetSentry reports that exception as structured evidence.
    # Filter at the emitting logger (parent filters do not filter children).
    logger = logging.getLogger("smbprotocol.connection")
    def redundant_worker_error(record):
        return not (record.name == "smbprotocol.connection"
                    and record.msg == "SMB receive worker died (outstanding=%d)"
                    and record.exc_info)
    logger.addFilter(redundant_worker_error)
    try:
        yield
    finally:
        logger.removeFilter(redundant_worker_error)


@_quiet_smb_worker()
def probe_smb(host: str, *, port: int = 445, timeout: float = 2.0, socket_factory=socket.create_connection) -> SMBProbeData:
    """Perform an unauthenticated SMB negotiate using smbprotocol."""
    logging.getLogger("smbprotocol").setLevel(logging.WARNING)
    logging.getLogger("smbprotocol.connection").setLevel(logging.WARNING)
    try:
        from smbprotocol.connection import Connection, SecurityMode
    except ImportError as exc:
        raise ProbeError("SMB probe implementation unavailable: install smbprotocol.") from exc

    connection = Connection(uuid.uuid4(), host, port=port, require_signing=False)
    try:
        connection.connect(timeout=timeout)
        dialect_names = {
            0x0202: "SMB 2.0.2",
            0x0210: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0302: "SMB 3.0.2",
            0x0311: "SMB 3.1.1",
        }
        security_mode = getattr(connection, "server_security_mode", 0)
        return SMBProbeData(
            dialect=dialect_names.get(connection.dialect, f"0x{connection.dialect:04x}"),
            smb1_supported=None,
            signing_supported=bool(security_mode & SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED),
            signing_required=bool(security_mode & SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED),
            identity=str(getattr(connection, "server_guid", "")) or None,
            authentication_status="Not required for protocol negotiation",
        )
    except TimeoutError as exc:
        raise ProbeError(f"SMB negotiation timeout: {exc}") from exc
    except ConnectionResetError as exc:
        raise ProbeError(f"SMB connection reset during negotiation: {exc}") from exc
    except ConnectionRefusedError as exc:
        raise ProbeError(f"SMB connection refused: {exc}") from exc
    except OSError as exc:
        raise ProbeError(f"SMB transport error during negotiation: {exc}") from exc
    except Exception as exc:
        raise ProbeError(f"SMB negotiation rejected or malformed: {exc}") from exc
    finally:
        try:
            connection.disconnect()
        except Exception:
            pass


def _certificate_value(certificate: dict[str, Any], section: str, key: str) -> str | None:
    values = certificate.get(section, ())
    matches = [value for group in values for name, value in group if name == key]
    return ", ".join(matches) if matches else None


def certificate_metadata(connection) -> dict[str, Any]:
    """Extract certificate observations from an existing TLS connection; no I/O requests."""
    certificate = connection.getpeercert()
    if not certificate:
        certificate = _decode_peer_certificate(connection.getpeercert(binary_form=True))
    now = dt.datetime.now(dt.timezone.utc)
    cipher = connection.cipher()
    return {
        "tls_version": connection.version(), "cipher": cipher[0] if cipher else None,
        "subject": _certificate_value(certificate, "subject", "commonName"),
        "issuer": _certificate_value(certificate, "issuer", "organizationName"),
        "not_before": certificate.get("notBefore"), "not_after": certificate.get("notAfter"),
        "expired": _certificate_expired(certificate.get("notAfter"), now),
        "not_yet_valid": _certificate_not_yet_valid(certificate.get("notBefore"), now),
        "verification_result": "not performed (certificate verification disabled for observation)",
    }


def probe_tls(host: str, *, port: int, timeout: float = 3.0, socket_factory=socket.create_connection, context_factory=ssl.create_default_context) -> TLSProbeData:
    """Perform a read-only TLS handshake and optional HTTP header request."""
    context = context_factory()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket_factory((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as connection:
                certificate = connection.getpeercert()
                if not certificate:
                    certificate = _decode_peer_certificate(connection.getpeercert(binary_form=True))
                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")
                now = dt.datetime.now(dt.timezone.utc)
                expired = _certificate_expired(not_after, now)
                not_yet_valid = _certificate_not_yet_valid(not_before, now)
                status_code, headers = _read_http_headers(connection, host)
                cipher_info = connection.cipher()
                return TLSProbeData(
                    tls_version=connection.version(),
                    cipher=cipher_info[0] if cipher_info else None,
                    subject=_certificate_value(certificate, "subject", "commonName"),
                    issuer=_certificate_value(certificate, "issuer", "organizationName"),
                    not_before=not_before,
                    not_after=not_after,
                    expired=expired,
                    not_yet_valid=not_yet_valid,
                    verification_result="not performed (certificate verification disabled for observation)",
                    http_status=status_code,
                    security_headers=headers,
                )
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise ProbeError(f"TLS probe failed: {exc}") from exc


def _decode_peer_certificate(der_certificate: bytes | None) -> dict[str, Any]:
    if not der_certificate:
        return {}
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as temporary:
            temporary.write(ssl.DER_cert_to_PEM_cert(der_certificate).encode())
            temporary_path = temporary.name
        return ssl._ssl._test_decode_cert(temporary_path)
    except (AttributeError, OSError, ValueError):
        return {}
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def _certificate_expired(value: str | None, now: dt.datetime) -> bool | None:
    parsed = _parse_certificate_date(value)
    return None if parsed is None else now > parsed


def _certificate_not_yet_valid(value: str | None, now: dt.datetime) -> bool | None:
    parsed = _parse_certificate_date(value)
    return None if parsed is None else now < parsed


def _parse_certificate_date(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def _read_http_headers(connection, host: str) -> tuple[int | None, dict[str, str]]:
    try:
        connection.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        response = connection.recv(8192)
    except OSError:
        return None, {}
    header_block = response.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    lines = header_block.split("\r\n")
    status_code = None
    if lines and len(lines[0].split()) >= 2:
        try:
            status_code = int(lines[0].split()[1])
        except ValueError:
            pass
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.lower()] = value.strip()
    return status_code, headers
