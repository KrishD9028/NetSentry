"""Bounded protocol-native acquisition, reusing existing parsers and software model."""
from dataclasses import dataclass
import socket
import ssl
import time

from ..analysis.host_evidence import IdentityProbeResult, observation
from ..analysis.identity_probes import remaining, certificate_observations
from ..analysis.probes import certificate_metadata, _decode_peer_certificate, ProbeError
from ..analysis.service_probes import probe_http
from ..analysis.ssh import probe_ssh
from ..analysis.fingerprinting import collect_software_evidence
from ..analysis.models import SecurityCheckResult, CheckStatus
from ..analysis.correlation import SoftwareEvidence
from ..scanning.models import PortService, ServiceIdentity
from .software import normalize_software


@dataclass(frozen=True)
class AcquisitionResult(IdentityProbeResult):
    software: tuple[SoftwareEvidence, ...] = ()
    logical_requests: int | None = None


class DeadlineSocket:
    """Clamp every underlying operation to one shared absolute deadline."""
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.sock.close()
    def settimeout(self, timeout):
        self.sock.settimeout(min(timeout, remaining(self.deadline)))
    def sendall(self, data):
        self.settimeout(remaining(self.deadline))
        return self.sock.sendall(data)
    def recv(self, size):
        self.settimeout(remaining(self.deadline))
        return self.sock.recv(size)
    def __getattr__(self, name):
        return getattr(self.sock, name)


def acquire_http(context, *, tls=False, socket_factory=socket.create_connection, context_factory=ssl.create_default_context):
    action = 'https_fingerprint' if tls else 'http_fingerprint'
    endpoint = f'{context.host}:{context.port}/tcp'
    deadline = time.monotonic() + context.timeout
    evidence = []
    requests = 0
    def connect(address, timeout):
        nonlocal requests
        requests += 1
        return DeadlineSocket(socket_factory(address, timeout=remaining(deadline)), deadline)
    class TLSContext:
        def __init__(self):
            self.inner = context_factory()
            self.inner.check_hostname = False
            self.inner.verify_mode = ssl.CERT_NONE
        def wrap_socket(self, sock, **kwargs):
            nonlocal requests
            sock.settimeout(remaining(deadline))
            secure = self.inner.wrap_socket(sock.sock, **kwargs)
            wrapped = DeadlineSocket(secure, deadline)
            requests += 1
            evidence.append(observation('confirmed_protocol', 'tls', 'TLS handshake', action, 'tls_certificate', endpoint))
            try:
                metadata = certificate_metadata(secure)
                for item in certificate_observations(metadata, endpoint, action):
                    evidence.append(item)
                for key in ('tls_version', 'cipher', 'issuer'):
                    if metadata.get(key):
                        evidence.append(observation('protocol_property', f'{key}: {metadata[key]}', 'TLS handshake/certificate', action, 'tls_certificate', endpoint))
                cert = secure.getpeercert() or _decode_peer_certificate(secure.getpeercert(binary_form=True))
                for kind, value in cert.get('subjectAltName', ())[:32]:
                    evidence.append(observation('tls_certificate_identity', f'SAN {kind}: {value}', 'TLS certificate SAN', action, 'tls_certificate', endpoint))
            except (OSError, ValueError) as exc:
                evidence.append(observation('probe_limitation', str(exc), 'Certificate extraction', action, 'tls_certificate', endpoint))
            return wrapped
    try:
        data = probe_http(context.host, port=context.port, timeout=context.timeout, tls=tls, socket_factory=connect, context_factory=TLSContext)
        evidence.append(observation('confirmed_service', 'https' if tls else 'http', 'Valid HTTP response', action, 'http', endpoint))
        evidence.append(observation('protocol_property', f'HTTP status {data.status}', 'HTTP status line', action, 'http', endpoint))
        if data.server:
            evidence.append(observation('software_banner', data.server[:2048], 'HTTP Server header', action, 'http', endpoint))
        service = PortService(context.port, 'tcp', 'open', identities=(ServiceIdentity('http', 'HTTP response', {'status': data.status}),))
        check = SecurityCheckResult('NS-CHECK-HTTP', 'HTTP acquisition', CheckStatus.COMPLETED, context.port, 'tcp', 'http', details={'server': data.server})
        software = tuple(normalize_software(item, action_id=action, source_key='http', raw_value=data.server)
                         for item in collect_software_evidence(service, (check,), host=context.host))
        return AcquisitionResult('COMPLETED', 'One bounded HTTP response; no redirects, crawling or authentication.', tuple(evidence), software, requests)
    except (OSError, ProbeError) as exc:
        return AcquisitionResult('INCONCLUSIVE', str(exc), tuple(evidence), (), requests)


def acquire_https(context):
    return acquire_http(context, tls=True)


def acquire_ssh(context, *, probe=probe_ssh):
    action, endpoint = 'ssh_fingerprint', f'{context.host}:{context.port}/tcp'
    try:
        data = probe(context.host, port=context.port, timeout=context.timeout, enumerate_security=True)
    except (OSError, ProbeError) as exc:
        return AcquisitionResult('INCONCLUSIVE', str(exc))
    if not data.banner or not data.banner.startswith('SSH-'):
        return AcquisitionResult('INCONCLUSIVE', 'No SSH identification banner.')
    items = [observation('confirmed_service', 'ssh', 'SSH identification', action, 'ssh', endpoint),
             observation('software_banner', data.banner, 'SSH identification', action, 'ssh', endpoint)]
    for name, values in data.algorithms.items():
        items.append(observation('protocol_property', f'{name}: {", ".join(values)}'[:2048], 'SSH KEXINIT', action, 'ssh', endpoint))
    service = PortService(context.port, 'tcp', 'open', identities=(ServiceIdentity('ssh', 'SSH identification', {'banner': data.banner}),))
    software = tuple(normalize_software(item, action_id=action, source_key='ssh', raw_value=data.banner)
                     for item in collect_software_evidence(service, host=context.host))
    return AcquisitionResult('COMPLETED' if data.enumeration_status == 'completed' else 'INCONCLUSIVE',
                             data.enumeration_reason, tuple(items), software, 2)
