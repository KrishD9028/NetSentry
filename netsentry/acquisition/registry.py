"""Acquisition capabilities extend the existing registry; planner stays generic."""
from ..planning.models import ActionDefinition
from .adapters import acquire_http, acquire_https, acquire_ssh


def register_acquisition(registry):
    common = ('confirmed_service', 'software_banner', 'protocol_property', 'software_product', 'software_version', 'operating_system')
    registry.register(ActionDefinition('http_fingerprint', 'Read one bounded HTTP response.', 'software_evidence', common, ('http',), acquire_http,
                                      services=('http', 'http-alt'), fallback_ports=(80, 8080), information_value=3,
                                      discriminates=('operating_system',), reuse_checks=('NS-CHECK-HTTP',), reuse_sources=('HTTP Server header',)))
    registry.register(ActionDefinition('https_fingerprint', 'Read one HTTP response over TLS and certificate metadata.', 'software_evidence',
                                      common + ('confirmed_protocol', 'tls_certificate_identity', 'hostname', 'probe_limitation'), ('http', 'tls_certificate'), acquire_https,
                                      services=('https', 'https-alt', 'tls', 'ssl'), fallback_ports=(443, 8443), information_value=3, network_requests=2,
                                      source_outputs=(('software_product', ('http',)), ('software_version', ('http',)), ('operating_system', ('http',)), ('hostname', ('tls_certificate',))),
                                      discriminates=('operating_system',), reuse_checks=('NS-CHECK-HTTP',), reuse_sources=('HTTP Server header',)))
    registry.register(ActionDefinition('ssh_fingerprint', 'Reuse bounded SSH identification/KEXINIT without authentication.', 'software_evidence', common, ('ssh',), acquire_ssh,
                                      services=('ssh',), fallback_ports=(22,), information_value=3, network_requests=2,
                                      discriminates=('operating_system',), reuse_checks=('NS-CHECK-SSH',)))
