"""Trusted, in-process capability registration. Remote planners cannot register code."""
import math
import re

from .models import ActionDefinition, SafetyClass


class ActionRegistry:
    def __init__(self, actions=()):
        self._actions = {}
        for action in actions:
            self.register(action)

    def register(self, action):
        if not isinstance(action, ActionDefinition) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', action.action_id):
            raise ValueError('Invalid action definition or stable ID')
        if action.action_id in self._actions:
            raise ValueError('Duplicate action ID')
        if not isinstance(action.safety, SafetyClass) or action.transport not in {'tcp', 'udp'} or action.observed_transport not in {'tcp', 'udp'}:
            raise ValueError('Invalid action safety class or transport')
        for count in (action.cost, action.information_value, action.network_requests, action.noise):
            if type(count) is not int or count < 0:
                raise ValueError('Action costs/values must be nonnegative integers')
        if not math.isfinite(action.timeout) or action.timeout <= 0:
            raise ValueError('Action timeout must be positive and finite')
        for values in (action.produces, action.sources, action.services, action.prerequisites, action.discriminates, action.reuse_checks, action.reuse_sources):
            if not isinstance(values, tuple) or any(not isinstance(value, str) or not value or len(value) > 128 for value in values):
                raise ValueError('Action requirements and evidence declarations must be bounded string tuples')
        if not set(action.discriminates) <= set(action.produces):
            raise ValueError('Discrimination metadata must name declared evidence outputs')
        if type(action.authentication_required) is not bool or type(action.repeatable) is not bool:
            raise ValueError('Action policy flags must be booleans')
        if len({name for name, _ in action.source_outputs}) != len(action.source_outputs):
            raise ValueError('Duplicate source-output mapping')
        for name, sources in action.source_outputs:
            if name not in action.produces or not sources or not set(sources) <= set(action.sources):
                raise ValueError('Invalid per-output independence mapping')
        if not action.ip_versions or any(version not in {4, 6} for version in action.ip_versions):
            raise ValueError('Unsupported address family')
        if not action.produces or not action.sources:
            raise ValueError('Actions must declare evidence outputs and source independence')
        if any(type(p) is not int or not 1 <= p <= 65535 for p in (*action.fallback_ports, *((action.target_port,) if action.target_port is not None else ()))):
            raise ValueError('Invalid action port')
        if action.handler is not None and not callable(action.handler):
            raise ValueError('Action handler must be callable or unavailable')
        if action.safety in {SafetyClass.LOCAL, SafetyClass.PASSIVE} and action.network_requests:
            raise ValueError('Local/passive actions cannot declare active network requests')
        if action.safety == SafetyClass.SAFE_ACTIVE and action.network_requests < 1:
            raise ValueError('Active actions must reserve a network-request allowance')
        self._actions[action.action_id] = action

    def catalog(self):
        """JSON-safe descriptors for future AI adapters, with no implementation handles."""
        from dataclasses import fields
        return [{**{field.name: (getattr(action, field.name).value if field.name == 'safety' else getattr(action, field.name))
                    for field in fields(action) if field.name != 'handler'},
                 'implemented': action.handler is not None} for action in self]

    def get(self, action_id):
        return self._actions.get(action_id)

    def __iter__(self):
        return iter(sorted(self._actions.values(), key=lambda a: a.action_id))


def identity_registry(probes=None):
    from ..analysis.identity_probes import probe_netbios_identity, probe_rdp_identity
    from ..analysis.rpc_identity import probe_rpc_identity
    available = {'netbios_identity': probe_netbios_identity, 'rdp_identity': probe_rdp_identity,
                 'rpc_identity': probe_rpc_identity} if probes is None else dict(probes)

    def handler(name):
        probe = available.get(name)
        if probe is None:
            return None
        return lambda context: probe(context.host, port=context.port, timeout=context.timeout)

    registry = ActionRegistry((
        ActionDefinition('netbios_identity', 'Read one IPv4 NetBIOS node-status response.', 'host_identity',
                         ('hostname', 'netbios_name', 'workgroup', 'mac_address'), ('netbios',), handler('netbios_identity'),
                         services=('smb', 'microsoft-ds', 'netbios-ssn'), fallback_ports=(139, 445),
                         transport='udp', ip_versions=(4,), target_port=137, information_value=3, network_requests=1),
        ActionDefinition('rdp_identity', 'Read a CredSSP NTLM challenge; stop before authentication.', 'host_identity',
                         ('hostname', 'netbios_name', 'dns_name', 'netbios_domain', 'dns_domain', 'os_version',
                          'operating_system', 'candidate_cpe', 'ntlm_target_name', 'tls_certificate_identity'),
                         ('rdp_ntlm', 'tls_certificate'), handler('rdp_identity'),
                         services=('rdp', 'ms-wbt-server'), fallback_ports=(3389,), information_value=2,
                         cost=3, network_requests=4, noise=2,
                         source_outputs=tuple((name, ('rdp_ntlm',)) for name in
                                              ('netbios_name', 'dns_name', 'netbios_domain', 'dns_domain', 'os_version',
                                               'operating_system', 'candidate_cpe', 'ntlm_target_name')) +
                                        (('tls_certificate_identity', ('tls_certificate',)),)),
        ActionDefinition('rpc_identity', 'Read one endpoint-mapper page of at most eight entries.', 'service_enumeration',
                         ('rpc_interface', 'rpc_annotation', 'confirmed_service'), ('rpc',), handler('rpc_identity'),
                         services=('msrpc',), fallback_ports=(135,), information_value=2,
                         cost=3, network_requests=3, noise=2),
    ))
    from ..acquisition.registry import register_acquisition
    register_acquisition(registry)
    return registry
