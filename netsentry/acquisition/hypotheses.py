"""Explicit OS hypotheses: supporting records are not independent OS proofs."""
from ..analysis.host_evidence import observation


def refresh_hypotheses(evidence):
    evidence.observations[:] = [o for o in evidence.observations if o.probe != 'os_hypothesis']
    candidates = []
    for item in evidence.observations:
        family = None
        if item.attribute == 'software_banner':
            if item.value.startswith('SSH-') and 'OpenSSH_for_Windows_' in item.value:
                family = 'Microsoft Windows'
            elif item.value.startswith('SSH-') and ('Ubuntu' in item.value or 'Debian' in item.value):
                family = 'Linux'
            elif item.value.startswith('Microsoft-IIS/'):
                family = 'Microsoft Windows'
        elif item.attribute == 'reported_os_family':
            family = item.value
        if family:
            candidates.append((family, (item,)))
    netbios = [o for o in evidence.observations if o.probe == 'netbios_identity' and o.attribute == 'netbios_name']
    rpc = [o for o in evidence.observations if o.attribute == 'rpc_interface']
    smb = [o for o in evidence.observations if o.attribute == 'protocol_version' and o.value.startswith('SMB ')]
    if smb and netbios and rpc:
        candidates.append(('Microsoft Windows', (smb[0], netbios[0], rpc[0])))
    for family, support in candidates:
        other = tuple(o.value for o in evidence.observations if o.attribute == 'operating_system' and o.value != family)
        other += tuple(name for name, _ in candidates if name != family)
        source = support[0].independence_key if len(support) == 1 else 'protocol_hypothesis'
        evidence.add(observation('operating_system', family, 'OS hypothesis from reported metadata; compatibility/emulation possible',
                                 'os_hypothesis', source, support[0].endpoint, hypothesis=True,
                                 support=tuple(f'{o.probe} {o.endpoint}: {o.value}' for o in support),
                                 contradictions=tuple(sorted(set(other))),
                                 limitations='Circumstantial/self-reported evidence; does not establish edition, build or patch state.'))
