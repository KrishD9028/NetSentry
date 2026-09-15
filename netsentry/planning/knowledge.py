"""A disposable view of assessment and HostEvidence, not a second fact store."""
from dataclasses import dataclass

from ..analysis.host_evidence import ATTRIBUTES
from .models import Goal

IMPORTANCE = {'operating_system': 8, 'hostname': 5, 'os_version': 7,
              'dns_name': 3, 'netbios_name': 3, 'dns_domain': 3,
              'netbios_domain': 3, 'workgroup': 2, 'mac_address': 2,
              'mac_vendor': 1, 'os_edition': 2, 'candidate_cpe': 2}


@dataclass(frozen=True)
class KnowledgeState:
    host: str
    facts: dict
    probable: dict
    contradictory: dict
    goals: tuple[Goal, ...]
    endpoints: tuple[dict, ...]
    software: tuple[dict, ...]
    potential_cves: tuple[dict, ...]
    observations: tuple[dict, ...]
    attempts: tuple[dict, ...]
    budget: dict

    @classmethod
    def derive(cls, assessment, evidence, budget):
        resolved = {name: evidence.resolve(name) for name in ATTRIBUTES}
        goals = []
        for name, result in resolved.items():
            if result['state'] != 'CONFIRMED':
                goals.append(Goal(name, name, result['state'], IMPORTANCE[name],
                                  'Host identity informs subsequent assessment; evidence is not yet confirmed.',
                                  sources=tuple(sorted({o['independence_key'] for o in result['observations']}))))
        endpoints = tuple({'port': item.port, 'transport': item.protocol, 'state': item.state,
                           'service': item.service if item.identification_status == 'CONFIRMED' else None,
                           'hint': item.service_hint,
                           'protocols': tuple(i['protocol'] for i in item.identities)} for item in assessment.observations)
        for item in endpoints:
            # A successful follow-up may demonstrate a service without changing
            # assessment dispatch/state. Reflect that evidence in this derived view.
            endpoint = f"{assessment.host}:{item['port']}/{item['transport']}"
            demonstrated = [o.value for o in evidence.observations if o.attribute == 'confirmed_service'
                            and o.endpoint == endpoint and not o.hypothesis]
            if item['state'] == 'open' and item['service'] is None and demonstrated:
                item['service'] = demonstrated[0] if len(set(demonstrated)) == 1 else None
            if item['state'] != 'open':
                continue
            if not item['service']:
                goals.append(Goal(f"service:{item['transport']}:{item['port']}", 'confirmed_service', 'UNRESOLVED', 8,
                                  'An unknown open service limits security-check applicability.', item['port']))
            if item['service'] and not any(s.get('port') == item['port'] for s in assessment.software_evidence):
                goals.append(Goal(f"product:{item['port']}", 'software_product', 'UNRESOLVED', 5,
                                  'Product evidence enables targeted version enumeration.', item['port']))
            if item['service'] == 'msrpc'  or item['hint'] == 'msrpc':
                if not any(o.attribute == 'rpc_interface' and o.endpoint == f"{assessment.host}:{item['port']}/tcp" for o in evidence.observations):
                    goals.append(Goal(f"rpc:{item['port']}", 'rpc_interface', 'UNRESOLVED', 1,
                                      'RPC interface inventory is useful metadata, not OS identity.', item['port']))
        software = tuple(dict(item) for item in assessment.software_evidence)
        for item in software:
            if not item.get('version'):
                cve_needs_version = any(c.get('product') == item['product'] for c in assessment.potential_correlations)
                goals.append(Goal(f"version:{item.get('port')}:{item['product']}", 'software_version', 'UNRESOLVED',
                                  10 if cve_needs_version else 7,
                                  'Product version is required for CVE applicability.' if cve_needs_version else 'Version evidence enables applicability decisions.',
                                  item.get('port'), item['product']))
        groups = {}
        for item in software:
            groups.setdefault((item.get('port'), item['product']), set()).update([item['version']] if item.get('version') else [])
        for (port, product), versions in groups.items():
            if len(versions) > 1:
                goals.append(Goal(f'version-conflict:{port}:{product}', 'software_version', 'CONTRADICTORY', 9,
                                  'Conflicting software versions prevent reliable applicability decisions.', port, product))
        return cls(assessment.host,
                   {n: r for n, r in resolved.items() if r['state'] == 'CONFIRMED'},
                   {n: r for n, r in resolved.items() if r['state'] == 'PROBABLE'},
                   {n: r for n, r in resolved.items() if r['state'] == 'CONTRADICTORY'},
                   tuple(sorted(goals, key=lambda g: g.goal_id)), endpoints, software,
                   tuple(assessment.potential_correlations), tuple(o.to_dict() for o in evidence.observations),
                   tuple(dict(a) for a in evidence.attempts), budget.snapshot())

    def to_dict(self):
        from dataclasses import asdict
        data = asdict(self)
        data['completed_actions'] = [a for a in self.attempts if a.get('status', '').upper() == 'COMPLETED']
        data['failed_or_inconclusive_actions'] = [a for a in self.attempts if a.get('status', '').upper() in {'FAILED', 'INCONCLUSIVE', 'INVALID_RESULT'}]
        data['unavailable_actions'] = [a for a in self.attempts if a.get('status', '').upper() in {'UNAVAILABLE', 'UNSUPPORTED'}]
        return data
