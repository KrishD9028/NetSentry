"""Route acquired software through the existing strict correlation boundary."""
from ..analysis.correlation import bind_correlation


def correlate_acquired(acquired, all_software, provider):
    matches, diagnostics = [], []
    for item in acquired:
        versions = {other['version'] for other in all_software if other['product'].casefold() == item.product.casefold()
                    and other.get('port') == item.port and other.get('version') is not None}
        context = {'host': item.host, 'port': item.port, 'product': item.product, 'source': item.source}
        if len(versions) > 1:
            diagnostics.append({**context, 'status': 'INDETERMINATE', 'reason': 'Conflicting observed versions; automatic correlation withheld.'})
            continue
        if provider is None:
            continue
        if hasattr(provider, 'evaluate'):
            candidates, reasons = provider.evaluate(item)
            diagnostics.extend({**context, **reason} for reason in reasons)
        else:
            candidates = provider.correlate(item)
        for candidate in candidates:
            bound = bind_correlation(candidate, item)
            if bound is not None:
                matches.append(bound.to_dict())
    return matches, diagnostics
