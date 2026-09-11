QUICK_PORTS = [22, 80, 443, 3389, 8080, 8443]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]


def _parse_range(start: str, end: str) -> list[int]:
    try:
        start_value = int(start)
        end_value = int(end)
    except ValueError as exc:
        raise ValueError(f"Invalid port range: {start}-{end!r}.") from exc

    if not 1 <= start_value <= 65535 or not 1 <= end_value <= 65535:
        raise ValueError(f"Port values must be between 1 and 65535: {start}-{end!r}.")
    if start_value > end_value:
        raise ValueError(f"Invalid reversed port range: {start}-{end!r}.")
    return list(range(start_value, end_value + 1))


def parse_port_spec(spec: str) -> list[int]:
    """Parse a comma-separated string of ports and ranges into a deduplicated list."""
    if spec is None or not spec.strip():
        raise ValueError("No ports were provided. Use one or more port numbers or ranges.")

    ports: list[int] = []
    for item in spec.split(","):
        value = item.strip()
        if not value:
            raise ValueError("Port specification contains an empty value.")

        if "-" in value:
            parts = value.split("-", 1)
            if not parts[0] or not parts[1]:
                raise ValueError(f"Invalid port range: {value!r}.")
            ports.extend(_parse_range(parts[0], parts[1]))
            continue

        try:
            port_number = int(value)
        except ValueError as exc:
            raise ValueError(f"Invalid port number: {value!r}.") from exc

        if not 1 <= port_number <= 65535:
            raise ValueError(f"Port numbers must be between 1 and 65535: {value!r}.")
        ports.append(port_number)

    unique_ports = sorted(set(ports))
    if not unique_ports:
        raise ValueError("Port specification did not resolve to any valid ports.")
    return unique_ports


def resolve_ports(profile: str, port_spec: str | None = None) -> list[int]:
    """Resolve a profile name or explicit port list to a concrete port collection."""
    normalized = (profile or "quick").lower()

    if normalized == "quick":
        return list(QUICK_PORTS)
    if normalized == "common":
        return list(COMMON_PORTS)
    if normalized == "custom":
        if not port_spec:
            raise ValueError("The custom profile requires --ports to be provided.")
        return parse_port_spec(port_spec)
    if normalized == "full":
        if not port_spec:
            raise ValueError("The full scan requires explicit ports such as --ports 1-65535.")
        return parse_port_spec(port_spec)

    raise ValueError(f"Unknown scan profile: {profile!r}. Use quick, common, custom, or full.")
