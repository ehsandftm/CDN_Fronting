# CDN Scanner - Domain Parser
import ipaddress
import re

def extract_targets(parsed: dict) -> list:
    targets = []
    seen = set()
    candidates = []
    if parsed.get("address"):
        candidates.append(parsed["address"])
    if parsed.get("host"):
        candidates.append(parsed["host"])
    if parsed.get("sni"):
        candidates.append(parsed["sni"])
    for c in candidates:
        c = c.strip()
        if not c or c in seen:
            continue
        seen.add(c)
        t = _classify(c)
        if t:
            if t["type"] == "cidr":
                targets.extend(_expand_cidr(c))
            else:
                targets.append(t)
    return targets

def _classify(value: str):
    try:
        ipaddress.ip_address(value)
        return {"value": value, "type": "ip"}
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return {"value": value, "type": "cidr"}
    except ValueError:
        pass
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
    if re.match(pattern, value):
        return {"value": value, "type": "domain"}
    return None

def _expand_cidr(cidr: str) -> list:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        ips = list(network.hosts())[:256]
        return [{"value": str(ip), "type": "ip"} for ip in ips]
    except Exception:
        return []
