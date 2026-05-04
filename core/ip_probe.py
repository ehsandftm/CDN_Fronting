import httpx
from core.tcp_checker import tcp_tls_probe
from core import TCP_TIMEOUT, DOH_PROVIDERS


def probe(
    ip: str,
    sni: str,
    host: str,
    port: int = 443,
    custom_dns: str | None = None,
) -> dict:
    """
    Full Stage 1 + Stage 2 pipeline for one target.

    Args:
        ip:         target IP (from domain_parser or user input)
        sni:        SNI to use in TLS handshake
                    Mode 1 → target domain
                    Mode 2 → host from template
        host:       host header value (from template, fixed)
        port:       almost always 443
        custom_dns: optional user-provided DNS server IP (e.g. "8.8.8.8")

    Returns:
        {
            "ok":         True / False,
            "latency_ms": float or None,
            "ip_used":    str   - which IP actually worked (may differ from input)
            "error":      str
        }
    """

    # ─────────────────────────────────────────────────────────────
    # Stage 1: first attempt with the IP we already have
    # ─────────────────────────────────────────────────────────────
    result = tcp_tls_probe(ip=ip, port=port, sni=sni, timeout=TCP_TIMEOUT)

    if result["ok"]:
        # Stage 1 passed → no need for DNS fallback
        return {
            "ok":         True,
            "latency_ms": result["latency_ms"],
            "ip_used":    ip,
            "error":      "",
        }

    # ─────────────────────────────────────────────────────────────
    # Stage 2: DNS Fallback
    #
    # Why we do DNS fallback:
    #   The original IP might be blocked by ISP.
    #   But the domain might resolve to a different IP
    #   via a trusted DoH provider that ISP cannot intercept
    #   (because DoH runs on port 443 HTTPS).
    #
    # We resolve `host` (the real domain) not `sni`
    # because in Mode 2, sni == host (both from template).
    # In Mode 1, host is the origin domain we want to reach.
    # ─────────────────────────────────────────────────────────────
    fallback_ips = _dns_fallback(domain=host, custom_dns=custom_dns)

    if not fallback_ips:
        # All DNS resolvers failed
        return {
            "ok":         False,
            "latency_ms": None,
            "ip_used":    ip,
            "error":      f"stage1 failed + dns fallback empty | stage1_err: {result['error']}",
        }

    # ─────────────────────────────────────────────────────────────
    # Stage 1 retry with each new IP from DNS fallback
    #
    # Why loop over all IPs:
    #   DNS may return multiple A records.
    #   We try each one until one passes Stage 1.
    #   First success wins.
    # ─────────────────────────────────────────────────────────────
    for new_ip in fallback_ips:
        if new_ip == ip:
            # Skip the IP we already tried in Stage 1
            continue

        retry = tcp_tls_probe(ip=new_ip, port=port, sni=sni, timeout=TCP_TIMEOUT)

        if retry["ok"]:
            return {
                "ok":         True,
                "latency_ms": retry["latency_ms"],
                "ip_used":    new_ip,
                "error":      "",
            }

    # All fallback IPs also failed Stage 1
    return {
        "ok":         False,
        "latency_ms": None,
        "ip_used":    ip,
        "error":      f"all fallback IPs failed stage1 | stage1_err: {result['error']}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Internal: DNS Fallback resolver
# ─────────────────────────────────────────────────────────────────────────────

def _dns_fallback(domain: str, custom_dns: str | None) -> list[str]:
    """
    Try DNS resolvers in priority order:
      1. Custom DNS server (user-provided, optional)
      2. DOH_PROVIDERS from core/__init__.py (Quad9 → Google → CF)

    Returns list of IPv4 addresses, empty list if all fail.
    """

    all_ips: list[str] = []

    # ── Priority 1: Custom DNS (user-provided) ──────────────────
    if custom_dns:
        ips = _resolve_via_doh(
            domain=domain,
            provider=f"https://{custom_dns}/dns-query",
        )
        if ips:
            # Custom DNS worked → use it first, no need to try others
            return ips

    # ── Priority 2: Built-in DoH providers ──────────────────────
    # DOH_PROVIDERS = [Quad9, Google, CF] (defined in core/__init__.py)
    for provider in DOH_PROVIDERS:
        ips = _resolve_via_doh(domain=domain, provider=provider)
        if ips:
            all_ips.extend(ips)
            # First successful provider is enough
            # We collect its IPs and stop (avoid duplicate resolution)
            break

    return all_ips


def _resolve_via_doh(domain: str, provider: str) -> list[str]:
    """
    Single DoH query to one provider.

    Why httpx (not socket):
        DoH runs over HTTPS (port 443).
        socket cannot do HTTPS natively.
        httpx handles TLS + HTTP/2 automatically.

    Why port 443 matters:
        ISPs can block UDP port 53 (plain DNS).
        They cannot easily block port 443 without breaking all HTTPS.
        So DoH bypasses most ISP DNS censorship.
    """
    try:
        response = httpx.get(
            provider,
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=TCP_TIMEOUT,
            # We do NOT verify SSL here for the same reason as tcp_checker:
            # some custom DNS IPs may have cert issues
            verify=False,
        )

        if response.status_code != 200:
            return []

        data = response.json()
        ips: list[str] = []

        for answer in data.get("Answer", []):
            # type == 1 means A record (IPv4)
            if answer.get("type") == 1:
                ip_val = answer.get("data", "").strip()
                if ip_val:
                    ips.append(ip_val)

        return ips

    except Exception:
        return []