# core/config_builder.py
# Build the output vless:// link with mode-aware address/SNI/alias.

from urllib.parse import urlencode, quote


def build_vless_link(
    parsed:      dict,
    connect_to:  str,
    sni_override: str   = "",
    mode:        str    = "mode2",
    latency_ms:  float  = None,
) -> str:
    """
    Build a new vless:// link after scanning.

    Mode 1 (Netlify/Vercel — domain-based):
        address → connect_to  (the CDN domain being tested, e.g. "a16z.com")
        sni     → connect_to  (same as address — CDN domain)
        host    → parsed host (user's FIXED unique subdomain, e.g. "notfyfrz.gtgp.space")
        alias   → "a16z.com-45ms"

    Mode 2 (CF/CloudFront — IP-based):
        address → connect_to      (the target IP, e.g. "13.224.47.1")
        sni     → parsed host     (FIXED from template — same as host)
        host    → parsed host     (FIXED from template)
        alias   → "CF-13.224.47.1-78ms"

    Args:
        parsed:       output of parse_vless() — all template fields
        connect_to:   IP (mode2) or domain (mode1) to use as address
        sni_override: SNI from the pipeline candidate (already mode-aware)
        mode:         "mode1" or "mode2"
        latency_ms:   measured latency; None = omit from alias (skip_xray mode)
    """

    uuid = parsed["uuid"]
    port = parsed.get("port", 443)

    # ── Determine correct SNI and host per mode ──────────────────────────────
    template_host = parsed.get("host") or parsed.get("sni") or parsed.get("address", "")

    if mode == "mode1":
        # SNI = the CDN domain (connect_to), host = fixed template host
        sni  = connect_to
        host = template_host
    else:
        # Mode 2: SNI = fixed template host (same as host), host = fixed template host
        sni  = template_host
        host = template_host

    # Allow explicit override only if there's a real reason (edge cases)
    if sni_override and sni_override not in (connect_to, template_host):
        sni = sni_override

    # ── Build query string params ─────────────────────────────────────────────
    params = {}

    # Required
    _add_if(params, "encryption",  parsed.get("encryption"))
    _add_if(params, "security",    parsed.get("security"))
    _add_if(params, "type",        parsed.get("type"))

    # TLS / transport
    _add_if(params, "host",        host)   # always the fixed template host
    _add_if(params, "path",        parsed.get("path"))
    _add_if(params, "sni",         sni)    # mode-aware
    _add_if(params, "fp",          parsed.get("fp"))
    _add_if(params, "alpn",        parsed.get("alpn"))
    _add_if(params, "flow",        parsed.get("flow"))

    # Reality
    _add_if(params, "pbk",         parsed.get("pbk"))
    _add_if(params, "sid",         parsed.get("sid"))
    _add_if(params, "spx",         parsed.get("spx"))

    # gRPC
    _add_if(params, "serviceName", parsed.get("serviceName"))
    _add_if(params, "authority",   parsed.get("authority"))

    if parsed.get("allowInsecure") == "1":
        params["allowInsecure"] = "1"

    query = urlencode(params, quote_via=quote)

    # ── Mode-aware alias ──────────────────────────────────────────────────────
    lat_str = f"-{int(round(latency_ms))}ms" if latency_ms is not None else ""

    if mode == "mode1":
        raw_alias = f"{connect_to}{lat_str}"
    else:
        raw_alias = f"CF-{connect_to}{lat_str}"

    alias = quote(raw_alias, safe="")

    return f"vless://{uuid}@{connect_to}:{port}?{query}#{alias}"


def _add_if(d: dict, key: str, value):
    """Add key only when value is non-empty."""
    if value is not None and value != "":
        d[key] = value
