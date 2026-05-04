# CDN Scanner - Template Parser
# Parses a vless:// link into a structured dictionary

import re
from urllib.parse import urlparse, parse_qs, unquote


def parse_vless(link: str) -> dict:
    """
    Parse a vless:// link and return all fields as a dict.
    Returns None if the link is invalid.
    """

    link = link.strip()

    # Basic validation
    if not link.startswith("vless://"):
        return None

    try:
        # Split alias from the end: vless://...#alias
        alias = ""
        if "#" in link:
            link, alias = link.rsplit("#", 1)
            alias = unquote(alias)

        # Parse the URL structure
        parsed = urlparse(link)

        uuid = parsed.username
        address = parsed.hostname
        port = parsed.port or 443

        # Parse all query parameters
        params = parse_qs(parsed.query, keep_blank_values=True)

        def get(key, default=""):
            val = params.get(key, [default])
            return val[0] if val else default

        result = {
            "alias":         alias,
            "uuid":          uuid,
            "address":       address,
            "port":          int(port),

            # TLS settings
            "security":      get("security", "tls"),
            "sni":           get("sni"),
            "fp":            get("fp"),
            "alpn":          get("alpn"),
            "insecure":      get("insecure", "0"),
            "allowInsecure": get("allowInsecure", "0"),
            "pbk":           get("pbk"),
            "sid":           get("sid"),
            "spx":           get("spx"),

            # Transport settings
            "type":          get("type", "tcp"),
            "host":          get("host"),
            "path":          get("path", "/"),
            "encryption":    get("encryption", "none"),
            "flow":          get("flow"),
            "ed":            get("ed"),

            # gRPC settings
            "serviceName":   get("serviceName"),
            "authority":     get("authority"),

            # Detected mode (set later by main logic)
            "mode":          None,
        }

        # Validate required fields
        if not result["uuid"] or not result["address"]:
            return None

        return result

    except Exception:
        return None


def build_preview(parsed: dict) -> dict:
    """
    Build a clean preview dict for display in the UI.
    Same as what v2rayN shows before connecting.
    """
    if not parsed:
        return {}

    return {
        "Alias":          parsed.get("alias", "-"),
        "Address":        parsed.get("address", "-"),
        "Port":           parsed.get("port", 443),
        "UUID":           parsed.get("uuid", "-"),
        "Encryption":     parsed.get("encryption", "none"),
        "Flow":           parsed.get("flow", "-"),
        "Transport":      parsed.get("type", "-"),
        "Host":           parsed.get("host", "-"),
        "Path":           parsed.get("path", "-"),
        "TLS":            parsed.get("security", "-"),
        "SNI":            parsed.get("sni", "-"),
        "Fingerprint":    parsed.get("fp", "-"),
        "ALPN":           parsed.get("alpn", "-"),
        "AllowInsecure":  parsed.get("allowInsecure", "0"),
    }