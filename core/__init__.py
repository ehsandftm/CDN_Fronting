VERSION  = "1.0.0"
APP_NAME = "CDN-Scanner"

MODE_NETLIFY    = "mode1"
MODE_CLOUDFRONT = "mode2"

DOH_PROVIDERS = [
    "https://149.112.112.112/dns-query",
    "https://8.8.8.8/dns-query",
    "https://1.1.1.1/dns-query",
]

TCP_TIMEOUT  = 3
XRAY_TIMEOUT = 10
XRAY_BINARY  = "xray.exe"
TCP_PORT     = 443
MAX_WORKERS  = 50

from .template_parser import parse_vless
from .domain_parser   import extract_targets
from .dns_resolver    import resolve_domain
from .tcp_checker     import tcp_ping, tcp_ping_batch
from .config_builder  import build_vless_link
from .xray_validator  import validate_with_xray

check_tcp    = tcp_ping
build_config = build_vless_link

__all__ = [
    "VERSION", "APP_NAME",
    "MODE_NETLIFY", "MODE_CLOUDFRONT",
    "DOH_PROVIDERS",
    "TCP_TIMEOUT", "XRAY_TIMEOUT",
    "XRAY_BINARY",
    "TCP_PORT", "MAX_WORKERS",
    "parse_vless",
    "extract_targets",
    "resolve_domain",
    "tcp_ping", "tcp_ping_batch", "check_tcp",
    "build_vless_link", "build_config",
    "validate_with_xray",
]
