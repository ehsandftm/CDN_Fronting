# ════════════════════════════════════════════════════════════
# core/__init__.py
# Global Configuration & Exports
# ════════════════════════════════════════════════════════════

VERSION  = "0.0.2"
APP_NAME = "CDN-Scanner"

MODE_NETLIFY    = "mode1"
MODE_CLOUDFRONT = "mode2"

DOH_PROVIDERS = [
    "https://149.112.112.112/dns-query",
    "https://8.8.8.8/dns-query",
    "https://1.1.1.1/dns-query",
]

# --- OPTIMIZATION: INCREASED TIMEOUTS & RETRIES FOR UNSTABLE NETWORKS ---
# Why? DPI filtering often drops initial TCP SYN packets randomly.
# Increased timeouts and retries prevent false negatives on healthy IPs.
TCP_TIMEOUT  = 5       # Increased from 3s to 5s
XRAY_TIMEOUT = 15      # Increased from 10s to 15s
MAX_RETRIES  = 3       # Number of times to retry a failed connection
XRAY_BINARY  = "xray.exe"
TCP_PORT     = 443
MAX_WORKERS  = 50
XRAY_BATCH_SIZE = 25   # Stage 3: Test candidates in batches for stability

from .template_parser import parse_vless
from .domain_parser   import extract_targets
from .dns_resolver    import resolve_domain, test_dns_servers, test_dns_servers_e2e
from .tcp_checker     import tcp_ping, tcp_ping_batch
from .config_builder  import build_vless_link
from .xray_validator  import validate_with_xray

check_tcp    = tcp_ping
build_config = build_vless_link

__all__ = [
    "VERSION", "APP_NAME",
    "MODE_NETLIFY", "MODE_CLOUDFRONT",
    "DOH_PROVIDERS",
    "TCP_TIMEOUT", "XRAY_TIMEOUT", "MAX_RETRIES",
    "XRAY_BINARY",
    "TCP_PORT", "MAX_WORKERS", "XRAY_BATCH_SIZE",
    "parse_vless",
    "extract_targets",
    "resolve_domain", "test_dns_servers", "test_dns_servers_e2e",
    "tcp_ping", "tcp_ping_batch", "check_tcp",
    "build_vless_link", "build_config",
    "validate_with_xray",
]
