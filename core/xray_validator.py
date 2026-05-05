# core/xray_validator.py
# Stage 3: Validate a working candidate using xray as a real tunnel.
#
# Pipeline:
#   1. Build a temporary xray config JSON (mode-aware)
#   2. Launch xray.exe as a background subprocess
#   3. Wait for xray SOCKS5 port to open
#   4. Send HTTP GET through xray SOCKS5 proxy
#   5. Return result + latency

import os
import json
import time
import socket
import subprocess
import tempfile
import httpx
from urllib.parse import unquote
from core import XRAY_TIMEOUT, XRAY_BINARY

# Base SOCKS5 port — each worker gets a unique port:
# worker 0 → 10800, worker 1 → 10801, etc.
_BASE_PORT = 10800

_DEBUG = False

# Any HTTP response from the server means the tunnel works.
# Only timeout, connection error, and 5xx are real failures.
_VALID_STATUS_CODES = {200, 204, 301, 302, 403, 404}


def _wait_for_port(port: int, timeout: float = 3.0) -> bool:
    """Poll until xray opens its SOCKS5 port (100 ms interval)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return False


def validate_with_xray(
    parsed_config: dict,
    candidate:     dict,
    port:          int,
    worker_id:     int  = 0,
    test_url:      str  = "https://www.gstatic.com/generate_204",
    quick_test:    bool = False,   # False = full HTTP test (more reliable), True = SOCKS5 only (faster but unreliable)
) -> dict:
    """
    Validate a candidate through a real xray tunnel.

    Args:
        parsed_config: output of parse_vless() — original template fields
        candidate:     pipeline candidate dict:
                         connect_to    — IP (mode2) or domain (mode1) to connect to
                         sni           — TLS serverName (mode-aware from pipeline)
                         mode          — "mode1" or "mode2"
                         source_domain — original CDN domain or None
        port:          server port (usually 443)
        worker_id:     unique index → unique local SOCKS5 port (no port conflicts)
        test_url:      URL to GET through the tunnel to confirm it works

    Returns:
        { connect_to, sni, mode, ok, latency_ms, error }
    """
    connect_to = candidate["connect_to"]
    sni        = candidate.get("sni", "")
    mode       = candidate.get("mode", "mode2")
    local_port = _BASE_PORT + worker_id

    config   = _build_xray_config(parsed_config, candidate, port, local_port)
    tmp_file = None
    xray_proc = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
            tmp_file = f.name

        if _DEBUG:
            print(f"\n[DEBUG] {mode} | {connect_to}:{port} → SOCKS5:{local_port} | SNI={sni}")
            with open(tmp_file, encoding="utf-8") as dbg:
                print(f"[DEBUG] Config:\n{dbg.read()}")

        # Locate xray.exe — absolute path relative to project root
        base_dir  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        xray_path = os.path.join(base_dir, "xray", XRAY_BINARY)
        if not os.path.exists(xray_path):
            return _fail(connect_to, sni, mode, f"xray.exe not found at: {xray_path}", candidate.get("source_domain"))

        popen_kwargs = dict(
            stdout=subprocess.PIPE if _DEBUG else subprocess.DEVNULL,
            stderr=subprocess.PIPE if _DEBUG else subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        xray_proc = subprocess.Popen(
            [xray_path, "run", "-c", tmp_file], **popen_kwargs
        )

        if not _wait_for_port(local_port, timeout=3.0):
            return _fail(connect_to, sni, mode, "xray failed to open SOCKS5 port", candidate.get("source_domain"))

        if xray_proc.poll() is not None:
            return _fail(connect_to, sni, mode, f"xray crashed (exit={xray_proc.poll()})", candidate.get("source_domain"))

        start = time.perf_counter()

        if quick_test:
            # Quick test — match v2rayN's "Real delay" measurement
            # Just test SOCKS5 connect through tunnel (no full HTTP GET)
            result = _test_socks5_connect(local_port, XRAY_TIMEOUT)
        else:
            # Full test — complete HTTP GET through tunnel
            result = _test_via_socks5("127.0.0.1", local_port, test_url, XRAY_TIMEOUT)

        elapsed_ms = (time.perf_counter() - start) * 1000

        if result["ok"]:
            return {
                "connect_to":    connect_to,
                "sni":           sni,
                "mode":          mode,
                "ok":            True,
                "latency_ms":    round(elapsed_ms, 1),
                "error":         "",
                "source_domain": candidate.get("source_domain"),  # Pass through for Mode 1
            }
        return _fail(connect_to, sni, mode, result["error"], candidate.get("source_domain"))

    except Exception as e:
        return _fail(connect_to, sni, mode, str(e), candidate.get("source_domain"))

    finally:
        if xray_proc:
            try:
                xray_proc.kill()
                xray_proc.wait(timeout=3)
            except Exception:
                pass
        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except Exception:
                pass


def _test_via_socks5(
    socks_host: str,
    socks_port: int,
    test_url:   str,
    timeout:    float,
) -> dict:
    """Send HTTP GET through the xray SOCKS5 proxy to confirm tunnel works."""
    try:
        proxy_url = f"socks5://127.0.0.1:{socks_port}"
        with httpx.Client(
            mounts={"all://": httpx.HTTPTransport(proxy=httpx.Proxy(proxy_url))},
            timeout=timeout,
            follow_redirects=False,
            verify=False,
        ) as client:
            response = client.get(test_url)

        status = response.status_code

        if status in _VALID_STATUS_CODES:
            return {"ok": True, "error": ""}
        elif 500 <= status < 600:
            return {"ok": False, "error": f"server error: HTTP {status}"}
        else:
            # Any other status (429, 407, etc.) still means tunnel is alive
            return {"ok": True, "error": ""}

    except httpx.TimeoutException:
        return {"ok": False, "error": "timeout"}
    except httpx.ProxyError as e:
        return {"ok": False, "error": f"proxy error: {e}"}
    except httpx.ConnectError as e:
        return {"ok": False, "error": f"connect error: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _test_socks5_connect(
    socks_port: int,
    timeout:    float,
) -> dict:
    """
    Quick test — match v2rayN's "Real delay" measurement.
    Just establishes a SOCKS5 connection through the tunnel to google.com:80.
    Does NOT perform full HTTP GET (much faster, matches v2rayN).

    This is what v2rayN does for "Real delay test":
    - Connect to SOCKS5 proxy
    - Send SOCKS5 handshake
    - Connect to remote host (google.com:80) through tunnel
    - Measure round-trip time
    - Close connection
    """
    import socket
    import struct

    try:
        # Create socket and connect to SOCKS5 proxy
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(('127.0.0.1', socks_port))

        # SOCKS5 handshake: no authentication
        s.sendall(b'\x05\x01\x00')
        resp = s.recv(2)
        if len(resp) != 2 or resp[0] != 5:
            s.close()
            return {"ok": False, "error": "SOCKS5 handshake failed"}

        # Connect to google.com:80 through SOCKS5
        # Format: VER CMD RSV ATYP DST.ADDR DST.PORT
        #         0x05 0x01 0x00 0x03 domain_len domain port
        target_domain = b'www.google.com'
        target_port = 80

        request = (
            b'\x05\x01\x00\x03' +                      # SOCKS5 connect to domain
            bytes([len(target_domain)]) +              # domain length
            target_domain +                             # domain
            struct.pack('>H', target_port)              # port (big-endian)
        )
        s.sendall(request)

        # Wait for SOCKS5 response (connection established)
        resp = s.recv(10)
        if len(resp) < 4 or resp[1] != 0:
            s.close()
            return {"ok": False, "error": "SOCKS5 connect failed"}

        # Success! Connection through tunnel established
        s.close()
        return {"ok": True, "error": ""}

    except socket.timeout:
        return {"ok": False, "error": "timeout"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "connection refused"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _fail(connect_to: str, sni: str, mode: str, error: str, source_domain: str = None) -> dict:
    return {
        "connect_to":    connect_to,
        "sni":           sni,
        "mode":          mode,
        "ok":            False,
        "latency_ms":    None,
        "error":         error,
        "source_domain": source_domain,
    }


def _build_xray_config(
    parsed:     dict,
    candidate:  dict,
    port:       int,
    local_port: int,
) -> dict:
    """
    Build a complete xray JSON config for this candidate.

    Two values that change per candidate:
      connect_to    — what xray connects to (IP for mode2, domain for mode1)
      sni           — TLS serverName (mode-aware, comes from pipeline candidate)

    One value that is always fixed from the template:
      template_host — the transport Host header (ws/xhttp/h2)
                      This is the user's unique subdomain (e.g. "notfyfrz.gtgp.space")
                      and NEVER changes regardless of which CDN target we're testing.
    """
    connect_to    = candidate["connect_to"]
    sni           = candidate.get("sni", "")

    # template_host: the fixed routing subdomain from the original vless link.
    # Prefer "host" field; fall back to "sni" if host is absent (unusual links).
    template_host = parsed.get("host") or parsed.get("sni") or ""

    if _DEBUG:
        print(f"[DEBUG] config | mode={candidate.get('mode')} | "
              f"connect_to={connect_to} | sni={sni} | template_host={template_host}")

    config = {
        "log": {"loglevel": "warning" if _DEBUG else "none"},

        "inbounds": [{
            "port":     local_port,
            "listen":   "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False, "userLevel": 0},
        }],

        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": connect_to,    # IP (mode2) or CDN domain (mode1)
                    "port":    port,
                    "users": [{
                        "id":         parsed["uuid"],
                        "encryption": parsed.get("encryption", "none"),
                        "flow":       parsed.get("flow", ""),
                    }],
                }],
            },
            "streamSettings": _build_stream_settings(parsed, sni, template_host),
        }],
    }

    return config


def _build_stream_settings(parsed: dict, sni: str, template_host: str) -> dict:
    """
    Build xray streamSettings with explicit separation of two concerns:

      sni           → TLS/Reality serverName only
                      Mode 1: CDN domain  (e.g. "a16z.com")
                      Mode 2: template host (e.g. "notfyfrz.gtgp.space")

      template_host → transport Host header (ws/xhttp/h2/grpc)
                      ALWAYS the user's fixed unique subdomain.
                      Never the CDN domain, never the target IP.

    Transport types supported: ws, xhttp, http/h2, grpc, tcp
    Security types supported:  tls, reality, none
    """
    transport_type = parsed.get("type", "tcp")
    security       = parsed.get("security", "tls")

    # ALPN — fully URL-decode before splitting.
    # parse_qs usually decodes the value already, but links copied from
    # some clients may still contain %2C (comma) or %2F (slash).
    raw_alpn = parsed.get("alpn", "")
    if isinstance(raw_alpn, str) and raw_alpn:
        alpn_list = [
            a.strip()
            for a in unquote(raw_alpn).split(",")
            if a.strip()
        ]
    elif isinstance(raw_alpn, list):
        alpn_list = raw_alpn
    else:
        alpn_list = ["h2", "http/1.1"]

    stream = {"network": transport_type, "security": security}

    # ── TLS ───────────────────────────────────────────────────────────────────
    if security == "tls":
        allow_insecure = (
            str(parsed.get("allowInsecure", "0")) == "1"
            or str(parsed.get("insecure",     "0")) == "1"
        )
        stream["tlsSettings"] = {
            "serverName":    sni,                        # mode-aware
            "fingerprint":   parsed.get("fp", "chrome"),
            "allowInsecure": allow_insecure,
            "alpn":          alpn_list,
        }

    # ── Reality ───────────────────────────────────────────────────────────────
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName":  sni,                          # mode-aware
            "fingerprint": parsed.get("fp", "chrome"),
            "publicKey":   parsed.get("pbk",  ""),
            "shortId":     parsed.get("sid",  ""),
            "spiderX":     parsed.get("spx",  "/"),
        }

    # ── Transport — Host header is ALWAYS template_host ───────────────────────
    #
    # Why never sni here?
    #   Mode 1: sni = CDN domain ("a16z.com") — CDN routes by Host, not by SNI.
    #           If Host = CDN domain, CDN won't know which user subdomain to route to.
    #   Mode 2: sni = template_host, so they happen to be equal anyway.
    #
    # template_host is the user's unique subdomain that the CDN uses for routing.

    if transport_type == "ws":
        stream["wsSettings"] = {
            "path":    parsed.get("path", "/"),
            "headers": {"Host": template_host},
        }

    elif transport_type == "xhttp":
        stream["xhttpSettings"] = {
            "path": parsed.get("path", "/"),
            "host": template_host,
            # xhttp transport mode (stream-up / packet-up / auto).
            # Distinct from app "mode1/mode2". Default "auto" is safe.
            "mode": "auto",
        }

    elif transport_type in ("http", "h2"):
        stream["httpSettings"] = {
            "path": parsed.get("path", "/"),
            "host": [template_host],   # xray requires a list here
        }

    elif transport_type == "grpc":
        stream["grpcSettings"] = {
            "serviceName": parsed.get("serviceName", ""),
            "authority":   parsed.get("authority",   ""),
        }

    # tcp: no extra transport settings needed

    return stream
