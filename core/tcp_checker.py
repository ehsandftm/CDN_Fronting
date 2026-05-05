# ════════════════════════════════════════════════════════════
# core/tcp_checker.py
# Network Probe Layer with Built-in Retry Mechanism
# ════════════════════════════════════════════════════════════

import ssl
import socket
import time
import concurrent.futures
from core import TCP_TIMEOUT, MAX_RETRIES, MAX_WORKERS


def tcp_tls_probe(ip: str, port: int, sni: str) -> dict:
    """
    TCP connect + TLS handshake with SNI.
    Includes a retry loop to combat random packet drops in heavily filtered networks.
    """
    last_error = ""
    
    # Retry Loop: If connection fails, try again up to MAX_RETRIES
    for attempt in range(MAX_RETRIES):
        start = time.perf_counter()
        try:
            # Setup SSL context (bypass certificate validation for CDN IPs)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            # Step A: TCP connect
            raw_sock = socket.create_connection((ip, port), timeout=TCP_TIMEOUT)

            # Step B: TLS handshake
            tls_sock = ctx.wrap_socket(
                raw_sock,
                server_hostname=sni,
                do_handshake_on_connect=True,
            )

            latency_ms = (time.perf_counter() - start) * 1000
            tls_sock.close()

            return {
                "ok":         True,
                "latency_ms": round(latency_ms, 1),
                "error":      "",
            }

        except Exception as e:
            last_error = str(e)
            # Sleep briefly before the next retry to let the network breathe
            time.sleep(0.5)
            continue

    # If all retries fail, then the IP is truly blocked/dead
    return _fail(f"Failed after {MAX_RETRIES} retries. Last error: {last_error}")


def _tcp_only(ip: str, port: int) -> dict:
    """
    TCP connect only (no TLS). Used when no SNI is provided.
    Also includes retry logic.
    """
    last_error = ""
    for attempt in range(MAX_RETRIES):
        start = time.perf_counter()
        try:
            sock = socket.create_connection((ip, port), timeout=TCP_TIMEOUT)
            latency_ms = (time.perf_counter() - start) * 1000
            sock.close()
            return {"ok": True, "latency_ms": round(latency_ms, 1), "error": ""}
        except Exception as e:
            last_error = str(e)
            time.sleep(0.5)
            continue

    return _fail(f"Failed after {MAX_RETRIES} retries. Last error: {last_error}")


def _fail(error: str) -> dict:
    return {
        "ok":         False,
        "latency_ms": None,
        "error":      error,
    }


def tcp_ping(item, port: int = 443, sni: str = "") -> dict:
    """Standardized entry point for pinging a single item."""
    if isinstance(item, str):
        item = {"value": item, "type": "ip"}
    elif not isinstance(item, dict):
        ip_str = str(item)
        return {
            "value": ip_str, "ip": ip_str, "type": "ip",
            "tcp_ok": False, "ok": False,
            "latency_ms": 0.0, "error": "invalid item type"
        }

    ip = item.get("value", "") or item.get("ip", "")

    if not ip:
        return {
            **item, "value": "", "ip": "",
            "tcp_ok": False, "ok": False,
            "latency_ms": 0.0, "error": "empty ip"
        }

    if sni:
        result = tcp_tls_probe(ip, port, sni)
    else:
        result = _tcp_only(ip, port)

    ok         = result["ok"]
    latency_ms = result["latency_ms"] or 0.0
    error      = result["error"]

    return {
        **item,
        "value":      ip,
        "tcp_ok":     ok,
        "ip":         ip,
        "ok":         ok,
        "latency_ms": latency_ms,
        "error":      error,
    }


def tcp_ping_batch(items: list, port: int = 443, sni: str = "", max_workers: int = MAX_WORKERS) -> list:
    """Pings a list of items concurrently."""
    if not items:
        return []

    workers = min(max_workers, len(items))
    results = [None] * len(items)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_idx = {
            executor.submit(tcp_ping, item, port, sni): idx
            for idx, item in enumerate(items)
        }

        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                raw_item = items[idx]
                base_ip = raw_item.get("value", "") if isinstance(raw_item, dict) else str(raw_item)
                results[idx] = {
                    "value": base_ip, "ip": base_ip, "type": "ip",
                    "tcp_ok": False, "ok": False,
                    "latency_ms": 0.0, "error": f"thread error: {e}"
                }

    return results
