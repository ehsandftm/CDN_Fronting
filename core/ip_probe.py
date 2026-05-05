# ════════════════════════════════════════════════════════════
# core/ip_probe.py
# Stage 1 + Stage 2 Pipeline with Smart Routing
# ════════════════════════════════════════════════════════════

import httpx
from core.tcp_checker import tcp_tls_probe
from core import TCP_TIMEOUT, DOH_PROVIDERS


def probe(
    ip: str,
    sni: str,
    host: str,
    port: int = 443,
    custom_dns: str | None = None,
    force_custom_dns: bool = False,
    is_domain: bool = False,
) -> dict:
    """
    Full Stage 1 + Stage 2 pipeline for one target.
    Includes Smart Routing to bypass ISP poisoning timeouts.
    """

    # ── SMART ROUTING (Bypass Poisoning) ─────────────────────────────
    # If the user forced custom DNS and the target is a domain,
    # we completely skip Stage 1 (OS DNS IP) to avoid timeouts
    # on poisoned IPs. We jump straight to Stage 2 (DoH).
    if force_custom_dns and is_domain:
        return _stage_2_dns_fallback(
            original_ip=ip,
            domain=host,
            sni=sni,
            port=port,
            custom_dns=custom_dns,
            bypassed_stage1=True,
        )

    # ── STAGE 1: First attempt with the provided IP ──────────────────
    result = tcp_tls_probe(ip=ip, port=port, sni=sni)

    if result["ok"]:
        return {
            "ok":         True,
            "latency_ms": result["latency_ms"],
            "ip_used":    ip,
            "error":      "",
        }

    # If target is an IP (Mode 2), DNS fallback makes no sense. Stop here.
    if not is_domain:
        return {
            "ok":         False,
            "latency_ms": None,
            "ip_used":    ip,
            "error":      f"stage1 failed (direct IP, no fallback) | {result['error']}",
        }

    # ── STAGE 2: DNS Fallback (DoH) ──────────────────────────────────
    return _stage_2_dns_fallback(
        original_ip=ip,
        domain=host,
        sni=sni,
        port=port,
        custom_dns=custom_dns,
        bypassed_stage1=False,
        stage1_error=result["error"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Internal Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _stage_2_dns_fallback(
    original_ip: str,
    domain: str,
    sni: str,
    port: int,
    custom_dns: str | None,
    bypassed_stage1: bool,
    stage1_error: str = "",
) -> dict:
    """Executes DNS over HTTPS fallback and tests the new IPs."""
    
    fallback_ips = _dns_fallback(domain=domain, custom_dns=custom_dns)

    if not fallback_ips:
        reason = "bypassed" if bypassed_stage1 else f"stage1_err: {stage1_error}"
        return {
            "ok":         False,
            "latency_ms": None,
            "ip_used":    original_ip,
            "error":      f"dns fallback empty | {reason}",
        }

    for new_ip in fallback_ips:
        # Don't re-test the poisoned IP if we didn't bypass stage 1
        if new_ip == original_ip and not bypassed_stage1:
            continue

        retry = tcp_tls_probe(ip=new_ip, port=port, sni=sni)

        if retry["ok"]:
            return {
                "ok":         True,
                "latency_ms": retry["latency_ms"],
                "ip_used":    new_ip,
                "error":      "",
            }

    reason = "bypassed" if bypassed_stage1 else f"stage1_err: {stage1_error}"
    return {
        "ok":         False,
        "latency_ms": None,
        "ip_used":    original_ip,
        "error":      f"all fallback IPs failed | {reason}",
    }


def _dns_fallback(domain: str, custom_dns: str | None) -> list[str]:
    """Try Custom DNS first, then built-in DoH providers."""
    all_ips: list[str] = []

    if custom_dns:
        ips = _resolve_via_doh(domain=domain, provider=f"https://{custom_dns}/dns-query")
        if ips:
            return ips

    for provider in DOH_PROVIDERS:
        ips = _resolve_via_doh(domain=domain, provider=provider)
        if ips:
            all_ips.extend(ips)
            break

    return all_ips


def _resolve_via_doh(domain: str, provider: str) -> list[str]:
    """Single DoH query to one provider."""
    try:
        response = httpx.get(
            provider,
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=TCP_TIMEOUT,
            verify=False,
        )

        if response.status_code != 200:
            return []

        data = response.json()
        ips: list[str] = []

        for answer in data.get("Answer", []):
            if answer.get("type") == 1:
                ip_val = answer.get("data", "").strip()
                if ip_val:
                    ips.append(ip_val)

        return ips
    except Exception:
        return []
