# core/dns_resolver.py
# Stage 2 DNS Fallback
# Try order: custom DNS → system DNS → DoH providers

import socket
import httpx
import time
import random
import concurrent.futures
from core import DOH_PROVIDERS, TCP_TIMEOUT


# Known domains with their expected IP ranges (for poisoning detection)
# NOTE: These are VALID ranges. If DNS returns something else, it's poisoned.
KNOWN_DOMAINS = {
    "google.com": [
        "64.233.",   # Common in Europe/Asia
        "74.125.",   # Common worldwide
        "142.250.",  # Common worldwide
        "172.217.",  # Common worldwide
        "172.253.",  # Common worldwide
        "209.85.",   # Common worldwide
        "216.58.",   # Common worldwide
    ],
    "cloudflare.com": ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22."],
    "github.com": ["140.82.", "192.30.", "20.200.", "20.201.", "20.205.", "20.207."],
}

# Sample Netlify/Vercel domains for target testing
NETLIFY_TEST_DOMAINS = [
    "a16z.com", "netlify.com", "stripe.dev", "vercel.app",
    "segment.com", "reddit.com", "apollo.com"
]


def _query_dns_doh(dns_ip: str, domain: str, timeout: float = TCP_TIMEOUT) -> dict:
    """
    Query DNS over HTTPS and return result.

    Tries multiple DoH endpoint formats for compatibility:
    1. https://DNS_IP/dns-query (standard)
    2. https://dns.google/resolve (Google specific)

    Returns:
        {"success": True, "ips": [...], "latency_ms": 45.2}
        or
        {"success": False, "error": "timeout"}
    """
    # Map common DNS IPs to their DoH endpoints
    DOH_ENDPOINTS = {
        "8.8.8.8": "https://dns.google/resolve",
        "8.8.4.4": "https://dns.google/resolve",
        "1.1.1.1": "https://1.1.1.1/dns-query",
        "1.0.0.1": "https://1.0.0.1/dns-query",
        "9.9.9.9": "https://dns.quad9.net/dns-query",
        "149.112.112.112": "https://dns.quad9.net/dns-query",
    }

    start = time.perf_counter()

    # Try specific endpoint first if known
    provider = DOH_ENDPOINTS.get(dns_ip, f"https://{dns_ip}/dns-query")

    try:
        # Google DNS uses different format
        if "dns.google" in provider:
            response = httpx.get(
                provider,
                params={"name": domain, "type": "A"},
                timeout=timeout,
                verify=False,
            )
        else:
            # Standard DoH format
            response = httpx.get(
                provider,
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=timeout,
                verify=False,
            )

        latency_ms = (time.perf_counter() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            ips = [
                a["data"]
                for a in data.get("Answer", [])
                if a.get("type") == 1
            ]
            if ips:
                return {
                    "success": True,
                    "ips": ips,
                    "latency_ms": round(latency_ms, 1),
                    "error": ""
                }

        return {
            "success": False,
            "ips": [],
            "latency_ms": round(latency_ms, 1),
            "error": f"HTTP {response.status_code}"
        }
    except httpx.TimeoutException:
        return {"success": False, "ips": [], "latency_ms": None, "error": "timeout"}
    except Exception as e:
        return {"success": False, "ips": [], "latency_ms": None, "error": str(e)[:50]}


def _check_poisoning(dns_ip: str) -> dict:
    """
    Check if DNS returns poisoned (fake) IPs.

    Returns:
        {"poisoned": False, "details": "..."}
        or
        {"poisoned": True, "details": "google.com returned 10.10.34.35 (not in known range)"}
    """
    for domain, expected_prefixes in KNOWN_DOMAINS.items():
        result = _query_dns_doh(dns_ip, domain)

        if not result["success"]:
            continue

        # Check if ANY returned IP matches expected ranges
        ips = result["ips"]
        matches = any(
            any(ip.startswith(prefix) for prefix in expected_prefixes)
            for ip in ips
        )

        if not matches:
            return {
                "poisoned": True,
                "details": f"{domain} returned {ips[0]} (not in known range)"
            }

    return {"poisoned": False, "details": "All known domains resolved correctly"}


def _test_target_reachability(dns_ip: str, num_samples: int = 3) -> dict:
    """
    Test if DNS can resolve target domains AND if those IPs are reachable.

    Returns:
        {
            "success_rate": 3/3,
            "avg_e2e_latency": 165.5,  # DNS + TCP combined
            "details": ["a16z.com: 75.2.60.5 reachable (120ms)", ...]
        }
    """
    from core.tcp_checker import tcp_ping

    # Pick random sample domains
    test_domains = random.sample(NETLIFY_TEST_DOMAINS, min(num_samples, len(NETLIFY_TEST_DOMAINS)))

    success_count = 0
    total_latency = 0
    details = []

    for domain in test_domains:
        # Step 1: Resolve domain
        dns_result = _query_dns_doh(dns_ip, domain)

        if not dns_result["success"]:
            details.append(f"❌ {domain}: DNS resolution failed ({dns_result['error']})")
            continue

        # Step 2: TCP ping the resolved IP
        ip = dns_result["ips"][0]
        tcp_result = tcp_ping(ip, 443)

        if tcp_result["ok"]:
            e2e_latency = dns_result["latency_ms"] + tcp_result["latency_ms"]
            total_latency += e2e_latency
            success_count += 1
            details.append(f"✅ {domain}: {ip} reachable ({int(e2e_latency)}ms E2E)")
        else:
            details.append(f"⚠️ {domain}: {ip} resolved but unreachable ({tcp_result['error']})")

    avg_latency = (total_latency / success_count) if success_count > 0 else None

    return {
        "success_rate": f"{success_count}/{len(test_domains)}",
        "success_count": success_count,
        "total_count": len(test_domains),
        "avg_e2e_latency": round(avg_latency, 1) if avg_latency else None,
        "details": details
    }


def test_dns_servers_e2e(dns_list: list[str], mode: str = "e2e") -> list[dict]:
    """
    Test multiple DNS servers with E2E validation (default) or simple query.

    Args:
        dns_list: List of DNS IP addresses
        mode: "e2e" (full test) or "simple" (quick query only)

    Returns:
        List of dicts sorted by quality score:
        [
            {
                "dns": "8.8.8.8",
                "working": True,
                "mode": "e2e",
                "dns_latency": 45.2,
                "e2e_latency": 165.5,
                "poisoned": False,
                "reachable": "3/3",
                "score": 95,
                "details": [...],
                "recommendation": "EXCELLENT"
            },
            ...
        ]
    """
    results = []

    def test_single_dns_e2e(dns_ip: str) -> dict:
        # Phase 1: Basic query test
        basic_result = _query_dns_doh(dns_ip, "www.google.com")

        if not basic_result["success"]:
            return {
                "dns": dns_ip,
                "working": False,
                "mode": mode,
                "dns_latency": None,
                "e2e_latency": None,
                "poisoned": None,
                "reachable": "0/0",
                "score": 0,
                "details": [f"❌ DNS unreachable: {basic_result['error']}"],
                "recommendation": "FAILED",
                "error": basic_result["error"]
            }

        dns_latency = basic_result["latency_ms"]

        if mode == "simple":
            # Simple mode: just check if DNS responds
            return {
                "dns": dns_ip,
                "working": True,
                "mode": "simple",
                "dns_latency": dns_latency,
                "e2e_latency": dns_latency,
                "poisoned": False,
                "reachable": "N/A",
                "score": 100 - int(dns_latency / 2),  # Simple scoring
                "details": [f"✅ DNS responds ({dns_latency}ms)"],
                "recommendation": "WORKING",
                "error": ""
            }

        # Phase 2: Poisoning check
        poison_result = _check_poisoning(dns_ip)

        if poison_result["poisoned"]:
            return {
                "dns": dns_ip,
                "working": False,
                "mode": "e2e",
                "dns_latency": dns_latency,
                "e2e_latency": None,
                "poisoned": True,
                "reachable": "0/0",
                "score": 10,
                "details": [
                    f"✅ DNS responds ({dns_latency}ms)",
                    f"❌ POISONED: {poison_result['details']}"
                ],
                "recommendation": "DO NOT USE",
                "error": "poisoned"
            }

        # Phase 3: Target reachability test
        reach_result = _test_target_reachability(dns_ip)

        # Calculate score (0-100)
        speed_score = max(0, 100 - int(dns_latency))  # 0-100
        reach_score = (reach_result["success_count"] / reach_result["total_count"]) * 100

        # Weighted score: 40% speed, 30% clean, 30% reachability
        score = int(
            (speed_score * 0.4) +
            (100 * 0.3) +  # Not poisoned = 30 points
            (reach_score * 0.3)
        )

        # Recommendation
        if reach_result["success_count"] == reach_result["total_count"]:
            recommendation = "EXCELLENT" if score >= 80 else "GOOD"
        elif reach_result["success_count"] > 0:
            recommendation = "USABLE"
        else:
            # 0 targets reachable = useless for Mode 1
            recommendation = "POOR (No targets reachable)"

        return {
            "dns": dns_ip,
            "working": True,
            "mode": "e2e",
            "dns_latency": dns_latency,
            "e2e_latency": reach_result["avg_e2e_latency"],
            "poisoned": False,
            "reachable": reach_result["success_rate"],
            "score": score,
            "details": [
                f"✅ DNS responds ({dns_latency}ms)",
                f"✅ Clean (not poisoned)",
            ] + reach_result["details"],
            "recommendation": recommendation,
            "error": ""
        }

    # Test all DNS servers in parallel
    max_workers = min(5, len(dns_list))  # Limit to 5 for E2E (more intensive)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_single_dns_e2e, dns): dns for dns in dns_list}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                dns = futures[future]
                results.append({
                    "dns": dns,
                    "working": False,
                    "mode": mode,
                    "dns_latency": None,
                    "e2e_latency": None,
                    "poisoned": None,
                    "reachable": "0/0",
                    "score": 0,
                    "details": [f"❌ Test error: {str(e)[:50]}"],
                    "recommendation": "ERROR",
                    "error": f"thread error: {e}"
                })

    # Sort by score (highest first)
    results.sort(key=lambda x: x["score"], reverse=True)

    return results


def test_dns_servers(dns_list: list[str], test_domain: str = "www.google.com", mode: str = "e2e") -> list[dict]:
    """
    Test multiple DNS servers (default: E2E mode for accurate results).

    Args:
        dns_list: List of DNS IP addresses (e.g., ["8.8.8.8", "1.1.1.1"])
        test_domain: DEPRECATED (kept for backward compatibility)
        mode: "e2e" (default, full validation) or "simple" (quick query only)

    Returns:
        List of dicts sorted by quality score (E2E) or latency (simple)
    """
    return test_dns_servers_e2e(dns_list, mode=mode)


def resolve_domain(domain: str, custom_dns: str = "") -> list[str]:
    """
    Resolve domain to IPs.
    Try order: custom DNS (DoH) → system DNS → hardcoded DoH providers.

    If custom_dns contains multiple IPs (comma or newline separated),
    tests all and uses the fastest working one.
    """
    if custom_dns.strip():
        # Support multiple DNS servers (comma or newline separated)
        dns_list = [
            dns.strip()
            for dns in custom_dns.replace('\n', ',').split(',')
            if dns.strip()
        ]

        if len(dns_list) > 1:
            # Multiple DNS servers - test all and use fastest
            test_results = test_dns_servers(dns_list, domain)
            for result in test_results:
                if result["working"] and result["ips"]:
                    return result["ips"]
        elif len(dns_list) == 1:
            # Single DNS server - use directly
            ips = _resolve_custom_doh(domain, dns_list[0])
            if ips:
                return ips

    ips = _resolve_system_dns(domain)
    if ips:
        return ips

    return _resolve_doh(domain)


def _resolve_custom_doh(domain: str, dns_ip: str) -> list[str]:
    """
    DoH query against user-specified DNS server IP.
    Works with any DNS server that supports DoH (8.8.8.8, 1.1.1.1, 9.9.9.9, etc.)
    """
    provider = f"https://{dns_ip}/dns-query"
    try:
        response = httpx.get(
            provider,
            params={"name": domain, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=TCP_TIMEOUT,
            verify=False,
        )
        if response.status_code == 200:
            data = response.json()
            return [
                a["data"]
                for a in data.get("Answer", [])
                if a.get("type") == 1
            ]
    except Exception:
        pass
    return []


def _resolve_system_dns(domain: str) -> list[str]:
    """System OS DNS — may be poisoned in censored networks."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except Exception:
        return []


def _resolve_doh(domain: str) -> list[str]:
    """Try hardcoded DoH providers in order until one works."""
    for provider in DOH_PROVIDERS:
        try:
            response = httpx.get(
                provider,
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=TCP_TIMEOUT,
            )
            if response.status_code == 200:
                data = response.json()
                ips = [
                    a["data"]
                    for a in data.get("Answer", [])
                    if a.get("type") == 1
                ]
                if ips:
                    return ips
        except Exception:
            continue
    return []
