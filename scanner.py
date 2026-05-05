# scanner.py
# CDN Scanner — CLI interface
# Same pipeline as main.py but without WebSocket/FastAPI.
#
# Pipeline:
#   Stage 0 — Parse template + build candidates
#   Stage 1 — TCP:443 + TLS handshake (per-candidate SNI)
#   Stage 2 — DNS fallback for failed domains → re-test in Stage 1
#   Stage 3 — Xray tunnel validation

import sys
import time
import ipaddress
import concurrent.futures

from core import (
    parse_vless,
    resolve_domain,
    tcp_ping,
    validate_with_xray,
    build_vless_link,
    TCP_PORT,
    MAX_WORKERS,
    XRAY_TIMEOUT,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers (mirrors main.py, no FastAPI dependency)
# ─────────────────────────────────────────────────────────────────────────────

def _classify_single(value: str) -> dict:
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return {"type": "ip", "value": value}
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return {"type": "cidr", "value": value}
    except ValueError:
        pass
    return {"type": "domain", "value": value}


def _expand_cidr(cidr: str, max_ips: int = 65536) -> list[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in list(network.hosts())[:max_ips]]
    except ValueError:
        return []


def _build_candidates(
    raw_targets: list[dict],
    mode: str,
    template_sni: str,
) -> list[dict]:
    """
    Convert raw targets to pipeline candidates.

    Candidate:
      connect_to    — IP or domain to TCP-connect to
      sni           — SNI for TLS handshake
      mode          — "mode1" or "mode2"
      source_domain — domain for DNS fallback (None = no fallback)
    """
    candidates: list[dict] = []

    for t in raw_targets:
        ttype = t["type"]

        if mode == "mode1":
            if ttype == "csv":
                candidates.append({
                    "connect_to":    t["ip"],
                    "sni":           t["domain"],
                    "mode":          mode,
                    "source_domain": t["domain"],
                })
            elif ttype == "domain":
                candidates.append({
                    "connect_to":    t["value"],
                    "sni":           t["value"],
                    "mode":          mode,
                    "source_domain": t["value"],
                })
            elif ttype == "ip":
                candidates.append({
                    "connect_to":    t["value"],
                    "sni":           template_sni,
                    "mode":          mode,
                    "source_domain": None,
                })
            elif ttype == "cidr":
                for ip in _expand_cidr(t["value"]):
                    candidates.append({
                        "connect_to":    ip,
                        "sni":           template_sni,
                        "mode":          mode,
                        "source_domain": None,
                    })

        else:  # mode2
            if ttype == "ip":
                candidates.append({
                    "connect_to":    t["value"],
                    "sni":           template_sni,
                    "mode":          mode,
                    "source_domain": None,
                })
            elif ttype == "cidr":
                for ip in _expand_cidr(t["value"]):
                    candidates.append({
                        "connect_to":    ip,
                        "sni":           template_sni,
                        "mode":          mode,
                        "source_domain": None,
                    })
            elif ttype in ("domain", "csv"):
                domain = t.get("value") or t.get("domain", "")
                if domain:
                    candidates.append({
                        "connect_to":    domain,
                        "sni":           template_sni,
                        "mode":          mode,
                        "source_domain": domain,
                    })

    return candidates


def _run_stage1_batch(
    candidates: list[dict],
    port:       int,
    log,
) -> tuple[list[dict], list[dict]]:
    """
    Stage 1: TCP:443 + TLS handshake for every candidate.
    Prints a progress line every 10% for large batches.
    Returns: (passed, failed_domains)
    """
    if not candidates:
        return [], []

    passed:         list[dict] = []
    failed_domains: list[dict] = []
    done_count = 0
    total      = len(candidates)
    workers    = min(MAX_WORKERS, total)

    # Print progress at 10% intervals for large batches
    report_every = max(1, total // 10)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_candidate = {
            executor.submit(tcp_ping, c["connect_to"], port, c["sni"]): c
            for c in candidates
        }
        for future in concurrent.futures.as_completed(future_to_candidate):
            c = future_to_candidate[future]
            try:
                result = future.result()
                if result["ok"]:
                    passed.append(c)
                elif c.get("source_domain"):
                    failed_domains.append(c)
            except Exception:
                if c.get("source_domain"):
                    failed_domains.append(c)

            done_count += 1
            if total > 100 and done_count % report_every == 0:
                pct = int(done_count / total * 100)
                log(f"      TCP progress: {done_count}/{total} ({pct}%) | passed so far: {len(passed)}")

    return passed, failed_domains


def _run_stage2(
    failed_candidates: list[dict],
    custom_dns: str,
    log,
) -> list[dict]:
    """
    Stage 2: DNS fallback for domains that failed Stage 1.
    Returns new candidates to be re-checked in Stage 1.
    """
    new_candidates: list[dict] = []
    seen_ips: set[str] = set()

    for fc in failed_candidates:
        domain = fc["source_domain"]
        if not domain:
            continue

        ips = resolve_domain(domain, custom_dns=custom_dns)

        if ips:
            log(f"      DNS fallback: {domain} → {len(ips)} IP(s)")
            for ip in ips:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    new_candidates.append({
                        "connect_to":    ip,          # TCP test uses IP
                        "sni":           fc["sni"],
                        "mode":          fc["mode"],
                        "source_domain": domain,      # KEEP original domain for final config!
                        "resolved_ip":   ip,
                    })
        else:
            log(f"      WARN: {domain} → could not resolve via any DNS")

    return new_candidates


# ─────────────────────────────────────────────────────────────────────────────
# Main scan function
# ─────────────────────────────────────────────────────────────────────────────

def scan(
    vless_link:  str,
    mode:        str  = "mode2",
    targets_raw: str  = "",
    custom_dns:  str  = "",
    max_results: int  = 10,
    xray_workers:int  = 5,
    skip_xray:   bool = False,
    verbose:     bool = True,
) -> list[dict]:
    """
    Find the best CDN IPs for a vless link.

    Args:
        vless_link:   Original vless:// link
        mode:         "mode1" (Netlify/Vercel) or "mode2" (CF/CloudFront)
        targets_raw:  Newline-separated targets (CSV/IP/CIDR/domain).
                      Leave blank to use the link's own address.
        custom_dns:   Custom DNS server IP for Stage 2 fallback (e.g. "8.8.8.8")
        max_results:  Maximum good results to return
        xray_workers: Parallel workers for xray validation
        skip_xray:    If True, skip Stage 3 and return Stage 1 survivors only
        verbose:      Print progress to terminal

    Returns:
        List of result dicts sorted by latency (best first):
        [{"connect_to", "sni", "mode", "ok", "latency_ms", "link"}, ...]
    """

    def log(msg: str):
        if verbose:
            print(msg)

    # ── Stage 0A: Parse VLESS link ───────────────────────────────────────────
    log(f"\n[Stage 0] Parsing vless link...")

    parsed = parse_vless(vless_link)
    if not parsed:
        log("ERROR: Invalid vless link!")
        return []

    log(f"  uuid      : {parsed['uuid'][:8]}...")
    log(f"  address   : {parsed['address']}")
    log(f"  transport : {parsed['type']}")
    log(f"  security  : {parsed['security']}")
    log(f"  sni       : {parsed.get('sni', '-')}")
    log(f"  host      : {parsed.get('host', '-')}")
    log(f"  mode      : {mode}")

    # ── Stage 0B: Build candidates ───────────────────────────────────────────
    template_sni = (
        parsed.get("host")
        or parsed.get("sni")
        or parsed.get("address", "")
    )
    port = parsed.get("port", TCP_PORT)

    if targets_raw.strip():
        # Parse the provided targets
        raw_targets = _parse_targets_text(targets_raw)
    else:
        # Use only the link's address as the single target
        raw_targets = [_classify_single(parsed.get("address", ""))]

    candidates = _build_candidates(raw_targets, mode, template_sni)

    if not candidates:
        log(f"ERROR: No valid candidates for mode={mode}")
        return []

    log(f"\n  {len(candidates)} candidate(s) ready")

    # ── Stage 1: TCP:443 + TLS handshake ────────────────────────────────────
    log(f"\n[Stage 1] TCP+TLS check on {len(candidates)} candidate(s) (port {port})...")

    stage1_passed, failed_domains = _run_stage1_batch(candidates, port, log)

    log(f"  {len(stage1_passed)} passed | {len(failed_domains)} domain(s) for DNS fallback")

    # ── Stage 2: DNS fallback ────────────────────────────────────────────────
    if failed_domains:
        log(f"\n[Stage 2] DNS fallback for {len(failed_domains)} domain(s)...")

        stage2_resolved = _run_stage2(failed_domains, custom_dns, log)

        if stage2_resolved:
            log(f"  Re-checking {len(stage2_resolved)} resolved IP(s) in Stage 1...")
            s2_passed, _ = _run_stage1_batch(stage2_resolved, port, log)
            stage1_passed.extend(s2_passed)
            log(f"  {len(s2_passed)} additional IP(s) passed")

    log(f"\n  {len(stage1_passed)} candidate(s) ready for xray validation")

    if not stage1_passed:
        log("ERROR: No candidate passed TCP check!")
        return []

    # ── Stage 3: Xray validation ─────────────────────────────────────────────
    if skip_xray:
        log("\n[Stage 3] Skipped (fast mode)")
        results = []
        for c in stage1_passed[:max_results]:
            # Mode 1: Use original domain as address
            # Mode 2: Use IP as address
            if c["mode"] == "mode1" and c.get("source_domain"):
                config_address = c["source_domain"]
            else:
                config_address = c["connect_to"]

            results.append({
                "connect_to": c["connect_to"],
                "sni":        c["sni"],
                "mode":       c["mode"],
                "ok":         True,
                "latency_ms": None,
                "link":       build_vless_link(parsed, config_address, c["sni"], c["mode"], None),
                "source_domain": c.get("source_domain"),
            })
        return results

    log(f"\n[Stage 3] Xray validation: {len(stage1_passed)} candidate(s) | {xray_workers} worker(s)...")
    log(f"  Timeout per test: {XRAY_TIMEOUT}s — please wait...")

    xray_results: list[dict] = []
    good_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=xray_workers) as executor:
        future_to_candidate = {
            executor.submit(
                validate_with_xray,
                parsed,
                c,
                port,
                idx % xray_workers,
            ): c
            for idx, c in enumerate(stage1_passed)
        }

        for future in concurrent.futures.as_completed(future_to_candidate):
            c = future_to_candidate[future]
            try:
                result = future.result()
                xray_results.append(result)

                if result["ok"]:
                    good_count += 1
                    log(f"  PASS  {result['connect_to']:30s} → {result['latency_ms']:7.1f} ms")
                else:
                    log(f"  FAIL  {c['connect_to']:30s} → {result['error']}")

                # Early exit if we have enough good results
                if good_count >= max_results * 2:
                    log(f"\n  Target reached ({good_count} good) — cancelling remaining")
                    for f in future_to_candidate:
                        f.cancel()
                    break

            except Exception as e:
                log(f"  ERROR {c['connect_to']} → {e}")

    good_results = [r for r in xray_results if r["ok"]]

    if not good_results:
        log("\nERROR: No candidate passed xray validation!")
        return []

    good_results.sort(key=lambda x: x["latency_ms"])
    good_results = good_results[:max_results]

    final_results = []
    for r in good_results:
        # Mode 1: Use original domain as address
        # Mode 2: Use IP as address
        if r["mode"] == "mode1" and r.get("source_domain"):
            config_address = r["source_domain"]
        else:
            config_address = r["connect_to"]

        r["link"] = build_vless_link(parsed, config_address, r["sni"], r["mode"], r["latency_ms"])
        final_results.append(r)

    log(f"\n{'=' * 60}")
    log(f"TOP {len(final_results)} RESULT(S):")
    log(f"{'=' * 60}")
    for i, r in enumerate(final_results, 1):
        log(f"  {i:2d}. {r['connect_to']:30s} | {r['latency_ms']:7.1f} ms")
        log(f"      {r['link']}")
    log(f"{'=' * 60}\n")

    return final_results


def _parse_targets_text(text: str) -> list[dict]:
    """Parse newline-separated target text (same logic as main.py)."""
    results = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                domain_part = parts[0]
                ip_part     = parts[2]
                if domain_part:
                    try:
                        ipaddress.ip_address(ip_part)
                        results.append({"type": "csv", "domain": domain_part, "ip": ip_part})
                    except ValueError:
                        results.append({"type": "domain", "value": domain_part})
            continue

        if "/" in line:
            try:
                ipaddress.ip_network(line, strict=False)
                results.append({"type": "cidr", "value": line})
            except ValueError:
                pass
            continue

        try:
            ipaddress.ip_address(line)
            results.append({"type": "ip", "value": line})
            continue
        except ValueError:
            pass

        if "." in line and " " not in line and len(line) > 3:
            results.append({"type": "domain", "value": line})

    return results


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """
    Usage:
        python scanner.py "vless://..." --mode mode1
        python scanner.py "vless://..." --mode mode2 --max 5 --workers 3
        python scanner.py "vless://..." --targets targets.txt --output results.txt
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="CDN Scanner — Find the best CDN IPs for a vless link"
    )
    parser.add_argument("link", help="vless:// link")
    parser.add_argument(
        "--mode", choices=["mode1", "mode2"], default="mode2",
        help="mode1=Netlify/Vercel (domain-based), mode2=CF/CloudFront (IP-based) [default: mode2]"
    )
    parser.add_argument(
        "--targets", type=str, default=None, dest="targets_file",
        help="Path to a file with targets (CSV/IP/CIDR/domain, one per line)"
    )
    parser.add_argument(
        "--dns", type=str, default="", dest="custom_dns",
        help="Custom DNS server IP for Stage 2 fallback (e.g. 8.8.8.8)"
    )
    parser.add_argument(
        "--max", type=int, default=10, dest="max_results",
        help="Maximum number of results [default: 10]"
    )
    parser.add_argument(
        "--workers", type=int, default=5, dest="xray_workers",
        help="Parallel xray workers [default: 5]"
    )
    parser.add_argument(
        "--skip-xray", action="store_true", dest="skip_xray",
        help="Skip Stage 3 xray validation (TCP check only, faster)"
    )
    parser.add_argument(
        "--output", type=str, default=None, dest="output_file",
        help="Save final links to a file (one per line)"
    )

    args = parser.parse_args()

    targets_raw = ""
    if args.targets_file:
        try:
            with open(args.targets_file, encoding="utf-8") as f:
                targets_raw = f.read()
        except Exception as e:
            print(f"ERROR reading targets file: {e}")
            sys.exit(1)

    # Validate custom DNS if provided (supports multiple IPs separated by comma)
    if args.custom_dns.strip():
        dns_input = args.custom_dns.strip()
        dns_list = [d.strip() for d in dns_input.replace('\n', ',').split(',') if d.strip()]

        for dns in dns_list:
            parts = dns.split(".")
            if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                print(f"ERROR: Invalid DNS IP address: {dns}")
                sys.exit(1)

    start_time = time.time()
    results = scan(
        vless_link=args.link,
        mode=args.mode,
        targets_raw=targets_raw,
        custom_dns=args.custom_dns,
        max_results=args.max_results,
        xray_workers=args.xray_workers,
        skip_xray=args.skip_xray,
        verbose=True,
    )
    elapsed = time.time() - start_time

    print(f"Total time: {elapsed:.1f}s")

    if not results:
        print("No results found.")
        sys.exit(1)

    if args.output_file:
        try:
            with open(args.output_file, "w", encoding="utf-8") as f:
                for r in results:
                    f.write(r["link"] + "\n")
            print(f"Saved {len(results)} link(s) to '{args.output_file}'")
        except Exception as e:
            print(f"ERROR saving file: {e}")


if __name__ == "__main__":
    main()
