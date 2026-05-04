# scanner.py
# ─────────────────────────────────────────────────────────────────────────────
# CDN Scanner - Main Scanner File
# This file connects all core modules and builds a complete pipeline:
#   1. Parse vless link
#   2. Extract CDN targets (domain / IP / CIDR)
#   3. Resolve DNS -> IP list
#   4. Fast TCP ping (pre-filter)
#   5. Real xray test (final filter)
#   6. Build new links with good IPs
# ─────────────────────────────────────────────────────────────────────────────

import sys
import time
import concurrent.futures

from core import (
    parse_vless,
    extract_targets,
    resolve_domain,
    tcp_ping_batch,
    validate_with_xray,
    build_vless_link,
    TCP_PORT,
    MAX_WORKERS,
    XRAY_TIMEOUT,
)


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner function
# ─────────────────────────────────────────────────────────────────────────────

def scan(
    vless_link: str,
    max_results: int = 10,
    xray_workers: int = 5,
    verbose: bool = True,
) -> list[dict]:
    """
    Takes a vless link and finds the best CDN IPs.

    Args:
        vless_link:   Original vless link
        max_results:  Maximum number of good results to return
        xray_workers: Number of parallel workers for xray testing
        verbose:      Show progress in terminal

    Returns:
        List of result dicts, sorted by latency (ascending):
        [
            {
                "ip":         "1.2.3.4",
                "ok":         True,
                "latency_ms": 123.4,
                "error":      "",
                "link":       "vless://..."
            },
            ...
        ]
    """

    def log(msg: str):
        # Only print if verbose mode is enabled
        if verbose:
            print(msg)

    # ─────────────────────────────────────────────────────────────────────────
    # Step 1: Parse vless link
    # ─────────────────────────────────────────────────────────────────────────
    log("\n[1/5] Parsing vless link...")

    parsed = parse_vless(vless_link)
    if not parsed:
        log("ERROR: Invalid vless link!")
        return []

    log(f"      OK - UUID     : {parsed['uuid'][:8]}...")
    log(f"      OK - Address  : {parsed['address']}")
    log(f"      OK - Transport: {parsed['type']}")
    log(f"      OK - SNI      : {parsed.get('sni', '-')}")
    log(f"      OK - Host     : {parsed.get('host', '-')}")

    # ─────────────────────────────────────────────────────────────────────────
    # Step 2: Extract CDN targets
    # FIX: extract_targets expects a dict (parsed), NOT a list of strings
    # It reads "address", "host", "sni" keys internally from the dict
    # ─────────────────────────────────────────────────────────────────────────
    log("\n[2/5] Extracting CDN targets...")

    # Pass the full parsed dict directly - extract_targets reads address/host/sni itself
    targets = extract_targets(parsed)

    if not targets:
        log("ERROR: No targets found!")
        return []

    log(f"      OK - {len(targets)} target(s) found:")
    for t in targets[:5]:
        # each target is a dict: {"value": "...", "type": "domain"/"ip"/"cidr"}
        log(f"           [{t['type']:6s}] {t['value']}")

    # ─────────────────────────────────────────────────────────────────────────
    # Step 3: Resolve DNS -> IP list
    # Only domain-type targets need DNS resolution
    # IP-type targets are already IPs, add them directly
    # ─────────────────────────────────────────────────────────────────────────
    log("\n[3/5] Resolving DNS...")

    all_ips: list[str] = []

    for target in targets:
        if target["type"] == "ip":
            # Already an IP, no DNS needed
            all_ips.append(target["value"])
            log(f"      OK - {target['value']} -> direct IP (no DNS needed)")

        elif target["type"] == "domain":
            # Resolve domain to IPs via DNS over HTTPS
            ips = resolve_domain(target["value"])
            if ips:
                preview = ips[:3]
                suffix = "..." if len(ips) > 3 else ""
                log(f"      OK - {target['value']} -> {len(ips)} IP(s): {preview}{suffix}")
                all_ips.extend(ips)
            else:
                log(f"      WARN - {target['value']} -> could not resolve")

    # Remove duplicates while preserving order
    all_ips = list(dict.fromkeys(all_ips))

    if not all_ips:
        log("ERROR: No IPs resolved!")
        return []

    log(f"      OK - Total unique IPs: {len(all_ips)}")

    # ─────────────────────────────────────────────────────────────────────────
    # Step 4: Fast TCP ping (pre-filter)
    # This quickly eliminates unreachable IPs before the slow xray test
    # ─────────────────────────────────────────────────────────────────────────
    log(f"\n[4/5] TCP ping on {len(all_ips)} IP(s) (port {TCP_PORT})...")

    tcp_results = tcp_ping_batch(all_ips, port=TCP_PORT, max_workers=MAX_WORKERS)

    # Keep only IPs that responded to TCP
    alive_ips = [r["ip"] for r in tcp_results if r["ok"]]

    log(f"      OK - {len(alive_ips)} alive out of {len(all_ips)}")

    if not alive_ips:
        log("ERROR: No IP responded to TCP!")
        return []

    # ─────────────────────────────────────────────────────────────────────────
    # Step 5: Real xray test (final filter)
    # Each worker gets a unique worker_id to use a different local port
    # This prevents port conflicts when running multiple xray instances
    # ─────────────────────────────────────────────────────────────────────────
    log(f"\n[5/5] xray testing {len(alive_ips)} IP(s) with {xray_workers} parallel worker(s)...")
    log(f"      Please wait, this may take a few minutes...")

    xray_results: list[dict] = []
    good_count = 0

    # Use ThreadPoolExecutor for parallel execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=xray_workers) as executor:

        # Submit each IP with a unique worker_id to avoid port conflicts between xray instances
        future_to_ip = {
            executor.submit(
                validate_with_xray,
                parsed,              # original parsed config dict
                ip,                  # IP being tested
                TCP_PORT,            # port (443)
                idx % xray_workers,  # unique worker_id (0, 1, 2, ...)
            ): ip
            for idx, ip in enumerate(alive_ips)
        }

        # Collect results as they complete (not in submission order)
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                xray_results.append(result)

                if result["ok"]:
                    good_count += 1
                    log(f"      PASS  {ip:20s} -> {result['latency_ms']:7.1f} ms")
                else:
                    log(f"      FAIL  {ip:20s} -> {result['error']}")

                # Early exit: if we already have enough good results, cancel the rest
                if good_count >= max_results * 2:
                    log(f"\n      TARGET REACHED: {good_count} good results - cancelling remaining")
                    for f in future_to_ip:
                        f.cancel()
                    break

            except Exception as e:
                log(f"      ERROR {ip} -> unexpected error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Process final results
    # ─────────────────────────────────────────────────────────────────────────

    # Keep only successful results
    good_results = [r for r in xray_results if r["ok"]]

    if not good_results:
        log("\nERROR: No IP passed the xray test!")
        return []

    # Sort by latency ascending (best first)
    good_results.sort(key=lambda x: x["latency_ms"])

    # Keep only top max_results
    good_results = good_results[:max_results]

    # Build a new vless link for each good IP
    final_results = []
    for result in good_results:
        new_link = build_vless_link(parsed, result["ip"])
        result["link"] = new_link
        final_results.append(result)

    # ─────────────────────────────────────────────────────────────────────────
    # Print summary
    # ─────────────────────────────────────────────────────────────────────────
    log(f"\n{'=' * 60}")
    log(f"TOP RESULTS - {len(final_results)} best IP(s):")
    log(f"{'=' * 60}")

    for i, r in enumerate(final_results, 1):
        log(f"  {i:2d}. {r['ip']:20s} | {r['latency_ms']:7.1f} ms | {r['link'][:60]}...")

    log(f"{'=' * 60}\n")

    return final_results


# ─────────────────────────────────────────────────────────────────────────────
# Command line entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """
    Run scanner from command line:
        python scanner.py "vless://..."
        python scanner.py "vless://..." --max 5 --workers 3
        python scanner.py "vless://..." --output results.txt
    """

    import argparse

    parser = argparse.ArgumentParser(
        description="CDN Scanner - Find the best CDN IPs for a vless link"
    )

    parser.add_argument(
        "link",
        help="Original vless link"
    )

    parser.add_argument(
        "--max",
        type=int,
        default=10,
        dest="max_results",
        help="Maximum number of results (default: 10)"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        dest="xray_workers",
        help="Number of parallel xray workers (default: 5)"
    )

    parser.add_argument(
        "--output",
        type=str,
        default=None,
        dest="output_file",
        help="Save final links to a file (optional)"
    )

    args = parser.parse_args()

    # Run the scan
    start_time = time.time()
    results = scan(
        vless_link=args.link,
        max_results=args.max_results,
        xray_workers=args.xray_workers,
        verbose=True,
    )
    elapsed = time.time() - start_time

    print(f"Total time: {elapsed:.1f} seconds")

    if not results:
        print("No results found!")
        sys.exit(1)

    # Save to file if --output was provided
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