# ════════════════════════════════════════════════════════════
# CDN Scanner - main.py
# FastAPI server + WebSocket real-time progress
# ════════════════════════════════════════════════════════════

import os
import uuid
import asyncio
import threading
import ipaddress
import concurrent.futures
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core import (
    parse_vless,
    extract_targets,
    resolve_domain,
    tcp_ping,
    validate_with_xray,
    build_vless_link,
    TCP_PORT,
    MAX_WORKERS,
    XRAY_BATCH_SIZE,
    APP_NAME,
    VERSION,
)

# ════════════════════════════════════════════════════════════
# App Setup
# ════════════════════════════════════════════════════════════

app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    docs_url="/docs" if os.getenv("DEV_MODE") else None,
    redoc_url=None,
)

_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ════════════════════════════════════════════════════════════
# Scan Storage
# ════════════════════════════════════════════════════════════

_scans: dict[str, dict] = {}
_scans_lock = threading.Lock()


def _new_scan_record() -> tuple[str, dict]:
    scan_id = str(uuid.uuid4())
    record = {
        "status":   "pending",
        "progress": 0,
        "results":  [],
        "error":    None,
        "created":  datetime.now(timezone.utc),
        "events":   asyncio.Queue(maxsize=0),
        "cancel":   threading.Event(),
    }
    with _scans_lock:
        _scans[scan_id] = record
    return scan_id, record


def _get_scan(scan_id: str) -> Optional[dict]:
    with _scans_lock:
        return _scans.get(scan_id)


# ════════════════════════════════════════════════════════════
# Pydantic Models
# ════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    link:             str
    max_workers:      Optional[int] = None
    max_results:      int  = 0      # 0 = no limit; stops Stage 3 early once reached
    skip_xray:        bool = False
    mode:             str  = "mode2"
    targets_raw:      str  = ""
    custom_dns:       str  = ""
    force_custom_dns: bool = False


class ScanStartResponse(BaseModel):
    ok:      bool
    scan_id: str
    ws_url:  str


class ScanResult(BaseModel):
    ip:         str
    latency_ms: float
    link:       str


class ScanStatusResponse(BaseModel):
    ok:       bool
    scan_id:  str
    status:   str
    progress: int
    results:  list[ScanResult]
    error:    Optional[str]


# ════════════════════════════════════════════════════════════
# Routes
# ════════════════════════════════════════════════════════════

@app.get("/", include_in_schema=False)
async def serve_index():
    index_path = os.path.join(_static_dir, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return JSONResponse({"app": APP_NAME, "version": VERSION, "status": "running"})


@app.get("/health", tags=["system"])
async def health_check():
    return {
        "status":  "ok",
        "app":     APP_NAME,
        "version": VERSION,
        "time":    datetime.now(timezone.utc).isoformat(),
    }


class DNSTestRequest(BaseModel):
    dns_list: str  # Comma or newline separated DNS IPs
    mode: str = "e2e"  # "e2e" (default) or "simple"


@app.post("/test-dns", tags=["tools"])
async def test_dns(req: DNSTestRequest):
    """
    Test multiple DNS servers with E2E validation (default) or simple query.

    Example input:
    {
        "dns_list": "8.8.8.8, 1.1.1.1, 9.9.9.9",
        "mode": "e2e"  // or "simple"
    }

    Returns (E2E mode):
    {
        "ok": true,
        "mode": "e2e",
        "total": 3,
        "working": 2,
        "results": [
            {
                "dns": "8.8.8.8",
                "working": true,
                "dns_latency": 45.2,
                "e2e_latency": 165.5,
                "poisoned": false,
                "reachable": "3/3",
                "score": 95,
                "recommendation": "EXCELLENT",
                "details": ["✅ DNS responds (45ms)", "✅ Clean", "✅ a16z.com: 75.2.60.5 reachable (120ms E2E)", ...]
            },
            ...
        ]
    }
    """
    from core.dns_resolver import test_dns_servers

    dns_input = req.dns_list.strip()
    if not dns_input:
        raise HTTPException(status_code=400, detail="DNS list is empty")

    mode = req.mode.lower()
    if mode not in ["e2e", "simple"]:
        raise HTTPException(status_code=400, detail="Mode must be 'e2e' or 'simple'")

    # Parse and validate DNS list
    dns_list = [d.strip() for d in dns_input.replace('\n', ',').split(',') if d.strip()]

    for dns in dns_list:
        parts = dns.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            raise HTTPException(status_code=400, detail=f"Invalid DNS IP address: {dns}")

    # Test all DNS servers
    results = test_dns_servers(dns_list, mode=mode)

    return {
        "ok": True,
        "mode": mode,
        "total": len(results),
        "working": sum(1 for r in results if r["working"]),
        "results": results
    }


@app.get("/scan/{scan_id}/status", tags=["scan"])
async def get_scan_status(scan_id: str):
    record = _get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan not found")
    return ScanStatusResponse(
        ok=True,
        scan_id=scan_id,
        status=record["status"],
        progress=record["progress"],
        results=[
            ScanResult(ip=r["ip"], latency_ms=r["latency_ms"], link=r["link"])
            for r in record["results"]
        ],
        error=record["error"],
    )


@app.post("/scan/{scan_id}/cancel", tags=["scan"])
async def cancel_scan(scan_id: str):
    """Signal the scan thread to stop gracefully."""
    record = _get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan not found")
    record["cancel"].set()
    return {"ok": True, "scan_id": scan_id}


@app.post("/scan", tags=["scan"])
async def start_scan(req: ScanRequest):
    raw_link = req.link.strip()
    if not raw_link.startswith("vless://"):
        raise HTTPException(status_code=400, detail="Only vless:// links are supported")

    # Validate custom DNS if provided (supports multiple IPs separated by comma or newline)
    if req.custom_dns.strip():
        dns_input = req.custom_dns.strip()
        dns_list = [d.strip() for d in dns_input.replace('\n', ',').split(',') if d.strip()]

        for dns in dns_list:
            parts = dns.split(".")
            if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                raise HTTPException(status_code=400, detail=f"Invalid DNS IP address: {dns}")

    scan_id, record = _new_scan_record()
    thread = threading.Thread(
        target=_run_scan,
        args=(scan_id, record, req),
        daemon=True,
        name=f"scan-{scan_id[:8]}",
    )
    thread.start()

    return {"ok": True, "scan_id": scan_id, "ws_url": f"/ws/{scan_id}"}


# ════════════════════════════════════════════════════════════
# Event Helper
# ════════════════════════════════════════════════════════════

def _push_event(record: dict, event_type: str, payload: dict):
    event = {
        "type":    event_type,
        "payload": payload,
        "ts":      datetime.now(timezone.utc).isoformat(),
    }
    try:
        record["events"].put_nowait(event)
    except Exception:
        pass


# ════════════════════════════════════════════════════════════
# Pipeline Helpers
# ════════════════════════════════════════════════════════════

def _parse_raw_targets(raw: str) -> list[dict]:
    """
    Parse free-text targets from the UI textarea.

    Supported formats per line:
      CSV:    "a16z.com | A_RECORD | 75.2.60.5"  → {"type":"csv","domain":...,"ip":...}
      CIDR:   "13.224.0.0/16"                    → {"type":"cidr","value":...}
      IP:     "1.2.3.4"                           → {"type":"ip","value":...}
      Domain: "example.com"                       → {"type":"domain","value":...}
    """
    results: list[dict] = []

    for raw_line in raw.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # CSV: "domain | record_type | ip"
        if "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                domain_part = parts[0]
                ip_part     = parts[2]
                if domain_part:
                    try:
                        ipaddress.ip_address(ip_part)
                        # Valid paired entry — keep domain+IP together
                        results.append({
                            "type":   "csv",
                            "domain": domain_part,
                            "ip":     ip_part,
                        })
                    except ValueError:
                        # IP column invalid — just add the domain
                        results.append({"type": "domain", "value": domain_part})
            continue

        # CIDR
        if "/" in line:
            try:
                ipaddress.ip_network(line, strict=False)
                results.append({"type": "cidr", "value": line})
            except ValueError:
                pass
            continue

        # Plain IP
        try:
            ipaddress.ip_address(line)
            results.append({"type": "ip", "value": line})
            continue
        except ValueError:
            pass

        # Domain
        if "." in line and " " not in line and len(line) > 3:
            results.append({"type": "domain", "value": line})

    return results


def _expand_cidr(cidr: str, max_ips: int = 65536) -> list[str]:
    """Expand CIDR block to individual IP strings."""
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

    Candidate format:
    {
        "connect_to":    str,        # IP or domain to TCP-connect to
        "sni":           str,        # SNI for TLS handshake
        "mode":          str,        # "mode1" or "mode2"
        "source_domain": str|None,   # domain for DNS fallback (None = no fallback)
    }

    Mode 1 (Netlify/Vercel — domain-based):
        CSV entry  → connect_to=ip_hint, sni=domain, source_domain=domain
        Domain     → connect_to=domain,  sni=domain, source_domain=domain
        Raw IP     → connect_to=ip,      sni=template_sni, source_domain=None

    Mode 2 (CF/CloudFront — IP-based):
        IP/CIDR    → connect_to=ip,      sni=template_sni, source_domain=None
        Domain     → connect_to=domain,  sni=template_sni, source_domain=domain
    """
    candidates: list[dict] = []

    for t in raw_targets:
        ttype = t["type"]

        if mode == "mode1":
            if ttype == "csv":
                # IP hint from abroad: test this IP with SNI=domain
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
    candidates:  list[dict],
    port:        int,
    on_progress = None,   # optional callable(done: int, total: int)
) -> tuple[list[dict], list[dict]]:
    """
    Stage 1: TCP:443 + TLS handshake for every candidate with its own SNI.
    Calls on_progress(done, total) as futures complete so the UI stays alive.

    Returns:
        passed         — candidates that connected successfully
        failed_domains — candidates that failed AND have a source_domain
                         (eligible for Stage 2 DNS fallback)
    """
    if not candidates:
        return [], []

    passed:         list[dict] = []
    failed_domains: list[dict] = []
    done_count = 0
    total      = len(candidates)
    workers    = min(MAX_WORKERS, total)

    # Report at most every 1% of total — caps at every 50 completions for
    # small batches, never more frequent than once per completion.
    report_every = max(1, min(50, total // 100))

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
            if on_progress and (
                done_count % report_every == 0 or done_count == total
            ):
                on_progress(done_count, total)

    return passed, failed_domains


def _run_stage2(
    failed_candidates: list[dict],
    custom_dns: str,
    record: dict,
) -> list[dict]:
    """
    Stage 2: DNS fallback for domains that failed Stage 1.
    Tries: custom DNS → system DNS → DoH providers.
    Returns new candidates (resolved IPs) to be re-checked in Stage 1.
    """
    new_candidates: list[dict] = []
    seen_ips: set[str] = set()

    for fc in failed_candidates:
        domain = fc["source_domain"]
        if not domain:
            continue

        ips = resolve_domain(domain, custom_dns=custom_dns)

        if ips:
            _push_event(record, "log", {
                "msg": f"  🔍 {domain} → {len(ips)} IP(s) via DNS fallback"
            })
            for ip in ips:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    new_candidates.append({
                        "connect_to":    ip,          # TCP test uses IP
                        "sni":           fc["sni"],   # SNI stays = original domain
                        "mode":          fc["mode"],
                        "source_domain": domain,      # KEEP original domain for final config!
                        "resolved_ip":   ip,          # Track which IP was tested
                    })
        else:
            _push_event(record, "log", {
                "msg": f"  ⚠️  {domain} → could not resolve via any DNS"
            })

    return new_candidates


# ════════════════════════════════════════════════════════════
# Scan Engine — runs in its own thread
# ════════════════════════════════════════════════════════════

def _run_scan(scan_id: str, record: dict, req: ScanRequest):
    """
    Full pipeline:
      Stage 0 — Parse template + build candidates
      Stage 1 — TCP:443 + TLS handshake (per-candidate SNI)
      Stage 2 — DNS fallback for failed domains → re-test in Stage 1
      Stage 3 — Xray tunnel validation
    """
    cancel  = record["cancel"]
    workers = min(req.max_workers or MAX_WORKERS, MAX_WORKERS)
    mode    = req.mode

    try:
        with _scans_lock:
            record["status"] = "running"

        _push_event(record, "log", {
            "msg": f"🚀 Scan started | mode={mode} | workers={workers}"
        })

        # ── Stage 0A: Parse VLESS link ───────────────────────────
        _push_event(record, "progress", {"value": 5, "step": "parse"})

        parsed = parse_vless(req.link)
        if not parsed:
            raise ValueError("Invalid vless link — could not parse")

        _push_event(record, "log", {
            "msg": (
                f"✅ Link parsed | uuid={parsed['uuid'][:8]}... "
                f"| transport={parsed['type']} | security={parsed['security']}"
            )
        })

        # ── Stage 0B: Build candidates ───────────────────────────
        _push_event(record, "progress", {"value": 10, "step": "extract"})

        # template_sni: used as fixed SNI for Mode 2 (host from template)
        template_sni = (
            parsed.get("host")
            or parsed.get("sni")
            or parsed.get("address", "")
        )
        port = parsed.get("port", TCP_PORT)

        if req.targets_raw.strip():
            raw_targets = _parse_raw_targets(req.targets_raw)
            if not raw_targets:
                raise ValueError(
                    "Targets field has no valid entries. "
                    "Expected: CSV / IP / CIDR / domain format."
                )
        else:
            # Fallback: use only the link's address field as the single target.
            # extract_targets also pulls host/sni which are NOT scan targets.
            addr = parsed.get("address", "")
            if not addr:
                raise ValueError("No address found in vless link")
            raw_targets = [_classify_single(addr)]

        candidates = _build_candidates(raw_targets, mode, template_sni)

        if not candidates:
            raise ValueError(f"No valid candidates built for {mode}")

        # Inform user how many IPs came from CIDR expansion
        cidr_count = sum(1 for t in raw_targets if t["type"] == "cidr")
        if cidr_count:
            _push_event(record, "log", {
                "msg": f"  📡 {cidr_count} CIDR block(s) expanded to {len(candidates)} IPs total"
            })

        _push_event(record, "log", {
            "msg": f"🎯 {len(candidates)} candidate(s) ready"
        })

        if len(candidates) > 5000:
            _push_event(record, "log", {
                "msg": (
                    f"  ⚠️  Large scan ({len(candidates)} IPs) — "
                    f"Stage 1 may take several minutes with {MAX_WORKERS} workers"
                )
            })

        if cancel.is_set():
            raise ValueError("Scan cancelled by user")

        # ── Stage 1: TCP:443 + TLS handshake (or skip if force DNS) ────
        # Progress: 20% → 35% (granular updates as futures complete)
        _push_event(record, "progress", {"value": 20, "step": "stage1"})

        # Force Custom DNS: Skip Stage 1 for domains, go straight to DNS resolution
        if req.force_custom_dns and req.custom_dns.strip():
            _push_event(record, "log", {
                "msg": f"⚡ Force Custom DNS enabled - bypassing Stage 1 for domains"
            })

            # Separate domains from IPs
            stage1_passed = []
            failed_domains = []

            for c in candidates:
                # If it's a domain (has source_domain), force DNS resolution
                if c.get("source_domain"):
                    failed_domains.append(c)
                else:
                    # IPs still go through Stage 1
                    stage1_passed.append(c)

            if stage1_passed:
                _push_event(record, "log", {
                    "msg": f"🔌 Stage 1: TCP+TLS check on {len(stage1_passed)} IP candidate(s)..."
                })

                def _s1_progress(done, total):
                    pct = 20 + int((done / total) * 15)
                    with _scans_lock:
                        record["progress"] = pct
                    _push_event(record, "progress", {
                        "value": pct,
                        "step":  "stage1",
                        "done":  done,
                        "total": total,
                    })

                s1_passed, _ = _run_stage1_batch(stage1_passed, port, _s1_progress)
                stage1_passed = s1_passed
        else:
            # Normal flow: Test all candidates
            _push_event(record, "log", {
                "msg": f"🔌 Stage 1: TCP+TLS check on {len(candidates)} candidate(s)..."
            })

            def _s1_progress(done, total):
                pct = 20 + int((done / total) * 15)   # 20% → 35%
                with _scans_lock:
                    record["progress"] = pct
                _push_event(record, "progress", {
                    "value": pct,
                    "step":  "stage1",
                    "done":  done,
                    "total": total,
                })

            stage1_passed, failed_domains = _run_stage1_batch(candidates, port, _s1_progress)

        _push_event(record, "log", {
            "msg": (
                f"✅ Stage 1: {len(stage1_passed)} passed, "
                f"{len(failed_domains)} domain(s) going to DNS fallback"
            )
        })

        if cancel.is_set():
            raise ValueError("Scan cancelled by user")

        # ── Stage 2: DNS fallback for failed domains ─────────────
        if failed_domains:
            _push_event(record, "progress", {"value": 35, "step": "stage2"})
            _push_event(record, "log", {
                "msg": f"🔍 Stage 2: DNS fallback for {len(failed_domains)} domain(s)..."
            })

            stage2_resolved = _run_stage2(failed_domains, req.custom_dns, record)

            if stage2_resolved:
                _push_event(record, "log", {
                    "msg": f"🔌 Stage 2: TCP+TLS re-check on {len(stage2_resolved)} resolved IP(s)..."
                })

                def _s2_progress(done, total):
                    pct = 40 + int((done / total) * 10)  # 40% → 50%
                    with _scans_lock:
                        record["progress"] = pct
                    _push_event(record, "progress", {
                        "value": pct,
                        "step":  "stage2_check",
                        "done":  done,
                        "total": total,
                    })

                s2_passed, _ = _run_stage1_batch(stage2_resolved, port, _s2_progress)
                stage1_passed.extend(s2_passed)

                _push_event(record, "log", {
                    "msg": f"✅ Stage 2: {len(s2_passed)} additional IP(s) passed"
                })

        _push_event(record, "log", {
            "msg": f"📋 {len(stage1_passed)} candidate(s) ready for xray validation"
        })

        if not stage1_passed:
            raise ValueError(
                "No candidate passed TCP check (Stages 1 & 2). "
                "All targets are unreachable on port 443."
            )

        if cancel.is_set():
            raise ValueError("Scan cancelled by user")

        # ── Stage 3: Xray validation ─────────────────────────────
        _push_event(record, "progress", {"value": 50, "step": "stage3"})

        valid_results: list[dict] = []

        if req.skip_xray:
            _push_event(record, "log", {"msg": "⚡ Fast mode: xray validation skipped"})
            for c in stage1_passed:
                valid_results.append({
                    "connect_to": c["connect_to"],
                    "sni":        c["sni"],
                    "mode":       c["mode"],
                    "ok":         True,
                    "latency_ms": 0.0,
                })
        else:
            # ── Stage 3 with chunking for stability ──────────────────
            total = len(stage1_passed)
            done_count = 0

            # Split candidates into batches for better memory/CPU management
            batches = [
                stage1_passed[i:i + XRAY_BATCH_SIZE]
                for i in range(0, len(stage1_passed), XRAY_BATCH_SIZE)
            ]

            _push_event(record, "log", {
                "msg": f"🔬 Stage 3: {len(batches)} batch(es) of max {XRAY_BATCH_SIZE} candidates (for stability)"
            })

            def _xray_check(candidate, worker_id):
                return validate_with_xray(
                    parsed_config=parsed,
                    candidate=candidate,
                    port=port,
                    worker_id=worker_id,
                )

            # Process each batch sequentially (batches are independent)
            for batch_idx, batch in enumerate(batches):
                if cancel.is_set():
                    raise ValueError("Scan cancelled by user")

                # Early stop if max results reached
                if req.max_results and len(valid_results) >= req.max_results:
                    _push_event(record, "log", {
                        "msg": f"🎯 Reached {req.max_results} result(s) — skipping remaining batches"
                    })
                    break

                _push_event(record, "log", {
                    "msg": f"  📦 Batch {batch_idx + 1}/{len(batches)}: Testing {len(batch)} candidate(s)..."
                })

                # Test this batch in parallel
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = {
                        executor.submit(_xray_check, c, idx): c
                        for idx, c in enumerate(batch)
                    }

                    for future in concurrent.futures.as_completed(futures):
                        if cancel.is_set():
                            for f in futures:
                                f.cancel()
                            raise ValueError("Scan cancelled by user")

                        done_count += 1
                        result = future.result()

                        pct = 50 + int((done_count / total) * 40)
                        with _scans_lock:
                            record["progress"] = pct

                        _push_event(record, "progress", {
                            "value": pct,
                            "step":  f"stage3_batch{batch_idx+1}",
                            "done":  done_count,
                            "total": total,
                        })

                        if result["ok"]:
                            valid_results.append(result)

                            # Mode 1: Use original domain as address (not resolved IP)
                            # Mode 2: Use IP as address
                            if result["mode"] == "mode1" and result.get("source_domain"):
                                config_address = result["source_domain"]  # Use domain for resilience
                                # Show "domain (IP)" in UI for clarity
                                display_address = f"{result['source_domain']} ({result['connect_to']})"
                            else:
                                config_address = result["connect_to"]     # Use IP
                                display_address = result["connect_to"]

                            _push_event(record, "result", {
                                "ip":         display_address,
                                "latency_ms": result["latency_ms"],
                                "link":       build_vless_link(
                                    parsed,
                                    config_address,  # Domain for mode1, IP for mode2
                                    result["sni"],
                                    result["mode"],
                                    result["latency_ms"],
                                ),
                            })

                            # Early stop once max_results good results collected
                            if req.max_results and len(valid_results) >= req.max_results:
                                _push_event(record, "log", {
                                    "msg": f"🎯 Reached {req.max_results} result(s) — stopping early"
                                })
                                for f in futures:
                                    f.cancel()
                                break

                # Log batch completion
                batch_results = sum(1 for r in valid_results if r in valid_results[-len(batch):])
                _push_event(record, "log", {
                    "msg": f"  ✅ Batch {batch_idx + 1}: {batch_results}/{len(batch)} passed"
                })

        # ── Final: sort + store ──────────────────────────────────
        _push_event(record, "progress", {"value": 95, "step": "build"})

        # None latency (skip_xray mode) sorts to the end
        valid_results.sort(key=lambda x: x["latency_ms"] if x["latency_ms"] is not None else float("inf"))

        final_results = []
        for r in valid_results:
            # Mode 1: Use original domain as address (not resolved IP)
            # Mode 2: Use IP as address
            if r["mode"] == "mode1" and r.get("source_domain"):
                config_address = r["source_domain"]
            else:
                config_address = r["connect_to"]

            # Show "domain (IP)" for Mode 1, just IP for Mode 2
            if r["mode"] == "mode1" and r.get("source_domain"):
                display_address = f"{r['source_domain']} ({r['connect_to']})"
            else:
                display_address = r["connect_to"]

            final_results.append({
                "ip":         display_address,  # Show domain + IP for Mode 1
                "latency_ms": r["latency_ms"] or 0.0,
                "link":       build_vless_link(
                    parsed,
                    config_address,  # Domain for mode1, IP for mode2
                    r["sni"],
                    r["mode"],
                    r["latency_ms"],
                ),
            })

        with _scans_lock:
            record["results"]  = final_results
            record["status"]   = "done"
            record["progress"] = 100

        _push_event(record, "log", {
            "msg": f"✅ Scan finished | {len(final_results)} valid candidate(s) found"
        })
        _push_event(record, "done", {"total_results": len(final_results)})

    except Exception as e:
        with _scans_lock:
            record["status"] = "error"
            record["error"]  = str(e)
        _push_event(record, "error", {"msg": str(e)})
        _push_event(record, "done",  {"total_results": 0})


def _classify_single(value: str) -> dict:
    """Classify a single string as ip / cidr / domain."""
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


# ════════════════════════════════════════════════════════════
# WebSocket
# ════════════════════════════════════════════════════════════

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    record = _get_scan(scan_id)
    if not record:
        await websocket.close(code=4004, reason="scan not found")
        return

    await websocket.accept()

    # Send current state immediately so late connections are caught up
    await websocket.send_json({
        "type":    "progress",
        "payload": {"value": record["progress"], "step": record["status"]},
        "ts":      datetime.now(timezone.utc).isoformat(),
    })

    try:
        while True:
            try:
                event = await asyncio.wait_for(record["events"].get(), timeout=30.0)
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({
                        "type": "ping", "payload": {},
                        "ts":   datetime.now(timezone.utc).isoformat(),
                    })
                    continue
                except Exception:
                    break

            await websocket.send_json(event)

            if event["type"] in ("done", "error"):
                await asyncio.sleep(0.1)
                break

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════
# Cleanup
# ════════════════════════════════════════════════════════════

@app.on_event("startup")
async def start_cleanup_task():
    asyncio.create_task(_cleanup_old_scans())


async def _cleanup_old_scans():
    MAX_AGE_SECONDS = 3600
    while True:
        await asyncio.sleep(600)
        now = datetime.now(timezone.utc)
        to_delete = []
        with _scans_lock:
            for sid, rec in _scans.items():
                if rec["status"] in ("done", "error"):
                    if (now - rec["created"]).total_seconds() > MAX_AGE_SECONDS:
                        to_delete.append(sid)
            for sid in to_delete:
                del _scans[sid]
        if to_delete:
            print(f"🧹 {len(to_delete)} old scan(s) deleted")


# ════════════════════════════════════════════════════════════
# Entry Point
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    import webbrowser
    import threading

    port = int(os.environ.get("PORT", 5000))

    print(f"")
    print(f"  ╔══════════════════════════════════╗")
    print(f"  ║   {APP_NAME} v{VERSION}          ║")
    print(f"  ║   http://localhost:{port}           ║")
    print(f"  ╚══════════════════════════════════╝")
    print(f"")

    # Auto-open browser after 1.5 seconds (gives server time to start)
    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open(f"http://localhost:{port}")

    threading.Thread(target=open_browser, daemon=True).start()

    uvicorn.run(
        "main:app" if os.getenv("DEV_MODE") else app,
        host="0.0.0.0",
        port=port,
        reload=bool(os.getenv("DEV_MODE")),
        log_level="info",
        ws_ping_interval=20,
        ws_ping_timeout=30,
    )
