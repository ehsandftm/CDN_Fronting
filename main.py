# ════════════════════════════════════════════════════════════
# CDN Scanner - main.py  (پارت 1 از 3)
# FastAPI server + WebSocket real-time progress
# ════════════════════════════════════════════════════════════

# ── Imports استاندارد ──────────────────────────────────────
import os
import uuid
import asyncio
import threading
import concurrent.futures
from datetime import datetime, timezone
from typing import Optional

# ── FastAPI ────────────────────────────────────────────────
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# ── Core modules (همه از __init__.py export شدن) ──────────
from core import (
    parse_vless,
    extract_targets,
    resolve_domain,
    tcp_ping_batch,
    validate_with_xray,
    build_vless_link,
    TCP_PORT,
    MAX_WORKERS,
    APP_NAME,
    VERSION,
)

# ════════════════════════════════════════════════════════════
# App Setup
# ════════════════════════════════════════════════════════════

app = FastAPI(
    title=APP_NAME,
    version=VERSION,
    # docs فقط در dev mode فعاله
    docs_url="/docs" if os.getenv("DEV_MODE") else None,
    redoc_url=None,
)

# فایل‌های static (index.html و ...) رو سرو میکنه
# اگه پوشه static وجود داشت mount میکنه
_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount(
        "/static",
        StaticFiles(directory=_static_dir),
        name="static",
    )

# ════════════════════════════════════════════════════════════
# Scan Storage
# در حافظه نگه میداریم - برای یه .exe standalone کافیه
# ════════════════════════════════════════════════════════════

# هر scan یه dict داره با این ساختار:
# {
#   "status":   "pending" | "running" | "done" | "error",
#   "progress": 0-100,
#   "results":  [...],
#   "error":    None | str,
#   "created":  datetime,
#   "events":   asyncio.Queue  ← پیام‌های WebSocket اینجا میان
# }
_scans: dict[str, dict] = {}

# Lock برای thread-safe دسترسی به _scans
_scans_lock = threading.Lock()


def _new_scan_record() -> tuple[str, dict]:
    """
    یه scan record جدید میسازه و scan_id برمیگردونه.
    هم scan_id هم record رو برمیگردونه.
    """
    scan_id = str(uuid.uuid4())
    record = {
        "status":   "pending",
        "progress": 0,
        "results":  [],
        "error":    None,
        "created":  datetime.now(timezone.utc),
        # asyncio.Queue برای ارسال event به WebSocket
        # maxsize=0 یعنی نامحدود
        "events":   asyncio.Queue(maxsize=0),
    }
    with _scans_lock:
        _scans[scan_id] = record
    return scan_id, record


def _get_scan(scan_id: str) -> Optional[dict]:
    """scan record رو از storage میگیره."""
    with _scans_lock:
        return _scans.get(scan_id)


# ════════════════════════════════════════════════════════════
# Pydantic Models - اعتبارسنجی ورودی/خروجی
# ════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    """
    ورودی POST /scan
    فقط link اجباریه، بقیه اختیاری
    """
    link: str                          # vless:// link اصلی
    max_workers: Optional[int] = None  # override MAX_WORKERS اگه خواستن
    skip_xray: bool = False            # فقط TCP check (سریع‌تر)


class ScanStartResponse(BaseModel):
    """خروجی POST /scan - فقط scan_id برمیگردونه"""
    ok: bool
    scan_id: str
    ws_url: str   # آدرس WebSocket که UI باید connect کنه


class ScanResult(BaseModel):
    """یه نتیجه موفق برای یه IP"""
    ip:         str
    latency_ms: float
    link:       str


class ScanStatusResponse(BaseModel):
    """خروجی GET /scan/{scan_id}/status"""
    ok:       bool
    scan_id:  str
    status:   str
    progress: int
    results:  list[ScanResult]
    error:    Optional[str]


# ════════════════════════════════════════════════════════════
# Routes - صفحه اصلی و health
# ════════════════════════════════════════════════════════════

@app.get("/", include_in_schema=False)
async def serve_index():
    """
    صفحه اصلی - index.html رو سرو میکنه.
    اگه فایل نبود، یه پیام ساده برمیگردونه.
    """
    index_path = os.path.join(_static_dir, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    # fallback اگه static folder نبود
    return JSONResponse({
        "app":     APP_NAME,
        "version": VERSION,
        "status":  "running",
        "hint":    "place index.html in ./static/",
    })


@app.get("/health", tags=["system"])
async def health_check():
    """
    Health check endpoint.
    برای بررسی اینکه سرور زنده‌ست.
    """
    return {
        "status":  "ok",
        "app":     APP_NAME,
        "version": VERSION,
        "time":    datetime.now(timezone.utc).isoformat(),
    }


@app.get("/scan/{scan_id}/status", tags=["scan"])
async def get_scan_status(scan_id: str):
    """
    GET /scan/{scan_id}/status
    وضعیت فعلی یه scan رو برمیگردونه.
    برای polling - اگه WebSocket نداشتن.
    """
    record = _get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan not found")

    return ScanStatusResponse(
        ok=True,
        scan_id=scan_id,
        status=record["status"],
        progress=record["progress"],
        results=[
            ScanResult(
                ip=r["ip"],
                latency_ms=r["latency_ms"],
                link=r["link"],
            )
            for r in record["results"]
        ],
        error=record["error"],
    )
# ════════════════════════════════════════════════════════════
# CDN Scanner - main.py  (پارت 2 از 3)
# POST /scan + scan engine (pipeline کامل)
# ════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════
# Event Helper
# هر پیامی که به WebSocket میره از اینجا میگذره
# ════════════════════════════════════════════════════════════

def _push_event(record: dict, event_type: str, payload: dict):
    """
    یه event به Queue اضافه میکنه.
    چون این تابع در thread معمولی (sync) صدا زده میشه،
    از put_nowait استفاده میکنیم نه await.

    event_type های ممکن:
      - "progress"  → آپدیت درصد پیشرفت
      - "result"    → یه IP موفق پیدا شد
      - "log"       → پیام لاگ برای UI
      - "done"      → اسکن تموم شد
      - "error"     → خطا رخ داد
    """
    event = {
        "type":    event_type,
        "payload": payload,
        "ts":      datetime.now(timezone.utc).isoformat(),
    }
    try:
        # put_nowait چون در thread sync هستیم
        record["events"].put_nowait(event)
    except Exception:
        # اگه Queue پر بود یا بسته بود، نادیده میگیریم
        pass


# ════════════════════════════════════════════════════════════
# Scan Engine - قلب برنامه
# این تابع در یه thread جداگانه اجرا میشه
# تا event loop اصلی FastAPI بلاک نشه
# ════════════════════════════════════════════════════════════

def _run_scan(scan_id: str, record: dict, req: ScanRequest):
    """
    Pipeline کامل اسکن:
      1. Parse vless link
      2. Extract targets
      3. Resolve domains → IPs
      4. TCP check (فیلتر سریع)
      5. Xray validation (اختیاری)
      6. ساخت link های نهایی
    """

    # تعداد worker ها - از request یا default
    workers = min(req.max_workers or MAX_WORKERS, MAX_WORKERS)

    try:
        # ── وضعیت: در حال اجرا ──────────────────────
        with _scans_lock:
            record["status"] = "running"

        _push_event(record, "log", {
            "msg": f"🚀 شروع اسکن | workers={workers}"
        })

        # ════════════════════════════════════════════
        # مرحله 1: Parse کردن vless link
        # ════════════════════════════════════════════
        _push_event(record, "progress", {"value": 5, "step": "parse"})

        try:
            parsed = parse_vless(req.link)
        except Exception as e:
            raise ValueError(f"خطا در parse link: {e}")

        _push_event(record, "log", {
            "msg": f"✅ Link parse شد | uuid={parsed['uuid'][:8]}..."
        })

        # ════════════════════════════════════════════
        # مرحله 2: استخراج targets از link
        # domain_parser متن خام link رو میخواد
        # ════════════════════════════════════════════
        _push_event(record, "progress", {"value": 10, "step": "extract"})

        targets = extract_targets(req.link)
        if not targets:
            raise ValueError("هیچ IP یا domain ای در link پیدا نشد")

        _push_event(record, "log", {
            "msg": f"🎯 {len(targets)} target پیدا شد"
        })

        # ════════════════════════════════════════════
        # مرحله 3: Resolve کردن domain ها به IP
        # ════════════════════════════════════════════
        _push_event(record, "progress", {"value": 20, "step": "resolve"})

        resolved_ips = []
        for t in targets:
            if t["type"] == "domain":
                # DoH resolver - domain → list of IPs
                ips = resolve_domain(t["value"])
                _push_event(record, "log", {
                    "msg": f"🔍 {t['value']} → {len(ips)} IP"
                })
                for ip in ips:
                    # IP های resolve شده رو به فرمت استاندارد تبدیل میکنیم
                    resolved_ips.append({"value": ip, "type": "ip"})
            else:
                # IP یا CIDR مستقیم اضافه میشه
                resolved_ips.append(t)

        if not resolved_ips:
            raise ValueError("هیچ IP ای resolve نشد")

        _push_event(record, "log", {
            "msg": f"📋 {len(resolved_ips)} IP برای تست آماده شد"
        })

        # ════════════════════════════════════════════
        # مرحله 4: TCP Check (فیلتر سریع)
        # فقط IPهایی که پورت باز دارن رو نگه میداریم
        # ════════════════════════════════════════════
        _push_event(record, "progress", {"value": 35, "step": "tcp"})

        port = parsed.get("port", TCP_PORT)
        tcp_results = tcp_ping_batch(resolved_ips, port)

        # فقط موفق‌ها رو نگه میداریم
        reachable = [r for r in tcp_results if r["tcp_ok"]]

        _push_event(record, "log", {
            "msg": (
                f"🔌 TCP check: {len(reachable)}/{len(resolved_ips)} "
                f"IP قابل دسترس"
            )
        })

        if not reachable:
            raise ValueError("هیچ IP ای از TCP check رد نشد")

        # ════════════════════════════════════════════
        # مرحله 5: Xray Validation (موازی)
        # اگه skip_xray=True بود، این مرحله رو رد میکنیم
        # ════════════════════════════════════════════
        _push_event(record, "progress", {"value": 50, "step": "xray"})

        valid_results = []

        if req.skip_xray:
            # ── حالت سریع: فقط TCP نتایج ─────────────
            _push_event(record, "log", {
                "msg": "⚡ حالت سریع: xray validation رد شد"
            })
            # TCP نتایج رو به فرمت xray نتایج تبدیل میکنیم
            for item in reachable:
                valid_results.append({
                    "ok":         True,
                    "ip":         item["value"],
                    "latency_ms": item.get("latency_ms", 0.0),
                })
        else:
            # ── حالت کامل: xray tunnel test ──────────
            total = len(reachable)
            done_count = 0

            def _xray_check(item, worker_id):
                """هر IP رو با xray تست میکنه."""
                return validate_with_xray(
                    parsed_config=parsed,
                    test_ip=item["value"],
                    port=port,
                    worker_id=worker_id,
                )

            # ThreadPoolExecutor - همه رو موازی تست میکنیم
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=workers
            ) as executor:

                futures = {
                    executor.submit(_xray_check, item, idx): item
                    for idx, item in enumerate(reachable)
                }

                for future in concurrent.futures.as_completed(futures):
                    done_count += 1
                    result = future.result()

                    # درصد پیشرفت: از 50% تا 90%
                    progress_val = 50 + int((done_count / total) * 40)
                    with _scans_lock:
                        record["progress"] = progress_val

                    _push_event(record, "progress", {
                        "value": progress_val,
                        "step":  "xray",
                        "done":  done_count,
                        "total": total,
                    })

                    if result["ok"]:
                        valid_results.append(result)
                        # بلافاصله نتیجه رو به UI میفرستیم
                        _push_event(record, "result", {
                            "ip":         result["ip"],
                            "latency_ms": result["latency_ms"],
                            "link": build_vless_link(parsed, result["ip"]),
                        })

        # ════════════════════════════════════════════
        # مرحله 6: ساخت link های نهایی + مرتب‌سازی
        # ════════════════════════════════════════════
        _push_event(record, "progress", {"value": 95, "step": "build"})

        # بر اساس latency مرتب میکنیم (بهترین اول)
        valid_results.sort(key=lambda x: x["latency_ms"])

        final_results = []
        for r in valid_results:
            final_results.append({
                "ip":         r["ip"],
                "latency_ms": r["latency_ms"],
                "link":       build_vless_link(parsed, r["ip"]),
            })

        # نتایج رو در record ذخیره میکنیم
        with _scans_lock:
            record["results"]  = final_results
            record["status"]   = "done"
            record["progress"] = 100

        _push_event(record, "log", {
            "msg": f"✅ اسکن تموم شد | {len(final_results)} IP موفق"
        })

        # سیگنال پایان به WebSocket
        _push_event(record, "done", {
            "total_results": len(final_results),
        })

    except Exception as e:
        # ── مدیریت خطا ───────────────────────────────
        with _scans_lock:
            record["status"] = "error"
            record["error"]  = str(e)

        _push_event(record, "error", {"msg": str(e)})
        _push_event(record, "done",  {"total_results": 0})


# ════════════════════════════════════════════════════════════
# Route: POST /scan
# اسکن رو شروع میکنه و scan_id برمیگردونه
# ════════════════════════════════════════════════════════════

@app.post("/scan", tags=["scan"])
async def start_scan(req: ScanRequest):
    """
    POST /scan
    Body: { "link": "vless://...", "skip_xray": false }

    Returns: { "ok": true, "scan_id": "...", "ws_url": "ws://..." }

    UI باید:
      1. این endpoint رو صدا بزنه
      2. scan_id بگیره
      3. به ws_url وصل بشه برای real-time progress
    """

    # اعتبارسنجی link
    raw_link = req.link.strip()
    if not raw_link.startswith("vless://"):
        raise HTTPException(
            status_code=400,
            detail="فقط vless:// link پشتیبانی میشه",
        )

    # ساخت record جدید
    scan_id, record = _new_scan_record()

    # scan رو در یه thread جداگانه اجرا میکنیم
    # تا event loop اصلی FastAPI بلاک نشه
    thread = threading.Thread(
        target=_run_scan,
        args=(scan_id, record, req),
        daemon=True,   # با بسته شدن برنامه thread هم میمیره
        name=f"scan-{scan_id[:8]}",
    )
    thread.start()

    return {
        "ok":      True,
        "scan_id": scan_id,
        # UI باید به این آدرس WebSocket وصل بشه
        "ws_url":  f"/ws/{scan_id}",
    }
# ════════════════════════════════════════════════════════════
# CDN Scanner - main.py  (پارت 3 از 3)
# WebSocket /ws/{scan_id} + __main__ runner
# ════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════
# WebSocket Route
# UI از اینجا real-time progress میگیره
# ════════════════════════════════════════════════════════════

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """
    WebSocket /ws/{scan_id}

    UI باید:
      1. POST /scan بزنه → scan_id بگیره
      2. به این endpoint وصل بشه
      3. منتظر event بمونه

    فرمت هر event که میفرستیم (JSON):
    {
      "type":    "progress" | "result" | "log" | "done" | "error",
      "payload": { ... },
      "ts":      "2024-01-01T00:00:00Z"
    }

    انواع event:
      progress → { "value": 0-100, "step": "tcp"|"xray"|... }
      result   → { "ip": "...", "latency_ms": 123, "link": "vless://..." }
      log      → { "msg": "..." }
      done     → { "total_results": N }
      error    → { "msg": "..." }
    """

    # ── 1. پیدا کردن scan record ─────────────────────
    record = _get_scan(scan_id)
    if not record:
        # scan_id نامعتبر - connection رو رد میکنیم
        await websocket.close(code=4004, reason="scan not found")
        return

    # ── 2. قبول کردن connection ──────────────────────
    await websocket.accept()

    # وضعیت فعلی رو بلافاصله میفرستیم
    # (اگه client دیر وصل شد، از اول بدونه)
    await websocket.send_json({
        "type": "progress",
        "payload": {
            "value": record["progress"],
            "step":  record["status"],
        },
        "ts": datetime.now(timezone.utc).isoformat(),
    })

    # ── 3. Loop اصلی: خوندن از Queue و فرستادن به UI ─
    try:
        while True:
            # از Queue یه event میگیریم
            # asyncio.wait_for با timeout جلوگیری میکنه از hang کردن
            try:
                event = await asyncio.wait_for(
                    record["events"].get(),
                    timeout=30.0,   # 30 ثانیه صبر میکنیم
                )
            except asyncio.TimeoutError:
                # اگه 30 ثانیه event نیومد، یه ping میفرستیم
                # تا connection زنده بمونه
                try:
                    await websocket.send_json({
                        "type":    "ping",
                        "payload": {},
                        "ts":      datetime.now(timezone.utc).isoformat(),
                    })
                    continue
                except Exception:
                    # اگه ping هم fail شد، client رفته
                    break

            # event رو به UI میفرستیم
            await websocket.send_json(event)

            # اگه "done" یا "error" بود، loop رو تموم میکنیم
            if event["type"] in ("done", "error"):
                # کمی صبر میکنیم تا پیام برسه
                await asyncio.sleep(0.1)
                break

    except WebSocketDisconnect:
        # client خودش disconnect کرد - مشکلی نیست
        pass
    except Exception:
        # هر خطای دیگه‌ای رو نادیده میگیریم
        # scan در thread خودش ادامه میده
        pass
    finally:
        # connection رو میبندیم
        try:
            await websocket.close()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════
# Cleanup - پاک کردن scan های قدیمی
# از پر شدن حافظه جلوگیری میکنه
# ════════════════════════════════════════════════════════════

@app.on_event("startup")
async def start_cleanup_task():
    """
    یه background task راه میندازه که هر 10 دقیقه
    scan های قدیمی (بیشتر از 1 ساعت) رو پاک میکنه.
    """
    asyncio.create_task(_cleanup_old_scans())


async def _cleanup_old_scans():
    """
    هر 10 دقیقه scan های قدیمی رو پاک میکنه.
    scan هایی که بیشتر از 3600 ثانیه (1 ساعت) پیر شدن.
    """
    MAX_AGE_SECONDS = 3600  # 1 ساعت

    while True:
        # هر 10 دقیقه یه بار اجرا میشه
        await asyncio.sleep(600)

        now = datetime.now(timezone.utc)
        to_delete = []

        with _scans_lock:
            for sid, rec in _scans.items():
                # فقط scan های تموم‌شده رو پاک میکنیم
                if rec["status"] in ("done", "error"):
                    age = (now - rec["created"]).total_seconds()
                    if age > MAX_AGE_SECONDS:
                        to_delete.append(sid)

            for sid in to_delete:
                del _scans[sid]

        if to_delete:
            print(f"🧹 {len(to_delete)} scan قدیمی پاک شد")


# ════════════════════════════════════════════════════════════
# CORS Middleware (اختیاری)
# اگه UI از domain دیگه‌ای لود میشه، این لازمه
# ════════════════════════════════════════════════════════════

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    # در production باید domain مشخص بشه
    # فعلاً برای dev همه رو قبول میکنیم
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ════════════════════════════════════════════════════════════
# Entry Point
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    # پورت از environment variable یا 5000
    port = int(os.environ.get("PORT", 5000))

    print(f"")
    print(f"  ╔══════════════════════════════════╗")
    print(f"  ║   {APP_NAME} v{VERSION}          ║")
    print(f"  ║   http://localhost:{port}           ║")
    print(f"  ╚══════════════════════════════════╝")
    print(f"")

    uvicorn.run(
        # اگه DEV_MODE بود، reload فعاله
        "main:app" if os.getenv("DEV_MODE") else app,
        host="0.0.0.0",
        port=port,
        # reload فقط در dev mode
        reload=bool(os.getenv("DEV_MODE")),
        # لاگ‌های کمتر در production
        log_level="info",
        # WebSocket timeout
        ws_ping_interval=20,
        ws_ping_timeout=30,
    )