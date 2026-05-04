# core/xray_validator.py
# Stage 3: Validate a working IP using xray as a real tunnel
#
# Pipeline:
#   1. Build a temporary xray config JSON
#   2. Launch xray.exe as a background subprocess
#   3. Wait for xray SOCKS5 port to open
#   4. Send HTTP GET through xray SOCKS5 proxy
#   5. Return result + latency
#
# ── FIX تاریخچه ──────────────────────────────────────────────────────────────
# مشکل: HTTP 404 به عنوان FAIL تشخیص داده می‌شد
# دلیل: test_url = connectivitycheck.gstatic.com
#        سرور پشت CDN این URL را نمی‌شناخت → 404
#        ولی 404 یعنی tunnel کار می‌کند! فقط URL اشتباه بود.
# راه‌حل:
#   1. test_url را به gstatic.com/generate_204 تغییر دادیم
#   2. _VALID_STATUS_CODES را گسترش دادیم تا 404 هم OK باشد
#   3. فقط timeout و 5xx را FAIL می‌دانیم
# ─────────────────────────────────────────────────────────────────────────────

import os
import json
import time
import socket
import subprocess
import tempfile
import httpx
from core import XRAY_TIMEOUT, XRAY_BINARY

# ── تنظیمات اصلی ─────────────────────────────────────────────────────────────

# Base port برای SOCKS5 proxy های محلی
# هر worker یه port منحصربه‌فرد می‌گیرد تا conflict نشود
# worker 0 → 10800
# worker 1 → 10801
# worker 2 → 10802
# ...
_BASE_PORT = 10800

# DEBUG FLAG:
# True  = نمایش xray logs و config (برای debugging)
# False = حالت silent (برای production)
_DEBUG = False

# ── HTTP Status Codes که نشان‌دهنده "tunnel کار می‌کند" هستند ────────────────
#
# منطق اصلی:
#   اگه HTTP response از سرور گرفتیم → tunnel کار می‌کند ✅
#   اگه timeout یا connection error → tunnel کار نمی‌کند ❌
#   اگه 5xx → سرور خراب است ❌
#
# چرا 404 هم OK است؟
#   وقتی xray tunnel برقرار است و request به سرور می‌رسد،
#   سرور ممکن است برای URL ناشناخته 404 بدهد.
#   این یعنی tunnel کار می‌کند - فقط URL اشتباه است.
#
# چرا 301/302 هم OK است؟
#   Redirect = سرور جواب داد و ما را به جای دیگری هدایت کرد.
#   این نشان می‌دهد tunnel برقرار است.
#
# چرا 403 هم OK است؟
#   Forbidden = سرور جواب داد ولی دسترسی نداریم.
#   این هم نشان می‌دهد tunnel برقرار است.
#
# چه چیزی FAIL است؟
#   - timeout → xray یا CDN جواب نمی‌دهد
#   - connection error → tunnel برقرار نشد
#   - 5xx → سرور خراب است (مشکل از IP است)
_VALID_STATUS_CODES = {200, 204, 301, 302, 403, 404}


def _wait_for_port(port: int, timeout: float = 3.0) -> bool:
    """
    صبر می‌کند تا xray پورت SOCKS5 خود را باز کند.

    به جای time.sleep ثابت، هر 100ms چک می‌کنیم.
    این هم سریع‌تر است هم قابل‌اطمینان‌تر.

    Returns:
        True  = پورت باز شد (xray آماده است)
        False = timeout شد (xray start نشد)
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            # سعی می‌کنیم به پورت وصل شویم
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True  # پورت باز است!
        except (ConnectionRefusedError, OSError):
            # هنوز باز نشده، 100ms صبر می‌کنیم
            time.sleep(0.1)
    return False  # timeout شد


def validate_with_xray(
    parsed_config: dict,
    test_ip: str,
    port: int,
    worker_id: int = 0,
    # ── FIX: test_url تغییر کرد ──────────────────────────────
    # قبلاً: http://connectivitycheck.gstatic.com
    #   مشکل: سرور این URL را نمی‌شناخت → 404 → FAIL اشتباه
    #
    # حالا: https://www.gstatic.com/generate_204
    #   این URL همیشه 204 برمی‌گرداند
    #   اگه CDN آن را block کند، 404 می‌آید که ما آن را هم OK می‌دانیم
    test_url: str = "https://www.gstatic.com/generate_204",
) -> dict:
    """
    یک IP را با xray به عنوان tunnel واقعی تست می‌کند.

    Args:
        parsed_config: خروجی parse_vless() - فیلدهای config اصلی
        test_ip:       آدرس IP برای تست
        port:          پورت سرور (معمولاً 443)
        worker_id:     شماره worker برای port منحصربه‌فرد SOCKS5
        test_url:      URL برای GET از طریق xray proxy

    Returns:
        {
            "ip":         "1.2.3.4",
            "ok":         True / False,
            "latency_ms": 123.4 or None,
            "error":      "" or error message
        }
    """

    # پورت محلی منحصربه‌فرد برای این worker
    local_port = _BASE_PORT + worker_id

    # ساخت config موقت xray
    config = _build_xray_config(parsed_config, test_ip, port, local_port)

    tmp_file  = None
    xray_proc = None

    try:
        # نوشتن xray config در یک فایل JSON موقت
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        ) as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
            tmp_file = f.name

        if _DEBUG:
            print(f"\n[DEBUG] Config: {tmp_file}")
            print(f"[DEBUG] Testing: {test_ip}:{port} -> SOCKS5:{local_port}")
            with open(tmp_file, "r", encoding="utf-8") as dbg:
                print(f"[DEBUG] Content:\n{dbg.read()}")

        # پیدا کردن مسیر xray.exe
        # ساختار پروژه: CDN-Scanner/xray/xray.exe
        xray_path = os.path.join("xray", XRAY_BINARY)
        if not os.path.exists(xray_path):
            return _fail(test_ip, f"xray.exe not found at: {xray_path}")

        # اجرای xray به عنوان background process
        # creationflags=CREATE_NO_WINDOW: پنجره console در Windows مخفی می‌شود
        if _DEBUG:
            xray_proc = subprocess.Popen(
                [xray_path, "run", "-c", tmp_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            xray_proc = subprocess.Popen(
                [xray_path, "run", "-c", tmp_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

        # صبر می‌کنیم تا xray پورت SOCKS5 را باز کند (حداکثر 3 ثانیه)
        port_ready = _wait_for_port(local_port, timeout=3.0)

        if not port_ready:
            if _DEBUG and xray_proc.stderr:
                err = xray_proc.stderr.read().decode("utf-8", errors="replace")
                print(f"[DEBUG] xray failed to open port: {err[:500]}")
            return _fail(test_ip, "xray failed to start (port not opened)")

        # بررسی می‌کنیم xray هنوز زنده است
        if xray_proc.poll() is not None:
            return _fail(test_ip, f"xray crashed (exit={xray_proc.poll()})")

        if _DEBUG:
            print(f"[DEBUG] xray port {local_port} is OPEN and ready")

        # ارسال request تست از طریق SOCKS5 proxy
        start = time.perf_counter()

        result = _test_via_socks5(
            socks_host="127.0.0.1",
            socks_port=local_port,
            test_url=test_url,
            timeout=XRAY_TIMEOUT,
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        if _DEBUG:
            print(f"[DEBUG] Result: {result} in {elapsed_ms:.1f}ms")

        if result["ok"]:
            return {
                "ip":         test_ip,
                "ok":         True,
                "latency_ms": round(elapsed_ms, 1),
                "error":      "",
            }
        else:
            return _fail(test_ip, result["error"])

    except Exception as e:
        if _DEBUG:
            print(f"[DEBUG] EXCEPTION for {test_ip}: {type(e).__name__}: {e}")
        return _fail(test_ip, str(e))

    finally:
        # همیشه xray را kill می‌کنیم و فایل موقت را پاک می‌کنیم
        # finally = حتی اگه exception بیاید اجرا می‌شود
        if xray_proc:
            if _DEBUG:
                try:
                    if xray_proc.stderr:
                        remaining = xray_proc.stderr.read(500)
                        if remaining:
                            txt = remaining.decode("utf-8", errors="replace")
                            if txt.strip():
                                print(f"[DEBUG] xray logs: {txt}")
                except Exception:
                    pass
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
    test_url: str,
    timeout: float,
) -> dict:
    """
    یک HTTP GET از طریق SOCKS5 proxy ارسال می‌کند.

    ── FIX: منطق تشخیص موفقیت ──────────────────────────────────────────────
    قبلاً: فقط 200 و 204 را OK می‌دانستیم
    حالا:  هر status code که نشان‌دهنده "tunnel کار می‌کند" باشد را OK می‌دانیم

    چرا follow_redirects=False؟
        301/302 را خودمان OK می‌دانیم.
        اگه redirect را دنبال کنیم، ممکن است به URL دیگری برویم
        که آن URL هم 404 بدهد و ما گیج شویم.
        بهتر است همان اولین response را بگیریم.

    چرا verify=False؟
        بعضی CDN IP ها certificate اشتباه دارند.
        ما فقط می‌خواهیم بدانیم tunnel کار می‌کند،
        نه اینکه certificate معتبر است.
    """
    try:
        # آدرس SOCKS5 proxy که xray باز کرده
        proxy_url = f"socks5://127.0.0.1:{socks_port}"

        with httpx.Client(
            mounts={
                # "all://" = این proxy را برای همه protocol ها اعمال کن
                # http + https هر دو از طریق xray می‌روند
                "all://": httpx.HTTPTransport(
                    proxy=httpx.Proxy(proxy_url),
                ),
            },
            timeout=timeout,
            # redirect را دنبال نمی‌کنیم - 301/302 خودش OK است
            follow_redirects=False,
            # certificate validation را غیرفعال می‌کنیم
            verify=False,
        ) as client:
            response = client.get(test_url)

        status = response.status_code

        if _DEBUG:
            print(f"[DEBUG] HTTP status: {status}")

        # ── منطق تشخیص موفقیت ────────────────────────────────────────────────
        #
        # CASE 1: status در لیست _VALID_STATUS_CODES است
        #   → tunnel کار می‌کند ✅
        if status in _VALID_STATUS_CODES:
            return {"ok": True, "error": ""}

        # CASE 2: 5xx = مشکل از سرور است
        #   → این IP مشکل دارد یا سرور خراب است ❌
        elif 500 <= status < 600:
            return {"ok": False, "error": f"server error: HTTP {status}"}

        # CASE 3: هر status code دیگری (مثل 429, 407, 410, ...)
        #   → باز هم یعنی tunnel کار می‌کند، فقط سرور یه چیز خاص برگرداند
        #   → OK می‌دانیم ✅
        else:
            if _DEBUG:
                print(f"[DEBUG] Unexpected status {status} - treating as OK (tunnel works)")
            return {"ok": True, "error": ""}

    except httpx.TimeoutException:
        # timeout = xray یا CDN جواب نداد
        # این یعنی tunnel کار نمی‌کند ❌
        return {"ok": False, "error": "timeout"}

    except httpx.ProxyError as e:
        # proxy error = نتوانستیم به SOCKS5 proxy وصل شویم
        # یا xray crash کرد یا port بسته شد ❌
        return {"ok": False, "error": f"proxy error: {e}"}

    except httpx.ConnectError as e:
        # connection error = tunnel برقرار نشد ❌
        return {"ok": False, "error": f"connect error: {e}"}

    except Exception as e:
        # هر خطای دیگری
        return {"ok": False, "error": str(e)}


def _fail(ip: str, error: str) -> dict:
    """
    یک نتیجه شکست استاندارد برمی‌گرداند.

    این تابع کمکی است تا همه جاهایی که FAIL برمی‌گردانیم
    یک فرمت یکسان داشته باشند.
    """
    return {
        "ip":         ip,
        "ok":         False,
        "latency_ms": None,
        "error":      error,
    }


def _build_xray_config(parsed: dict, ip: str, port: int, local_port: int) -> dict:
    """
    یک xray JSON config کامل برای یک IP تست می‌سازد.

    ساختار config:
    ┌─────────────────────────────────────────────────────┐
    │  httpx                                              │
    │    ↓                                                │
    │  SOCKS5 (127.0.0.1:local_port)  ← inbound          │
    │    ↓                                                │
    │  xray                                               │
    │    ↓                                                │
    │  CDN IP (ip:port) با TLS/WS     ← outbound         │
    │    ↓                                                │
    │  سرور اصلی                                          │
    └─────────────────────────────────────────────────────┘

    Args:
        parsed:     خروجی parse_vless() - تمام فیلدهای config
        ip:         IP جدید که می‌خواهیم تست کنیم
        port:       پورت سرور (معمولاً 443)
        local_port: پورت محلی SOCKS5 برای این worker
    """

    config = {
        "log": {
            # در debug mode: warning logs نشان می‌دهد
            # در production: هیچ log نشان نمی‌دهد
            "loglevel": "warning" if _DEBUG else "none",
        },

        # ── Inbound: SOCKS5 proxy محلی ────────────────────────────────────
        # httpx به این پورت وصل می‌شود
        # xray این traffic را می‌گیرد و به CDN می‌فرستد
        "inbounds": [{
            "port":     local_port,      # پورت منحصربه‌فرد این worker
            "listen":   "127.0.0.1",     # فقط localhost - امنیت
            "protocol": "socks",
            "settings": {
                "auth":      "noauth",   # بدون username/password
                "udp":       False,      # فقط TCP نیاز داریم
                "userLevel": 0,
            },
        }],

        # ── Outbound: اتصال به CDN با IP جدید ────────────────────────────
        # IP اصلی لینک را با IP جدید جایگزین می‌کنیم
        # بقیه تنظیمات (uuid, sni, host, path) ثابت می‌مانند
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": ip,       # ← IP جدید جایگزین IP اصلی می‌شود
                    "port":    port,     # معمولاً 443
                    "users": [{
                        "id":         parsed["uuid"],
                        "encryption": parsed.get("encryption", "none"),
                        "flow":       parsed.get("flow", ""),
                    }],
                }],
            },
            # streamSettings بر اساس transport type ساخته می‌شود
            # ws, xhttp, grpc, tcp, h2
            "streamSettings": _build_stream_settings(parsed),
        }],
    }

    return config
def _build_stream_settings(parsed: dict) -> dict:
    """
    streamSettings را بر اساس transport type و TLS mode می‌سازد.

    Transport های پشتیبانی‌شده:
        ws    = WebSocket (Mode 2 - Cloudflare)
        xhttp = xHTTP    (Mode 1 - Netlify)
        http  = HTTP/2
        h2    = HTTP/2 (نام دیگر)
        grpc  = gRPC
        tcp   = TCP ساده

    Security های پشتیبانی‌شده:
        tls     = TLS استاندارد
        reality = Reality (پروتکل جدید xray)
        none    = بدون رمزنگاری

    ── منطق SNI ──────────────────────────────────────────────────────────────
    SNI (Server Name Indication) به سرور می‌گوید با کدام certificate جواب دهد.
    اولویت: sni field → host field → address field
    این اولویت‌بندی مهم است چون بعضی لینک‌ها sni ندارند ولی host دارند.
    """

    transport_type = parsed.get("type", "tcp")
    security       = parsed.get("security", "tls")

    # ── SNI: اولویت‌بندی ─────────────────────────────────────────────────────
    # sni > host > address
    # چرا؟ sni صریح‌ترین فیلد است، host دومی است، address آخرین fallback
    sni = (
        parsed.get("sni")
        or parsed.get("host")
        or parsed.get("address", "")
    )

    # ── ALPN: پارس کردن ──────────────────────────────────────────────────────
    # ALPN = Application-Layer Protocol Negotiation
    # به سرور می‌گوید از چه پروتکلی استفاده کند (h2 یا http/1.1)
    #
    # مشکل: در URL، کاما به صورت %2C encode می‌شود
    # مثال: "h2%2Chttp%2F1.1" → ["h2", "http/1.1"]
    raw_alpn = parsed.get("alpn", "")
    if isinstance(raw_alpn, str) and raw_alpn:
        alpn_list = [
            a.strip()
            for a in raw_alpn.replace("%2C", ",").split(",")
            if a.strip()
        ]
    elif isinstance(raw_alpn, list):
        alpn_list = raw_alpn
    else:
        # default: هر دو پروتکل را قبول می‌کنیم
        alpn_list = ["h2", "http/1.1"]

    # ── ساختار پایه streamSettings ───────────────────────────────────────────
    stream = {
        "network":  transport_type,
        "security": security,
    }

    # ── TLS Settings ──────────────────────────────────────────────────────────
    if security == "tls":
        # allowInsecure: آیا certificate نامعتبر را قبول کنیم؟
        # از هر دو فیلد allowInsecure و insecure چک می‌کنیم
        # چون بعضی کلاینت‌ها یکی و بعضی دیگری را استفاده می‌کنند
        allow_insecure = (
            str(parsed.get("allowInsecure", "0")) == "1"
            or str(parsed.get("insecure", "0")) == "1"
        )
        stream["tlsSettings"] = {
            "serverName":    sni,
            # fingerprint: xray وانمود می‌کند یه browser است
            # chrome = fingerprint مرورگر Chrome
            "fingerprint":   parsed.get("fp", "chrome"),
            "allowInsecure": allow_insecure,
            "alpn":          alpn_list,
        }

    # ── Reality Settings ──────────────────────────────────────────────────────
    elif security == "reality":
        # Reality یه پروتکل جدید xray است که TLS را شبیه‌سازی می‌کند
        # نیاز به publicKey و shortId دارد
        stream["realitySettings"] = {
            "serverName":  sni,
            "fingerprint": parsed.get("fp", "chrome"),
            "publicKey":   parsed.get("pbk", ""),
            "shortId":     parsed.get("sid", ""),
            "spiderX":     parsed.get("spx", "/"),
        }

    # ── Transport: WebSocket ──────────────────────────────────────────────────
    # Mode 2: Cloudflare CDN
    # Cloudflare از Host header برای routing استفاده می‌کند
    # یعنی IP می‌تواند هر IP Cloudflare باشد، ولی Host باید درست باشد
    if transport_type == "ws":
        ws_host = parsed.get("host", sni)
        stream["wsSettings"] = {
            "path": parsed.get("path", "/"),
            "headers": {
                # Host header: Cloudflare با این تشخیص می‌دهد
                # traffic را به کجا route کند
                "Host": ws_host,
            },
        }

    # ── Transport: xHTTP ──────────────────────────────────────────────────────
    # Mode 1: Netlify CDN
    # xhttp یه transport جدید در xray است که HTTP را شبیه‌سازی می‌کند
    elif transport_type == "xhttp":
        stream["xhttpSettings"] = {
            "path": parsed.get("path", "/"),
            "host": parsed.get("host", sni),
            # mode: auto = xray خودش بهترین mode را انتخاب می‌کند
            "mode": parsed.get("mode", "auto"),
        }

    # ── Transport: HTTP/2 ─────────────────────────────────────────────────────
    # هم "http" هم "h2" را پشتیبانی می‌کنیم
    # توجه: host در HTTP/2 باید list باشد (نه string)
    elif transport_type in ("http", "h2"):
        stream["httpSettings"] = {
            "path": parsed.get("path", "/"),
            "host": [parsed.get("host", sni)],  # ← list!
        }

    # ── Transport: gRPC ───────────────────────────────────────────────────────
    # gRPC از serviceName برای routing استفاده می‌کند
    elif transport_type == "grpc":
        stream["grpcSettings"] = {
            "serviceName": parsed.get("serviceName", ""),
            "authority":   parsed.get("authority", ""),
        }

    # ── Transport: TCP ────────────────────────────────────────────────────────
    # TCP ساده - نیازی به تنظیمات اضافه ندارد
    elif transport_type == "tcp":
        pass  # فقط network و security کافی است

    return stream