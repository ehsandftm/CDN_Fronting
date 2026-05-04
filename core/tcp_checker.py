# core/tcp_checker.py
# Stage 1: TCP connect + TLS handshake with SNI
#
# Why TLS handshake matters:
#   - TCP connect only checks if port 443 is open
#   - TLS handshake confirms the CDN actually routes our SNI correctly
#   - A CDN IP might accept TCP but reject our SNI → false positive without TLS check

import ssl
import socket
import time
import concurrent.futures

# ════════════════════════════════════════════════════════════
# تنظیمات پیش‌فرض
# ════════════════════════════════════════════════════════════
DEFAULT_TIMEOUT     = 3.0   # ثانیه - برای هر probe
DEFAULT_MAX_WORKERS = 50    # تعداد thread های همزمان


def tcp_tls_probe(ip: str, port: int, sni: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    TCP connect + TLS handshake با SNI.

    Returns:
        {"ok": bool, "latency_ms": float|None, "error": str}
    """
    start = time.perf_counter()

    try:
        # SSL context - certificate validation غیرفعال
        # چون CDN IP های shared هستند و cert با IP match نمی‌کند
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        # Step A: TCP connect
        raw_sock = socket.create_connection((ip, port), timeout=timeout)

        # Step B: TLS handshake با SNI
        # server_hostname=sni → همان چیزی که xray بعداً می‌فرستد
        tls_sock = ctx.wrap_socket(
            raw_sock,
            server_hostname=sni,
            do_handshake_on_connect=True,
        )

        # latency = TCP + TLS = واقعی‌ترین معیار
        latency_ms = (time.perf_counter() - start) * 1000
        tls_sock.close()

        return {
            "ok":         True,
            "latency_ms": round(latency_ms, 1),
            "error":      "",
        }

    except socket.timeout:
        return _fail("tcp timeout")
    except ConnectionRefusedError:
        return _fail("connection refused")
    except ssl.SSLError as e:
        return _fail(f"tls error: {e.reason}")
    except OSError as e:
        return _fail(f"os error: {e.strerror}")
    except Exception as e:
        return _fail(str(e))


def _fail(error: str) -> dict:
    """نتیجه استاندارد برای شکست."""
    return {
        "ok":         False,
        "latency_ms": None,
        "error":      error,
    }


def _tcp_only(ip: str, port: int, timeout: float) -> dict:
    """
    فقط TCP connect - بدون TLS.
    وقتی SNI نداریم از این استفاده می‌کنیم.
    """
    start = time.perf_counter()
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        latency_ms = (time.perf_counter() - start) * 1000
        sock.close()
        return {"ok": True, "latency_ms": round(latency_ms, 1), "error": ""}
    except socket.timeout:
        return _fail("tcp timeout")
    except ConnectionRefusedError:
        return _fail("connection refused")
    except OSError as e:
        return _fail(f"os error: {e.strerror}")
    except Exception as e:
        return _fail(str(e))


# ════════════════════════════════════════════════════════════
# tcp_ping
#
# ⚠️ KEY FIX: خروجی هر دو فرمت را دارد:
#   - "value" + "tcp_ok"  → فرمت داخلی
#   - "ip"    + "ok"      → فرمتی که scanner.py انتظار دارد
#
# چرا هر دو؟
#   scanner.py از r["ip"] و r["ok"] استفاده می‌کند.
#   کد داخلی ما از r["value"] و r["tcp_ok"] استفاده می‌کند.
#   با داشتن هر دو، هیچ‌کدام نمی‌شکنند.
# ════════════════════════════════════════════════════════════

def tcp_ping(item, port: int = 443, sni: str = "", timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    یه IP رو تست می‌کند.

    Args:
        item:    string ("1.2.3.4") یا dict ({"value": "1.2.3.4"} یا {"ip": "1.2.3.4"})
        port:    پورت هدف (معمولاً 443)
        sni:     اگه خالی باشد، فقط TCP connect انجام می‌شود
        timeout: timeout به ثانیه

    Returns:
        dict با فیلدهای: value, ip, type, tcp_ok, ok, latency_ms, error
    """

    # ── normalize: هر فرمتی را قبول می‌کنیم ────────────────
    if isinstance(item, str):
        # scanner.py یه string فرستاده مثل "1.2.3.4"
        item = {"value": item, "type": "ip"}
    elif not isinstance(item, dict):
        # نه string نه dict → مستقیم fail
        ip_str = str(item)
        return {
            "value": ip_str, "ip": ip_str, "type": "ip",
            "tcp_ok": False, "ok": False,
            "latency_ms": 0.0, "error": "invalid item type"
        }

    # ip را از هر دو کلید ممکن می‌خوانیم
    ip = item.get("value", "") or item.get("ip", "")

    if not ip:
        return {
            **item,
            "value": "", "ip": "",
            "tcp_ok": False, "ok": False,
            "latency_ms": 0.0, "error": "empty ip"
        }

    # ── انتخاب روش تست ─────────────────────────────────────
    if sni:
        # SNI داریم → TLS handshake کامل (دقیق‌تر، شبیه‌سازی xray)
        result = tcp_tls_probe(ip, port, sni, timeout)
    else:
        # SNI نداریم → فقط TCP connect (سریع‌تر)
        result = _tcp_only(ip, port, timeout)

    ok         = result["ok"]
    latency_ms = result["latency_ms"] or 0.0
    error      = result["error"]

    return {
        **item,           # هر فیلد اضافه‌ای که item داشت نگه می‌داریم
        # ── فرمت داخلی ──────────────────────────────────────
        "value":      ip,
        "tcp_ok":     ok,
        # ── فرمت scanner.py ─────────────────────────────────
        # scanner.py از r["ip"] و r["ok"] استفاده می‌کند
        "ip":         ip,
        "ok":         ok,
        # ── مشترک ───────────────────────────────────────────
        "latency_ms": latency_ms,
        "error":      error,
    }


# ════════════════════════════════════════════════════════════
# tcp_ping_batch
#
# لیستی از IP ها را موازی تست می‌کند.
# بدون batch: 500 IP × 3s = 25 دقیقه!
# با batch (50 thread): ~3 ثانیه
# ════════════════════════════════════════════════════════════

def tcp_ping_batch(
    items:       list,
    port:        int   = 443,
    sni:         str   = "",
    timeout:     float = DEFAULT_TIMEOUT,
    max_workers: int   = DEFAULT_MAX_WORKERS,
) -> list:
    """
    لیستی از IP ها را به صورت موازی تست می‌کند.

    Args:
        items:       لیست string یا dict
        port:        پورت هدف
        sni:         اگه داده شود TLS هم چک می‌شود
        timeout:     timeout هر probe
        max_workers: تعداد thread های همزمان

    Returns:
        لیست نتایج - همان ترتیب ورودی حفظ می‌شود
    """
    if not items:
        return []

    # تعداد worker را به اندازه items محدود می‌کنیم
    workers = min(max_workers, len(items))

    results = [None] * len(items)  # ترتیب اصلی حفظ می‌شود

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_idx = {
            executor.submit(tcp_ping, item, port, sni, timeout): idx
            for idx, item in enumerate(items)
        }

        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                # ── normalize raw_item برای error case ───────
                raw_item = items[idx]
                if isinstance(raw_item, str):
                    base_ip = raw_item
                    base    = {"value": raw_item, "type": "ip"}
                elif isinstance(raw_item, dict):
                    base_ip = raw_item.get("value", "") or raw_item.get("ip", "")
                    base    = raw_item
                else:
                    base_ip = str(raw_item)
                    base    = {"value": base_ip, "type": "ip"}

                results[idx] = {
                    **base,
                    "value":      base_ip,
                    "ip":         base_ip,
                    "tcp_ok":     False,
                    "ok":         False,
                    "latency_ms": 0.0,
                    "error":      f"thread error: {e}",
                }

    return results