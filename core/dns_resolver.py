# CDN Scanner - DNS Resolver
# دو روش برای پیدا کردن IP یه domain:
# 1. DNS معمولی سیستم
# 2. DNS over HTTPS (DoH) به عنوان fallback

import socket
import httpx
from core import DOH_PROVIDERS, TCP_TIMEOUT


def resolve_domain(domain: str) -> list[str]:
    """
    یه domain میگیره و لیست IPهاش رو برمیگردونه.
    اول DNS معمولی رو امتحان میکنه، اگه نشد DoH رو امتحان میکنه.
    """

    # --- روش اول: DNS معمولی ---
    ips = _resolve_system_dns(domain)
    if ips:
        return ips

    # --- روش دوم: DNS over HTTPS ---
    ips = _resolve_doh(domain)
    if ips:
        return ips

    # هیچکدام کار نکرد
    return []


def _resolve_system_dns(domain: str) -> list[str]:
    """
    از DNS سیستم عامل استفاده میکنه (socket).
    """
    try:
        # getaddrinfo لیست کامل آدرسها رو برمیگردونه
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        # هر result یه tuple هست، index 4 آدرس IP رو داره
        ips = list({r[4][0] for r in results})  # set برای حذف duplicate
        return ips
    except Exception:
        return []


def _resolve_doh(domain: str) -> list[str]:
    """
    از DNS over HTTPS استفاده میکنه.
    به ترتیب از DOH_PROVIDERS امتحان میکنه تا یکی جواب بده.
    """
    for provider in DOH_PROVIDERS:
        try:
            # درخواست DoH با فرمت JSON
            response = httpx.get(
                provider,
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=TCP_TIMEOUT,
                # verify=False  # اگه SSL مشکل داشت uncomment کن
            )

            if response.status_code == 200:
                data = response.json()
                ips = []

                # Answer section رو بررسی میکنیم
                for answer in data.get("Answer", []):
                    # type=1 یعنی A record (IPv4)
                    if answer.get("type") == 1:
                        ips.append(answer["data"])

                if ips:
                    return ips

        except Exception:
            # این provider کار نکرد، بعدی رو امتحان کن
            continue

    return []