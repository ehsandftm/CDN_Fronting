# CDN Scanner - Config Builder
# یه vless link جدید میسازه با IP جدید
# ساختار link اصلی حفظ میشه، فقط address عوض میشه

from urllib.parse import urlencode, quote


def build_vless_link(parsed: dict, new_ip: str) -> str:
    """
    یه vless link جدید میسازه.

    Args:
        parsed:  خروجی parse_vless() - اطلاعات config اصلی
        new_ip:  IP جدیدی که میخوایم جایگزین کنیم

    Returns:
        یه vless:// link کامل با IP جدید
    """

    uuid = parsed["uuid"]
    port = parsed.get("port", 443)

    # alias جدید: اسم اصلی + IP جدید
    original_alias = parsed.get("alias", "CDN")
    # کاراکترهای خاص alias رو encode میکنیم
    new_alias = quote(f"{original_alias} | {new_ip}", safe="")

    # پارامترهای query string رو جمع میکنیم
    params = {}

    # --- پارامترهای اجباری ---
    _add_if(params, "security",      parsed.get("security"))
    _add_if(params, "type",          parsed.get("type"))

    # --- پارامترهای TLS ---
    _add_if(params, "sni",           parsed.get("sni"))
    _add_if(params, "fp",            parsed.get("fp"))
    _add_if(params, "alpn",          parsed.get("alpn"))

    # اگه allowInsecure فعال بود اضافه کن
    if parsed.get("allowInsecure") == "1":
        params["allowInsecure"] = "1"

    # --- پارامترهای Reality ---
    _add_if(params, "pbk",           parsed.get("pbk"))
    _add_if(params, "sid",           parsed.get("sid"))
    _add_if(params, "spx",           parsed.get("spx"))

    # --- پارامترهای Transport ---
    _add_if(params, "host",          parsed.get("host"))
    _add_if(params, "path",          parsed.get("path"))
    _add_if(params, "serviceName",   parsed.get("serviceName"))
    _add_if(params, "authority",     parsed.get("authority"))

    # --- پارامترهای اختیاری ---
    _add_if(params, "encryption",    parsed.get("encryption"))
    _add_if(params, "flow",          parsed.get("flow"))

    # ساخت query string
    query = urlencode(params, quote_via=quote)

    # ساخت link نهایی
    # فرمت: vless://UUID@IP:PORT?params#alias
    link = f"vless://{uuid}@{new_ip}:{port}?{query}#{new_alias}"

    return link


def _add_if(d: dict, key: str, value):
    """
    فقط اگه value وجود داشت و خالی نبود، به dict اضافه میکنه.
    از اضافه شدن پارامترهای خالی جلوگیری میکنه.
    """
    if value is not None and value != "":
        d[key] = value