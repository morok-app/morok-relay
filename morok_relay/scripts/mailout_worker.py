"""
morok.email — воркер вихідної пошти. Крутиться на CX23 (mail-out).

Цикл: relay1 /outbound/claim → send_external (DKIM, IPv4-bind) →
/outbound/report. Авторизація — спільний токен (X-Mailout-Token).

Прогрів IP: MAILOUT_DAILY_CAP листів/добу (лічильник у файлі).
Перші 2 тижні тримати 30-50, далі поступово піднімати.

Запуск (systemd або вручну):
    MAILOUT_RELAY=https://relay1.morok.app \\
    MAILOUT_TOKEN=<секрет із .env relay1> \\
    MAILOUT_DAILY_CAP=30 \\
    python3 -m morok_relay.scripts.mailout_worker
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request

from morok_relay.mail_out import send_external

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("mailout.worker")

RELAY = os.environ.get("MAILOUT_RELAY", "https://relay1.morok.app").rstrip("/")
TOKEN = os.environ.get("MAILOUT_TOKEN", "")
DAILY_CAP = int(os.environ.get("MAILOUT_DAILY_CAP", "30"))
POLL_SECONDS = int(os.environ.get("MAILOUT_POLL", "15"))
COUNTER_FILE = "/var/lib/morok/mailout_counter.json"


def _api(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        RELAY + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "X-Mailout-Token": TOKEN},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def _load_counter() -> dict:
    try:
        with open(COUNTER_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_counter(c: dict) -> None:
    os.makedirs(os.path.dirname(COUNTER_FILE), exist_ok=True)
    with open(COUNTER_FILE, "w") as f:
        json.dump(c, f)


def _sent_today() -> int:
    c = _load_counter()
    today = time.strftime("%Y-%m-%d")
    return int(c.get(today, 0))


def _bump_today() -> None:
    c = _load_counter()
    today = time.strftime("%Y-%m-%d")
    c = {today: int(c.get(today, 0)) + 1}   # тримаємо тільки сьогодні
    _save_counter(c)


# постійні SMTP-відмови (5xx) — не ретраїмо; решта — тимчасові
def _is_permanent(err: str) -> bool:
    e = err.lower()
    for code in ("550", "551", "553", "554", "no mx", "bad recipient"):
        if code in e:
            return True
    return False


def main() -> None:
    if not TOKEN:
        raise SystemExit("MAILOUT_TOKEN не задано")
    log.info("mailout worker up: relay=%s cap=%d/day poll=%ds",
             RELAY, DAILY_CAP, POLL_SECONDS)
    while True:
        try:
            left = DAILY_CAP - _sent_today()
            if left <= 0:
                log.info("daily cap reached (%d) — сплю годину", DAILY_CAP)
                time.sleep(3600)
                continue
            batch = _api("/api/v1/mail/outbound/claim",
                         {"limit": min(left, 5)})
            jobs = batch.get("jobs", [])
            if not jobs:
                time.sleep(POLL_SECONDS)
                continue
            for j in jobs:
                ok, info = send_external(
                    j["from_addr"], j["to_addr"],
                    j.get("subject") or "(без теми)",
                    j.get("text") or "",
                )
                if ok:
                    _bump_today()
                    _api("/api/v1/mail/outbound/report",
                         {"id": j["id"], "ok": True})
                    log.info("delivered %s", j["id"])
                else:
                    perm = _is_permanent(info)
                    _api("/api/v1/mail/outbound/report",
                         {"id": j["id"], "ok": False,
                          "error": info, "retry": not perm})
                    log.warning("failed %s (%s) perm=%s", j["id"], info, perm)
        except KeyboardInterrupt:
            break
        except Exception as e:
            log.error("worker loop error: %s", e)
            time.sleep(30)


if __name__ == "__main__":
    main()
