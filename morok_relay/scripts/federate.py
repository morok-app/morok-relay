"""
Федерація з іншим релеєм — без ручного SQL.

Раніше оператори мали вставляти рядок у federation_peers руками на ОБОХ
серверах, звіряючи 64-символьні ключі очима. Цей скрипт робить те саме
за дві команди, зберігаючи головну гарантію безпеки: довіра НЕ дається
автоматично.

    # 1. Познайомитись (обидва оператори виконують у себе)
    python -m morok_relay.scripts.federate relay.друга-сторона.com

    # 2. Звірити відбиток голосом/у Signal, і лише тоді:
    python -m morok_relay.scripts.federate --trust relay.друга-сторона.com

Інші команди:
    --list                     показати всіх пірів і їхній статус
    --untrust <hostname>       відкликати довіру (форвардинг зупиняється)
    --show <hostname>          показати відбиток конкретного піра

ЧОМУ ДОВІРА ОКРЕМИМ КРОКОМ. Handshake доводить лише те, що на тому боці
хтось володіє приватним ключем до заявленого публічного. Він НЕ доводить,
що це саме той, кого ви очікуєте: за DNS чи TLS міг сісти хтось інший і
підсунути свій ключ. Тому власник релея звіряє відбиток по СТОРОННЬОМУ
каналу (дзвінок, Signal, особиста зустріч) — так само, як звіряють safety
numbers у месенджері. is_trusted відкриває форвардинг конвертів, тож
автоматичне проставляння перетворило б федерацію на відкриті двері.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
import time

from sqlalchemy import select

# Модуль, а не змінну: init_db() перепризначає _session_factory на рівні
# модуля (той самий підхід, що у federation_worker).
from .. import db as db_module
from ..config import get_settings
from ..federation_client import remote_handshake
from ..models import FederationPeer

C_RESET = "\033[0m"; C_BOLD = "\033[1m"; C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"; C_RED = "\033[31m"; C_DIM = "\033[2m"


def fingerprint(pubkey: bytes) -> str:
    """
    Короткий відбиток для звіряння голосом.

    Читати 64 hex-символи по телефону — гарантована помилка, тому даємо
    8 груп по 4 цифри (як safety number у месенджері). SHA-256 над ключем,
    щоб відбиток не розкривав сам ключ і мав рівномірний розподіл.
    """
    digest = hashlib.sha256(pubkey).digest()
    nums = [str(int.from_bytes(digest[i:i + 2], "big") % 10000).zfill(4)
            for i in range(0, 16, 2)]
    return " ".join(nums)


def _print_peer(peer: FederationPeer) -> None:
    mark = f"{C_GREEN}довірений{C_RESET}" if peer.is_trusted \
        else f"{C_YELLOW}НЕ довірений{C_RESET}"
    last = (time.strftime("%Y-%m-%d %H:%M", time.localtime(peer.last_handshake_at))
            if peer.last_handshake_at else "—")
    print(f"  {C_BOLD}{peer.hostname}{C_RESET}  [{mark}]")
    print(f"    відбиток   {C_BOLD}{fingerprint(peer.pubkey)}{C_RESET}")
    print(f"    ключ       {C_DIM}{peer.pubkey.hex()}{C_RESET}")
    print(f"    handshake  {last}")


async def cmd_list() -> int:
    factory = db_module._session_factory
    async with factory() as session:
        peers = (await session.execute(
            select(FederationPeer).order_by(FederationPeer.hostname)
        )).scalars().all()
    if not peers:
        print("Пірів немає. Додати:")
        print("  python -m morok_relay.scripts.federate relay.приклад.com")
        return 0
    print(f"\n{C_BOLD}Федеративні піри ({len(peers)}){C_RESET}\n")
    for p in peers:
        _print_peer(p)
        print()
    return 0


async def cmd_show(hostname: str) -> int:
    factory = db_module._session_factory
    async with factory() as session:
        peer = (await session.execute(
            select(FederationPeer).where(FederationPeer.hostname == hostname)
        )).scalar_one_or_none()
    if peer is None:
        print(f"{C_RED}Піра {hostname} немає в базі.{C_RESET}")
        return 1
    print()
    _print_peer(peer)
    print()
    return 0


async def cmd_add(hostname: str) -> int:
    """Handshake з піром + запис його ключа (недовіреним)."""
    settings = get_settings()
    if not settings.relay_privkey_hex or not settings.relay_pubkey_hex:
        print(f"{C_RED}У .env немає ключів релея — федерація неможлива.{C_RESET}")
        return 1

    print(f"\n{C_BOLD}Знайомство з {hostname}…{C_RESET}")
    result = await remote_handshake(hostname)
    if not result or not result.get("accepted"):
        print(f"{C_RED}✗ Handshake не вдався.{C_RESET}")
        print("  Перевірте: чи піднятий той релей, чи правильний домен,")
        print("  чи має він валідний TLS-сертифікат.")
        return 1

    their_pubkey_hex = result.get("our_pubkey_hex") or ""
    their_name = result.get("our_relay_name") or hostname
    try:
        their_pubkey = bytes.fromhex(their_pubkey_hex)
    except ValueError:
        print(f"{C_RED}✗ Пір повернув некоректний ключ.{C_RESET}")
        return 1
    if len(their_pubkey) != 32:
        print(f"{C_RED}✗ Ключ піра має бути 32 байти, отримано {len(their_pubkey)}.{C_RESET}")
        return 1

    factory = db_module._session_factory
    async with factory() as session:
        peer = (await session.execute(
            select(FederationPeer).where(FederationPeer.hostname == hostname)
        )).scalar_one_or_none()

        if peer is not None:
            if peer.pubkey != their_pubkey:
                # TOFU-порушення: ключ під тим самим іменем змінився. Це або
                # переустановка релея, або атака. Мовчки перезаписати не
                # можна — рішення за людиною.
                print(f"\n{C_RED}{C_BOLD}⚠ УВАГА: ключ цього релея ЗМІНИВСЯ{C_RESET}")
                print(f"  було:  {C_DIM}{peer.pubkey.hex()}{C_RESET}")
                print(f"         відбиток {fingerprint(peer.pubkey)}")
                print(f"  стало: {C_DIM}{their_pubkey.hex()}{C_RESET}")
                print(f"         відбиток {fingerprint(their_pubkey)}")
                print("\n  Так буває при переустановці релея — але так само")
                print("  виглядає й підміна. Звʼяжіться з оператором ІНШИМ каналом.")
                print(f"\n  Якщо зміна очікувана:")
                print(f"    python -m morok_relay.scripts.federate --untrust {hostname}")
                print(f"    python -m morok_relay.scripts.federate --replace-key {hostname}")
                return 1
            peer.last_handshake_at = int(time.time())
            await session.commit()
            print(f"{C_GREEN}✓ Пір уже відомий, handshake оновлено.{C_RESET}\n")
            _print_peer(peer)
        else:
            peer = FederationPeer(
                hostname=hostname,
                pubkey=their_pubkey,
                is_trusted=False,           # довіра — лише вручну, див. шапку
                last_handshake_at=int(time.time()),
            )
            session.add(peer)
            await session.commit()
            print(f"{C_GREEN}✓ Релей «{their_name}» записано.{C_RESET}\n")
            _print_peer(peer)

        trusted = peer.is_trusted

    if not trusted:
        print(f"\n{C_YELLOW}{C_BOLD}Лишився один крок — підтвердити довіру.{C_RESET}")
        print("  1. Звʼяжіться з оператором того релея ІНШИМ каналом")
        print("     (дзвінок, Signal — будь-що, крім самого релея).")
        print("  2. Звірте відбиток вище — він має збігтися у вас обох.")
        print("  3. Якщо збігся:")
        print(f"     {C_BOLD}python -m morok_relay.scripts.federate --trust {hostname}{C_RESET}")
        print(f"\n  {C_DIM}Доки довіри нема — конверти між релеями не ходять.{C_RESET}")
    return 0


async def _set_trust(hostname: str, value: bool) -> int:
    factory = db_module._session_factory
    async with factory() as session:
        peer = (await session.execute(
            select(FederationPeer).where(FederationPeer.hostname == hostname)
        )).scalar_one_or_none()
        if peer is None:
            print(f"{C_RED}Піра {hostname} немає. Спершу:{C_RESET}")
            print(f"  python -m morok_relay.scripts.federate {hostname}")
            return 1
        if peer.is_trusted == value:
            state = "довірений" if value else "недовірений"
            print(f"Пір {hostname} і так {state}. Нічого не змінено.")
            return 0
        peer.is_trusted = value
        await session.commit()
        fp = fingerprint(peer.pubkey)

    if value:
        print(f"{C_GREEN}✓ {hostname} тепер довірений — конверти ходитимуть.{C_RESET}")
        print(f"  відбиток {fp}")
        print(f"\n  {C_DIM}Не забудьте: інший оператор має зробити те саме у себе.{C_RESET}")
    else:
        print(f"{C_YELLOW}✓ Довіру до {hostname} відкликано.{C_RESET}")
        print(f"  {C_DIM}Запис лишився — щоб видалити зовсім, приберіть рядок у БД.{C_RESET}")
    return 0


async def cmd_replace_key(hostname: str) -> int:
    """Прийняти НОВИЙ ключ піра після свідомої перевірки (TOFU-скидання)."""
    print(f"\n{C_YELLOW}Скидання ключа для {hostname}.{C_RESET}")
    print("Робіть це, ЛИШЕ якщо оператор підтвердив переустановку іншим каналом.")
    ans = input("Продовжити? [y/N] ").strip().lower()
    if ans != "y":
        print("Скасовано.")
        return 1

    result = await remote_handshake(hostname)
    if not result or not result.get("accepted"):
        print(f"{C_RED}✗ Handshake не вдався.{C_RESET}")
        return 1
    try:
        new_pubkey = bytes.fromhex(result.get("our_pubkey_hex") or "")
    except ValueError:
        print(f"{C_RED}✗ Некоректний ключ від піра.{C_RESET}")
        return 1
    if len(new_pubkey) != 32:
        print(f"{C_RED}✗ Ключ має бути 32 байти.{C_RESET}")
        return 1

    factory = db_module._session_factory
    async with factory() as session:
        peer = (await session.execute(
            select(FederationPeer).where(FederationPeer.hostname == hostname)
        )).scalar_one_or_none()
        if peer is None:
            print(f"{C_RED}Піра немає в базі.{C_RESET}")
            return 1
        peer.pubkey = new_pubkey
        peer.is_trusted = False          # довіру доведеться підтвердити знову
        peer.last_handshake_at = int(time.time())
        await session.commit()
        fp = fingerprint(new_pubkey)

    print(f"{C_GREEN}✓ Ключ оновлено, довіру скинуто.{C_RESET}")
    print(f"  новий відбиток {C_BOLD}{fp}{C_RESET}")
    print(f"\n  Звірте його і потім:")
    print(f"    python -m morok_relay.scripts.federate --trust {hostname}")
    return 0


async def main() -> int:
    parser = argparse.ArgumentParser(
        prog="federate",
        description="Федерація Morok-релеїв без ручного SQL.",
    )
    parser.add_argument("hostname", nargs="?", help="домен релея-піра")
    parser.add_argument("--list", action="store_true", help="показати всіх пірів")
    parser.add_argument("--trust", metavar="HOST", help="підтвердити довіру")
    parser.add_argument("--untrust", metavar="HOST", help="відкликати довіру")
    parser.add_argument("--show", metavar="HOST", help="показати відбиток піра")
    parser.add_argument("--replace-key", metavar="HOST",
                        help="прийняти новий ключ після переустановки піра")
    args = parser.parse_args()

    if db_module._session_factory is None:
        await db_module.init_db()

    if args.list:
        return await cmd_list()
    if args.trust:
        return await _set_trust(args.trust, True)
    if args.untrust:
        return await _set_trust(args.untrust, False)
    if args.show:
        return await cmd_show(args.show)
    if args.replace_key:
        return await cmd_replace_key(args.replace_key)
    if args.hostname:
        return await cmd_add(args.hostname)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
