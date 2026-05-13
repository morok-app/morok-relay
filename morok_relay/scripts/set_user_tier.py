"""
Set a user's tier from the command line. Server-side admin tool.

Usage:
    python -m morok_relay.scripts.set_user_tier <pubkey_hex> <tier>

Example:
    python -m morok_relay.scripts.set_user_tier 9f2a...4f premium

Why a script and not an API: tier is a paid feature. We don't want anyone
self-promoting to premium via a leaked admin token. Promotion happens
only on the server, by someone with shell access.
"""
import asyncio
import sys

from sqlalchemy import select

from ..db import close_db, init_db
from ..models import User, UserTier


async def _main(pubkey_hex: str, tier_str: str) -> int:
    if len(pubkey_hex) != 64 or not all(c in "0123456789abcdef" for c in pubkey_hex):
        print(f"ERROR: pubkey_hex must be 64 hex chars, got: {pubkey_hex!r}")
        return 1

    try:
        tier = UserTier(tier_str)
    except ValueError:
        valid = ", ".join(t.value for t in UserTier)
        print(f"ERROR: tier must be one of: {valid}")
        return 1

    await init_db()

    # We use the same session factory the app uses
    from ..db import _session_factory
    if _session_factory is None:
        print("ERROR: DB session factory not initialized")
        return 1

    pubkey_bytes = bytes.fromhex(pubkey_hex)

    async with _session_factory() as db:
        stmt = select(User).where(User.pubkey == pubkey_bytes)
        user = (await db.execute(stmt)).scalar_one_or_none()

        if user is None:
            print(f"ERROR: no user found with pubkey {pubkey_hex[:16]}...")
            return 2

        old_tier = user.tier.value
        user.tier = tier
        await db.commit()

        print(
            f"OK: user {pubkey_hex[:16]}... "
            f"(@{user.username or 'no-username'}) "
            f"tier: {old_tier} -> {tier.value}"
        )

    await close_db()
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python -m morok_relay.scripts.set_user_tier <pubkey_hex> <tier>")
        print("Tier: free | premium | admin")
        sys.exit(1)
    sys.exit(asyncio.run(_main(sys.argv[1], sys.argv[2])))
