"""
Search every keychain view this account can read for a needle you supply. **A
research diagnostic, not a user tool.**

The question it answers for OpenTagViewer issue #193: a third-party Find My
accessory's owner rings it over a link encrypted with a pre-shared LTK, and the
question is *where that key lives* on the account. If it syncs through iCloud
Keychain, it is in one of the views this script can read, and a byte search
finds it. A miss narrows the answer too -- see the caveat at the bottom.

WARNING -- READ BEFORE RUNNING
==============================

This is NOT official FindMy.py or OpenTagViewer tooling. It exists for Find My
gadget compatibility research, and it will print out details about YOUR OWN
account: every keychain item this account can read, including password items,
Wi-Fi keys and certificates, listed with their attributes.

It performs escrow recovery against your Apple account, which spends one of a
device's unlock attempts. Apple may cap these. A run you did not mean to make
still happened.

Do not paste its output into an issue, a chat, or anywhere else. The default
listing shows attributes only; the optional item inspector shows decrypted
payloads, which are your secrets.

Run it from a terminal yourself. It refuses to run non-interactively, so an
LLM or a script cannot run it and read what it printed.

What it needs from you
======================

- Your Apple ID sign-in (email, password, 2FA) -- the same as the other
  examples.
- The screen-lock passcode of one recoverable device, for escrow recovery.
  That is its PIN or login password, not the Apple ID password.
- The needle: the bytes to search for, pasted as hex. For OpenTagViewer#193
  that is the 16-byte LTK from an `HCI_LE_Start_Encryption` command in an HCI
  snoop or PacketLogger capture of the owner's iPhone connecting to the
  accessory.
  Paste it freshly captured -- see the rotation caveat at the bottom.

What it does
============

1. Sign in (or restore `account.json`), open the keychain session.
2. Offer the recoverable escrow records; recover one with your passcode.
3. Fetch this peer's key shares, and with them every view they open.
4. Fetch and decrypt every readable item in each of those views.
5. Search each item -- raw bytes, and base64-decoded where an attribute is a
   base64 string -- for the needle as captured and byte-reversed.
6. Report per view: how many items were readable and whether any matched.
   A match reports the *item and field it matched in*, never the value.
7. Optionally, let you inspect individual items interactively. That is where
   the WARNING above stops being a formality.

It writes nothing to the account: no peer is created, no voucher signed, no
escrow record enrolled. Recovery reads.

On a miss
=========

If the key rotates on the order of minutes -- which the #193 reporter observed
-- then a needle captured hours ago is probably no longer the stored value, and
a miss means "not stored *now*", not "never stored". Sweep promptly after
capturing. A prompt miss and a stale miss look identical, which is worth saying
in any report of the result.
"""

from __future__ import annotations

import asyncio
import base64
import getpass
import logging
import os
import sys

from _login import get_account_async  # pyright: ignore [reportMissingImports]

from findmy.errors import UnauthorizedError
from findmy.keychain.items import (
    describe_item,
    fetch_view,
    make_securityd_client,
    readable_items,
)
from findmy.keychain.session import AsyncKeychainSession

ANISETTE_SERVER = None
ANISETTE_LIBS_PATH = "ani_libs.bin"
ACCOUNT_STORE = "account.json"

def _red(text: str) -> str:
    """
    Colour the banner red, but only when it is going to a terminal.

    Escape codes in a redirected log are raw noise there and break the `grep`
    a researcher runs over an output file -- so a run whose output is not being
    watched live keeps the text and drops the colour.
    """
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        return f"\033[1;31m{text}\033[0m"
    return text


BANNER = _red("""
========================================================================
 keychain sweep -- RESEARCH DIAGNOSTIC, NOT A USER TOOL
========================================================================
 This inspects YOUR OWN iCloud keychain: every readable item, including
 passwords, Wi-Fi keys and certificates.

 It spends one escrow-recovery attempt, which Apple may cap.

 Do not paste its output anywhere public.
========================================================================
""")

# One field at a time in the inspector, so a secret is shown only when asked
# for by name -- `v_Data` is where payloads live, the rest are attributes.
INSPECTABLE = ("v_Data", "class", "acct", "agrp", "vwht", "labl", "srvr", "atyp", "pdmn")


def _needles(hex_needle: str) -> dict[str, bytes]:
    """
    The needle as captured and byte-reversed;
    OpenTagViewer#193 found both orders in use.
    """
    raw = bytes.fromhex(hex_needle.replace(" ", ""))
    return {"as-captured": raw, "byte-reversed": raw[::-1]}


def _match(value: object, needles: dict[str, bytes]) -> str | None:
    """
    Whether this attribute contains the needle, in raw or base64-decoded form.

    Returns *which* needle matched, never the surrounding bytes -- the caller
    prints locations, not values.
    """
    blobs: list[bytes] = []
    if isinstance(value, (bytes, bytearray)):
        blobs.append(bytes(value))
    elif isinstance(value, str):
        blobs.append(value.encode())
        try:
            blobs.append(base64.b64decode(value, validate=True))
        except Exception:
            pass  # not base64; the ASCII form was already searched

    for blob in blobs:
        for label, needle in needles.items():
            if needle in blob:
                return label
    return None


async def sweep(
    account, session: AsyncKeychainSession, peer, hex_needle: str
) -> dict[str, dict[bytes, dict]]:
    """
    Search every view the peer's shares open, and return the readable items.

    Read-only. The returned mapping is what the interactive inspector reads, so
    nothing is fetched twice and nothing is decrypted twice.
    """
    needles = _needles(hex_needle)
    shares = await session.key_shares(peer)
    views = sorted({s.service for s in shares if s.view_keys})
    print(f"\n{len(views)} view(s) yielded keys: {', '.join(views)}")

    securityd = make_securityd_client(account)
    all_items: dict[str, dict[bytes, dict]] = {}
    matches = 0

    for view in views:
        keyring = next(s.view_keys for s in shares if s.service == view and s.view_keys)
        contents = await fetch_view(securityd, view)
        items = readable_items(contents, keyring)
        all_items[view] = items

        print(f"\n[{view}] {len(items)} readable item(s) of {len(contents.items)}")
        for account_id, item in items.items():
            for field, value in item.items():
                where = _match(value, needles)
                if where:
                    matches += 1
                    # describe_item prints attributes and a payload size, never
                    # payload contents -- so the report stays safe to read aloud.
                    print(
                        f"  MATCH ({where}) in {field}: "
                        f"{describe_item(item)}  [acct={account_id.hex()[:16]}...]"
                    )

    if not matches:
        print("\nNo view held the needle. See the docstring's rotation caveat before")
        print("reading that as 'the key is derived rather than stored': a needle")
        print("captured minutes before the sweep misses either way.")

    return all_items


def inspect(all_items: dict[str, dict[bytes, dict]]) -> None:
    """
    Interactive item inspector. The only place payload bytes reach the screen.

    Gated per field, because the sweep's listing is safe to have read and this
    is not: two prompts deep is far enough that nobody arrives here by
    accident, and a field name is a smaller commitment than "dump everything".
    """
    print("\n--- Item inspector ---")
    print("Items are addressed as <view>:<number>. Type 'list' to relist,")
    print("'quit' to leave. Inspecting a field prints it in full -- that is")
    print("the part that is your secret, and it is your terminal.")

    while True:
        try:
            typed = input("\nitem or field> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if typed in {"q", "quit", ""}:
            return
        if typed == "list":
            for view, items in all_items.items():
                print(f"\n[{view}]")
                for n, item in enumerate(items.values()):
                    print(f"  {view}:{n}  {describe_item(item)}")
            continue

        view, _, index = typed.partition(":")
        try:
            item = all_items[view][list(all_items[view].keys())[int(index)]]
        except (KeyError, ValueError, IndexError):
            print("Not an item this run listed. Type 'list'.")
            continue

        print(f"\n{describe_item(item)}")
        fields = [f for f in INSPECTABLE if f in item]
        print(f"Fields: {', '.join(fields)} (nothing else is offered)")
        field = input("field> ").strip()
        if field not in item:
            print("No such field.")
            continue
        if field not in INSPECTABLE:
            print("Only fields in the known set are shown, so a renamed")
            print("attribute cannot carry a secret out unlooked-at.")
            continue

        value = item[field]
        if isinstance(value, bytes):
            print(f"{field}: {len(value)} bytes")
            confirm = input("print hex? y/N> ").strip().lower()
            if confirm == "y":
                print(value.hex())
        else:
            print(f"{field}: {value!r}")


async def main() -> int:
    """Sign in, recover, sweep, optionally inspect."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        # The prompt below is not the gate -- this is. An agent or a script runs
        # without a terminal, and piping `echo y |` past the prompt is the first
        # thing it tries. Refusing a non-interactive run is what makes the
        # banner true when it says an LLM cannot run this and read the output.
        print(BANNER)
        print("This tool is interactive-only. Run it from a terminal yourself.")
        return 1

    print(BANNER)
    if input("Continue? y/N> ").strip().lower() != "y":
        print("Aborted.")
        return 1

    logging.basicConfig(level=logging.WARNING, format="%(levelname)-8s %(message)s")

    hex_needle = input("\nneedle (hex, spaces ok)> ").strip()
    try:
        _needles(hex_needle)
    except ValueError:
        print("That is not hex.")
        return 1

    account = await get_account_async(ACCOUNT_STORE, ANISETTE_SERVER, ANISETTE_LIBS_PATH)

    try:
        try:
            session_cm = await AsyncKeychainSession.open(account)
        except UnauthorizedError:
            # The stored account.json carries an expired iCloud token, and
            # nothing in the restore path notices until the first call that
            # needs one -- which is here. Deleting the store is the remedy,
            # not re-trying: the next run takes the fresh-login path instead.
            print(
                "\nThe stored account session was rejected (the iCloud token in"
                f" {ACCOUNT_STORE} has most likely expired).\nDelete"
                f" {ACCOUNT_STORE} and run again to get a fresh sign-in."
            )
            return 1
        async with session_cm as session:
            options = await session.recovery_options()
            if not options.recoverable:
                print("No record on this account is currently recoverable.")
                return 1

            print(f"\n{len(options.recoverable)} record(s) can be recovered from:\n")
            for record in options.recoverable:
                print(f"  {record.describe()}")

            typed = input("\nserial> ").strip()
            chosen = next((r for r in options.recoverable if r.serial == typed), None)
            if chosen is None:
                print("No recoverable record has that serial.")
                return 1

            passcode = getpass.getpass("passcode (not echoed)> ")
            try:
                peer = await session.recover(chosen, passcode)
            finally:
                del passcode

            print("\nRecovered. Sweeping -- this fetches every view, which can take")
            print("a while on an account with a large keychain.\n")

            items = await sweep(account, session, peer, hex_needle)

            if input("\nInspect items interactively? y/N> ").strip().lower() == "y":
                inspect(items)
    finally:
        await account.close()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
