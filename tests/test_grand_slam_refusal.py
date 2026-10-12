"""
Which SRP step Grand Slam refused, and with what reason code.

OpenTagViewer#248 arrived with "Email verification failed: This action cannot be completed at
this time." and nothing else. That text comes from the ``init`` step, which carries no password,
so the user was being told something about credentials that had never been checked -- and the
``ec`` that would distinguish one such refusal from another had been dropped on the way out.
"""

from __future__ import annotations

from typing import Any

import pytest

from findmy.errors import GrandSlamRefusedError, InvalidCredentialsError
from findmy.reports.account import AsyncAppleAccount
from findmy.reports.anisette import RemoteAnisetteProvider


def _account_answering(*responses: dict[str, Any]) -> AsyncAppleAccount:
    """Build an account whose Grand Slam requests get these answers in order, offline."""
    account = AsyncAppleAccount(RemoteAnisetteProvider("http://127.0.0.1:1/"))
    queue = list(responses)

    async def answer(_params: dict[str, Any]) -> dict[str, Any]:
        return queue.pop(0)

    account._gsa_request = answer  # type: ignore[method-assign]  # noqa: SLF001
    return account


@pytest.mark.asyncio
async def test_a_refused_init_says_so_and_keeps_the_reason_code() -> None:
    """The case from #248: refused before the password was used."""
    # The code is made up. #248's was not logged, which is what this change is for.
    account = _account_answering(
        {"Status": {"ec": -22421, "em": "This action cannot be completed at this time."}},
    )

    with pytest.raises(GrandSlamRefusedError) as raised:
        await account._gsa_authenticate("someone@example.com", "hunter2")  # noqa: SLF001

    error = raised.value
    assert error.step == "init"
    assert error.before_password
    assert error.ec == -22421
    assert error.em == "This action cannot be completed at this time."
    assert "ec=-22421" in str(error)
    assert str(error).startswith("Email verification failed")


@pytest.mark.asyncio
async def test_existing_handlers_still_catch_it() -> None:
    """A subclass, so nothing that caught the old error changes behaviour by upgrading."""
    account = _account_answering({"Status": {"ec": 1, "em": "no"}})

    with pytest.raises(InvalidCredentialsError):
        await account._gsa_authenticate("someone@example.com", "hunter2")  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_refusal_without_a_message_still_raises_the_refusal() -> None:
    """Concatenating a missing ``em`` used to raise TypeError and lose the refusal entirely."""
    account = _account_answering({"Status": {"ec": -1}})

    with pytest.raises(GrandSlamRefusedError, match=r"ec=-1"):
        await account._gsa_authenticate("someone@example.com", "hunter2")  # noqa: SLF001


def test_a_refused_complete_is_about_the_password() -> None:
    """The other step, where a wrong password is reported, is not ``before_password``."""
    error = GrandSlamRefusedError("complete", -20101, "Your Apple ID or password was incorrect.")

    assert not error.before_password
    assert str(error).startswith("Password authentication failed (ec=-20101)")
