# SPDX-License-Identifier: AGPL-3.0-only

"""voucher_mint sends the form it is given and leaves it off when 0."""

import pytest

from katzenpost_thinclient import VOUCHER_FORM_COMPACT, VOUCHER_FORM_LONG

from .test_new_methods import make_client

REPLY = {
    "error_code": 0, "voucher": b"v", "voucher_payload": b"p",
    "voucher_write_cap": b"w", "voucher_read_cap": b"r",
    "voucher_secret_key": b"s", "voucher_public_key": b"k",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("form", [0, VOUCHER_FORM_LONG, VOUCHER_FORM_COMPACT])
async def test_voucher_mint_form(form):
    client = make_client()
    sent = {}

    async def fake_send_and_wait(query_id, request):
        sent.update(request["voucher_mint"])
        return REPLY

    client._send_and_wait = fake_send_and_wait
    args = (b"write cap", "alice") + ((form,) if form else ())
    result = await client.voucher_mint(*args)
    assert result.voucher == b"v"
    assert sent["display_name"] == "alice"
    assert sent.get("form") == (form or None)
