/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Client

/-! # Vouchers

The daemon does the cryptography; the client passes opaque byte strings. -/

namespace ThinClient

/-- Mint a Voucher from the joiner's MessageStream write cap `messageWriteCap` and chosen
`displayName`. `form` is `voucherFormLong`, to join a group whose inductors only read the long
form, or `voucherFormCompact`; 0 (the default) lets the daemon choose, which is the compact form.
The reply carries the Voucher, the payload to publish to VoucherStream box 0, the rendezvous
stream caps and the reply keypair; it fails with the daemon's error code, for instance for a
malformed write cap. -/
def voucherMint (messageWriteCap : ByteArray) (displayName : String) (form : UInt8 := 0) :
    ClientM VoucherMintReply := do
  call { queryId := ← freshQueryId, messageWriteCap, displayName, form : VoucherMint }

def voucherInduct (voucher voucherPayload whoReply : ByteArray) : ClientM VoucherInductReply := do
  call { queryId := ← freshQueryId, voucher, voucherPayload, whoReply : VoucherInduct }

def voucherOpen (voucherSecretKey sealedReply messageWriteCap : ByteArray) :
    ClientM VoucherOpenReply := do
  call { queryId := ← freshQueryId, voucherSecretKey, sealedReply, messageWriteCap : VoucherOpen }

def voucherDeriveStream (voucher : ByteArray) : ClientM VoucherDeriveStreamReply := do
  call { queryId := ← freshQueryId, voucher : VoucherDeriveStream }

end ThinClient
