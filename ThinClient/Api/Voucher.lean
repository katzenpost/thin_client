/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Client

/-! # Vouchers

The daemon does the cryptography; the client passes opaque byte strings. -/

namespace ThinClient

def voucherMint (messageWriteCap : ByteArray) (displayName : String) : ClientM VoucherMintReply := do
  call { queryId := ← freshQueryId, messageWriteCap, displayName : VoucherMint }

def voucherInduct (voucher voucherPayload whoReply : ByteArray) : ClientM VoucherInductReply := do
  call { queryId := ← freshQueryId, voucher, voucherPayload, whoReply : VoucherInduct }

def voucherOpen (voucherSecretKey sealedReply messageWriteCap : ByteArray) :
    ClientM VoucherOpenReply := do
  call { queryId := ← freshQueryId, voucherSecretKey, sealedReply, messageWriteCap : VoucherOpen }

def voucherDeriveStream (voucher : ByteArray) : ClientM VoucherDeriveStreamReply := do
  call { queryId := ← freshQueryId, voucher : VoucherDeriveStream }

end ThinClient
