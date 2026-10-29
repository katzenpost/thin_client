/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Client

/-! # NIKE keys and sealed boxes

The daemon does the cryptography and keeps no keys; the client passes opaque byte strings.
`nikeScheme` names an hpqc NIKE, e.g. "X25519-CTIDH1024". -/

namespace ThinClient

def nikeGenerateKeyPair (nikeScheme : String) : ClientM NIKEGenerateKeyPairReply := do
  call { queryId := ← freshQueryId, nikeScheme : NIKEGenerateKeyPair }

/-- A degenerate (all zero) shared secret is an error. -/
def nikeDeriveSecret (nikeScheme : String) (privateKey publicKey : ByteArray) :
    ClientM NIKEDeriveSecretReply := do
  call { queryId := ← freshQueryId, nikeScheme, privateKey, publicKey : NIKEDeriveSecret }

def boxSeal (nikeScheme : String) (publicKey plaintext : ByteArray) : ClientM BoxSealReply := do
  call { queryId := ← freshQueryId, nikeScheme, publicKey, plaintext : BoxSeal }

def boxOpen (nikeScheme : String) (privateKey ciphertext : ByteArray) : ClientM BoxOpenReply := do
  call { queryId := ← freshQueryId, nikeScheme, privateKey, ciphertext : BoxOpen }

end ThinClient
