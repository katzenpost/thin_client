/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cborg

/-! # Fixed-size identifiers

Identifiers and BACAP values are byte strings of a fixed length, checked when decoded. -/

namespace ThinClient

open Cborg

instance {n : Nat} : BEq (FixedBytes n) := ⟨fun a b => a.bytes.data == b.bytes.data⟩
instance {n : Nat} : Hashable (FixedBytes n) := ⟨fun a => hash a.bytes.data⟩
instance {n : Nat} : Repr (FixedBytes n) := ⟨fun a _ => repr a.bytes.data⟩

def FixedBytes.ofBytes? {n : Nat} (b : ByteArray) : Option (FixedBytes n) :=
  if h : b.size = n then some ⟨b, h⟩ else none

/-- `n` bytes from the system's secure random source. -/
def FixedBytes.random (n : Nat) : IO (FixedBytes n) := do
  let b ← IO.getRandomBytes n.toUSize
  match FixedBytes.ofBytes? b with
  | some r => pure r
  | none => throw (IO.userError s!"getRandomBytes returned {b.size} bytes, wanted {n}")

abbrev MessageId := FixedBytes 16
abbrev QueryId := FixedBytes 16
abbrev SurbId := FixedBytes 16
abbrev InstanceToken := FixedBytes 16
abbrev Hash32 := FixedBytes 32

/-- A BACAP write capability: Ed25519 private key and starting message box index. -/
abbrev WriteCap := FixedBytes 168
/-- A BACAP read capability: Ed25519 public key and starting message box index. -/
abbrev ReadCap := FixedBytes 136
abbrev MessageBoxIndex := FixedBytes 104

end ThinClient
