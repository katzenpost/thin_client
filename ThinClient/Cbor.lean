/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cborg

/-! # CBOR helpers

Maps with non-record keys, and byte strings carrying an encoded value. -/

namespace ThinClient

open Cborg

/-- A CBOR map, its entries kept in wire order. An empty map is written as `null`, which is how
the daemon writes an unset map. -/
structure CborMap (κ ν : Type) where
  entries : Array (κ × ν) := #[]
  deriving Inhabited

namespace CborMap

variable {κ ν : Type}

def find? [BEq κ] (m : CborMap κ ν) (k : κ) : Option ν :=
  m.entries.find? (·.1 == k) |>.map (·.2)

def size (m : CborMap κ ν) : Nat := m.entries.size

instance [Serialise κ] [Serialise ν] : Serialise (CborMap κ ν) where
  encode m :=
    if m.entries.isEmpty then encodeNull
    else encodeMapLen m.entries.size.toUInt64 ++
      m.entries.foldl (fun e (k, v) => e ++ encode k ++ encode v) Encoding.empty
  decode := do
    if (← peekTokenType) == .TypeNull then decodeNull; return {}
    let entry : Decoder (κ × ν) := do
      let k ← decode
      let v ← decode
      pure (k, v)
    let entries ← match ← decodeMapLenOrIndef with
      | some n => decodeSequenceLenN Array.push (Array.mkEmpty (min n 1024)) id n entry
      | none => decodeSequenceLenIndef Array.push #[] id entry
    return ⟨entries⟩

end CborMap

/-- A value carried as its own CBOR encoding inside a byte string. -/
structure Wrapped (α : Type) where
  val : α
  deriving Inhabited

instance {α : Type} [Serialise α] : Serialise (Wrapped α) where
  encode w := encodeBytes (serialise w.val)
  decode := do
    let bs ← decodeBytes
    match deserialise bs with
    | .ok a => pure ⟨a⟩
    | .error e => Decoder.fail s!"wrapped value: {e.msg}"

end ThinClient
