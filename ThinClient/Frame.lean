/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Error

/-! # Framing

Each message on the daemon socket is a 4-byte big-endian length followed by that many bytes of
CBOR. -/

namespace ThinClient.Frame

def maxSize : Nat := 40 * 1024 * 1024

def encodeLength (n : UInt32) : ByteArray :=
  ⟨#[(n >>> 24).toUInt8, (n >>> 16).toUInt8, (n >>> 8).toUInt8, n.toUInt8]⟩

def decodeLength (a b c d : UInt8) : UInt32 :=
  a.toUInt32 * 0x1000000 + b.toUInt32 * 0x10000 + c.toUInt32 * 0x100 + d.toUInt32

theorem decodeLength_encodeLength (n : UInt32) :
    decodeLength (n >>> 24).toUInt8 (n >>> 16).toUInt8 (n >>> 8).toUInt8 n.toUInt8 = n := by
  apply UInt32.toNat_inj.mp
  simp only [decodeLength, UInt32.toNat_add, UInt32.toNat_mul, UInt8.toNat_toUInt32,
    UInt32.toNat_toUInt8, UInt32.toNat_shiftRight]
  have := n.toNat_lt
  simp
  omega

def encode (body : ByteArray) : Except ProtocolViolation ByteArray :=
  if body.size > maxSize then .error (.oversizedFrame body.size)
  else .ok (encodeLength body.size.toUInt32 ++ body)

/-- Bytes received but not yet returned as complete frames. -/
structure Reader where
  buf : ByteArray := .empty

namespace Reader

/-- The next complete frame in the buffer, if there is one. -/
def next? (r : Reader) : Except ProtocolViolation (Option (ByteArray × Reader)) :=
  if r.buf.size < 4 then .ok none
  else
    let len := (decodeLength r.buf[0]! r.buf[1]! r.buf[2]! r.buf[3]!).toNat
    if len > maxSize then .error (.oversizedFrame len)
    else if r.buf.size < 4 + len then .ok none
    else .ok (some (r.buf.extract 4 (4 + len), ⟨r.buf.extract (4 + len) r.buf.size⟩))

/-- Append a chunk and take out every frame it completes. -/
def push (r : Reader) (chunk : ByteArray) : Except ProtocolViolation (Array ByteArray × Reader) := do
  let mut r : Reader := ⟨r.buf ++ chunk⟩
  let mut out := #[]
  for _ in [0:r.buf.size / 4 + 1] do
    match ← r.next? with
    | none => break
    | some (frame, r') => out := out.push frame; r := r'
  return (out, r)

end Reader

end ThinClient.Frame
