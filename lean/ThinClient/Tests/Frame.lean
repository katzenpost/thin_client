/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Frame
import ThinClient.Tests.Util

/-! # Framing

Frames survive being split or merged across reads at every position. -/

namespace ThinClient.Tests.Frame

open ThinClient.Frame

def bytes (start : UInt8) (n : Nat) : ByteArray := ⟨(Array.range n).map (start + ·.toUInt8)⟩

/-- Feed `stream` in chunks cut at `cuts`, collecting the frames. -/
def readAll (stream : ByteArray) (cuts : List Nat) : Except ProtocolViolation (Array ByteArray) := do
  let mut r : Reader := {}
  let mut out := #[]
  let mut pos := 0
  for c in cuts ++ [stream.size] do
    let (frames, r') ← r.push (stream.extract pos c)
    out := out ++ frames
    r := r'
    pos := c
  return out

def suite : TestM Unit := do
  let bodies := #[bytes 1 5, ByteArray.empty, bytes 100 300]
  let stream := bodies.foldl (fun acc b => acc ++ (encode b).toOption.get!) ByteArray.empty
  checkEq "length prefix" (hex (encode (bytes 0 258)).toOption.get! |>.take 8) "00000102"
  let same (fs : Array ByteArray) := fs.size == bodies.size &&
    (fs.zip bodies).all fun (a, b) => sameBytes a b
  check "one chunk" (match readAll stream [] with | .ok fs => same fs | _ => false)
  let mut allSplits := true
  for i in [0:stream.size + 1] do
    for j in [i:stream.size + 1] do
      match readAll stream [i, j] with
      | .ok fs => if !same fs then allSplits := false
      | .error _ => allSplits := false
  check "every two-cut split" allSplits
  check "byte at a time" (match readAll stream (List.range stream.size) with
    | .ok fs => same fs | _ => false)
  let oversized := encodeLength (maxSize + 1).toUInt32 ++ bytes 0 10
  check "oversized frame rejected" (match readAll oversized [] with
    | .error (.oversizedFrame _) => true | _ => false)
  check "partial frame waits" (match readAll (stream.extract 0 8) [] with
    | .ok fs => fs.size == 0 | _ => false)
  check "complete frame is returned" (match readAll (stream.extract 0 9) [] with
    | .ok fs => fs.size == 1 | _ => false)

end ThinClient.Tests.Frame
