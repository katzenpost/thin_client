/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Util.HexBytes

/-! # Test helpers

`check` records a failure without stopping; `runSuite` prints a summary and reports whether
anything failed. -/

namespace ThinClient.Tests

abbrev TestM := StateT (Nat × Nat) IO

def check (name : String) (ok : Bool) (detail : Unit → String := fun _ => "") : TestM Unit := do
  let (pass, fail) ← get
  if ok then set (pass + 1, fail)
  else
    set (pass, fail + 1)
    let d := detail ()
    IO.println s!"FAIL {name}{if d.isEmpty then "" else ": " ++ d}"

def checkEq {α : Type} [BEq α] [ToString α] (name : String) (expected actual : α) : TestM Unit :=
  check name (expected == actual) fun _ => s!"expected {expected}, got {actual}"

/-- Fail `name` with the error, or continue with the value. -/
def expectOk {α : Type} (name : String) (x : Except String α) : TestM (Option α) := do
  match x with
  | .ok a => pure (some a)
  | .error e => check name false (fun _ => e); pure none

def runSuite (name : String) (t : TestM Unit) : IO Bool := do
  let ((), (pass, fail)) ← t.run (0, 0)
  IO.println s!"{name}: {pass} passed, {fail} failed"
  return fail == 0

def hex (b : ByteArray) : String := Cryptlib.Util.HexBytes.byteArrayToHex b

def unhex (s : String) : Except String ByteArray :=
  match Cryptlib.Util.HexBytes.hexStringToByteArray s with
  | some b => .ok b
  | none => .error s!"not hex: {s.take 16}"

def sameBytes (a b : ByteArray) : Bool := a.data == b.data

end ThinClient.Tests
