/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Error
import ThinClient.Tests.Util

/-! # Error code interpretation -/

namespace ThinClient.Tests.Errors

open ThinClient

def describe : Option ThinClientError → String
  | none => "success"
  | some e => toString e

def expect (name : String) (got : Option ThinClientError) (want : String) : TestM Unit :=
  checkEq name want (describe got)

def suite : TestM Unit := do
  for e in DaemonError.all do
    check s!"daemon code {e.toCode} round trip" (DaemonError.ofCode? e.toCode == some e)
  for e in ReplicaError.all do
    check s!"replica code {e.toCode} round trip" (ReplicaError.ofCode? e.toCode == some e)
  checkEq "daemon codes are 1..34" ((List.range 34).map (· + 1))
    (DaemonError.all.map (·.toCode.toNat))
  checkEq "replica codes are 1..11" ((List.range 11).map (· + 1))
    (ReplicaError.all.map (·.toCode.toNat))
  expect "thin code 0" (ThinClientError.ofCode 0) "success"
  expect "thin code 1" (ThinClientError.ofCode 1) "Connection lost"
  expect "thin code 34" (ThinClientError.ofCode 34)
    "Message box index is too far ahead of the capability to check"
  expect "thin code 99" (ThinClientError.ofCode 99) "Unknown thin client error code: 99"
  expect "replica code 1" (ThinClientError.ofReplicaCode 1) "box ID not found"
  expect "replica code 12" (ThinClientError.ofReplicaCode 12) "unknown replica error code: 12"
  -- The start-resending reply reads 1–11 as replica codes and the rest as thin client codes.
  expect "resend code 1" (ThinClientError.ofResendCode 1) "box ID not found"
  expect "resend code 11" (ThinClientError.ofResendCode 11) "tombstone"
  expect "resend code 24" (ThinClientError.ofResendCode 24) "Start resending cancelled"
  expect "resend code 0" (ThinClientError.ofResendCode 0) "success"
  expect "copy command failed with replica error"
    (ThinClientError.ofCopyCommandCode 26 10 3)
    "copy command failed: box already exists (failed envelope index 3)"
  expect "copy command failed without replica reply"
    (ThinClientError.ofCopyCommandCode 26 0 2)
    "copy command failed: no replica reply (failed envelope index 2)"
  expect "copy command other code" (ThinClientError.ofCopyCommandCode 27 0 0) "Payload too large"
  check "tombstone is expected" ((ThinClientError.ofResendCode 11).any (·.isExpectedOutcome))
  check "box not found is expected" ((ThinClientError.ofResendCode 1).any (·.isExpectedOutcome))
  check "box exists is expected" ((ThinClientError.ofResendCode 10).any (·.isExpectedOutcome))
  check "connection lost is not expected"
    (!(ThinClientError.ofCode 1).any (·.isExpectedOutcome))

end ThinClient.Tests.Errors
