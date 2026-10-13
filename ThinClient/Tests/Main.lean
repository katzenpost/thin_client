/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Tests.Errors
import ThinClient.Tests.Frame
import ThinClient.Tests.Vectors
import ThinClient.Tests.Protocol
import ThinClient.Tests.Client

open ThinClient.Tests

def main : IO UInt32 := do
  let results := #[
    ← runSuite "errors" Errors.suite,
    ← runSuite "frame" Frame.suite,
    ← runSuite "vectors" (Vectors.suite ".lake/requests.json"),
    ← runSuite "protocol" Protocol.suite,
    ← runSuite "client" Client.suite]
  return if results.all id then 0 else 1
