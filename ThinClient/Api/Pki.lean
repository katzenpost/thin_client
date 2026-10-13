/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Client

/-! # PKI queries -/

namespace ThinClient

/-- The daemon's current PKI document. -/
def pkiDocument : ClientM Document := do
  let some doc := (← currentState).document | throw .missingPkiDocument
  pure doc

/-- The PKI document for `epoch`, from the documents of recent epochs. -/
def pkiDocumentForEpoch (epoch : UInt64) : ClientM Document := do
  let some doc := (← currentState).documentForEpoch? epoch | throw .missingPkiDocument
  pure doc

/-- The signed, certificate-wrapped PKI document for `epoch` (0 for the current one), and its
epoch. -/
def getPkiDocumentRaw (epoch : UInt64 := 0) : ClientM (ByteArray × UInt64) := do
  let r ← call { queryId := ← freshQueryId, epoch : GetPKIDocument }
  pure (r.payload, r.epoch)

def getDirectoryAuthorities : ClientM (Array DirectoryAuthority) := do
  let r ← call { queryId := ← freshQueryId : GetDirectoryAuthorities }
  pure r.authorities

/-- Every service in the current PKI document offering `capability`. -/
def getServices (capability : String) : ClientM (Array ServiceDescriptor) := do
  return findServices capability (← pkiDocument)

/-- One of the services offering `capability`, chosen at random. -/
def getService (capability : String) : ClientM ServiceDescriptor := do
  let services ← getServices capability
  if services.isEmpty then throw (.serviceNotFound capability)
  let i ← IO.rand 0 (services.size - 1)
  pure services[i]!

end ThinClient
