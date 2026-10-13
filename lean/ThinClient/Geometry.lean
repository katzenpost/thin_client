/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cborg
import CryptWalker.Sphinx.geometry_cbor

/-! # Geometries

The daemon reports two geometries when a client connects: the Sphinx packet geometry, whose type,
encoding and hash come from CryptWalker, and the Pigeonhole geometry defined here. -/

namespace ThinClient

open Cborg

export CryptWalker.Sphinx.Geometry (Geometry)

/-- Sizes of the Pigeonhole courier queries and replies, and the schemes they use. -/
structure PigeonholeGeometry where
  maxPlaintextPayloadLength : Nat
  courierQueryReadLength : Nat
  courierQueryWriteLength : Nat
  courierQueryReplyReadLength : Nat
  courierQueryReplyWriteLength : Nat
  nikeName : String
  signatureSchemeName : String
  deriving DecidableEq, Repr

namespace PigeonholeGeometry

def keys : List String :=
  ["MaxPlaintextPayloadLength", "CourierQueryReadLength", "CourierQueryWriteLength",
   "CourierQueryReplyReadLength", "CourierQueryReplyWriteLength", "NIKEName",
   "SignatureSchemeName"]

instance : Serialise PigeonholeGeometry where
  encode g := encodeRecord [
    field "MaxPlaintextPayloadLength" g.maxPlaintextPayloadLength,
    field "CourierQueryReadLength" g.courierQueryReadLength,
    field "CourierQueryWriteLength" g.courierQueryWriteLength,
    field "CourierQueryReplyReadLength" g.courierQueryReplyReadLength,
    field "CourierQueryReplyWriteLength" g.courierQueryReplyWriteLength,
    field "NIKEName" g.nikeName,
    field "SignatureSchemeName" g.signatureSchemeName]
  decode := do
    let r ← decodeRecord
    r.onlyKeys keys
    return {
      maxPlaintextPayloadLength := ← r.withDefault "MaxPlaintextPayloadLength" 0
      courierQueryReadLength := ← r.withDefault "CourierQueryReadLength" 0
      courierQueryWriteLength := ← r.withDefault "CourierQueryWriteLength" 0
      courierQueryReplyReadLength := ← r.withDefault "CourierQueryReplyReadLength" 0
      courierQueryReplyWriteLength := ← r.withDefault "CourierQueryReplyWriteLength" 0
      nikeName := ← r.withDefault "NIKEName" ""
      signatureSchemeName := ← r.withDefault "SignatureSchemeName" "" }

def validate (g : PigeonholeGeometry) : Except String Unit := do
  if g.maxPlaintextPayloadLength == 0 then throw "MaxPlaintextPayloadLength must be positive"
  if g.nikeName.isEmpty then throw "NIKEName must be set"
  if g.signatureSchemeName != "Ed25519" then throw "SignatureSchemeName must be Ed25519"

end PigeonholeGeometry

end ThinClient
