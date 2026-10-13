/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Messages

/-! # Test fixtures

Messages a daemon sends, built from fixed bytes. -/

namespace ThinClient.Tests.Fixtures

open Cborg ThinClient

def bytes (start : UInt8) (n : Nat) : ByteArray := ⟨(Array.range n).map (start + ·.toUInt8)⟩

def fixed (n : Nat) (start : UInt8) : FixedBytes n :=
  ⟨bytes start n, by simp [bytes, ByteArray.size]⟩

def sphinxGeometry : Geometry :=
  match CryptWalker.Sphinx.Geometry.ofNIKE "x25519" 2000 true 5 with
  | .ok g => g
  | .error _ => default

def pigeonholeGeometry : PigeonholeGeometry :=
  { maxPlaintextPayloadLength := 1553, courierQueryReadLength := 430,
    courierQueryWriteLength := 2082, courierQueryReplyReadLength := 1679,
    courierQueryReplyWriteLength := 103, nikeName := "x25519", signatureSchemeName := "Ed25519" }

def status (token : UInt8 := 0x50) (geometries := true) : Response :=
  .connectionStatusEvent {
    isConnected := true, instanceToken := fixed 16 token,
    sphinxGeometry := if geometries then some sphinxGeometry else none,
    pigeonholeGeometry := if geometries then some pigeonholeGeometry else none }

def document (epoch : UInt64) : Document := { (default : Document) with epoch }

def documentEvent (epoch : UInt64 := 1000) : Response :=
  .newPkiDocumentEvent { payload := serialise (document epoch) }

def sessionReply : Response := .sessionTokenReply { appId := bytes 0x40 16, resumed := false }

def counterReply (q : QueryId) (counter : UInt64) (errorCode : UInt8 := 0) : Response :=
  .getMessageBoxIndexCounterReply { queryId := q, counter, errorCode }

def index : MessageBoxIndex := fixed 104 0x10

end ThinClient.Tests.Fixtures
