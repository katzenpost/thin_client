/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import ThinClient.Messages
import ThinClient.Tests.Util

/-! # Test vectors from the daemon's types

`testdata/vectors.json`, written by `scripts/gen-vectors`, holds every request and response as
the daemon encodes them. Each body must decode and re-encode to the same bytes, and each
response frame must decode to the variant it names. The client's own request frames are written
to `.lake/requests.json` for `gen-vectors verify` to decode with the daemon's types. -/

namespace ThinClient.Tests.Vectors

open Lean (Json)
open Cborg
open ThinClient

structure Vector where
  name : String
  key : String
  body : ByteArray
  frame : ByteArray

def Vector.ofJson (j : Json) : Except String Vector := do
  return {
    name := ← (← j.getObjVal? "name").getStr?
    key := ← (← j.getObjVal? "key").getStr?
    body := ← unhex (← (← j.getObjVal? "body").getStr?)
    frame := ← unhex (← (← j.getObjVal? "frame").getStr?) }

/-- Decode a request body, then give its re-encoded body and the frame this client sends. -/
def requestRoundTrip (key : String) (body : ByteArray) : Except String (ByteArray × ByteArray) :=
  let go {α : Type} [Request α] : Except String (ByteArray × ByteArray) := do
    let m : α ← (deserialise body).mapError (·.msg)
    pure (serialise m, encodeRequest m)
  match key with
  | "session_token" => go (α := SessionToken)
  | "thin_close" => go (α := ThinClose)
  | "send_message" => go (α := SendMessage)
  | "new_keypair" => go (α := NewKeypair)
  | "encrypt_read" => go (α := EncryptRead)
  | "encrypt_write" => go (α := EncryptWrite)
  | "start_resending_encrypted_message" => go (α := StartResendingEncryptedMessage)
  | "cancel_resending_encrypted_message" => go (α := CancelResendingEncryptedMessage)
  | "start_resending_copy_command" => go (α := StartResendingCopyCommand)
  | "cancel_resending_copy_command" => go (α := CancelResendingCopyCommand)
  | "next_message_box_index" => go (α := NextMessageBoxIndex)
  | "get_message_box_index_counter" => go (α := GetMessageBoxIndexCounter)
  | "get_pki_document" => go (α := GetPKIDocument)
  | "get_directory_authorities" => go (α := GetDirectoryAuthorities)
  | "create_courier_envelopes_from_payload" => go (α := CreateCourierEnvelopesFromPayload)
  | "create_courier_envelopes_from_multi_payload" => go (α := CreateCourierEnvelopesFromMultiPayload)
  | "create_courier_envelopes_from_tombstone_range" =>
    go (α := CreateCourierEnvelopesFromTombstoneRange)
  | "voucher_mint" => go (α := VoucherMint)
  | "voucher_induct" => go (α := VoucherInduct)
  | "voucher_open" => go (α := VoucherOpen)
  | "voucher_derive_stream" => go (α := VoucherDeriveStream)
  | k => .error s!"unknown request {k}"

def checkRequest (v : Vector) : TestM (Option Json) := do
  let some (body, frame) ← expectOk v.name (requestRoundTrip v.key v.body) | pure none
  check s!"{v.name}: body re-encodes identically" (sameBytes body v.body)
    fun _ => s!"\n  want {hex v.body}\n  got  {hex body}"
  pure (some (Json.mkObj [("name", v.name), ("frame", hex frame)]))

def checkResponse (v : Vector) : TestM (Option Response) := do
  match Response.decode v.frame with
  | .error e => check s!"{v.name}: decode" false (fun _ => toString e); pure none
  | .ok r =>
    checkEq s!"{v.name}: variant" v.key r.key
    let body := toByteArray r.toKeyBody.2
    check s!"{v.name}: body re-encodes identically" (sameBytes body v.body)
      fun _ => s!"\n  want {hex v.body}\n  got  {hex body}"
    let again := Response.decode r.encode
    check s!"{v.name}: one-entry frame decodes" (match again with
      | .ok r' => sameBytes (toByteArray r'.toKeyBody.2) v.body | _ => false)
    pure (some r)

/-- The PKI document and geometries the vectors carry agree with each other. -/
def checkDocument (rs : List Response) : TestM Unit := do
  let doc? := rs.findSome? fun
    | .newPkiDocumentEvent e => some e
    | _ => none
  let status? := rs.findSome? fun
    | .connectionStatusEvent e => if e.sphinxGeometry.isSome then some e else none
    | _ => none
  let (some ev, some status) := (doc?, status?)
    | check "document and status vectors present" false
  let some (some doc) ← expectOk "document decodes" ev.document? | pure ()
  check "document re-encodes identically" (sameBytes (serialise doc) ev.payload)
    fun _ => s!"\n  want {hex ev.payload}\n  got  {hex (serialise doc)}"
  checkEq "epoch" 123456 doc.epoch
  checkEq "topology layers" 2 doc.topology.size
  checkEq "first mix" "mix1" (doc.topology[0]!.map (·.name) |>.toList |> String.intercalate ",")
  checkEq "replica" "replica1" (doc.storageReplicas.map (·.name) |>.toList |> String.intercalate ",")
  let services := findServices "echo" doc
  checkEq "echo services" 1 services.size
  checkEq "echo endpoint" "+echo" (String.fromUTF8! (services[0]!.recipientQueueId))
  checkEq "no other services" 0 (findServices "nope" doc).size
  let some geometry := status.sphinxGeometry | check "sphinx geometry present" false
  check "sphinx geometry validates" (geometry.validate matches .ok ())
  check "sphinx geometry is CryptWalker's" (match
      CryptWalker.Protocols.Sphinx.Geometry.ofNIKE "x25519" 2000 true 5 with
    | .ok g => g == geometry | _ => false)
  check "sphinx geometry hash is the document's" (sameBytes ⟨geometry.hash.toArray⟩ doc.sphinxGeometryHash)
  let some ph := status.pigeonholeGeometry | check "pigeonhole geometry present" false
  check "pigeonhole geometry validates" (ph.validate matches .ok ())

def suite (requestsOut : System.FilePath) : TestM Unit := do
  let raw ← IO.FS.readFile "testdata/vectors.json"
  let parsed := do
    let j ← Json.parse raw
    let reqs ← (← j.getObjVal? "requests").getArr?
    let resps ← (← j.getObjVal? "responses").getArr?
    return (← reqs.mapM Vector.ofJson, ← resps.mapM Vector.ofJson)
  let some (reqs, resps) ← expectOk "vectors parse" parsed | pure ()
  let mut frames := #[]
  for v in reqs do
    if let some f ← checkRequest v then frames := frames.push f
  let mut decoded := []
  for v in resps do
    if let some r ← checkResponse v then decoded := r :: decoded
  checkDocument decoded
  check "no variant" (match Response.decode (toByteArray (encodeRecord [("x", some encodeNull)])) with
    | .error (.protocol .noVariant) => true | _ => false)
  check "two variants" (match Response.decode (toByteArray (encodeRecord
      [field "shutdown_event" ShutdownEvent.mk, field "thin_close" ThinClose.mk])) with
    | .error (.protocol (.multipleVariants _)) => true | _ => false)
  IO.FS.createDirAll (requestsOut.parent.getD ".")
  IO.FS.writeFile requestsOut (Json.mkObj [("requests", Json.arr frames)]).pretty

end ThinClient.Tests.Vectors
