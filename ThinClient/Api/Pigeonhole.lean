/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Client

/-! # Pigeonhole

Encrypted reads and writes of BACAP message boxes, carried to storage replicas by couriers. The
daemon holds no capabilities: the client encrypts a read or write with `encryptRead` or
`encryptWrite`, then has the daemon resend it with `startResendingEncryptedMessage` until a
courier answers. Requests being resent are tracked so that a reconnect to a new daemon instance
resends them. -/

namespace ThinClient

open Cborg

structure KeypairResult where
  writeCap : WriteCap
  readCap : ReadCap
  firstMessageIndex : MessageBoxIndex

structure EncryptResult where
  messageCiphertext : ByteArray
  envelopeDescriptor : ByteArray
  envelopeHash : Hash32
  nextMessageBoxIndex : MessageBoxIndex

structure StartResendingResult where
  /-- The box's contents for a read; empty for a write. -/
  plaintext : ByteArray
  /-- The courier that carried the message, so it can be resent elsewhere if that courier leaves
  the PKI document. -/
  courierIdentityHash : Option Hash32
  courierQueueId : ByteArray

/-- A read with a read capability, or a write with a write capability. -/
inductive BoxAccess where
  | read (cap : ReadCap) (index : MessageBoxIndex)
  | write (cap : WriteCap)

structure ResendOptions where
  /-- Report a missing box at once instead of resending until it appears. -/
  noRetryOnBoxIdNotFound : Bool := false
  /-- Report a write to a box that already exists as `boxAlreadyExists` instead of success. -/
  noIdempotentBoxAlreadyExists : Bool := false
  replyIndex : Option UInt8 := none

structure TombstoneEnvelope where
  messageCiphertext : ByteArray
  envelopeDescriptor : ByteArray
  envelopeHash : Hash32
  boxIndex : MessageBoxIndex

structure TombstoneRangeResult where
  envelopes : Array TombstoneEnvelope
  next : MessageBoxIndex

structure CreateEnvelopesResult where
  envelopes : Array ByteArray
  /-- Payload left over for the next call. -/
  buffer : ByteArray
  nextDestIndices : Array MessageBoxIndex

private def required {α : Type} (name : String) : Option α → ClientM α
  | some a => pure a
  | none => throw (.protocol (.missingField name))

def newKeypair (seed : FixedBytes 32) : ClientM KeypairResult := do
  let r ← call { queryId := ← freshQueryId, seed : NewKeypair }
  return {
    writeCap := ← required "write_cap" r.writeCap
    readCap := ← required "read_cap" r.readCap
    firstMessageIndex := ← required "first_message_index" r.firstMessageIndex }

private def encryptResult (r : EncryptReply) : ClientM EncryptResult := do
  return {
    messageCiphertext := r.messageCiphertext
    envelopeDescriptor := r.envelopeDescriptor
    envelopeHash := ← required "envelope_hash" r.envelopeHash
    nextMessageBoxIndex := ← required "next_message_box_index" r.nextMessageBoxIndex }

def encryptRead (readCap : ReadCap) (index : MessageBoxIndex) : ClientM EncryptResult := do
  encryptResult (← call { queryId := ← freshQueryId, readCap, messageBoxIndex := index : EncryptRead })

def encryptWrite (plaintext : ByteArray) (writeCap : WriteCap) (index : MessageBoxIndex) :
    ClientM EncryptResult := do
  encryptResult (← call {
    queryId := ← freshQueryId, plaintext, writeCap, messageBoxIndex := index : EncryptWrite })

/-- Have the daemon resend an encrypted read or write until a courier answers. -/
def startResendingEncryptedMessage (access : BoxAccess) (envelopeDescriptor messageCiphertext : ByteArray)
    (envelopeHash : Hash32) (options : ResendOptions := {}) : ClientM StartResendingResult := do
  let (readCap, writeCap, index) := match access with
    | .read cap index => (some cap, none, some index)
    | .write cap => (none, some cap, none)
  let req : StartResendingEncryptedMessage := {
    queryId := ← freshQueryId, readCap, writeCap, messageBoxIndex := index,
    replyIndex := options.replyIndex, envelopeDescriptor, messageCiphertext, envelopeHash,
    noRetryOnBoxIdNotFound := options.noRetryOnBoxIdNotFound,
    noIdempotentBoxAlreadyExists := options.noIdempotentBoxAlreadyExists }
  let r ← tracking { key := envelopeHash, queryId := req.queryId, request := encodeRequest req }
    (call req)
  return { plaintext := r.plaintext, courierIdentityHash := r.courierIdentityHash,
           courierQueueId := r.courierQueueId }

/-- Stop resending the message with this envelope hash; its caller fails with
`startResendingCancelled`. -/
def cancelResendingEncryptedMessage (envelopeHash : Hash32) : ClientM Unit := do
  untrack envelopeHash
  discard <| call { queryId := ← freshQueryId, envelopeHash : CancelResendingEncryptedMessage }

/-- The key a copy command is tracked and cancelled by: BLAKE2b-256 of the write capability. -/
def writeCapHash (writeCap : WriteCap) : Hash32 :=
  let h := CryptWalker.Hash.Blake2b.hash256 writeCap.bytes
  ⟨⟨h.toArray⟩, h.size_toArray⟩

/-- Have the courier copy the stream of envelopes written with `writeCap` to their destinations,
resending until it completes. -/
def startResendingCopyCommand (writeCap : WriteCap) : ClientM Unit := do
  let req : StartResendingCopyCommand := { queryId := ← freshQueryId, writeCap }
  discard <| tracking { key := writeCapHash writeCap, queryId := req.queryId,
                        request := encodeRequest req } (call req)

def cancelResendingCopyCommand (writeCapHash : Hash32) : ClientM Unit := do
  untrack writeCapHash
  discard <| call { queryId := ← freshQueryId, writeCapHash : CancelResendingCopyCommand }

def nextMessageBoxIndex (index : MessageBoxIndex) : ClientM MessageBoxIndex := do
  let r ← call { queryId := ← freshQueryId, messageBoxIndex := index : NextMessageBoxIndex }
  required "next_message_box_index" r.nextMessageBoxIndex

def getMessageBoxIndexCounter (index : MessageBoxIndex) : ClientM UInt64 := do
  let r ← call { queryId := ← freshQueryId, messageBoxIndex := index : GetMessageBoxIndexCounter }
  pure r.counter

/-- Courier envelopes that write `payload` into the boxes of `destWriteCap` from `destStartIndex`.
`isStart` and `isLast` mark the first and last chunks of a copy stream. -/
def createCourierEnvelopesFromPayload (payload : ByteArray) (destWriteCap : WriteCap)
    (destStartIndex : MessageBoxIndex) (isStart isLast : Bool) :
    ClientM (Array ByteArray × MessageBoxIndex) := do
  let r ← call { queryId := ← freshQueryId, payload, destWriteCap, destStartIndex, isStart, isLast :
                 CreateCourierEnvelopesFromPayload }
  return (r.envelopes, ← required "next_dest_index" r.nextDestIndex)

/-- As `createCourierEnvelopesFromPayload`, for several destinations at once, packing envelopes
across calls through `buffer`. -/
def createCourierEnvelopesFromMultiPayload (destinations : Array DestinationPayload)
    (isStart isLast : Bool) (buffer : ByteArray := .empty) : ClientM CreateEnvelopesResult := do
  let r ← call { queryId := ← freshQueryId, destinations, isStart, isLast, buffer :
                 CreateCourierEnvelopesFromMultiPayload }
  return { envelopes := r.envelopes, buffer := r.buffer, nextDestIndices := r.nextDestIndices }

/-- Courier envelopes that tombstone up to `maxCount` boxes of `destWriteCap` from
`destStartIndex`. -/
def createCourierEnvelopesFromTombstoneRange (destWriteCap : WriteCap)
    (destStartIndex : MessageBoxIndex) (maxCount : UInt32) (isStart isLast : Bool)
    (buffer : ByteArray := .empty) : ClientM (Array ByteArray × ByteArray × MessageBoxIndex) := do
  let r ← call { queryId := ← freshQueryId, destWriteCap, destStartIndex, maxCount, isStart, isLast,
                 buffer : CreateCourierEnvelopesFromTombstoneRange }
  return (r.envelopes, r.buffer, ← required "next_dest_index" r.nextDestIndex)

/-- Encrypt tombstones (empty writes) for `maxCount` boxes from `start`. If one fails, the result
holds the tombstones made so far and the error is thrown. -/
def tombstoneRange (writeCap : WriteCap) (start : MessageBoxIndex) (maxCount : Nat) :
    ClientM TombstoneRangeResult := do
  let mut cur := start
  let mut envelopes := #[]
  for _ in [0:maxCount] do
    let e ← encryptWrite .empty writeCap cur
    let tombstone : TombstoneEnvelope := {
      messageCiphertext := e.messageCiphertext, envelopeDescriptor := e.envelopeDescriptor,
      envelopeHash := e.envelopeHash, boxIndex := cur }
    envelopes := envelopes.push tombstone
    cur := e.nextMessageBoxIndex
  return { envelopes, next := cur }

end ThinClient
