/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Error
import ThinClient.Ids
import ThinClient.Geometry
import ThinClient.Pki

/-! # Messages

Every message exchanged with the daemon. A request travels as a one-entry map from the request's
key to its body. The daemon's messages travel as a map holding every response key, all `null`
but one; `Response.decode` turns that into one constructor of `Response`.

A request that the daemon answers has an `Rpc` instance naming its reply type, so sending it
yields the reply's type directly.

## Encoding

Bodies are maps keyed by the daemon's field names. A value the daemon may leave unset is an
`Option`, written as `null` when absent unless the daemon omits the key instead. -/

namespace ThinClient

open Cborg

/-- `none` and `false` are left out of the map. -/
private def omitFalse (key : String) (b : Bool) : Field := optField key (if b then some true else none)
private def omitEmpty {α : Type} [Serialise α] (key : String) (as : Array α) : Field :=
  optField key (if as.isEmpty then none else some as)
private def omitEmptyStr (key : String) (s : String) : Field :=
  optField key (if s.isEmpty then none else some s)

/-! ## Requests -/

structure SessionToken where
  clientInstanceToken : InstanceToken

instance : Serialise SessionToken where
  encode m := encodeRecord [field "client_instance_token" m.clientInstanceToken]
  decode := do
    let r ← decodeRecord
    return { clientInstanceToken := ← r.required "client_instance_token" }

structure ThinClose where

instance : Serialise ThinClose where
  encode _ := encodeRecord []
  decode := do let _ ← decodeRecord; return {}

structure SendMessage where
  id : Option MessageId := none
  withSurb : Bool
  surbId : Option SurbId
  destinationIdHash : Hash32
  recipientQueueId : ByteArray
  payload : ByteArray

instance : Serialise SendMessage where
  encode m := encodeRecord [
    nullableField "id" m.id, field "with_surb" m.withSurb, nullableField "surbid" m.surbId,
    field "destination_id_hash" m.destinationIdHash,
    field "recipient_queue_id" m.recipientQueueId, field "payload" m.payload]
  decode := do
    let r ← decodeRecord
    return {
      id := ← r.optional "id"
      withSurb := ← r.withDefault "with_surb" false
      surbId := ← r.optional "surbid"
      destinationIdHash := ← r.required "destination_id_hash"
      recipientQueueId := ← r.withDefault "recipient_queue_id" .empty
      payload := ← r.withDefault "payload" .empty }

structure NewKeypair where
  queryId : QueryId
  seed : FixedBytes 32

instance : Serialise NewKeypair where
  encode m := encodeRecord [field "query_id" m.queryId, field "seed" m.seed]
  decode := do
    let r ← decodeRecord
    return { queryId := ← r.required "query_id", seed := ← r.required "seed" }

structure EncryptRead where
  queryId : QueryId
  readCap : ReadCap
  messageBoxIndex : MessageBoxIndex

instance : Serialise EncryptRead where
  encode m := encodeRecord [field "query_id" m.queryId, field "read_cap" m.readCap,
    field "message_box_index" m.messageBoxIndex]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      readCap := ← r.required "read_cap"
      messageBoxIndex := ← r.required "message_box_index" }

structure EncryptWrite where
  queryId : QueryId
  plaintext : ByteArray
  writeCap : WriteCap
  messageBoxIndex : MessageBoxIndex

instance : Serialise EncryptWrite where
  encode m := encodeRecord [field "query_id" m.queryId, field "plaintext" m.plaintext,
    field "write_cap" m.writeCap, field "message_box_index" m.messageBoxIndex]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      plaintext := ← r.withDefault "plaintext" .empty
      writeCap := ← r.required "write_cap"
      messageBoxIndex := ← r.required "message_box_index" }

/-- Send an encrypted read or write until the courier answers. A read carries `readCap`, a write
carries `writeCap`. -/
structure StartResendingEncryptedMessage where
  queryId : QueryId
  readCap : Option ReadCap
  writeCap : Option WriteCap
  messageBoxIndex : Option MessageBoxIndex
  replyIndex : Option UInt8 := none
  envelopeDescriptor : ByteArray
  messageCiphertext : ByteArray
  envelopeHash : Hash32
  /-- Report a missing box at once instead of retrying. -/
  noRetryOnBoxIdNotFound : Bool := false
  /-- Report a box that already exists as an error instead of success. -/
  noIdempotentBoxAlreadyExists : Bool := false

instance : Serialise StartResendingEncryptedMessage where
  encode m := encodeRecord [
    field "query_id" m.queryId, nullableField "read_cap" m.readCap,
    nullableField "write_cap" m.writeCap, nullableField "message_box_index" m.messageBoxIndex,
    optField "reply_index" m.replyIndex, field "envelope_descriptor" m.envelopeDescriptor,
    field "message_ciphertext" m.messageCiphertext, field "envelope_hash" m.envelopeHash,
    omitFalse "no_retry_on_box_id_not_found" m.noRetryOnBoxIdNotFound,
    omitFalse "no_idempotent_box_already_exists" m.noIdempotentBoxAlreadyExists]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      readCap := ← r.optional "read_cap"
      writeCap := ← r.optional "write_cap"
      messageBoxIndex := ← r.optional "message_box_index"
      replyIndex := ← r.optional "reply_index"
      envelopeDescriptor := ← r.withDefault "envelope_descriptor" .empty
      messageCiphertext := ← r.withDefault "message_ciphertext" .empty
      envelopeHash := ← r.required "envelope_hash"
      noRetryOnBoxIdNotFound := ← r.withDefault "no_retry_on_box_id_not_found" false
      noIdempotentBoxAlreadyExists := ← r.withDefault "no_idempotent_box_already_exists" false }

structure CancelResendingEncryptedMessage where
  queryId : QueryId
  envelopeHash : Hash32

instance : Serialise CancelResendingEncryptedMessage where
  encode m := encodeRecord [field "query_id" m.queryId, field "envelope_hash" m.envelopeHash]
  decode := do
    let r ← decodeRecord
    return { queryId := ← r.required "query_id", envelopeHash := ← r.required "envelope_hash" }

structure StartResendingCopyCommand where
  queryId : QueryId
  writeCap : WriteCap
  courierIdentityHash : Option Hash32 := none
  courierQueueId : Option ByteArray := none

instance : Serialise StartResendingCopyCommand where
  encode m := encodeRecord [field "query_id" m.queryId, field "write_cap" m.writeCap,
    optField "courier_identity_hash" m.courierIdentityHash,
    optField "courier_queue_id" m.courierQueueId]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      writeCap := ← r.required "write_cap"
      courierIdentityHash := ← r.optional "courier_identity_hash"
      courierQueueId := ← r.optional "courier_queue_id" }

structure CancelResendingCopyCommand where
  queryId : QueryId
  /-- BLAKE2b-256 of the write capability. -/
  writeCapHash : Hash32

instance : Serialise CancelResendingCopyCommand where
  encode m := encodeRecord [field "query_id" m.queryId, field "write_cap_hash" m.writeCapHash]
  decode := do
    let r ← decodeRecord
    return { queryId := ← r.required "query_id", writeCapHash := ← r.required "write_cap_hash" }

structure NextMessageBoxIndex where
  queryId : QueryId
  messageBoxIndex : MessageBoxIndex

instance : Serialise NextMessageBoxIndex where
  encode m := encodeRecord [field "query_id" m.queryId,
    field "message_box_index" m.messageBoxIndex]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      messageBoxIndex := ← r.required "message_box_index" }

structure GetMessageBoxIndexCounter where
  queryId : QueryId
  messageBoxIndex : MessageBoxIndex

instance : Serialise GetMessageBoxIndexCounter where
  encode m := encodeRecord [field "query_id" m.queryId,
    field "message_box_index" m.messageBoxIndex]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      messageBoxIndex := ← r.required "message_box_index" }

/-- The signed PKI document for `epoch`; epoch 0 asks for the current one. -/
structure GetPKIDocument where
  queryId : QueryId
  epoch : UInt64

instance : Serialise GetPKIDocument where
  encode m := encodeRecord [field "query_id" m.queryId, field "epoch" m.epoch]
  decode := do
    let r ← decodeRecord
    return { queryId := ← r.required "query_id", epoch := ← r.withDefault "epoch" 0 }

structure GetDirectoryAuthorities where
  queryId : QueryId

instance : Serialise GetDirectoryAuthorities where
  encode m := encodeRecord [field "query_id" m.queryId]
  decode := do
    let r ← decodeRecord
    return { queryId := ← r.required "query_id" }

structure CreateCourierEnvelopesFromPayload where
  queryId : QueryId
  payload : ByteArray
  destWriteCap : WriteCap
  destStartIndex : MessageBoxIndex
  isStart : Bool
  isLast : Bool

instance : Serialise CreateCourierEnvelopesFromPayload where
  encode m := encodeRecord [field "query_id" m.queryId, field "payload" m.payload,
    field "dest_write_cap" m.destWriteCap, field "dest_start_index" m.destStartIndex,
    field "is_start" m.isStart, field "is_last" m.isLast]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      payload := ← r.withDefault "payload" .empty
      destWriteCap := ← r.required "dest_write_cap"
      destStartIndex := ← r.required "dest_start_index"
      isStart := ← r.withDefault "is_start" false
      isLast := ← r.withDefault "is_last" false }

structure DestinationPayload where
  payload : ByteArray
  writeCap : WriteCap
  startIndex : MessageBoxIndex

instance : Serialise DestinationPayload where
  encode m := encodeRecord [field "payload" m.payload, field "write_cap" m.writeCap,
    field "start_index" m.startIndex]
  decode := do
    let r ← decodeRecord
    return {
      payload := ← r.withDefault "payload" .empty
      writeCap := ← r.required "write_cap"
      startIndex := ← r.required "start_index" }

structure CreateCourierEnvelopesFromMultiPayload where
  queryId : QueryId
  destinations : Array DestinationPayload
  isStart : Bool
  isLast : Bool
  buffer : ByteArray

instance : Serialise CreateCourierEnvelopesFromMultiPayload where
  encode m := encodeRecord [field "query_id" m.queryId, field "destinations" m.destinations,
    field "is_start" m.isStart, field "is_last" m.isLast, field "buffer" m.buffer]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      destinations := ← r.withDefault "destinations" #[]
      isStart := ← r.withDefault "is_start" false
      isLast := ← r.withDefault "is_last" false
      buffer := ← r.withDefault "buffer" .empty }

structure CreateCourierEnvelopesFromTombstoneRange where
  queryId : QueryId
  destWriteCap : WriteCap
  destStartIndex : MessageBoxIndex
  maxCount : UInt32
  isStart : Bool
  isLast : Bool
  buffer : ByteArray

instance : Serialise CreateCourierEnvelopesFromTombstoneRange where
  encode m := encodeRecord [field "query_id" m.queryId, field "dest_write_cap" m.destWriteCap,
    field "dest_start_index" m.destStartIndex, field "max_count" m.maxCount,
    field "is_start" m.isStart, field "is_last" m.isLast, field "buffer" m.buffer]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      destWriteCap := ← r.required "dest_write_cap"
      destStartIndex := ← r.required "dest_start_index"
      maxCount := ← r.withDefault "max_count" 0
      isStart := ← r.withDefault "is_start" false
      isLast := ← r.withDefault "is_last" false
      buffer := ← r.withDefault "buffer" .empty }

structure VoucherMint where
  queryId : QueryId
  messageWriteCap : ByteArray
  displayName : String

instance : Serialise VoucherMint where
  encode m := encodeRecord [field "query_id" m.queryId,
    field "message_write_cap" m.messageWriteCap, field "display_name" m.displayName]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      messageWriteCap := ← r.withDefault "message_write_cap" .empty
      displayName := ← r.withDefault "display_name" "" }

structure VoucherInduct where
  queryId : QueryId
  voucher : ByteArray
  voucherPayload : ByteArray
  whoReply : ByteArray

instance : Serialise VoucherInduct where
  encode m := encodeRecord [field "query_id" m.queryId, field "voucher" m.voucher,
    field "voucher_payload" m.voucherPayload, field "who_reply" m.whoReply]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      voucher := ← r.withDefault "voucher" .empty
      voucherPayload := ← r.withDefault "voucher_payload" .empty
      whoReply := ← r.withDefault "who_reply" .empty }

structure VoucherOpen where
  queryId : QueryId
  voucherSecretKey : ByteArray
  sealedReply : ByteArray
  messageWriteCap : ByteArray

instance : Serialise VoucherOpen where
  encode m := encodeRecord [field "query_id" m.queryId,
    field "voucher_secret_key" m.voucherSecretKey, field "sealed_reply" m.sealedReply,
    field "message_write_cap" m.messageWriteCap]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      voucherSecretKey := ← r.withDefault "voucher_secret_key" .empty
      sealedReply := ← r.withDefault "sealed_reply" .empty
      messageWriteCap := ← r.withDefault "message_write_cap" .empty }

structure VoucherDeriveStream where
  queryId : QueryId
  voucher : ByteArray

instance : Serialise VoucherDeriveStream where
  encode m := encodeRecord [field "query_id" m.queryId, field "voucher" m.voucher]
  decode := do
    let r ← decodeRecord
    return { queryId := ← r.required "query_id", voucher := ← r.withDefault "voucher" .empty }

/-! ## Replies and events -/

structure SessionTokenReply where
  appId : ByteArray
  resumed : Bool

instance : Serialise SessionTokenReply where
  encode m := encodeRecord [field "app_id" m.appId, field "resumed" m.resumed]
  decode := do
    let r ← decodeRecord
    return {
      appId := ← r.withDefault "app_id" .empty
      resumed := ← r.withDefault "resumed" false }

structure ShutdownEvent where

instance : Serialise ShutdownEvent where
  encode _ := encodeRecord []
  decode := do let _ ← decodeRecord; return {}

structure ConnectionStatusEvent where
  isConnected : Bool
  instanceToken : InstanceToken
  sphinxGeometry : Option Geometry
  pigeonholeGeometry : Option PigeonholeGeometry

/-- `err` is always `null`. -/
instance : Serialise ConnectionStatusEvent where
  encode m := encodeRecord [field "is_connected" m.isConnected, ("err", some encodeNull),
    field "instance_token" m.instanceToken, nullableField "sphinx_geometry" m.sphinxGeometry,
    nullableField "pigeonhole_geometry" m.pigeonholeGeometry]
  decode := do
    let r ← decodeRecord
    return {
      isConnected := ← r.withDefault "is_connected" false
      instanceToken := ← r.required "instance_token"
      sphinxGeometry := ← r.optional "sphinx_geometry"
      pigeonholeGeometry := ← r.optional "pigeonhole_geometry" }

/-- The daemon's current PKI document, without signatures, as encoded CBOR. -/
structure NewPKIDocumentEvent where
  payload : ByteArray

instance : Serialise NewPKIDocumentEvent where
  encode m := encodeRecord [field "payload" m.payload]
  decode := do
    let r ← decodeRecord
    return { payload := ← r.withDefault "payload" .empty }

def NewPKIDocumentEvent.document? (e : NewPKIDocumentEvent) : Except String (Option Document) :=
  if e.payload.isEmpty then .ok none
  else (deserialise e.payload).map some |>.mapError (·.msg)

structure MessageSentEvent where
  messageId : Option MessageId
  surbId : Option SurbId
  /-- Unix time in seconds. -/
  sentAt : Int
  /-- Nanoseconds. -/
  replyEta : Int
  forwardRoute : Array String := #[]
  returnRoute : Array String := #[]
  err : String := ""

instance : Serialise MessageSentEvent where
  encode m := encodeRecord [nullableField "message_id" m.messageId,
    nullableField "surbid" m.surbId, field "sent_at" m.sentAt, field "reply_eta" m.replyEta,
    omitEmpty "forward_route" m.forwardRoute, omitEmpty "return_route" m.returnRoute,
    omitEmptyStr "err" m.err]
  decode := do
    let r ← decodeRecord
    return {
      messageId := ← r.optional "message_id"
      surbId := ← r.optional "surbid"
      sentAt := ← r.withDefault "sent_at" 0
      replyEta := ← r.withDefault "reply_eta" 0
      forwardRoute := ← r.withDefault "forward_route" #[]
      returnRoute := ← r.withDefault "return_route" #[]
      err := ← r.withDefault "err" "" }

structure MessageReplyEvent where
  messageId : Option MessageId
  surbId : Option SurbId
  payload : ByteArray
  replyIndex : Option UInt8 := none
  errorCode : UInt8

instance : Serialise MessageReplyEvent where
  encode m := encodeRecord [nullableField "message_id" m.messageId,
    nullableField "surbid" m.surbId, field "payload" m.payload,
    optField "reply_index" m.replyIndex, field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      messageId := ← r.optional "message_id"
      surbId := ← r.optional "surbid"
      payload := ← r.withDefault "payload" .empty
      replyIndex := ← r.optional "reply_index"
      errorCode := ← r.withDefault "error_code" 0 }

structure MessageIDGarbageCollected where
  messageId : Option MessageId

instance : Serialise MessageIDGarbageCollected where
  encode m := encodeRecord [nullableField "message_id" m.messageId]
  decode := do
    let r ← decodeRecord
    return { messageId := ← r.optional "message_id" }

structure NewKeypairReply where
  queryId : QueryId
  writeCap : Option WriteCap
  readCap : Option ReadCap
  firstMessageIndex : Option MessageBoxIndex
  errorCode : UInt8

instance : Serialise NewKeypairReply where
  encode m := encodeRecord [field "query_id" m.queryId, nullableField "write_cap" m.writeCap,
    nullableField "read_cap" m.readCap, nullableField "first_message_index" m.firstMessageIndex,
    field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      writeCap := ← r.optional "write_cap"
      readCap := ← r.optional "read_cap"
      firstMessageIndex := ← r.optional "first_message_index"
      errorCode := ← r.withDefault "error_code" 0 }

/-- The reply to an encrypt read or encrypt write. -/
structure EncryptReply where
  queryId : QueryId
  messageCiphertext : ByteArray
  envelopeDescriptor : ByteArray
  envelopeHash : Option Hash32
  nextMessageBoxIndex : Option MessageBoxIndex
  errorCode : UInt8

instance : Serialise EncryptReply where
  encode m := encodeRecord [field "query_id" m.queryId,
    field "message_ciphertext" m.messageCiphertext,
    field "envelope_descriptor" m.envelopeDescriptor, nullableField "envelope_hash" m.envelopeHash,
    nullableField "next_message_box_index" m.nextMessageBoxIndex, field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      messageCiphertext := ← r.withDefault "message_ciphertext" .empty
      envelopeDescriptor := ← r.withDefault "envelope_descriptor" .empty
      envelopeHash := ← r.optional "envelope_hash"
      nextMessageBoxIndex := ← r.optional "next_message_box_index"
      errorCode := ← r.withDefault "error_code" 0 }

structure StartResendingEncryptedMessageReply where
  queryId : QueryId
  plaintext : ByteArray
  errorCode : UInt8
  courierIdentityHash : Option Hash32
  courierQueueId : ByteArray

instance : Serialise StartResendingEncryptedMessageReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "plaintext" m.plaintext,
    field "error_code" m.errorCode, nullableField "courier_identity_hash" m.courierIdentityHash,
    field "courier_queue_id" m.courierQueueId]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      plaintext := ← r.withDefault "plaintext" .empty
      errorCode := ← r.withDefault "error_code" 0
      courierIdentityHash := ← r.optional "courier_identity_hash"
      courierQueueId := ← r.withDefault "courier_queue_id" .empty }

/-- The reply to a request whose only result is its error code. -/
structure StatusReply where
  queryId : QueryId
  errorCode : UInt8

instance : Serialise StatusReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return { queryId := ← r.required "query_id", errorCode := ← r.withDefault "error_code" 0 }

structure StartResendingCopyCommandReply where
  queryId : QueryId
  errorCode : UInt8
  replicaErrorCode : UInt8 := 0
  /-- 1-based position of the envelope the copy failed at. -/
  failedEnvelopeIndex : UInt64 := 0

instance : Serialise StartResendingCopyCommandReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "error_code" m.errorCode,
    optField "replica_error_code" (if m.replicaErrorCode == 0 then none else some m.replicaErrorCode),
    optField "failed_envelope_index"
      (if m.failedEnvelopeIndex == 0 then none else some m.failedEnvelopeIndex)]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      errorCode := ← r.withDefault "error_code" 0
      replicaErrorCode := ← r.withDefault "replica_error_code" 0
      failedEnvelopeIndex := ← r.withDefault "failed_envelope_index" 0 }

structure NextMessageBoxIndexReply where
  queryId : QueryId
  nextMessageBoxIndex : Option MessageBoxIndex
  errorCode : UInt8

instance : Serialise NextMessageBoxIndexReply where
  encode m := encodeRecord [field "query_id" m.queryId,
    nullableField "next_message_box_index" m.nextMessageBoxIndex, field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      nextMessageBoxIndex := ← r.optional "next_message_box_index"
      errorCode := ← r.withDefault "error_code" 0 }

structure GetMessageBoxIndexCounterReply where
  queryId : QueryId
  counter : UInt64
  errorCode : UInt8

instance : Serialise GetMessageBoxIndexCounterReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "counter" m.counter,
    field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      counter := ← r.withDefault "counter" 0
      errorCode := ← r.withDefault "error_code" 0 }

/-- `payload` is the certificate-wrapped signed PKI document. -/
structure GetPKIDocumentReply where
  queryId : QueryId
  payload : ByteArray
  epoch : UInt64
  errorCode : UInt8

instance : Serialise GetPKIDocumentReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "payload" m.payload,
    field "epoch" m.epoch, field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      payload := ← r.withDefault "payload" .empty
      epoch := ← r.withDefault "epoch" 0
      errorCode := ← r.withDefault "error_code" 0 }

structure DirectoryAuthority where
  identifier : String
  pkiSignatureScheme : String
  wireKemScheme : String
  addresses : Array String
  identityPublicKeyPem : String
  linkPublicKeyPem : String
  identityKeyHash : Hash32

instance : Serialise DirectoryAuthority where
  encode m := encodeRecord [field "identifier" m.identifier,
    field "pki_signature_scheme" m.pkiSignatureScheme, field "wire_kem_scheme" m.wireKemScheme,
    field "addresses" m.addresses, field "identity_public_key_pem" m.identityPublicKeyPem,
    field "link_public_key_pem" m.linkPublicKeyPem, field "identity_key_hash" m.identityKeyHash]
  decode := do
    let r ← decodeRecord
    return {
      identifier := ← r.withDefault "identifier" ""
      pkiSignatureScheme := ← r.withDefault "pki_signature_scheme" ""
      wireKemScheme := ← r.withDefault "wire_kem_scheme" ""
      addresses := ← r.withDefault "addresses" #[]
      identityPublicKeyPem := ← r.withDefault "identity_public_key_pem" ""
      linkPublicKeyPem := ← r.withDefault "link_public_key_pem" ""
      identityKeyHash := ← r.required "identity_key_hash" }

structure GetDirectoryAuthoritiesReply where
  queryId : QueryId
  authorities : Array DirectoryAuthority
  errorCode : UInt8

instance : Serialise GetDirectoryAuthoritiesReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "authorities" m.authorities,
    field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      authorities := ← r.withDefault "authorities" #[]
      errorCode := ← r.withDefault "error_code" 0 }

structure CreateCourierEnvelopesFromPayloadReply where
  queryId : QueryId
  envelopes : Array ByteArray
  nextDestIndex : Option MessageBoxIndex
  errorCode : UInt8

instance : Serialise CreateCourierEnvelopesFromPayloadReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "envelopes" m.envelopes,
    nullableField "next_dest_index" m.nextDestIndex, field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      envelopes := ← r.withDefault "envelopes" #[]
      nextDestIndex := ← r.optional "next_dest_index"
      errorCode := ← r.withDefault "error_code" 0 }

structure CreateCourierEnvelopesFromMultiPayloadReply where
  queryId : QueryId
  envelopes : Array ByteArray
  buffer : ByteArray
  nextDestIndices : Array MessageBoxIndex
  errorCode : UInt8

instance : Serialise CreateCourierEnvelopesFromMultiPayloadReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "envelopes" m.envelopes,
    field "buffer" m.buffer, field "next_dest_indices" m.nextDestIndices,
    field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      envelopes := ← r.withDefault "envelopes" #[]
      buffer := ← r.withDefault "buffer" .empty
      nextDestIndices := ← r.withDefault "next_dest_indices" #[]
      errorCode := ← r.withDefault "error_code" 0 }

structure CreateCourierEnvelopesFromTombstoneRangeReply where
  queryId : QueryId
  envelopes : Array ByteArray
  buffer : ByteArray
  nextDestIndex : Option MessageBoxIndex
  errorCode : UInt8

instance : Serialise CreateCourierEnvelopesFromTombstoneRangeReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "envelopes" m.envelopes,
    field "buffer" m.buffer, nullableField "next_dest_index" m.nextDestIndex,
    field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      envelopes := ← r.withDefault "envelopes" #[]
      buffer := ← r.withDefault "buffer" .empty
      nextDestIndex := ← r.optional "next_dest_index"
      errorCode := ← r.withDefault "error_code" 0 }

structure VoucherMintReply where
  queryId : QueryId
  voucher : ByteArray
  voucherPayload : ByteArray
  voucherWriteCap : ByteArray
  voucherReadCap : ByteArray
  voucherSecretKey : ByteArray
  voucherPublicKey : ByteArray
  errorCode : UInt8

instance : Serialise VoucherMintReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "voucher" m.voucher,
    field "voucher_payload" m.voucherPayload, field "voucher_write_cap" m.voucherWriteCap,
    field "voucher_read_cap" m.voucherReadCap, field "voucher_secret_key" m.voucherSecretKey,
    field "voucher_public_key" m.voucherPublicKey, field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      voucher := ← r.withDefault "voucher" .empty
      voucherPayload := ← r.withDefault "voucher_payload" .empty
      voucherWriteCap := ← r.withDefault "voucher_write_cap" .empty
      voucherReadCap := ← r.withDefault "voucher_read_cap" .empty
      voucherSecretKey := ← r.withDefault "voucher_secret_key" .empty
      voucherPublicKey := ← r.withDefault "voucher_public_key" .empty
      errorCode := ← r.withDefault "error_code" 0 }

structure VoucherInductReply where
  queryId : QueryId
  displayName : String
  mutatedMessageReadCap : ByteArray
  sealedReply : ByteArray
  voucherWriteCap : ByteArray
  voucherReadCap : ByteArray
  salt : ByteArray
  errorCode : UInt8

instance : Serialise VoucherInductReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "display_name" m.displayName,
    field "mutated_message_read_cap" m.mutatedMessageReadCap,
    field "sealed_reply" m.sealedReply, field "voucher_write_cap" m.voucherWriteCap,
    field "voucher_read_cap" m.voucherReadCap, field "salt" m.salt,
    field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      displayName := ← r.withDefault "display_name" ""
      mutatedMessageReadCap := ← r.withDefault "mutated_message_read_cap" .empty
      sealedReply := ← r.withDefault "sealed_reply" .empty
      voucherWriteCap := ← r.withDefault "voucher_write_cap" .empty
      voucherReadCap := ← r.withDefault "voucher_read_cap" .empty
      salt := ← r.withDefault "salt" .empty
      errorCode := ← r.withDefault "error_code" 0 }

structure VoucherOpenReply where
  queryId : QueryId
  whoReply : ByteArray
  salt : ByteArray
  mutatedMessageWriteCap : ByteArray
  errorCode : UInt8

instance : Serialise VoucherOpenReply where
  encode m := encodeRecord [field "query_id" m.queryId, field "who_reply" m.whoReply,
    field "salt" m.salt, field "mutated_message_write_cap" m.mutatedMessageWriteCap,
    field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      whoReply := ← r.withDefault "who_reply" .empty
      salt := ← r.withDefault "salt" .empty
      mutatedMessageWriteCap := ← r.withDefault "mutated_message_write_cap" .empty
      errorCode := ← r.withDefault "error_code" 0 }

structure VoucherDeriveStreamReply where
  queryId : QueryId
  voucherWriteCap : ByteArray
  voucherReadCap : ByteArray
  errorCode : UInt8

instance : Serialise VoucherDeriveStreamReply where
  encode m := encodeRecord [field "query_id" m.queryId,
    field "voucher_write_cap" m.voucherWriteCap, field "voucher_read_cap" m.voucherReadCap,
    field "error_code" m.errorCode]
  decode := do
    let r ← decodeRecord
    return {
      queryId := ← r.required "query_id"
      voucherWriteCap := ← r.withDefault "voucher_write_cap" .empty
      voucherReadCap := ← r.withDefault "voucher_read_cap" .empty
      errorCode := ← r.withDefault "error_code" 0 }

/-! ## The daemon's messages -/

inductive Response where
  | sessionTokenReply (m : SessionTokenReply)
  | shutdownEvent (m : ShutdownEvent)
  | connectionStatusEvent (m : ConnectionStatusEvent)
  | newPkiDocumentEvent (m : NewPKIDocumentEvent)
  | messageSentEvent (m : MessageSentEvent)
  | messageReplyEvent (m : MessageReplyEvent)
  | messageIdGarbageCollected (m : MessageIDGarbageCollected)
  | newKeypairReply (m : NewKeypairReply)
  | encryptReadReply (m : EncryptReply)
  | encryptWriteReply (m : EncryptReply)
  | startResendingEncryptedMessageReply (m : StartResendingEncryptedMessageReply)
  | cancelResendingEncryptedMessageReply (m : StatusReply)
  | startResendingCopyCommandReply (m : StartResendingCopyCommandReply)
  | cancelResendingCopyCommandReply (m : StatusReply)
  | nextMessageBoxIndexReply (m : NextMessageBoxIndexReply)
  | getMessageBoxIndexCounterReply (m : GetMessageBoxIndexCounterReply)
  | getPkiDocumentReply (m : GetPKIDocumentReply)
  | getDirectoryAuthoritiesReply (m : GetDirectoryAuthoritiesReply)
  | createCourierEnvelopesFromPayloadReply (m : CreateCourierEnvelopesFromPayloadReply)
  | createCourierEnvelopesFromMultiPayloadReply (m : CreateCourierEnvelopesFromMultiPayloadReply)
  | createCourierEnvelopesFromTombstoneRangeReply
      (m : CreateCourierEnvelopesFromTombstoneRangeReply)
  | voucherMintReply (m : VoucherMintReply)
  | voucherInductReply (m : VoucherInductReply)
  | voucherOpenReply (m : VoucherOpenReply)
  | voucherDeriveStreamReply (m : VoucherDeriveStreamReply)
  /-- A key this client does not know. -/
  | unknown (key : String)

namespace Response

/-- The wire key and encoded body. -/
def toKeyBody : Response → String × Encoding
  | sessionTokenReply m => ("session_token_reply", encode m)
  | shutdownEvent m => ("shutdown_event", encode m)
  | connectionStatusEvent m => ("connection_status_event", encode m)
  | newPkiDocumentEvent m => ("new_pki_document_event", encode m)
  | messageSentEvent m => ("message_sent_event", encode m)
  | messageReplyEvent m => ("message_reply_event", encode m)
  | messageIdGarbageCollected m => ("message_id_garbage_collected", encode m)
  | newKeypairReply m => ("new_keypair_reply", encode m)
  | encryptReadReply m => ("encrypt_read_reply", encode m)
  | encryptWriteReply m => ("encrypt_write_reply", encode m)
  | startResendingEncryptedMessageReply m => ("start_resending_encrypted_message_reply", encode m)
  | cancelResendingEncryptedMessageReply m =>
    ("cancel_resending_encrypted_message_reply", encode m)
  | startResendingCopyCommandReply m => ("start_resending_copy_command_reply", encode m)
  | cancelResendingCopyCommandReply m => ("cancel_resending_copy_command_reply", encode m)
  | nextMessageBoxIndexReply m => ("next_message_box_index_reply", encode m)
  | getMessageBoxIndexCounterReply m => ("get_message_box_index_counter_reply", encode m)
  | getPkiDocumentReply m => ("get_pki_document_reply", encode m)
  | getDirectoryAuthoritiesReply m => ("get_directory_authorities_reply", encode m)
  | createCourierEnvelopesFromPayloadReply m =>
    ("create_courier_envelopes_from_payload_reply", encode m)
  | createCourierEnvelopesFromMultiPayloadReply m =>
    ("create_courier_envelopes_from_multi_payload_reply", encode m)
  | createCourierEnvelopesFromTombstoneRangeReply m =>
    ("create_courier_envelopes_from_tombstone_range_reply", encode m)
  | voucherMintReply m => ("voucher_mint_reply", encode m)
  | voucherInductReply m => ("voucher_induct_reply", encode m)
  | voucherOpenReply m => ("voucher_open_reply", encode m)
  | voucherDeriveStreamReply m => ("voucher_derive_stream_reply", encode m)
  | unknown k => (k, encodeNull)

def key (r : Response) : String := r.toKeyBody.1

/-- A one-entry map, as the daemon's decoder accepts. -/
def encode (r : Response) : ByteArray :=
  let (k, body) := r.toKeyBody
  toByteArray (encodeRecord [(k, some body)])

private def body {α : Type} [Serialise α] (raw : ByteArray) (wrap : α → Response) :
    Except String Response :=
  (deserialise raw).map wrap |>.mapError (·.msg)

def ofKeyBody (key : String) (raw : ByteArray) : Except String Response :=
  match key with
  | "session_token_reply" => body raw sessionTokenReply
  | "shutdown_event" => body raw shutdownEvent
  | "connection_status_event" => body raw connectionStatusEvent
  | "new_pki_document_event" => body raw newPkiDocumentEvent
  | "message_sent_event" => body raw messageSentEvent
  | "message_reply_event" => body raw messageReplyEvent
  | "message_id_garbage_collected" => body raw messageIdGarbageCollected
  | "new_keypair_reply" => body raw newKeypairReply
  | "encrypt_read_reply" => body raw encryptReadReply
  | "encrypt_write_reply" => body raw encryptWriteReply
  | "start_resending_encrypted_message_reply" => body raw startResendingEncryptedMessageReply
  | "cancel_resending_encrypted_message_reply" => body raw cancelResendingEncryptedMessageReply
  | "start_resending_copy_command_reply" => body raw startResendingCopyCommandReply
  | "cancel_resending_copy_command_reply" => body raw cancelResendingCopyCommandReply
  | "next_message_box_index_reply" => body raw nextMessageBoxIndexReply
  | "get_message_box_index_counter_reply" => body raw getMessageBoxIndexCounterReply
  | "get_pki_document_reply" => body raw getPkiDocumentReply
  | "get_directory_authorities_reply" => body raw getDirectoryAuthoritiesReply
  | "create_courier_envelopes_from_payload_reply" => body raw createCourierEnvelopesFromPayloadReply
  | "create_courier_envelopes_from_multi_payload_reply" =>
    body raw createCourierEnvelopesFromMultiPayloadReply
  | "create_courier_envelopes_from_tombstone_range_reply" =>
    body raw createCourierEnvelopesFromTombstoneRangeReply
  | "voucher_mint_reply" => body raw voucherMintReply
  | "voucher_induct_reply" => body raw voucherInductReply
  | "voucher_open_reply" => body raw voucherOpenReply
  | "voucher_derive_stream_reply" => body raw voucherDeriveStreamReply
  | k => .ok (unknown k)

private def isNull (raw : ByteArray) : Bool := raw.size == 1 && raw[0]! == 0xf6

/-- Decode a frame body: exactly one key may carry a value. -/
def decode (frame : ByteArray) : Except ThinClientError Response := do
  let r ← (deserialise (α := Record) frame).mapError (.decode ·.msg)
  match r.fields.filter (!isNull ·.2) |>.toList with
  | [] => throw (.protocol .noVariant)
  | [(k, raw)] => (ofKeyBody k raw).mapError (.decode s!"{k}: {·}")
  | kvs => throw (.protocol (.multipleVariants (kvs.map (·.1))))

/-- The query a reply answers. -/
def queryId? : Response → Option QueryId
  | newKeypairReply m => m.queryId
  | encryptReadReply m | encryptWriteReply m => m.queryId
  | startResendingEncryptedMessageReply m => m.queryId
  | cancelResendingEncryptedMessageReply m | cancelResendingCopyCommandReply m => m.queryId
  | startResendingCopyCommandReply m => m.queryId
  | nextMessageBoxIndexReply m => m.queryId
  | getMessageBoxIndexCounterReply m => m.queryId
  | getPkiDocumentReply m => m.queryId
  | getDirectoryAuthoritiesReply m => m.queryId
  | createCourierEnvelopesFromPayloadReply m => m.queryId
  | createCourierEnvelopesFromMultiPayloadReply m => m.queryId
  | createCourierEnvelopesFromTombstoneRangeReply m => m.queryId
  | voucherMintReply m => m.queryId
  | voucherInductReply m => m.queryId
  | voucherOpenReply m => m.queryId
  | voucherDeriveStreamReply m => m.queryId
  | _ => none

end Response

/-! ## Requests and their replies -/

/-- A message the client sends, and the key it travels under. -/
class Request (α : Type) extends Serialise α where
  key : String

/-- The one-entry map a request travels as. -/
def encodeRequest {α : Type} [Request α] (a : α) : ByteArray :=
  toByteArray (encodeRecord [field (Request.key α) a])

/-- A request the daemon answers, matched to its reply by query ID. -/
class Rpc (α : Type) extends Request α where
  Reply : Type
  queryId : α → QueryId
  reply? : Response → Option Reply
  /-- The failure a reply reports, read from its error code. -/
  error? : Reply → Option ThinClientError

instance : Request SessionToken := { key := "session_token" }
instance : Request ThinClose := { key := "thin_close" }
instance : Request SendMessage := { key := "send_message" }

instance : Rpc NewKeypair where
  key := "new_keypair"
  Reply := NewKeypairReply
  queryId := (·.queryId)
  reply? | .newKeypairReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc EncryptRead where
  key := "encrypt_read"
  Reply := EncryptReply
  queryId := (·.queryId)
  reply? | .encryptReadReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc EncryptWrite where
  key := "encrypt_write"
  Reply := EncryptReply
  queryId := (·.queryId)
  reply? | .encryptWriteReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc StartResendingEncryptedMessage where
  key := "start_resending_encrypted_message"
  Reply := StartResendingEncryptedMessageReply
  queryId := (·.queryId)
  reply? | .startResendingEncryptedMessageReply m => some m | _ => none
  error? m := ThinClientError.ofResendCode m.errorCode

instance : Rpc CancelResendingEncryptedMessage where
  key := "cancel_resending_encrypted_message"
  Reply := StatusReply
  queryId := (·.queryId)
  reply? | .cancelResendingEncryptedMessageReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc StartResendingCopyCommand where
  key := "start_resending_copy_command"
  Reply := StartResendingCopyCommandReply
  queryId := (·.queryId)
  reply? | .startResendingCopyCommandReply m => some m | _ => none
  error? m := ThinClientError.ofCopyCommandCode m.errorCode m.replicaErrorCode m.failedEnvelopeIndex

instance : Rpc CancelResendingCopyCommand where
  key := "cancel_resending_copy_command"
  Reply := StatusReply
  queryId := (·.queryId)
  reply? | .cancelResendingCopyCommandReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc NextMessageBoxIndex where
  key := "next_message_box_index"
  Reply := NextMessageBoxIndexReply
  queryId := (·.queryId)
  reply? | .nextMessageBoxIndexReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc GetMessageBoxIndexCounter where
  key := "get_message_box_index_counter"
  Reply := GetMessageBoxIndexCounterReply
  queryId := (·.queryId)
  reply? | .getMessageBoxIndexCounterReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc GetPKIDocument where
  key := "get_pki_document"
  Reply := GetPKIDocumentReply
  queryId := (·.queryId)
  reply? | .getPkiDocumentReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc GetDirectoryAuthorities where
  key := "get_directory_authorities"
  Reply := GetDirectoryAuthoritiesReply
  queryId := (·.queryId)
  reply? | .getDirectoryAuthoritiesReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc CreateCourierEnvelopesFromPayload where
  key := "create_courier_envelopes_from_payload"
  Reply := CreateCourierEnvelopesFromPayloadReply
  queryId := (·.queryId)
  reply? | .createCourierEnvelopesFromPayloadReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc CreateCourierEnvelopesFromMultiPayload where
  key := "create_courier_envelopes_from_multi_payload"
  Reply := CreateCourierEnvelopesFromMultiPayloadReply
  queryId := (·.queryId)
  reply? | .createCourierEnvelopesFromMultiPayloadReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc CreateCourierEnvelopesFromTombstoneRange where
  key := "create_courier_envelopes_from_tombstone_range"
  Reply := CreateCourierEnvelopesFromTombstoneRangeReply
  queryId := (·.queryId)
  reply? | .createCourierEnvelopesFromTombstoneRangeReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc VoucherMint where
  key := "voucher_mint"
  Reply := VoucherMintReply
  queryId := (·.queryId)
  reply? | .voucherMintReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc VoucherInduct where
  key := "voucher_induct"
  Reply := VoucherInductReply
  queryId := (·.queryId)
  reply? | .voucherInductReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc VoucherOpen where
  key := "voucher_open"
  Reply := VoucherOpenReply
  queryId := (·.queryId)
  reply? | .voucherOpenReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

instance : Rpc VoucherDeriveStream where
  key := "voucher_derive_stream"
  Reply := VoucherDeriveStreamReply
  queryId := (·.queryId)
  reply? | .voucherDeriveStreamReply m => some m | _ => none
  error? m := ThinClientError.ofCode m.errorCode

/-! ## Events -/

/-- What subscribers are told about. -/
inductive Event where
  | connectionStatus (m : ConnectionStatusEvent)
  | newPkiDocument (doc : Document)
  | messageSent (m : MessageSentEvent)
  | messageReply (m : MessageReplyEvent)
  | messageIdGarbageCollected (m : MessageIDGarbageCollected)
  | daemonDisconnected (graceful : Bool) (err : Option ThinClientError)

end ThinClient
