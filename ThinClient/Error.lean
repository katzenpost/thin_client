/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # Errors

Failures are values of `ThinClientError`. The daemon reports failures as numeric codes from two
namespaces, the thin client's (`DaemonError`) and the pigeonhole replicas' (`ReplicaError`); each
reply type says which namespace its `error_code` field uses, and the interpreters below turn a
code into a `ThinClientError`. Code 0 is success in both namespaces and has no constructor. -/

namespace ThinClient

inductive DaemonError where
  | connectionLost
  | timeout
  | invalidRequest
  | internalError
  | maxRetries
  | invalidChannel
  | channelNotFound
  | permissionDenied
  | invalidPayload
  | serviceUnavailable
  | duplicateCapability
  | courierCacheCorruption
  | propagationError
  | invalidWriteCapability
  | invalidReadCapability
  | invalidResumeWriteChannelRequest
  | invalidResumeReadChannelRequest
  | impossibleHash
  | impossibleNewWriteCap
  | impossibleNewStatefulWriter
  | capabilityAlreadyInUse
  | mkemDecryptionFailed
  | bacapDecryptionFailed
  | startResendingCancelled
  | invalidTombstoneSignature
  | copyCommandFailed
  | payloadTooLarge
  | voucherHashMismatch
  | voucherSignatureInvalid
  | voucherSealOpenFailed
  | courierInvalidEnvelope
  | courierInvalidEpoch
  | indexNotInChannel
  | indexTooFar
  deriving DecidableEq, Repr, Inhabited

namespace DaemonError

def toCode : DaemonError → UInt8
  | connectionLost => 1
  | timeout => 2
  | invalidRequest => 3
  | internalError => 4
  | maxRetries => 5
  | invalidChannel => 6
  | channelNotFound => 7
  | permissionDenied => 8
  | invalidPayload => 9
  | serviceUnavailable => 10
  | duplicateCapability => 11
  | courierCacheCorruption => 12
  | propagationError => 13
  | invalidWriteCapability => 14
  | invalidReadCapability => 15
  | invalidResumeWriteChannelRequest => 16
  | invalidResumeReadChannelRequest => 17
  | impossibleHash => 18
  | impossibleNewWriteCap => 19
  | impossibleNewStatefulWriter => 20
  | capabilityAlreadyInUse => 21
  | mkemDecryptionFailed => 22
  | bacapDecryptionFailed => 23
  | startResendingCancelled => 24
  | invalidTombstoneSignature => 25
  | copyCommandFailed => 26
  | payloadTooLarge => 27
  | voucherHashMismatch => 28
  | voucherSignatureInvalid => 29
  | voucherSealOpenFailed => 30
  | courierInvalidEnvelope => 31
  | courierInvalidEpoch => 32
  | indexNotInChannel => 33
  | indexTooFar => 34

def all : List DaemonError :=
  [connectionLost, timeout, invalidRequest, internalError, maxRetries, invalidChannel,
   channelNotFound, permissionDenied, invalidPayload, serviceUnavailable, duplicateCapability,
   courierCacheCorruption, propagationError, invalidWriteCapability, invalidReadCapability,
   invalidResumeWriteChannelRequest, invalidResumeReadChannelRequest, impossibleHash,
   impossibleNewWriteCap, impossibleNewStatefulWriter, capabilityAlreadyInUse,
   mkemDecryptionFailed, bacapDecryptionFailed, startResendingCancelled,
   invalidTombstoneSignature, copyCommandFailed, payloadTooLarge, voucherHashMismatch,
   voucherSignatureInvalid, voucherSealOpenFailed, courierInvalidEnvelope, courierInvalidEpoch,
   indexNotInChannel, indexTooFar]

def ofCode? (c : UInt8) : Option DaemonError := all.find? (·.toCode == c)

theorem mem_all (e : DaemonError) : e ∈ all := by cases e <;> decide

theorem ofCode?_toCode (e : DaemonError) : ofCode? e.toCode = some e := by
  cases e <;> rfl

theorem toCode_of_ofCode? {c : UInt8} {e : DaemonError} (h : ofCode? c = some e) :
    e.toCode = c := by
  simpa using List.find?_some h

theorem toCode_injective {a b : DaemonError} (h : a.toCode = b.toCode) : a = b := by
  have := ofCode?_toCode a
  rw [h, ofCode?_toCode] at this
  exact (Option.some.inj this).symm

theorem ofCode?_zero : ofCode? 0 = none := by decide

/-- The daemon's text for each code. -/
def message : DaemonError → String
  | connectionLost => "Connection lost"
  | timeout => "Timeout"
  | invalidRequest => "Invalid request"
  | internalError => "Internal error"
  | maxRetries => "Maximum retries exceeded"
  | invalidChannel => "Invalid channel"
  | channelNotFound => "Channel not found"
  | permissionDenied => "Permission denied"
  | invalidPayload => "Invalid payload"
  | serviceUnavailable => "Service unavailable"
  | duplicateCapability => "Duplicate capability"
  | courierCacheCorruption => "Courier cache corruption"
  | propagationError => "Propagation error"
  | invalidWriteCapability => "Invalid write capability"
  | invalidReadCapability => "Invalid read capability"
  | invalidResumeWriteChannelRequest => "Invalid resume write channel request"
  | invalidResumeReadChannelRequest => "Invalid resume read channel request"
  | impossibleHash => "Impossible hash error"
  | impossibleNewWriteCap => "Failed to create new write capability"
  | impossibleNewStatefulWriter => "Failed to create new stateful writer"
  | capabilityAlreadyInUse => "Capability already in use"
  | mkemDecryptionFailed => "MKEM decryption failed"
  | bacapDecryptionFailed => "BACAP decryption failed"
  | startResendingCancelled => "Start resending cancelled"
  | invalidTombstoneSignature => "Invalid tombstone signature"
  | copyCommandFailed => "Copy command failed"
  | payloadTooLarge => "Payload too large"
  | voucherHashMismatch => "Voucher payload does not hash to the voucher"
  | voucherSignatureInvalid => "Voucher signed please-add did not verify"
  | voucherSealOpenFailed => "Voucher sealed reply could not be opened"
  | courierInvalidEnvelope => "Courier rejected the envelope as malformed"
  | courierInvalidEpoch => "Courier rejected the envelope: replica epoch outside tolerance window"
  | indexNotInChannel => "Message box index is not on the capability's stream"
  | indexTooFar => "Message box index is too far ahead of the capability to check"

end DaemonError

inductive ReplicaError where
  | boxIdNotFound
  | invalidBoxId
  | invalidSignature
  | databaseFailure
  | invalidPayload
  | storageFull
  | internalError
  | invalidEpoch
  | replicationFailed
  | boxAlreadyExists
  | tombstone
  deriving DecidableEq, Repr, Inhabited

namespace ReplicaError

def toCode : ReplicaError → UInt8
  | boxIdNotFound => 1
  | invalidBoxId => 2
  | invalidSignature => 3
  | databaseFailure => 4
  | invalidPayload => 5
  | storageFull => 6
  | internalError => 7
  | invalidEpoch => 8
  | replicationFailed => 9
  | boxAlreadyExists => 10
  | tombstone => 11

def all : List ReplicaError :=
  [boxIdNotFound, invalidBoxId, invalidSignature, databaseFailure, invalidPayload, storageFull,
   internalError, invalidEpoch, replicationFailed, boxAlreadyExists, tombstone]

def ofCode? (c : UInt8) : Option ReplicaError := all.find? (·.toCode == c)

theorem mem_all (e : ReplicaError) : e ∈ all := by cases e <;> decide

theorem ofCode?_toCode (e : ReplicaError) : ofCode? e.toCode = some e := by
  cases e <;> rfl

theorem toCode_of_ofCode? {c : UInt8} {e : ReplicaError} (h : ofCode? c = some e) :
    e.toCode = c := by
  simpa using List.find?_some h

theorem toCode_injective {a b : ReplicaError} (h : a.toCode = b.toCode) : a = b := by
  have := ofCode?_toCode a
  rw [h, ofCode?_toCode] at this
  exact (Option.some.inj this).symm

theorem ofCode?_zero : ofCode? 0 = none := by decide

def message : ReplicaError → String
  | boxIdNotFound => "box ID not found"
  | invalidBoxId => "invalid box ID"
  | invalidSignature => "invalid signature"
  | databaseFailure => "database failure"
  | invalidPayload => "invalid payload"
  | storageFull => "storage full"
  | internalError => "replica internal error"
  | invalidEpoch => "invalid epoch"
  | replicationFailed => "replication failed"
  | boxAlreadyExists => "box already exists"
  | tombstone => "tombstone"

end ReplicaError

/-- Ways the daemon's messages can break the protocol. -/
inductive ProtocolViolation where
  | oversizedFrame (size : Nat)
  | noVariant
  | multipleVariants (keys : List String)
  | handshake (expected : String)
  | missingGeometry
  | badGeometry (reason : String)
  | unexpectedReply (key : String)
  | missingField (name : String)
  | undecodable (reason : String)
  deriving DecidableEq, Repr

def ProtocolViolation.message : ProtocolViolation → String
  | oversizedFrame n => s!"frame of {n} bytes exceeds the maximum"
  | noVariant => "message carries no variant"
  | multipleVariants ks => s!"message carries several variants: {ks}"
  | handshake expected => s!"handshake: expected {expected}"
  | missingGeometry => "daemon did not supply both geometries"
  | badGeometry reason => s!"bad geometry: {reason}"
  | unexpectedReply key => s!"unexpected reply {key}"
  | missingField name => s!"reply is missing {name}"
  | undecodable reason => s!"undecodable message: {reason}"

inductive ThinClientError where
  | transport (e : IO.Error)
  | decode (reason : String)
  | protocol (v : ProtocolViolation)
  | daemon (e : DaemonError)
  | unknownCode (code : UInt8)
  | replica (e : ReplicaError)
  | unknownReplicaCode (code : UInt8)
  /-- A copy command failed at envelope `envelopeIndex` (1-based), with the replica's error when
  the courier identified one. -/
  | copyCommandFailed (replica : Option ReplicaError) (envelopeIndex : UInt64)
  | offline
  | timeout
  | closed
  | missingPkiDocument
  | serviceNotFound (name : String)

namespace ThinClientError

instance : Inhabited ThinClientError := ⟨closed⟩

instance : ToString ThinClientError where
  toString
    | transport e => s!"transport: {e}"
    | decode r => s!"decode: {r}"
    | protocol v => s!"protocol: {v.message}"
    | daemon e => e.message
    | unknownCode c => s!"Unknown thin client error code: {c}"
    | replica e => e.message
    | unknownReplicaCode c => s!"unknown replica error code: {c}"
    | copyCommandFailed (some r) i =>
      s!"copy command failed: {r.message} (failed envelope index {i})"
    | copyCommandFailed none i => s!"copy command failed: no replica reply (failed envelope index {i})"
    | offline => "daemon is not connected to the mixnet"
    | timeout => "timed out"
    | closed => "thin client is closed"
    | missingPkiDocument => "no PKI document for that epoch"
    | serviceNotFound name => s!"no service {name} in the PKI document"

/-- Outcomes a caller usually handles as normal results rather than failures. -/
def isExpectedOutcome : ThinClientError → Bool
  | replica .tombstone | replica .boxIdNotFound | replica .boxAlreadyExists => true
  | _ => false

/-- A code in the thin client namespace. -/
def ofCode (c : UInt8) : Option ThinClientError :=
  if c == 0 then none
  else some ((DaemonError.ofCode? c).map daemon |>.getD (unknownCode c))

/-- A code in the replica namespace. -/
def ofReplicaCode (c : UInt8) : Option ThinClientError :=
  if c == 0 then none
  else some ((ReplicaError.ofCode? c).map replica |>.getD (unknownReplicaCode c))

/-- The start-resending reply's code field, which mixes the namespaces: 1–11 are replica codes,
everything else is a thin client code. -/
def ofResendCode (c : UInt8) : Option ThinClientError :=
  match ReplicaError.ofCode? c with
  | some e => some (replica e)
  | none => ofCode c

/-- A copy command's reply: on `copyCommandFailed`, the replica code and envelope index it
carries. -/
def ofCopyCommandCode (c replicaCode : UInt8) (envelopeIndex : UInt64) : Option ThinClientError :=
  if c == DaemonError.copyCommandFailed.toCode then
    some (copyCommandFailed (ReplicaError.ofCode? replicaCode) envelopeIndex)
  else ofCode c

theorem ofCode_zero : ofCode 0 = none := rfl
theorem ofReplicaCode_zero : ofReplicaCode 0 = none := rfl
theorem ofResendCode_zero : ofResendCode 0 = none := by decide

theorem ofCode_toCode (e : DaemonError) : ofCode e.toCode = some (daemon e) := by
  cases e <;> rfl

theorem ofReplicaCode_toCode (e : ReplicaError) : ofReplicaCode e.toCode = some (replica e) := by
  cases e <;> rfl

theorem ofResendCode_replica (e : ReplicaError) : ofResendCode e.toCode = some (replica e) := by
  simp [ofResendCode, ReplicaError.ofCode?_toCode]

end ThinClientError

end ThinClient
