/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Messages

/-! # Protocol

The client's protocol logic as pure functions. `onResponse` takes the client's state and a message
from the daemon, and gives the new state and the effects the connection must carry out: requests
to send, replies to hand to waiting callers, events to publish.

A connection starts with a handshake. The daemon sends its connection status, which must carry
both geometries, then its PKI document; the client answers with its session token, and the
daemon's session token reply completes the handshake. The daemon may send other messages in
between; more than `maxHandshakeFrames` of them fails the handshake.

Pigeonhole requests that the daemon resends until answered are tracked while they are in flight.
When the client reconnects to a different daemon instance, that instance knows nothing of them,
so the client sends them again and abandons every other unanswered request. -/

namespace ThinClient.Protocol

open Cborg

inductive Phase where
  | awaitingStatus
  | awaitingDocument
  | awaitingSessionReply
  | ready
  deriving DecidableEq, Repr

def Phase.next : Phase → Phase
  | awaitingStatus => awaitingDocument
  | awaitingDocument => awaitingSessionReply
  | awaitingSessionReply => ready
  | ready => ready

def Phase.expected : Phase → String
  | awaitingStatus => "connection_status_event"
  | awaitingDocument => "new_pki_document_event"
  | awaitingSessionReply => "session_token_reply"
  | ready => "nothing"

/-- A request the daemon resends until answered: its tracking key, its query and its encoding. -/
structure InFlight where
  key : Hash32
  queryId : QueryId
  request : ByteArray

def maxHandshakeFrames : Nat := 16

/-- PKI documents are kept for this many epochs. -/
def cacheEpochs : Nat := 5

structure State where
  instanceToken : InstanceToken
  phase : Phase := .awaitingStatus
  strayFrames : Nat := 0
  isConnected : Bool := false
  daemonToken : Option InstanceToken := none
  /-- The daemon instance before a reconnect, until the new handshake completes. -/
  previousDaemonToken : Option InstanceToken := none
  appId : ByteArray := .empty
  resumed : Bool := false
  sphinxGeometry : Option Geometry := none
  pigeonholeGeometry : Option PigeonholeGeometry := none
  document : Option Document := none
  documents : List Document := []
  inFlight : List InFlight := []
  shutdownReceived : Bool := false

inductive Effect where
  /-- Send this encoded request. -/
  | send (request : ByteArray)
  /-- Hand the reply to the caller waiting on this query. -/
  | resolve (queryId : QueryId) (reply : Response)
  | publish (event : Event)
  /-- The handshake is complete. -/
  | ready
  | fail (v : ProtocolViolation)
  /-- Fail every waiting caller whose query is not listed. -/
  | abandonExcept (keep : List QueryId)

namespace State

/-- Keep `doc` and the documents of the `cacheEpochs - 1` epochs before it. -/
def cacheDocument (s : State) (doc : Document) : State :=
  let older := s.documents.filter fun d => d.epoch != doc.epoch && d.epoch + cacheEpochs.toUInt64 > doc.epoch && d.epoch < doc.epoch
  { s with document := some doc, documents := (doc :: older).take cacheEpochs }

def documentForEpoch? (s : State) (epoch : UInt64) : Option Document :=
  s.documents.find? (·.epoch == epoch)

def track (s : State) (f : InFlight) : State :=
  { s with inFlight := f :: s.inFlight.filter (·.key != f.key) }

def untrack (s : State) (key : Hash32) : State :=
  { s with inFlight := s.inFlight.filter (·.key != key) }

/-- Start a new handshake after the connection was lost. -/
def reconnecting (s : State) : State :=
  { s with phase := .awaitingStatus, strayFrames := 0,
           previousDaemonToken := s.previousDaemonToken <|> s.daemonToken,
           shutdownReceived := false, isConnected := false }

end State

/-- The state changes and effects every message has, whatever the phase. -/
def absorb (s : State) : Response → State × List Effect
  | .connectionStatusEvent m =>
    ({ s with isConnected := m.isConnected, daemonToken := some m.instanceToken,
              sphinxGeometry := m.sphinxGeometry <|> s.sphinxGeometry,
              pigeonholeGeometry := m.pigeonholeGeometry <|> s.pigeonholeGeometry },
     [.publish (.connectionStatus m)])
  | .newPkiDocumentEvent m =>
    match m.document? with
    | .ok (some doc) => (s.cacheDocument doc, [.publish (.newPkiDocument doc)])
    | _ => (s, [])
  | .shutdownEvent _ => ({ s with shutdownReceived := true }, [])
  | .messageSentEvent m => (s, [.publish (.messageSent m)])
  | .messageReplyEvent m => (s, [.publish (.messageReply m)])
  | .messageIdGarbageCollected m => (s, [.publish (.messageIdGarbageCollected m)])
  | r => match r.queryId? with
    | some q => (s, [.resolve q r])
    | none => (s, [])

/-- A check of the geometries the daemon reports. -/
abbrev GeometryCheck := Geometry → PigeonholeGeometry → Except String Unit

/-- Both geometries must validate. -/
def validateGeometries : GeometryCheck := fun g p => do checkSphinxGeometry g; p.validate

/-- Why the geometries the daemon reported cannot be used, if they cannot. -/
def geometryProblem (check : GeometryCheck) (s : State) : Option ProtocolViolation :=
  match s.sphinxGeometry, s.pigeonholeGeometry with
  | some g, some p =>
    match check g p with
    | .error e => some (.badGeometry e)
    | .ok () => none
  | _, _ => some .missingGeometry

/-- After a reconnect to a different daemon instance: resend what is in flight and abandon the
rest. -/
def replay (s : State) : List Effect :=
  match s.previousDaemonToken with
  | some old => if s.daemonToken == some old then []
    else s.inFlight.reverse.map (.send ·.request) ++ [.abandonExcept (s.inFlight.map (·.queryId))]
  | none => []

/-- A frame that does not move the handshake on; too many fail it. -/
def stray (s : State) : State × List Effect :=
  if s.phase == .ready then (s, [])
  else if s.strayFrames + 1 > maxHandshakeFrames then (s, [.fail (.handshake s.phase.expected)])
  else ({ s with strayFrames := s.strayFrames + 1 }, [])

/-- Move through the handshake. -/
def advance (check : GeometryCheck) (s : State) (r : Response) : State × List Effect :=
  match s.phase, r with
  | .awaitingStatus, .connectionStatusEvent _ =>
    match geometryProblem check s with
    | some v => (s, [.fail v])
    | none => ({ s with phase := .awaitingDocument, strayFrames := 0 }, [])
  | .awaitingDocument, .newPkiDocumentEvent _ =>
    ({ s with phase := .awaitingSessionReply, strayFrames := 0 },
     [.send (encodeRequest ({ clientInstanceToken := s.instanceToken } : SessionToken))])
  | .awaitingSessionReply, .sessionTokenReply m =>
    ({ s with phase := .ready, strayFrames := 0, appId := m.appId, resumed := m.resumed,
              previousDaemonToken := none },
     .ready :: replay s)
  | _, _ => stray s

/-- `check` judges the geometries the daemon reports; the client uses `validateGeometries`. -/
def onResponse (check : GeometryCheck) (s : State) (r : Response) : State × List Effect :=
  let (s₁, e₁) := absorb s r
  let (s₂, e₂) := advance check s₁ r
  (s₂, e₁ ++ e₂)

/-- A frame that does not decode counts as a stray frame. -/
def onUndecodable (s : State) : State × List Effect := stray s

/-! ## The handshake order -/

theorem stray_phase (s : State) : (stray s).1.phase = s.phase := by
  unfold stray; split <;> (try split) <;> rfl

/-- A frame that does not decode never moves the handshake. -/
theorem onUndecodable_phase (s : State) : (onUndecodable s).1.phase = s.phase := stray_phase s

theorem absorb_phase (s : State) (r : Response) : (absorb s r).1.phase = s.phase := by
  cases r <;> simp only [absorb] <;> (try split) <;> rfl

theorem advance_phase (check : GeometryCheck) (s : State) (r : Response) :
    (advance check s r).1.phase = s.phase ∨ (advance check s r).1.phase = s.phase.next := by
  unfold advance
  split <;> (try split) <;> simp_all [Phase.next, stray_phase]

/-- Each message moves the handshake forward by at most one phase. -/
theorem onResponse_phase (check : GeometryCheck) (s : State) (r : Response) :
    (onResponse check s r).1.phase = s.phase ∨ (onResponse check s r).1.phase = s.phase.next := by
  have := advance_phase check (absorb s r).1 r
  rw [absorb_phase] at this
  exact this

/-- Leaving a phase takes the message that phase waits for. -/
theorem onResponse_advances (check : GeometryCheck) (s : State) (r : Response)
    (h : (onResponse check s r).1.phase ≠ s.phase) :
    (s.phase = .awaitingStatus ∧ ∃ m, r = .connectionStatusEvent m) ∨
    (s.phase = .awaitingDocument ∧ ∃ m, r = .newPkiDocumentEvent m) ∨
    (s.phase = .awaitingSessionReply ∧ ∃ m, r = .sessionTokenReply m) := by
  simp only [onResponse] at h
  generalize hs : absorb s r = p at h
  obtain ⟨s₁, e₁⟩ := p
  have hph : s₁.phase = s.phase := by rw [← absorb_phase s r, hs]
  simp only at h
  unfold advance at h
  split at h <;> (try split at h) <;> simp_all [stray_phase]

end ThinClient.Protocol
