/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Protocol
import ThinClient.Tests.Fixtures
import ThinClient.Tests.Util

/-! # The protocol core

Messages are fed through `Protocol.onResponse` directly; there is no connection. -/

namespace ThinClient.Tests.Protocol

open ThinClient ThinClient.Protocol ThinClient.Tests.Fixtures

def initial : State := { instanceToken := fixed 16 0x01 }

def step : State → Response → State × List Effect := onResponse validateGeometries

/-- Feed messages in order, collecting every effect. -/
def feed (s : State) (rs : List Response) : State × List Effect :=
  rs.foldl (fun (s, es) r => let (s', es') := step s r; (s', es ++ es')) (s, [])

def phaseName : Phase → String
  | .awaitingStatus => "awaitingStatus"
  | .awaitingDocument => "awaitingDocument"
  | .awaitingSessionReply => "awaitingSessionReply"
  | .ready => "ready"

def failed (es : List Effect) : Option ProtocolViolation :=
  es.findSome? fun | .fail v => some v | _ => none

def sends (es : List Effect) : List ByteArray := es.filterMap fun | .send r => some r | _ => none

def resolved (es : List Effect) : List QueryId :=
  es.filterMap fun | .resolve q _ => some q | _ => none

def readyCount (es : List Effect) : Nat := (es.filter fun | .ready => true | _ => false).length

def handshake : List Response := [status, documentEvent, sessionReply]

def badStatus : Response :=
  .connectionStatusEvent {
    isConnected := true, instanceToken := fixed 16 0x50,
    sphinxGeometry := some { sphinxGeometry with nikeName := "", kemName := "" },
    pigeonholeGeometry := some pigeonholeGeometry }

def replyEvent : Response :=
  .messageReplyEvent { messageId := none, surbId := none, payload := bytes 0 3, errorCode := 0 }

def suite : TestM Unit := do
  -- The handshake in order.
  let (s, es) := feed initial handshake
  checkEq "handshake reaches ready" "ready" (phaseName s.phase)
  checkEq "handshake signals ready once" 1 (readyCount es)
  checkEq "session token sent once" 1 (sends es).length
  check "session token carries the instance token" (match sends es with
    | [r] => sameBytes r (encodeRequest ({ clientInstanceToken := fixed 16 0x01 } : SessionToken))
    | _ => false)
  check "document kept" (s.document.map (·.epoch) == some 1000)
  check "connected" s.isConnected

  -- Out of order, and with other messages interleaved.
  let (s, _) := feed initial [documentEvent, sessionReply]
  checkEq "document before status waits" "awaitingStatus" (phaseName s.phase)
  let (s, es) := feed initial [status, .shutdownEvent {}, status, documentEvent,
    .messageIdGarbageCollected { messageId := none }, sessionReply]
  checkEq "interleaved frames tolerated" "ready" (phaseName s.phase)
  check "interleaved frames do not fail" (failed es).isNone
  let strays := List.replicate (maxHandshakeFrames + 1) (Response.shutdownEvent {})
  let (_, es) := feed initial (status :: strays)
  check "too many stray frames fail the handshake" (match failed es with
    | some (.handshake _) => true | _ => false)
  let (_, es) := feed initial (status :: List.replicate maxHandshakeFrames (Response.shutdownEvent {}))
  check "the stray frame limit itself is allowed" (failed es).isNone

  -- Geometries.
  let (s, es) := feed initial [status (geometries := false)]
  check "missing geometry fails" (failed es == some .missingGeometry)
  checkEq "missing geometry does not advance" "awaitingStatus" (phaseName s.phase)
  let (_, es) := feed initial [badStatus]
  check "invalid geometry fails" (match failed es with | some (.badGeometry _) => true | _ => false)

  -- Replies go to their query.
  let (ready, _) := feed initial handshake
  let q1 : QueryId := fixed 16 0xa0
  let q2 : QueryId := fixed 16 0xb0
  let (_, es) := feed ready [counterReply q2 2, counterReply q1 1]
  check "replies resolve their queries in arrival order" (resolved es == [q2, q1])
  let (_, es) := feed ready [replyEvent]
  check "events are published, not resolved" ((resolved es).isEmpty &&
    es.any fun | .publish (.messageReply _) => true | _ => false)

  -- The document cache.
  let s := [1000, 1001, 1002, 1003, 1004, 1005, 1006].foldl
    (fun s e => (step s (documentEvent e)).1) ready
  checkEq "cache keeps five epochs" [1006, 1005, 1004, 1003, 1002]
    (s.documents.map (·.epoch))
  check "an evicted epoch is gone" (s.documentForEpoch? 1001).isNone
  let s := [2, 0, 1].foldl (fun s e => (step s (documentEvent e)).1) ready
  checkEq "early epochs do not underflow" [1, 0] (s.documents.map (·.epoch))

  -- Reconnecting.
  let flying : InFlight := { key := fixed 32 0x77, queryId := q1, request := bytes 0x99 10 }
  let tracked := ready.track flying
  let (s, es) := feed tracked.reconnecting [status 0x51, documentEvent, sessionReply]
  checkEq "reconnect reaches ready" "ready" (phaseName s.phase)
  check "new instance: in-flight request resent" ((sends es).any (sameBytes · flying.request))
  check "new instance: other waiters abandoned" (es.any fun
    | .abandonExcept keep => keep == [q1] | _ => false)
  let (_, es) := feed tracked.reconnecting [status 0x50, documentEvent, sessionReply]
  check "same instance: nothing resent" ((sends es).length == 1)
  check "same instance: nothing abandoned" (!es.any fun | .abandonExcept _ => true | _ => false)
  let untracked := tracked.untrack flying.key
  let (_, es) := feed untracked.reconnecting [status 0x51, documentEvent, sessionReply]
  check "finished request not resent" ((sends es).length == 1)

end ThinClient.Tests.Protocol
