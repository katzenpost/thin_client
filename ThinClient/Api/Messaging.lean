/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Client

/-! # Messages to mixnet services

These need the daemon to be connected to the mixnet. -/

namespace ThinClient

private def checkSendable (payload : ByteArray) : ClientM Unit := do
  unless ← isConnected do throw .offline
  if payload.size > (← sphinxGeometry).userForwardPayloadLength then
    throw (.daemon .payloadTooLarge)

/-- Send `payload` to the queue `destQueue` on node `destNode`, with no way to reply. -/
def sendMessageWithoutReply (payload : ByteArray) (destNode : Hash32) (destQueue : ByteArray) :
    ClientM Unit := do
  checkSendable payload
  send { withSurb := false, surbId := none, destinationIdHash := destNode,
         recipientQueueId := destQueue, payload : SendMessage }

/-- Send `payload` with a reply block; the reply arrives as a `messageReply` event carrying
`surbId`. -/
def sendMessage (surbId : SurbId) (payload : ByteArray) (destNode : Hash32) (destQueue : ByteArray) :
    ClientM Unit := do
  checkSendable payload
  send { withSurb := true, surbId := some surbId, destinationIdHash := destNode,
         recipientQueueId := destQueue, payload : SendMessage }

/-- Send `payload` and wait up to `timeoutMs` milliseconds for the reply. -/
def blockingSendMessage (payload : ByteArray) (destNode : Hash32) (destQueue : ByteArray)
    (timeoutMs : Nat := 60000) : ClientM ByteArray := do
  let surbId ← FixedBytes.random 16
  withSubscription fun sub => do
    sendMessage surbId payload destNode destQueue
    sub.waitFor (timeoutMs := timeoutMs) fun
      | .messageReply m => if m.surbId == some surbId then some m.payload else none
      | _ => none

end ThinClient
