/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient
import ThinClient.Tests.Fixtures
import ThinClient.Tests.Util

/-! # The client against a fake daemon

The client talks to a scripted daemon over an in-memory pipe. Each scenario runs with a time
limit, so a hang fails the test instead of stalling it. -/

namespace ThinClient.Tests.Client

open Std.Async Cborg ThinClient ThinClient.Tests.Fixtures

/-- Two connected in-memory transports. -/
def pipe : IO (Transport × Transport) := do
  let toDaemon ← Std.CloseableChannel.new (α := ByteArray)
  let toClient ← Std.CloseableChannel.new (α := ByteArray)
  let closeBoth : Async Unit := do
    discard <| EIO.toBaseIO toDaemon.close
    discard <| EIO.toBaseIO toClient.close
  let side (out inp : Std.CloseableChannel ByteArray) : Transport := {
    send := fun bs => discard <| out.send bs
    recv := do await (← inp.recv)
    close := closeBoth }
  return (side toDaemon toClient, side toClient toDaemon)

/-- Two transports over a connected pair of unix sockets. -/
def unixPipe : IO (Transport × Transport) := do
  let (a, b) ← UnixSocket.Socket.pair
  return (.ofSocket a, .ofSocket b)

/-- The daemon end of a pipe. -/
structure Daemon where
  transport : Transport
  reader : IO.Ref Frame.Reader
  frames : IO.Ref (List ByteArray)

def Daemon.new (t : Transport) : IO Daemon :=
  return { transport := t, reader := ← IO.mkRef {}, frames := ← IO.mkRef [] }

def Daemon.send (d : Daemon) (r : Response) : Async Unit := do
  match Frame.encode r.encode with
  | .ok frame => d.transport.send frame
  | .error _ => throw (IO.userError "frame too large")

/-- The next request's key and body; `none` once the client has hung up. -/
partial def Daemon.next (d : Daemon) : Async (Option (String × ByteArray)) := do
  match ← d.frames.get with
  | f :: rest =>
    d.frames.set rest
    let r ← IO.ofExcept ((deserialise (α := Record) f).mapError (·.msg))
    match r.fields.toList.filter (fun (_, raw) => !(raw.size == 1 && raw[0]! == 0xf6)) with
    | [kv] => return some kv
    | _ => throw (IO.userError "request without exactly one variant")
  | [] =>
    match ← d.transport.recv with
    | none => return none
    | some chunk =>
      let (fs, r') ← IO.ofExcept ((← d.reader.get).push chunk |>.mapError (·.message))
      d.reader.set r'
      d.frames.modify (· ++ fs.toList)
      d.next

/-- The next request, which must be an `α`. -/
def Daemon.expect (d : Daemon) (α : Type) [Request α] : Async (α × ByteArray) := do
  let some (k, body) ← d.next | throw (IO.userError s!"client hung up, wanted {Request.key α}")
  unless k == Request.key α do throw (IO.userError s!"got {k}, wanted {Request.key α}")
  let a ← IO.ofExcept ((deserialise body).mapError (·.msg))
  return (a, body)

def Daemon.handshake (d : Daemon) (token : UInt8 := 0x50) : Async Unit := do
  d.send (status token)
  d.send documentEvent
  discard <| d.expect SessionToken
  d.send sessionReply

/-- Run `x` with a time limit. -/
def within (seconds : Nat) (x : Async Unit) : IO (Except String Unit) := do
  let t ← x.asTask
  let finished : Task (Option (Except String Unit)) :=
    (ExceptT.run t).map fun r => some (r.mapError toString)
  let timer ← (sleep (.ofNat (seconds * 1000)) : Async Unit).asTask
  let timedOut : Task (Option (Except String Unit)) := (ExceptT.run timer).map fun _ => none
  let r ← IO.waitAny [finished, timedOut]
  pure (r.getD (.error s!"timed out after {seconds}s"))

def expectError {α : Type} (name : String) (r : Except ThinClientError α) (ok : ThinClientError → Bool) :
    Async Unit := do
  match r with
  | .error e => unless ok e do throw (IO.userError s!"{name}: wrong error: {e}")
  | .ok _ => throw (IO.userError s!"{name}: succeeded, expected an error")

def expectOk {α : Type} (name : String) (r : Except ThinClientError α) : Async α := do
  match r with
  | .ok a => pure a
  | .error e => throw (IO.userError s!"{name}: {e}")

/-- Connect over `pipe` to a fresh daemon running `script`. -/
def withDaemon (script : Daemon → Async Unit) (k : Client → Async Unit)
    (pipe : IO (Transport × Transport) := pipe) : Async Unit := do
  let (ct, dt) ← pipe
  let d ← Daemon.new dt
  let daemon ← async (script d)
  let c ← expectOk "connect" (← (Client.connectWith (pure ct)).run)
  k c
  await daemon
  -- A socket closes once freed; hold the daemon end open until the client is done.
  d.transport.close

def handshakeAndCall (pipe : IO (Transport × Transport) := pipe) : Async Unit :=
  withDaemon (pipe := pipe) (fun d => do
    d.handshake
    let (req, _) ← d.expect GetMessageBoxIndexCounter
    d.send (counterReply req.queryId 7))
  fun c => do
    let n ← expectOk "call" (← run c (getMessageBoxIndexCounter index))
    unless n == 7 do throw (IO.userError s!"counter {n}")
    unless (← run c isConnected) matches .ok true do throw (IO.userError "not connected")

def errorReply : Async Unit :=
  withDaemon (fun d => do
    d.handshake
    let (req, _) ← d.expect GetMessageBoxIndexCounter
    d.send (counterReply req.queryId 0 (errorCode := 9)))
  fun c => do
    expectError "error reply" (← run c (getMessageBoxIndexCounter index))
      (· matches .daemon .invalidPayload)

def outOfOrder : Async Unit :=
  withDaemon (fun d => do
    d.handshake
    let (a, _) ← d.expect GetMessageBoxIndexCounter
    let (b, _) ← d.expect GetMessageBoxIndexCounter
    d.send (counterReply b.queryId 2)
    d.send (counterReply a.queryId 1))
  fun c => do
    let first ← async (run c (getMessageBoxIndexCounter index))
    sleep 50
    let second ← async (run c (getMessageBoxIndexCounter index))
    let r1 ← expectOk "first" (← await first)
    let r2 ← expectOk "second" (← await second)
    unless r1 == 1 && r2 == 2 do throw (IO.userError s!"replies crossed: {r1} {r2}")

def stopFailsWaiters : Async Unit :=
  withDaemon (fun d => do
    d.handshake
    discard <| d.expect GetMessageBoxIndexCounter
    discard <| d.expect ThinClose
    if (← d.next).isSome then throw (IO.userError "client kept talking after thin_close"))
  fun c => do
    let pending ← async (run c (getMessageBoxIndexCounter index))
    sleep 100
    discard <| run c stop
    expectError "pending call" (← await pending) (· matches .closed)
    expectError "call after stop" (← run c (getMessageBoxIndexCounter index)) (· matches .closed)

def eventsReachSubscribers : Async Unit :=
  withDaemon (fun d => do
    d.handshake
    let (req, _) ← d.expect GetMessageBoxIndexCounter
    d.send (.messageReplyEvent {
      messageId := none, surbId := some (fixed 16 0x30), payload := "pong".toUTF8, errorCode := 0 })
    d.send (counterReply req.queryId 1))
  fun c => do
    let r ← run c <| withSubscription fun sub => do
      discard <| getMessageBoxIndexCounter index
      sub.waitFor (timeoutMs := 5000) fun
        | .messageReply m => if m.surbId == some (fixed 16 0x30) then some m.payload else none
        | _ => none
    let payload ← expectOk "event" r
    unless payload.data == "pong".toUTF8.data do throw (IO.userError "wrong payload")

def eventTimeout : Async Unit :=
  withDaemon (fun d => d.handshake) fun c => do
    expectError "awaitEvent" (← run c (awaitEvent (fun _ => (none : Option Unit)) 200))
      (· matches .timeout)

def closeOnError : Async Unit :=
  withDaemon (fun d => do
    d.handshake
    discard <| d.expect ThinClose
    if (← d.next).isSome then throw (IO.userError "client kept talking after thin_close"))
  fun c => do
    expectError "body" (← run c (try (throw .offline : ClientM Unit) finally stop))
      (· matches .offline)

def handshakeFailure : Async Unit := do
  let (ct, dt) ← pipe
  let d ← Daemon.new dt
  let daemon ← async (d.send (status (geometries := false)))
  expectError "connect" (← (Client.connectWith (pure ct)).run) (· matches .protocol .missingGeometry)
  await daemon

/-- The daemon drops the connection with a resend and a plain call in flight; the client
reconnects to a new daemon instance, resends the first and abandons the second. -/
def reconnectReplays (pipe : IO (Transport × Transport) := pipe) : Async Unit := do
  let (ct1, dt1) ← pipe
  let (ct2, dt2) ← pipe
  let dials ← IO.mkRef [ct1, ct2]
  let dial : Async Transport := do
    match ← dials.modifyGet fun ts => (ts.head?, ts.drop 1) with
    | some t => pure t
    | none => throw (IO.userError "no more daemons")
  let d1 ← Daemon.new dt1
  let d2 ← Daemon.new dt2
  let first ← async do
    d1.handshake 0x50
    let (_, body) ← d1.expect StartResendingEncryptedMessage
    discard <| d1.expect GetMessageBoxIndexCounter
    d1.transport.close
    pure body
  let second ← async do
    d2.handshake 0x51
    let (req, body) ← d2.expect StartResendingEncryptedMessage
    d2.send (.startResendingEncryptedMessageReply {
      queryId := req.queryId, plaintext := "box".toUTF8, errorCode := 0,
      courierIdentityHash := none, courierQueueId := .empty })
    pure body
  let c ← expectOk "connect" (← (Client.connectWith dial).run)
  let disconnected ← async (run c (awaitEvent (fun | .daemonDisconnected _ _ => some () | _ => none) 10000))
  let resend ← async (run c (startResendingEncryptedMessage (.read (fixed 136 0x01) index)
    (bytes 0x60 40) (bytes 0x70 50) (fixed 32 0x80)))
  sleep 100
  let plain ← async (run c (getMessageBoxIndexCounter index))
  let sent ← await first
  let r ← expectOk "resend" (← await resend)
  unless r.plaintext.data == "box".toUTF8.data do throw (IO.userError "wrong plaintext")
  expectError "abandoned call" (← await plain) (· matches .daemon .connectionLost)
  discard <| expectOk "disconnect event" (← await disconnected)
  let resent ← await second
  unless sent.data == resent.data do throw (IO.userError "resend differs from the original")
  discard <| run c stop

/-- A dial that hands out `ts` in turn, then fails. -/
def dialing (ts : List Transport) : IO (Async Transport) := do
  let dials ← IO.mkRef ts
  return do
    match ← dials.modifyGet fun ts => (ts.head?, ts.drop 1) with
    | some t => pure t
    | none => throw (IO.userError "no more daemons")

def callTimesOut : Async Unit :=
  withDaemon (fun d => do
    d.handshake
    discard <| d.expect GetMessageBoxIndexCounter
    discard <| d.expect ThinClose)
  fun c => do
    expectError "call" (← run c (call (timeoutMs := some 200)
      { queryId := fixed 16 0xc0, messageBoxIndex := index : GetMessageBoxIndexCounter }))
      (· matches .timeout)
    discard <| run c stop

/-- After a reconnect, a daemon that never finishes the handshake is dropped and the next one
dialled. -/
def reconnectHandshakeTimesOut : Async Unit := do
  let (ct1, dt1) ← pipe
  let (ct2, dt2) ← pipe
  let (ct3, dt3) ← pipe
  let d1 ← Daemon.new dt1
  let d2 ← Daemon.new dt2
  let d3 ← Daemon.new dt3
  let first ← async do
    d1.handshake 0x50
    sleep 200
    d1.transport.close
  let stalled ← async do
    d2.send (status 0x51)
    if (← d2.next).isSome then throw (IO.userError "stalled daemon was sent a request")
  let third ← async do
    d3.handshake 0x52
    let (req, _) ← d3.expect GetMessageBoxIndexCounter
    d3.send (counterReply req.queryId 3)
  let c ← expectOk "connect" (← (Client.connectWith (← dialing [ct1, ct2, ct3])
    (handshakeTimeoutMs := 500)).run)
  sleep 500
  let n ← expectOk "call" (← run c (getMessageBoxIndexCounter index))
  unless n == 3 do throw (IO.userError s!"counter {n}")
  await first; await stalled; await third
  discard <| run c stop

/-- A subscriber that does not keep up is cut off instead of queueing without bound. -/
def slowSubscriberCutOff : Async Unit :=
  withDaemon (fun d => do
    d.handshake
    let (req, _) ← d.expect GetMessageBoxIndexCounter
    for i in [0:3] do
      d.send (.messageReplyEvent {
        messageId := none, surbId := some (fixed 16 i.toUInt8), payload := .empty, errorCode := 0 })
    d.send (counterReply req.queryId 1))
  fun c => do
    let sub ← expectOk "subscribe" (← run c (subscribe (capacity := 2)))
    discard <| expectOk "call" (← run c (getMessageBoxIndexCounter index))
    let mut received := 0
    while (← sub.recv).isSome do received := received + 1
    unless received ≤ 2 do throw (IO.userError s!"{received} events past capacity")

/-- A dial that completes after `stop` has its connection closed. -/
def dialAfterStop : Async Unit := do
  let (ct1, dt1) ← pipe
  let (ct2, dt2) ← pipe
  let d1 ← Daemon.new dt1
  let d2 ← Daemon.new dt2
  let dialled ← IO.mkRef 0
  let started ← IO.Promise.new
  let release ← IO.Promise.new
  let dial : Async Transport := do
    if (← dialled.modifyGet fun n => (n, n + 1)) == 0 then return ct1
    started.resolve ()
    discard <| await release.result?
    return ct2
  let first ← async do
    d1.handshake
    d1.transport.close
  let c ← expectOk "connect" (← (Client.connectWith dial).run)
  await first
  discard <| await started.result?
  discard <| run c stop
  release.resolve ()
  if (← d2.next).isSome then throw (IO.userError "client talked after stop")

def stateHidesInFlight : Async Unit :=
  withDaemon (fun d => d.handshake) fun c => do
    let flying : Protocol.InFlight := { key := fixed 32 0x77, queryId := fixed 16 0xa0,
                                         request := bytes 0x99 10 }
    let s ← expectOk "state" (← run c (tracking flying currentState))
    unless s.inFlight.isEmpty do throw (IO.userError "in-flight requests exposed")

def Daemon.sendRaw (d : Daemon) (variant : String) (body : Encoding) : Async Unit := do
  match Frame.encode (toByteArray (encodeRecord [(variant, some body)])) with
  | .ok frame => d.transport.send frame
  | .error _ => throw (IO.userError "frame too large")

/-- A daemon whose Sphinx geometry has a field this client does not know fails the connect with
the decode error. -/
def undecodableStatus : Async Unit := do
  let (ct, dt) ← pipe
  let d ← Daemon.new dt
  let geometry := encodeRecord ((Fixtures.sphinxGeometry.fields.map fun (k, e) => (k, some e)) ++
    [("FutureField", some (encode (7 : Nat)))])
  let daemon ← async (d.sendRaw "connection_status_event" (encodeRecord [
    field "is_connected" true, field "instance_token" (fixed 16 0x50),
    ("sphinx_geometry", some geometry), field "pigeonhole_geometry" Fixtures.pigeonholeGeometry]))
  expectError "connect" (← (Client.connectWith (pure ct)).run) fun
    | .protocol (.undecodable r) => (r.splitOn "FutureField").length > 1
    | _ => false
  await daemon

def undecodableReply : Async Unit :=
  withDaemon (fun d => do
    d.handshake
    let (req, _) ← d.expect GetMessageBoxIndexCounter
    d.sendRaw "get_message_box_index_counter_reply"
      (encodeRecord [field "query_id" req.queryId, field "counter" "seven"]))
  fun c => do
    expectError "call" (← run c (getMessageBoxIndexCounter index))
      (· matches .protocol (.undecodable _))

def suite : TestM Unit := do
  for (name, scenario) in [
      ("handshake and call", handshakeAndCall),
      ("handshake and call over a unix socket", handshakeAndCall unixPipe),
      ("error reply is thrown", errorReply),
      ("replies out of order", outOfOrder),
      ("stop fails waiting calls", stopFailsWaiters),
      ("events reach subscribers", eventsReachSubscribers),
      ("awaitEvent times out", eventTimeout),
      ("try/finally stop on error", closeOnError),
      ("failed handshake", handshakeFailure),
      ("reconnect replays in-flight requests", reconnectReplays),
      ("reconnect over a unix socket", reconnectReplays unixPipe),
      ("call times out", callTimesOut),
      ("reconnect handshake times out", reconnectHandshakeTimesOut),
      ("slow subscriber is cut off", slowSubscriberCutOff),
      ("dial completing after stop is closed", dialAfterStop),
      ("state hides in-flight requests", stateHidesInFlight),
      ("undecodable status fails the connect with its error", undecodableStatus),
      ("undecodable reply fails its caller", undecodableReply)] do
    match ← within 30 scenario with
    | .ok () => check name true
    | .error e => check name false (fun _ => e)

end ThinClient.Tests.Client
