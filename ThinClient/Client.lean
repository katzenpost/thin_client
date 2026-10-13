/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Std.Async
import Std.Sync
import ThinClient.Frame
import ThinClient.Protocol

/-! # Client

A connection to the daemon, and `ClientM`, the monad the thin client API runs in. `ClientM`
carries the connection and fails with a `ThinClientError`:

    withClient (.v4 (.ofParts 127 0 0 1)) 64331 do
      let kp ← newKeypair seed
      ...

A reader task feeds each frame from the daemon through `Protocol.onResponse` and carries out the
effects it returns. When the connection drops, the reader task reconnects, backing off from one
second up to a minute, and the protocol replays what was in flight. -/

namespace ThinClient

open Std.Async Std.Net

/-- A byte stream to the daemon. -/
structure Transport where
  send : ByteArray → Async Unit
  /-- The next bytes received; `none` once the stream has ended. -/
  recv : Async (Option ByteArray)
  close : Async Unit

def Transport.tcp (addr : IPAddr) (port : UInt16) : Async Transport := do
  let sock ← TCP.Socket.Client.mk
  sock.connect <| match addr with
    | .v4 a => .v4 ⟨a, port⟩
    | .v6 a => .v6 ⟨a, port⟩
  return { send := sock.send, recv := sock.recv? 65536, close := sock.shutdown }

abbrev Waiter := IO.Promise (Except ThinClientError Response)

structure Client where
  private dial : Async Transport
  private transport : IO.Ref Transport
  private writeLock : Std.Semaphore
  private state : IO.Ref Protocol.State
  private waiters : IO.Ref (Std.HashMap QueryId Waiter)
  private subscribers : IO.Ref (Array (Std.CloseableChannel Event))
  /-- Resolved when the current handshake completes or fails. -/
  private handshake : IO.Ref (IO.Promise (Except ThinClientError Unit))
  private closed : IO.Ref Bool

abbrev ClientM := ReaderT Client (ExceptT ThinClientError Async)

/-- Run `x` on `client`. Transport failures surface as `ThinClientError.transport`. -/
def run {α : Type} (client : Client) (x : ClientM α) : Async (Except ThinClientError α) :=
  tryCatch ((x.run client).run) (fun e => pure (.error (.transport e)))

instance : MonadLift (Except ThinClientError) ClientM where
  monadLift
    | .ok a => pure a
    | .error e => throw e

/-- Run `x`, turning its `IO.Error` into `ThinClientError.transport`. -/
def liftAsync {α : Type} (x : Async α) : ExceptT ThinClientError Async α :=
  ExceptT.mk (tryCatch (Except.ok <$> x) (fun e => pure (.error (.transport e))))

namespace Client

private def waitPromise {α : Type} (p : IO.Promise α) : Async (Option α) := await p.result?

private def spawn (x : Async Unit) : Async Unit := background x

private def withWriteLock {α : Type} (c : Client) (k : Async α) : Async α := do
  discard <| waitPromise (← c.writeLock.acquire)
  try k finally c.writeLock.release

/-- Frame and send an encoded request, in order with every other write. -/
def write (c : Client) (request : ByteArray) : Async Unit := do
  match Frame.encode request with
  | .error v => throw (IO.userError (ProtocolViolation.message v))
  | .ok frame => c.withWriteLock do (← c.transport.get).send frame

def publish (c : Client) (e : Event) : BaseIO Unit := do
  let subs ← c.subscribers.get
  let mut live := #[]
  for ch in subs do
    unless ← ch.isClosed do
      discard <| ch.send e
      live := live.push ch
  c.subscribers.set live

private def failWaiters (c : Client) (keep : QueryId → Bool) (err : ThinClientError) : BaseIO Unit := do
  let ws ← c.waiters.modifyGet fun m =>
    (m.toList.filter (!keep ·.1), m.filter fun q _ => keep q)
  for (_, w) in ws do w.resolve (.error err)

private def perform (c : Client) : Protocol.Effect → Async Unit
  | .send request => c.write request
  | .resolve q r => do
    match ← c.waiters.modifyGet fun m => (m.get? q, m.erase q) with
    | some w => w.resolve (.ok r)
    | none => pure ()
  | .publish e => c.publish e
  | .ready => do (← c.handshake.get).resolve (.ok ())
  | .fail v => do
    (← c.handshake.get).resolve (.error (.protocol v))
    (← c.transport.get).close
  | .abandonExcept keep => c.failWaiters (keep.contains ·) (.daemon .connectionLost)

private def handleFrame (c : Client) (frame : ByteArray) : Async Unit := do
  match Response.decode frame with
  | .error _ => pure ()
  | .ok r =>
    let effects ← c.state.modifyGet fun s => let (s', es) := Protocol.onResponse Protocol.validateGeometries s r; (es, s')
    for e in effects do c.perform e

/-- Read frames until the stream ends. -/
private partial def readFrames (c : Client) (t : Transport) (r : Frame.Reader) : Async Unit := do
  let chunk ← try t.recv catch _ => pure none
  match chunk with
  | none => pure ()
  | some bytes =>
    match r.push bytes with
    | .error _ => t.close
    | .ok (frames, r') =>
      for f in frames do c.handleFrame f
      c.readFrames t r'

/-- Redial until connected or closed, waiting `delay` seconds first and doubling up to a minute. -/
private partial def redial (c : Client) (delay : Nat) : Async (Option Transport) := do
  sleep (.ofNat (delay * 1000))
  if ← c.closed.get then return none
  try
    some <$> c.dial
  catch _ =>
    c.redial (min (delay * 2) 60)

/-- The reader task: read, and reconnect whenever the connection drops. -/
private partial def readLoop (c : Client) (t : Transport) : Async Unit := do
  c.readFrames t {}
  if ← c.closed.get then return
  let graceful ← c.state.modifyGet fun s => (s.shutdownReceived, s.reconnecting)
  c.publish (.daemonDisconnected graceful none)
  c.handshake.set (← IO.Promise.new)
  match ← c.redial 1 with
  | none => pure ()
  | some t' =>
    c.transport.set t'
    c.readLoop t'

/-- Wait until a handshake has completed. -/
private partial def awaitReady (c : Client) : ExceptT ThinClientError Async Unit := do
  if ← c.closed.get then throw .closed
  match ← waitPromise (← c.handshake.get) with
  | some (.ok ()) => pure ()
  | some (.error e) => if (← c.state.get).phase == .ready then pure () else throw e
  | none => c.awaitReady

/-- Connect through `dial` and complete the handshake within two minutes. -/
def connectWith (dial : Async Transport) : ExceptT ThinClientError Async Client := do
  let t ← liftAsync dial
  let token ← FixedBytes.random 16
  let handshake ← IO.Promise.new
  let c : Client := {
    dial
    transport := ← IO.mkRef t
    writeLock := ← Std.Semaphore.new 1
    state := ← IO.mkRef { instanceToken := token }
    waiters := ← IO.mkRef {}
    subscribers := ← IO.mkRef #[]
    handshake := ← IO.mkRef handshake
    closed := ← IO.mkRef false }
  spawn (c.readLoop t)
  spawn do
    sleep 120000
    handshake.resolve (.error .timeout)
  match ← waitPromise handshake with
  | some (.ok ()) => pure c
  | some (.error e) => c.closed.set true; t.close; throw e
  | none => c.closed.set true; t.close; throw .closed

def connect (addr : IPAddr) (port : UInt16) : ExceptT ThinClientError Async Client :=
  connectWith (Transport.tcp addr port)

/-- Close the connection. With `goodbye`, tell the daemon first so it drops this client's state;
without, the daemon keeps the session for a later reconnect. -/
def close (c : Client) (goodbye : Bool) : Async Unit := do
  if ← c.closed.swap true then return
  if goodbye then
    try c.write (encodeRequest ThinClose.mk) catch _ => pure ()
  try (← c.transport.get).close catch _ => pure ()
  c.failWaiters (fun _ => false) .closed
  (← c.handshake.get).resolve (.error .closed)
  for ch in ← c.subscribers.swap #[] do
    try ch.close catch _ => pure ()

end Client

/-! ## Operations -/

def client : ClientM Client := read

/-- Send a request that has no reply. -/
def send {α : Type} [Request α] (req : α) : ClientM Unit := do
  let c ← read
  c.awaitReady
  c.write (encodeRequest req)

/-- Send a request and wait for its reply. A reply reporting an error is thrown. -/
def call {α : Type} [Rpc α] (req : α) : ClientM (Rpc.Reply α) := do
  let c ← read
  c.awaitReady
  let q := Rpc.queryId req
  let w : Waiter ← IO.Promise.new
  c.waiters.modify (·.insert q w)
  try
    -- A close between `awaitReady` and registering the waiter would miss it.
    if ← c.closed.get then throw .closed
    c.write (encodeRequest req)
    let some result ← Client.waitPromise w | throw .closed
    let r ← liftM (m := Except ThinClientError) result
    let some reply := Rpc.reply? r | throw (.protocol (.unexpectedReply r.key))
    if let some e := Rpc.error? reply then throw e
    pure reply
  finally
    c.waiters.modify (·.erase q)

def freshQueryId : ClientM QueryId := FixedBytes.random 16

/-- Close the connection, telling the daemon to drop this client's state. -/
def stop : ClientM Unit := do (← read).close true

/-- Close the connection, leaving the daemon to keep the session. -/
def disconnect : ClientM Unit := do (← read).close false

def currentState : ClientM Protocol.State := do (← read).state.get

def isConnected : ClientM Bool := do return (← currentState).isConnected

def sphinxGeometry : ClientM Geometry := do
  let some g := (← currentState).sphinxGeometry | throw (.protocol .missingGeometry)
  pure g

def pigeonholeGeometry : ClientM PigeonholeGeometry := do
  let some g := (← currentState).pigeonholeGeometry | throw (.protocol .missingGeometry)
  pure g

/-- Track an in-flight request for the duration of `k`. -/
def tracking {α : Type} (f : Protocol.InFlight) (k : ClientM α) : ClientM α := do
  let c ← read
  c.state.modify (·.track f)
  try k finally c.state.modify (·.untrack f.key)

def untrack (key : Hash32) : ClientM Unit := do (← read).state.modify (·.untrack key)

/-- Connect, run `k`, and close the connection however `k` ends. -/
def withClient {α : Type} (addr : IPAddr) (port : UInt16) (k : ClientM α) :
    Async (Except ThinClientError α) := do
  match ← (Client.connect addr port).run with
  | .error e => pure (.error e)
  | .ok c => run c (try k finally stop)

/-! ## Events -/

/-- Events from the daemon, from the time of subscribing until closed. -/
structure Subscription where
  private channel : Std.CloseableChannel Event

def subscribe : ClientM Subscription := do
  let ch ← Std.CloseableChannel.new
  (← read).subscribers.modify (·.push ch)
  pure ⟨ch⟩

namespace Subscription

/-- The next event; `none` once the subscription or the client is closed. -/
def recv (s : Subscription) : Async (Option Event) := do await (← s.channel.recv)

def close (s : Subscription) : BaseIO Unit := discard <| EIO.toBaseIO s.channel.close

/-- The first event `p` accepts within `timeoutMs` milliseconds. -/
partial def waitFor {α : Type} (s : Subscription) (p : Event → Option α) (timeoutMs : Nat) :
    ClientM α := do
  let deadline := (← IO.monoMsNow) + timeoutMs
  let rec go : ClientM α := do
    let now ← IO.monoMsNow
    if now ≥ deadline then throw .timeout
    let timer ← Selector.sleep (.ofNat (deadline - now))
    let next ← Selectable.one #[
      .case s.channel.recvSelector (fun e => pure (some e)),
      .case timer (fun _ => pure none)]
    match next with
    | none => throw .timeout
    | some none => throw .closed
    | some (some e) => match p e with
      | some a => pure a
      | none => go
  go

end Subscription

/-- Run `k` with a subscription made before it starts, closed when it ends. -/
def withSubscription {α : Type} (k : Subscription → ClientM α) : ClientM α := do
  let s ← subscribe
  try k s finally s.close

/-- The first event `p` accepts within `timeoutMs` milliseconds of subscribing. -/
def awaitEvent {α : Type} (p : Event → Option α) (timeoutMs : Nat) : ClientM α :=
  withSubscription (·.waitFor p timeoutMs)

end ThinClient
