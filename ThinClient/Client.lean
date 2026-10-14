/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Std.Async
import Std.Sync
import UnixSocket
import ThinClient.Frame
import ThinClient.Protocol

/-! # Client

A connection to the daemon, and `ClientM`, the monad the thin client API runs in. `ClientM`
carries the connection and fails with a `ThinClientError`:

    withClient (.v4 (.ofParts 127 0 0 1)) 64331 do
      let kp ← newKeypair seed
      ...

`withClientUnix path` does the same over a unix socket, `@name` for an abstract one. A reader task feeds each frame from the daemon through `Protocol.onResponse` and carries out the
effects it returns. When the connection drops, the reader task reconnects, backing off from one
second up to a minute, and the protocol replays what was in flight. A handshake that does not
complete within `handshakeTimeoutMs` drops the connection. -/

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

/-- A transport over a connected unix socket. Each read blocks a dedicated thread; closing shuts
the socket down, which wakes it. -/
def Transport.ofSocket (s : UnixSocket.Socket) : Transport where
  send := fun bytes => s.send bytes
  recv := do Async.ofAsyncTask (← IO.asTask (prio := .dedicated) (s.recv? 65536))
  close := s.shutdown

/-- Connect to the unix socket at `path`, or to the abstract name after a leading `@`. -/
def Transport.unix (path : String) : Async Transport :=
  Transport.ofSocket <$> UnixSocket.Socket.connect path

abbrev Waiter := IO.Promise (Except ThinClientError Response)

def handshakeTimeoutMs : Nat := 120000

/-- How long `call` and `send` wait by default, for the handshake and then for the reply. -/
def callTimeoutMs : Nat := 120000

/-- Events a subscription holds before the subscriber is cut off. -/
def subscriptionCapacity : Nat := 1024

structure Client where
  private dial : Async Transport
  private handshakeTimeoutMs : Nat
  private transport : IO.Ref Transport
  /-- Counts connections, so a handshake timer can tell whether its connection is current. -/
  private generation : IO.Ref Nat
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

private def taskSelector {α : Type} (t : Task α) : Selector α where
  tryFn := do if ← IO.hasFinished t then return some t.get else return none
  registerFn w := discard <| BaseIO.chainTask t fun a => w.race (pure ()) (·.resolve (.ok a))
  unregisterFn := pure ()

/-- `t`'s value, or `.timeout` once the monotonic clock passes `deadline`. -/
private def awaitUntil {α : Type} (deadline : Option Nat) (t : Task α) :
    ExceptT ThinClientError Async α := do
  let some deadline := deadline | await t
  let now ← IO.monoMsNow
  if now ≥ deadline then
    if ← IO.hasFinished t then return t.get else throw ThinClientError.timeout
  let timer ← Selector.sleep (.ofNat (deadline - now))
  let r ← Selectable.one (α := Option α) #[
    .case (taskSelector t) (fun a => pure (some a)),
    .case timer (fun _ => pure none)]
  let some a := r | throw ThinClientError.timeout
  pure a

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
      if ← ch.trySend e then live := live.push ch
      else discard <| EIO.toBaseIO ch.close
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
  let step : Protocol.State → Protocol.State × List Protocol.Effect :=
    match Response.decode frame with
    | .error _ => Protocol.onUndecodable
    | .ok r => (Protocol.onResponse Protocol.validateGeometries · r)
  let effects ← c.state.modifyGet fun s => let (s', es) := step s; (es, s')
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

/-- Close `t` if its handshake has not completed in time. -/
private def watchHandshake (c : Client) (t : Transport) : Async Unit := do
  let gen ← c.generation.get
  spawn do
    sleep (.ofNat c.handshakeTimeoutMs)
    if (← c.generation.get) == gen && (← c.state.get).phase != .ready then
      try t.close catch _ => pure ()

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
    c.generation.modify (· + 1)
    -- `close` sets `closed` before taking the transport, so one of the two closes `t'`.
    if ← c.closed.get then
      try t'.close catch _ => pure ()
      return
    c.watchHandshake t'
    c.readLoop t'

/-- Wait until a handshake has completed, or `deadline` passes. -/
private partial def awaitReady (c : Client) (deadline : Option Nat) :
    ExceptT ThinClientError Async Unit := do
  if ← c.closed.get then throw .closed
  match ← awaitUntil deadline (← c.handshake.get).result? with
  | some (.ok ()) => pure ()
  | some (.error e) => if (← c.state.get).phase == .ready then pure () else throw e
  | none => c.awaitReady deadline

/-- Connect through `dial` and complete the handshake within `handshakeTimeoutMs`, which also
bounds each handshake after a reconnect. -/
def connectWith (dial : Async Transport) (handshakeTimeoutMs : Nat := ThinClient.handshakeTimeoutMs) :
    ExceptT ThinClientError Async Client := do
  let t ← liftAsync dial
  let token ← FixedBytes.random 16
  let handshake ← IO.Promise.new
  let c : Client := {
    dial
    handshakeTimeoutMs
    transport := ← IO.mkRef t
    generation := ← IO.mkRef 0
    writeLock := ← Std.Semaphore.new 1
    state := ← IO.mkRef { instanceToken := token }
    waiters := ← IO.mkRef {}
    subscribers := ← IO.mkRef #[]
    handshake := ← IO.mkRef handshake
    closed := ← IO.mkRef false }
  spawn (c.readLoop t)
  spawn do
    sleep (.ofNat handshakeTimeoutMs)
    handshake.resolve (.error .timeout)
  match ← waitPromise handshake with
  | some (.ok ()) => pure c
  | some (.error e) => c.closed.set true; t.close; throw e
  | none => c.closed.set true; t.close; throw .closed

def connect (addr : IPAddr) (port : UInt16) : ExceptT ThinClientError Async Client :=
  connectWith (Transport.tcp addr port)

/-- Connect to the daemon's unix socket at `path`, or its abstract name after a leading `@`. -/
def connectUnix (path : String) : ExceptT ThinClientError Async Client :=
  connectWith (Transport.unix path)

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

private def deadlineAfter (timeoutMs : Option Nat) : BaseIO (Option Nat) := do
  let now ← IO.monoMsNow
  return timeoutMs.map (now + ·)

/-- Send a request that has no reply, once a handshake has completed within `timeoutMs`. -/
def send {α : Type} [Request α] (req : α) (timeoutMs : Option Nat := some callTimeoutMs) :
    ClientM Unit := do
  let c ← read
  c.awaitReady (← deadlineAfter timeoutMs)
  c.write (encodeRequest req)

/-- Send a request and wait for its reply, failing with `.timeout` after `timeoutMs`; `none`
waits until the client closes. A reply reporting an error is thrown. -/
def call {α : Type} [Rpc α] (req : α) (timeoutMs : Option Nat := some callTimeoutMs) :
    ClientM (Rpc.Reply α) := do
  let c ← read
  let deadline ← deadlineAfter timeoutMs
  c.awaitReady deadline
  let q := Rpc.queryId req
  let w : Waiter ← IO.Promise.new
  c.waiters.modify (·.insert q w)
  try
    -- A close between `awaitReady` and registering the waiter would miss it.
    if ← c.closed.get then throw .closed
    c.write (encodeRequest req)
    let some result ← Client.awaitUntil deadline w.result? | throw .closed
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

/-- The protocol state, less the requests in flight, whose encodings carry capabilities. -/
def currentState : ClientM Protocol.State := do return { ← (← read).state.get with inFlight := [] }

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

/-- Connect through `dial`, run `k`, and close the connection however `k` ends. -/
def withClientVia {α : Type} (dial : Async Transport) (k : ClientM α) :
    Async (Except ThinClientError α) := do
  match ← (Client.connectWith dial).run with
  | .error e => pure (.error e)
  | .ok c => run c (try k finally stop)

def withClient {α : Type} (addr : IPAddr) (port : UInt16) (k : ClientM α) :
    Async (Except ThinClientError α) :=
  withClientVia (Transport.tcp addr port) k

def withClientUnix {α : Type} (path : String) (k : ClientM α) :
    Async (Except ThinClientError α) :=
  withClientVia (Transport.unix path) k

/-! ## Events -/

/-- Events from the daemon, from the time of subscribing until closed. -/
structure Subscription where
  private channel : Std.CloseableChannel Event

/-- A subscription that falls `capacity` events behind is closed. -/
def subscribe (capacity : Nat := subscriptionCapacity) : ClientM Subscription := do
  let ch ← Std.CloseableChannel.new (some (max capacity 1))
  (← read).subscribers.modify (·.push ch)
  pure ⟨ch⟩

namespace Subscription

/-- The next event; `none` once the subscription or the client is closed, or the subscriber fell
behind. -/
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
