/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient
import ThinClient.Tests.Util
import ThinClient.Tests.Frame

/-! # Integration tests

Against a running daemon connected to a mixnet, such as the docker mixnet:

    lake exe thinclient-integration 127.0.0.1 33399
-/

namespace ThinClient.Tests.Integration

open Std.Async Std.Net Cborg ThinClient

def fail {α : Type} (msg : String) : ClientM α := throw (.protocol (.missingField msg))

def expect (what : String) (ok : Bool) : ClientM Unit := unless ok do fail what

def randomSeed : IO (FixedBytes 32) := FixedBytes.random 32

/-- Write `plaintext` to the box at `index`. -/
def writeBox (plaintext : ByteArray) (wc : WriteCap) (index : MessageBoxIndex)
    (options : ResendOptions := {}) : ClientM Unit := do
  let e ← encryptWrite plaintext wc index
  discard <| startResendingEncryptedMessage (.write wc) e.envelopeDescriptor e.messageCiphertext
    e.envelopeHash options

/-- Read the box at `index`. -/
def readBox (rc : ReadCap) (index : MessageBoxIndex) (options : ResendOptions := {}) :
    ClientM ByteArray := do
  let e ← encryptRead rc index
  let r ← startResendingEncryptedMessage (.read rc index) e.envelopeDescriptor e.messageCiphertext
    e.envelopeHash options
  pure r.plaintext

def sameBytes' (a b : ByteArray) : Bool := a.data == b.data

def newKeypairBasic : ClientM Unit := do
  discard <| newKeypair (← randomSeed)

def writeThenRead : ClientM Unit := do
  let kp ← newKeypair (← randomSeed)
  let message := "Hello Bob, this is Alice!".toUTF8
  writeBox message kp.writeCap kp.firstMessageIndex { replyIndex := some 0 }
  let got ← readBox kp.readCap kp.firstMessageIndex { replyIndex := some 0 }
  expect "read back what was written" (sameBytes' got message)

def boxIndices : ClientM Unit := do
  let kp ← newKeypair (← randomSeed)
  let first ← getMessageBoxIndexCounter kp.firstMessageIndex
  let next ← nextMessageBoxIndex kp.firstMessageIndex
  let second ← getMessageBoxIndexCounter next
  expect "next index counts one further" (second == first + 1)

def courierEnvelopes : ClientM Unit := do
  let kp ← newKeypair (← randomSeed)
  let (envelopes, _) ← createCourierEnvelopesFromPayload (Tests.Frame.bytes 1 3000)
    kp.writeCap kp.firstMessageIndex true true
  expect "envelopes from one payload" (!envelopes.isEmpty)
  let kp2 ← newKeypair (← randomSeed)
  let r ← createCourierEnvelopesFromMultiPayload #[
    { payload := Tests.Frame.bytes 1 500, writeCap := kp.writeCap, startIndex := kp.firstMessageIndex },
    { payload := Tests.Frame.bytes 2 500, writeCap := kp2.writeCap, startIndex := kp2.firstMessageIndex }]
    true true
  expect "envelopes from several payloads" (!r.envelopes.isEmpty)
  expect "a next index per destination" (r.nextDestIndices.size == 2)

def boxNotFound : ClientM Unit := do
  let kp ← newKeypair (← randomSeed)
  try
    discard <| readBox kp.readCap kp.firstMessageIndex { noRetryOnBoxIdNotFound := true, replyIndex := some 0 }
    fail "reading an empty box succeeded"
  catch
    | .replica .boxIdNotFound => pure ()
    | e => throw e

def tombstoneBox : ClientM Unit := do
  let kp ← newKeypair (← randomSeed)
  writeBox "to be tombstoned".toUTF8 kp.writeCap kp.firstMessageIndex { replyIndex := some 0 }
  discard <| readBox kp.readCap kp.firstMessageIndex { replyIndex := some 0 }
  let t ← tombstoneRange kp.writeCap kp.firstMessageIndex 1
  expect "one tombstone" (t.envelopes.size == 1)
  for e in t.envelopes do
    discard <| startResendingEncryptedMessage (.write kp.writeCap) e.envelopeDescriptor
      e.messageCiphertext e.envelopeHash
  let mut seen := false
  for _ in [0:6] do
    sleep 10000
    try
      discard <| readBox kp.readCap kp.firstMessageIndex { replyIndex := some 0 }
    catch e =>
      if e matches .replica .tombstone then seen := true; break
      throw e
  expect "tombstone propagated" seen

def tombstoneRangeOfThree : ClientM Unit := do
  let kp ← newKeypair (← randomSeed)
  let mut index := kp.firstMessageIndex
  for i in [0:3] do
    writeBox s!"Message {i + 1} to be tombstoned".toUTF8 kp.writeCap index { replyIndex := some 0 }
    if i < 2 then index ← nextMessageBoxIndex index
  discard <| readBox kp.readCap index { replyIndex := some 0 }
  let t ← tombstoneRange kp.writeCap kp.firstMessageIndex 3
  expect "three tombstones" (t.envelopes.size == 3)
  for e in t.envelopes do
    discard <| startResendingEncryptedMessage (.write kp.writeCap) e.envelopeDescriptor
      e.messageCiphertext e.envelopeHash

/-- Copying a stream onto a box that already holds a message fails with the replica's error. -/
def copyOntoExistingBox : ClientM Unit := do
  let dest ← newKeypair (← randomSeed)
  writeBox "First message - this should work".toUTF8 dest.writeCap dest.firstMessageIndex
  discard <| readBox dest.readCap dest.firstMessageIndex { replyIndex := some 0 }
  let temp ← newKeypair (← randomSeed)
  let (chunks, _) ← createCourierEnvelopesFromPayload (Tests.Frame.bytes 7 2000)
    dest.writeCap dest.firstMessageIndex true true
  let mut index := temp.firstMessageIndex
  let mut last := index
  for chunk in chunks do
    writeBox chunk temp.writeCap index { replyIndex := some 0 }
    last := index
    index ← nextMessageBoxIndex index
  discard <| readBox temp.readCap last { replyIndex := some 0 }
  try
    startResendingCopyCommand temp.writeCap
    fail "copy onto an existing box succeeded"
  catch
    | .copyCommandFailed (some .boxAlreadyExists) i => expect "failed envelope index" (i > 0)
    | e => throw e

def directoryAuthorities : ClientM Unit := do
  expect "directory authorities" (!(← getDirectoryAuthorities).isEmpty)

/-- Echo through each echo service in turn until one answers; a mixnet may have dead ones. -/
def echo : ClientM Unit := do
  for service in ← getServices "echo" do
    let (node, queue) := service.toDestination
    let some nodeHash := FixedBytes.ofBytes? node | fail "node hash size"
    try
      let reply ← blockingSendMessage "hello".toUTF8 nodeHash queue (timeoutMs := 60000)
      expect "echo reply" (sameBytes' (reply.extract 0 5) "hello".toUTF8)
      return
    catch
      | .timeout => IO.println s!"     echo service {service.mixDescriptor.name} did not answer"
      | e => throw e
  fail "no echo service answered"

def scenarios : List (String × ClientM Unit) := [
  ("new keypair", newKeypairBasic),
  ("directory authorities", directoryAuthorities),
  ("box indices", boxIndices),
  ("courier envelopes", courierEnvelopes),
  ("write then read", writeThenRead),
  ("box not found", boxNotFound),
  ("tombstone a box", tombstoneBox),
  ("tombstone range", tombstoneRangeOfThree),
  ("copy onto an existing box", copyOntoExistingBox),
  ("echo", echo)]

def runAll (addr : IPAddr) (port : UInt16) : IO Bool := do
  let mut ok := true
  for (name, scenario) in scenarios do
    let r ← (withClient addr port scenario).block
    match r with
    | .ok () => IO.println s!"ok   {name}"
    | .error e => IO.println s!"FAIL {name}: {e}"; ok := false
  return ok

end ThinClient.Tests.Integration

def main (args : List String) : IO UInt32 := do
  let (host, port) := match args with
    | [h, p] => (h, p.toNat!)
    | _ => ("127.0.0.1", 33399)
  let some addr := Std.Net.IPv4Addr.ofString host
    | IO.eprintln s!"not an IPv4 address: {host}"; return 2
  let ok ← ThinClient.Tests.Integration.runAll (.v4 addr) port.toUInt16
  return if ok then 0 else 1
