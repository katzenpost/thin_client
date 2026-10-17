/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import ThinClient.Cbor
import Cryptlib.Primitives.Hash.Blake2b

/-! # PKI document

The consensus document the directory authorities publish each epoch, as the daemon hands it to
thin clients: without the authorities' signatures. Map keys are the Go field names.

## Encoding

Inside a `Document`, each mix descriptor is a byte string holding the descriptor's canonical CBOR
map, whose keys are sorted shortest first and then bytewise. Replica descriptors are plain maps
in field order. -/

namespace ThinClient

open Cborg

/-- A mix, gateway or service node. -/
structure MixDescriptor where
  name : String
  epoch : UInt64
  identityKey : ByteArray
  linkKey : ByteArray
  /-- Sphinx public key for each epoch. -/
  mixKeys : CborMap UInt64 ByteArray
  /-- Addresses by transport. -/
  addresses : CborMap String (Array String)
  /-- Service parameters by capability. -/
  kaetzchen : CborMap String (CborMap String Term)
  kaetzchenAdvertizedData : CborMap String (CborMap String Term)
  isGatewayNode : Bool
  isServiceNode : Bool
  loadWeight : UInt8
  authenticationType : String
  version : String
  deriving Inhabited

namespace MixDescriptor

/-- Fields are written in canonical key order. Unknown keys are ignored when decoding. -/
instance : Serialise MixDescriptor where
  encode d := encodeRecord [
    field "Name" d.name,
    field "Epoch" d.epoch,
    field "LinkKey" d.linkKey,
    field "MixKeys" d.mixKeys,
    field "Version" d.version,
    field "Addresses" d.addresses,
    field "Kaetzchen" d.kaetzchen,
    field "LoadWeight" d.loadWeight,
    field "IdentityKey" d.identityKey,
    field "IsGatewayNode" d.isGatewayNode,
    field "IsServiceNode" d.isServiceNode,
    field "AuthenticationType" d.authenticationType,
    field "KaetzchenAdvertizedData" d.kaetzchenAdvertizedData]
  decode := do
    let r ← decodeRecord
    return {
      name := ← r.withDefault "Name" ""
      epoch := ← r.withDefault "Epoch" 0
      identityKey := ← r.withDefault "IdentityKey" .empty
      linkKey := ← r.withDefault "LinkKey" .empty
      mixKeys := ← r.withDefault "MixKeys" {}
      addresses := ← r.withDefault "Addresses" {}
      kaetzchen := ← r.withDefault "Kaetzchen" {}
      kaetzchenAdvertizedData := ← r.withDefault "KaetzchenAdvertizedData" {}
      isGatewayNode := ← r.withDefault "IsGatewayNode" false
      isServiceNode := ← r.withDefault "IsServiceNode" false
      loadWeight := ← r.withDefault "LoadWeight" 0
      authenticationType := ← r.withDefault "AuthenticationType" ""
      version := ← r.withDefault "Version" "" }

/-- The queue a service listens on for `capability`, from its `endpoint` parameter. -/
def endpoint? (d : MixDescriptor) (capability : String) : Option String := do
  match ← (← d.kaetzchen.find? capability).find? "endpoint" with
  | .TString s => some s
  | _ => none

end MixDescriptor

/-- A Pigeonhole storage replica. -/
structure ReplicaDescriptor where
  name : String
  replicaId : UInt8
  epoch : UInt64
  identityKey : ByteArray
  linkKey : ByteArray
  /-- MKEM public key for each replica epoch. -/
  envelopeKeys : CborMap UInt64 ByteArray
  addresses : CborMap String (Array String)
  deriving Inhabited

instance : Serialise ReplicaDescriptor where
  encode d := encodeRecord [
    field "Name" d.name,
    field "ReplicaID" d.replicaId,
    field "Epoch" d.epoch,
    field "IdentityKey" d.identityKey,
    field "LinkKey" d.linkKey,
    field "EnvelopeKeys" d.envelopeKeys,
    field "Addresses" d.addresses]
  decode := do
    let r ← decodeRecord
    return {
      name := ← r.withDefault "Name" ""
      replicaId := ← r.withDefault "ReplicaID" 0
      epoch := ← r.withDefault "Epoch" 0
      identityKey := ← r.withDefault "IdentityKey" .empty
      linkKey := ← r.withDefault "LinkKey" .empty
      envelopeKeys := ← r.withDefault "EnvelopeKeys" {}
      addresses := ← r.withDefault "Addresses" {} }

structure Document where
  epoch : UInt64
  genesisEpoch : UInt64
  mu : Float
  lambdaP : Float
  lambdaL : Float
  lambdaM : Float
  lambdaG : Float
  lambdaR : Float
  /-- Mix layers, first hop first. -/
  topology : Array (Array MixDescriptor)
  gatewayNodes : Array MixDescriptor
  serviceNodes : Array MixDescriptor
  storageReplicas : Array ReplicaDescriptor
  configuredReplicaIds : ByteArray
  configuredReplicaIdentityKeys : Array ByteArray
  sharedRandomCommit : CborMap ByteArray ByteArray
  sharedRandomReveal : CborMap ByteArray ByteArray
  sharedRandomValue : ByteArray
  priorSharedRandom : Array ByteArray
  sphinxGeometryHash : ByteArray
  version : String
  pkiSignatureScheme : String
  deriving Inhabited

namespace Document

private def wrapAll (ds : Array MixDescriptor) : Array (Wrapped MixDescriptor) := ds.map (⟨·⟩)
private def unwrapAll (ws : Array (Wrapped MixDescriptor)) : Array MixDescriptor := ws.map (·.val)

instance : Serialise Document where
  encode d := encodeRecord [
    field "Epoch" d.epoch,
    field "GenesisEpoch" d.genesisEpoch,
    field "Mu" d.mu,
    field "LambdaP" d.lambdaP,
    field "LambdaL" d.lambdaL,
    field "LambdaM" d.lambdaM,
    field "LambdaG" d.lambdaG,
    field "LambdaR" d.lambdaR,
    field "Topology" (d.topology.map wrapAll),
    field "GatewayNodes" (wrapAll d.gatewayNodes),
    field "ServiceNodes" (wrapAll d.serviceNodes),
    field "StorageReplicas" d.storageReplicas,
    optField "ConfiguredReplicaIDs"
      (if d.configuredReplicaIds.isEmpty then none else some d.configuredReplicaIds),
    optField "ConfiguredReplicaIdentityKeys"
      (if d.configuredReplicaIdentityKeys.isEmpty then none else some d.configuredReplicaIdentityKeys),
    field "SharedRandomCommit" d.sharedRandomCommit,
    field "SharedRandomReveal" d.sharedRandomReveal,
    field "SharedRandomValue" d.sharedRandomValue,
    field "PriorSharedRandom" d.priorSharedRandom,
    field "SphinxGeometryHash" d.sphinxGeometryHash,
    field "Version" d.version,
    field "PKISignatureScheme" d.pkiSignatureScheme]
  decode := do
    let r ← decodeRecord
    return {
      epoch := ← r.withDefault "Epoch" 0
      genesisEpoch := ← r.withDefault "GenesisEpoch" 0
      mu := ← r.withDefault "Mu" 0
      lambdaP := ← r.withDefault "LambdaP" 0
      lambdaL := ← r.withDefault "LambdaL" 0
      lambdaM := ← r.withDefault "LambdaM" 0
      lambdaG := ← r.withDefault "LambdaG" 0
      lambdaR := ← r.withDefault "LambdaR" 0
      topology := (← r.withDefault "Topology" #[]).map unwrapAll
      gatewayNodes := unwrapAll (← r.withDefault "GatewayNodes" #[])
      serviceNodes := unwrapAll (← r.withDefault "ServiceNodes" #[])
      storageReplicas := ← r.withDefault "StorageReplicas" #[]
      configuredReplicaIds := ← r.withDefault "ConfiguredReplicaIDs" .empty
      configuredReplicaIdentityKeys := ← r.withDefault "ConfiguredReplicaIdentityKeys" #[]
      sharedRandomCommit := ← r.withDefault "SharedRandomCommit" {}
      sharedRandomReveal := ← r.withDefault "SharedRandomReveal" {}
      sharedRandomValue := ← r.withDefault "SharedRandomValue" .empty
      priorSharedRandom := ← r.withDefault "PriorSharedRandom" #[]
      sphinxGeometryHash := ← r.withDefault "SphinxGeometryHash" .empty
      version := ← r.withDefault "Version" ""
      pkiSignatureScheme := ← r.withDefault "PKISignatureScheme" "" }

end Document

/-- A service found in a PKI document: the node offering it and the queue it listens on. -/
structure ServiceDescriptor where
  recipientQueueId : ByteArray
  mixDescriptor : MixDescriptor
  deriving Inhabited

/-- The destination to send to: the BLAKE2b-256 hash of the node's identity key, and its
queue. -/
def ServiceDescriptor.toDestination (s : ServiceDescriptor) : ByteArray × ByteArray :=
  (⟨(Cryptlib.Primitives.Hash.Blake2b.hash256 s.mixDescriptor.identityKey).toArray⟩, s.recipientQueueId)

/-- Every service node offering `capability`. -/
def findServices (capability : String) (doc : Document) : Array ServiceDescriptor :=
  doc.serviceNodes.filterMap fun d =>
    d.endpoint? capability |>.map fun ep => { recipientQueueId := ep.toUTF8, mixDescriptor := d }

end ThinClient
