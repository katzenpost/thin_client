// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// gen-vectors writes every thin client message, encoded by the daemon's own
// types, to a JSON file of test vectors, and checks that request frames
// encoded by the Lean thin client decode to the same messages.
//
//	go run . gen ../../testdata/vectors.json
//	go run . verify ../../.lake/requests.json
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/bacap"

	"github.com/katzenpost/katzenpost/client/thin"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func id16(start byte) *[16]byte {
	var a [16]byte
	copy(a[:], seq(start, 16))
	return &a
}

func id32(start byte) *[32]byte {
	var a [32]byte
	copy(a[:], seq(start, 32))
	return &a
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func u8(v uint8) *uint8 { return &v }

type caps struct {
	write *bacap.WriteCap
	read  *bacap.ReadCap
	index *bacap.MessageBoxIndex
	next  *bacap.MessageBoxIndex
}

func newCaps() caps {
	rng := rand.NewChaCha8([32]byte{1, 2, 3})
	w := must(bacap.NewWriteCap(rng))
	idx := w.GetMessageBoxIndex()
	return caps{w, w.ReadCap(), idx, must(idx.NextIndex())}
}

func sphinxGeometry() *geo.Geometry {
	return geo.GeometryFromUserForwardPayloadLength(nikeschemes.ByName("x25519"), 2000, true, 5)
}

func pigeonholeGeometry() *pgeo.Geometry {
	return &pgeo.Geometry{
		MaxPlaintextPayloadLength:    1553,
		CourierQueryReadLength:       430,
		CourierQueryWriteLength:      2082,
		CourierQueryReplyReadLength:  1679,
		CourierQueryReplyWriteLength: 103,
		NIKEName:                     "x25519",
		SignatureSchemeName:          "Ed25519",
	}
}

func mixDescriptor(name string, start byte, gateway, service bool) *cpki.MixDescriptor {
	d := &cpki.MixDescriptor{
		Name:               name,
		Epoch:              123456,
		IdentityKey:        seq(start, 32),
		LinkKey:            seq(start+0x20, 32),
		MixKeys:            map[uint64][]byte{123456: seq(start+0x40, 32)},
		Addresses:          map[string][]string{"tcp": {"tcp://127.0.0.1:30001"}},
		IsGatewayNode:      gateway,
		IsServiceNode:      service,
		LoadWeight:         3,
		AuthenticationType: "tofu",
		Version:            "v1",
	}
	if service {
		d.Kaetzchen = map[string]map[string]interface{}{
			"echo": {"endpoint": "+echo", "concurrency": 4},
		}
		d.KaetzchenAdvertizedData = map[string]map[string]interface{}{
			"echo": {"note": "for tests"},
		}
	}
	return d
}

func pkiDocument() *cpki.Document {
	return &cpki.Document{
		Epoch:        123456,
		GenesisEpoch: 100000,
		Mu:           0.005,
		LambdaP:      0.001,
		LambdaL:      0.0005,
		LambdaM:      0.0002,
		LambdaG:      0.0001,
		LambdaR:      0.00005,
		Topology: [][]*cpki.MixDescriptor{
			{mixDescriptor("mix1", 0x10, false, false)},
			{mixDescriptor("mix2", 0x30, false, false)},
		},
		GatewayNodes: []*cpki.MixDescriptor{mixDescriptor("gateway1", 0x50, true, false)},
		ServiceNodes: []*cpki.MixDescriptor{mixDescriptor("servicenode1", 0x70, false, true)},
		StorageReplicas: []*cpki.ReplicaDescriptor{{
			Name:         "replica1",
			ReplicaID:    2,
			Epoch:        123456,
			IdentityKey:  seq(0x90, 32),
			LinkKey:      seq(0xa0, 32),
			EnvelopeKeys: map[uint64][]byte{77: seq(0xb0, 32)},
			Addresses:    map[string][]string{"tcp": {"tcp://127.0.0.1:30010"}},
		}},
		ConfiguredReplicaIDs:          []uint8{2},
		ConfiguredReplicaIdentityKeys: [][]byte{seq(0x90, 32)},
		SharedRandomCommit:            map[[32]byte][]byte{*id32(0xc0): seq(0xd0, 8)},
		SharedRandomReveal:            map[[32]byte][]byte{*id32(0xc0): seq(0xe0, 8)},
		SharedRandomValue:             seq(0xf0, 32),
		WeeklySharedRandom:            [][]byte{seq(0x01, 32)},
		SphinxGeometryHash:            sphinxGeometry().Hash(),
		Version:                       "v1",
		PKISignatureScheme:            "Ed25519",
	}
}

type named[T any] struct {
	name string
	msg  *T
}

func requests(c caps) []named[thin.Request] {
	q := id16(0x20)
	return []named[thin.Request]{
		{"session_token", &thin.Request{SessionToken: &thin.SessionToken{ClientInstanceToken: *id16(0x10)}}},
		{"thin_close", &thin.Request{ThinClose: &thin.ThinClose{}}},
		{"send_message", &thin.Request{SendMessage: &thin.SendMessage{
			WithSURB: true, SURBID: id16(0x30), DestinationIdHash: id32(0x40),
			RecipientQueueID: []byte("+echo"), Payload: []byte("hello")}}},
		{"send_message_no_surb", &thin.Request{SendMessage: &thin.SendMessage{
			DestinationIdHash: id32(0x40), RecipientQueueID: []byte("+echo"), Payload: []byte("hi")}}},
		{"new_keypair", &thin.Request{NewKeypair: &thin.NewKeypair{QueryID: q, Seed: seq(0x50, 32)}}},
		{"encrypt_read", &thin.Request{EncryptRead: &thin.EncryptRead{
			QueryID: q, ReadCap: c.read, MessageBoxIndex: c.index}}},
		{"encrypt_write", &thin.Request{EncryptWrite: &thin.EncryptWrite{
			QueryID: q, Plaintext: []byte("plaintext"), WriteCap: c.write, MessageBoxIndex: c.index}}},
		{"start_resending_read", &thin.Request{StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
			QueryID: q, ReadCap: c.read, MessageBoxIndex: must(c.index.MarshalBinary()),
			ReplyIndex: u8(1), EnvelopeDescriptor: seq(0x60, 40), MessageCiphertext: seq(0x70, 50),
			EnvelopeHash: id32(0x80), NoRetryOnBoxIDNotFound: true}}},
		{"start_resending_write", &thin.Request{StartResendingEncryptedMessage: &thin.StartResendingEncryptedMessage{
			QueryID: q, WriteCap: c.write, EnvelopeDescriptor: seq(0x60, 40),
			MessageCiphertext: seq(0x70, 50), EnvelopeHash: id32(0x80), NoIdempotentBoxAlreadyExists: true}}},
		{"cancel_resending_encrypted_message", &thin.Request{CancelResendingEncryptedMessage: &thin.CancelResendingEncryptedMessage{
			QueryID: q, EnvelopeHash: id32(0x80)}}},
		{"start_resending_copy_command", &thin.Request{StartResendingCopyCommand: &thin.StartResendingCopyCommand{
			QueryID: q, WriteCap: c.write}}},
		{"start_resending_copy_command_courier", &thin.Request{StartResendingCopyCommand: &thin.StartResendingCopyCommand{
			QueryID: q, WriteCap: c.write, CourierIdentityHash: id32(0x90), CourierQueueID: seq(0xa0, 8)}}},
		{"cancel_resending_copy_command", &thin.Request{CancelResendingCopyCommand: &thin.CancelResendingCopyCommand{
			QueryID: q, WriteCapHash: id32(0xb0)}}},
		{"next_message_box_index", &thin.Request{NextMessageBoxIndex: &thin.NextMessageBoxIndex{
			QueryID: q, MessageBoxIndex: c.index}}},
		{"get_message_box_index_counter", &thin.Request{GetMessageBoxIndexCounter: &thin.GetMessageBoxIndexCounter{
			QueryID: q, MessageBoxIndex: c.index}}},
		{"get_pki_document", &thin.Request{GetPKIDocument: &thin.GetPKIDocument{QueryID: q, Epoch: 123456}}},
		{"get_directory_authorities", &thin.Request{GetDirectoryAuthorities: &thin.GetDirectoryAuthorities{QueryID: q}}},
		{"create_courier_envelopes_from_payload", &thin.Request{CreateCourierEnvelopesFromPayload: &thin.CreateCourierEnvelopesFromPayload{
			QueryID: q, Payload: seq(0x01, 64), DestWriteCap: c.write, DestStartIndex: c.index,
			IsStart: true, IsLast: true}}},
		{"create_courier_envelopes_from_multi_payload", &thin.Request{CreateCourierEnvelopesFromPayloads: &thin.CreateCourierEnvelopesFromPayloads{
			QueryID: q, Destinations: []thin.DestinationPayload{
				{Payload: seq(0x01, 16), WriteCap: c.write, StartIndex: c.index},
				{Payload: seq(0x11, 16), WriteCap: c.write, StartIndex: c.next}},
			IsStart: true, Buffer: seq(0x21, 8)}}},
		{"create_courier_envelopes_from_tombstone_range", &thin.Request{CreateCourierEnvelopesFromTombstoneRange: &thin.CreateCourierEnvelopesFromTombstoneRange{
			QueryID: q, DestWriteCap: c.write, DestStartIndex: c.index, MaxCount: 10,
			IsLast: true, Buffer: seq(0x31, 8)}}},
		{"voucher_mint", &thin.Request{VoucherMint: &thin.VoucherMint{
			QueryID: q, MessageWriteCap: must(c.write.MarshalBinary()), DisplayName: "alice"}}},
		{"voucher_induct", &thin.Request{VoucherInduct: &thin.VoucherInduct{
			QueryID: q, Voucher: seq(0x41, 32), VoucherPayload: seq(0x51, 64), WhoReply: seq(0x61, 16)}}},
		{"voucher_open", &thin.Request{VoucherOpen: &thin.VoucherOpen{
			QueryID: q, VoucherSecretKey: seq(0x71, 32), SealedReply: seq(0x81, 48),
			MessageWriteCap: must(c.write.MarshalBinary())}}},
		{"voucher_derive_stream", &thin.Request{VoucherDeriveStream: &thin.VoucherDeriveStream{
			QueryID: q, Voucher: seq(0x41, 32)}}},
	}
}

func responses(c caps) []named[thin.Response] {
	q := id16(0x20)
	doc := must(cbor.Marshal(pkiDocument()))
	return []named[thin.Response]{
		{"session_token_reply", &thin.Response{SessionTokenReply: &thin.SessionTokenReply{AppID: seq(0x40, 16), Resumed: true}}},
		{"shutdown_event", &thin.Response{ShutdownEvent: &thin.ShutdownEvent{}}},
		{"connection_status_event", &thin.Response{ConnectionStatusEvent: &thin.ConnectionStatusEvent{
			IsConnected: true, InstanceToken: *id16(0x50), SphinxGeometry: sphinxGeometry(),
			PigeonholeGeometry: pigeonholeGeometry()}}},
		{"connection_status_event_offline", &thin.Response{ConnectionStatusEvent: &thin.ConnectionStatusEvent{
			InstanceToken: *id16(0x50)}}},
		{"new_pki_document_event", &thin.Response{NewPKIDocumentEvent: &thin.NewPKIDocumentEvent{Payload: doc}}},
		{"message_sent_event", &thin.Response{MessageSentEvent: &thin.MessageSentEvent{
			MessageID: id16(0x60), SURBID: id16(0x30), SentAt: time.Unix(1760000000, 0),
			ReplyETA: 3 * time.Second, ForwardRoute: []string{"gateway1", "mix1", "mix2"},
			ReturnRoute: []string{"mix2", "mix1", "gateway1"}}}},
		{"message_sent_event_err", &thin.Response{MessageSentEvent: &thin.MessageSentEvent{
			MessageID: id16(0x60), SentAt: time.Unix(1760000000, 0), Err: "no route"}}},
		{"message_reply_event", &thin.Response{MessageReplyEvent: &thin.MessageReplyEvent{
			MessageID: id16(0x60), SURBID: id16(0x30), Payload: []byte("hello"), ReplyIndex: u8(1)}}},
		{"message_reply_event_err", &thin.Response{MessageReplyEvent: &thin.MessageReplyEvent{
			MessageID: id16(0x60), Payload: []byte{}, ErrorCode: thin.ThinClientErrorTimeout}}},
		{"message_id_garbage_collected", &thin.Response{MessageIDGarbageCollected: &thin.MessageIDGarbageCollected{MessageID: id16(0x60)}}},
		{"new_keypair_reply", &thin.Response{NewKeypairReply: &thin.NewKeypairReply{
			QueryID: q, WriteCap: c.write, ReadCap: c.read, FirstMessageIndex: c.index}}},
		{"new_keypair_reply_err", &thin.Response{NewKeypairReply: &thin.NewKeypairReply{
			QueryID: q, ErrorCode: thin.ThinClientErrorInvalidRequest}}},
		{"encrypt_read_reply", &thin.Response{EncryptReadReply: &thin.EncryptReadReply{
			QueryID: q, MessageCiphertext: seq(0x70, 50), EnvelopeDescriptor: seq(0x60, 40),
			EnvelopeHash: id32(0x80), NextMessageBoxIndex: c.next}}},
		{"encrypt_write_reply", &thin.Response{EncryptWriteReply: &thin.EncryptWriteReply{
			QueryID: q, MessageCiphertext: seq(0x70, 50), EnvelopeDescriptor: seq(0x60, 40),
			EnvelopeHash: id32(0x80), NextMessageBoxIndex: c.next}}},
		{"start_resending_encrypted_message_reply", &thin.Response{StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
			QueryID: q, Plaintext: []byte("plaintext"), CourierIdentityHash: id32(0x90), CourierQueueID: seq(0xa0, 8)}}},
		{"start_resending_encrypted_message_reply_err", &thin.Response{StartResendingEncryptedMessageReply: &thin.StartResendingEncryptedMessageReply{
			QueryID: q, Plaintext: []byte{}, ErrorCode: 1, CourierQueueID: []byte{}}}},
		{"cancel_resending_encrypted_message_reply", &thin.Response{CancelResendingEncryptedMessageReply: &thin.CancelResendingEncryptedMessageReply{QueryID: q}}},
		{"start_resending_copy_command_reply", &thin.Response{StartResendingCopyCommandReply: &thin.StartResendingCopyCommandReply{QueryID: q}}},
		{"start_resending_copy_command_reply_err", &thin.Response{StartResendingCopyCommandReply: &thin.StartResendingCopyCommandReply{
			QueryID: q, ErrorCode: thin.ThinClientErrorCopyCommandFailed, ReplicaErrorCode: 10, FailedEnvelopeIndex: 3}}},
		{"cancel_resending_copy_command_reply", &thin.Response{CancelResendingCopyCommandReply: &thin.CancelResendingCopyCommandReply{QueryID: q}}},
		{"next_message_box_index_reply", &thin.Response{NextMessageBoxIndexReply: &thin.NextMessageBoxIndexReply{
			QueryID: q, NextMessageBoxIndex: c.next}}},
		{"get_message_box_index_counter_reply", &thin.Response{GetMessageBoxIndexCounterReply: &thin.GetMessageBoxIndexCounterReply{
			QueryID: q, Counter: 42}}},
		{"get_pki_document_reply", &thin.Response{GetPKIDocumentReply: &thin.GetPKIDocumentReply{
			QueryID: q, Payload: seq(0x01, 100), Epoch: 123456}}},
		{"get_directory_authorities_reply", &thin.Response{GetDirectoryAuthoritiesReply: &thin.GetDirectoryAuthoritiesReply{
			QueryID: q, Authorities: []*thin.DirectoryAuthority{{
				Identifier: "auth1", PKISignatureScheme: "Ed25519", WireKEMScheme: "xwing",
				Addresses:            []string{"tcp://127.0.0.1:30000"},
				IdentityPublicKeyPem: "-----BEGIN ED25519 PUBLIC KEY-----\n...\n",
				LinkPublicKeyPem:     "-----BEGIN XWING PUBLIC KEY-----\n...\n",
				IdentityKeyHash:      *id32(0xc0)}}}}},
		{"create_courier_envelopes_from_payload_reply", &thin.Response{CreateCourierEnvelopesFromPayloadReply: &thin.CreateCourierEnvelopesFromPayloadReply{
			QueryID: q, Envelopes: [][]byte{seq(0x01, 20), seq(0x21, 20)}, NextDestIndex: c.next}}},
		{"create_courier_envelopes_from_multi_payload_reply", &thin.Response{CreateCourierEnvelopesFromPayloadsReply: &thin.CreateCourierEnvelopesFromPayloadsReply{
			QueryID: q, Envelopes: [][]byte{seq(0x01, 20)}, Buffer: seq(0x41, 8),
			NextDestIndices: []*bacap.MessageBoxIndex{c.next, c.index}}}},
		{"create_courier_envelopes_from_tombstone_range_reply", &thin.Response{CreateCourierEnvelopesFromTombstoneRangeReply: &thin.CreateCourierEnvelopesFromTombstoneRangeReply{
			QueryID: q, Envelopes: [][]byte{seq(0x01, 20)}, Buffer: seq(0x51, 8), NextDestIndex: c.next}}},
		{"voucher_mint_reply", &thin.Response{VoucherMintReply: &thin.VoucherMintReply{
			QueryID: q, Voucher: seq(0x01, 32), VoucherPayload: seq(0x11, 64), VoucherWriteCap: seq(0x21, 168),
			VoucherReadCap: seq(0x31, 136), VoucherSecretKey: seq(0x41, 32), VoucherPublicKey: seq(0x51, 32)}}},
		{"voucher_induct_reply", &thin.Response{VoucherInductReply: &thin.VoucherInductReply{
			QueryID: q, DisplayName: "alice", MutatedMessageReadCap: seq(0x01, 136), SealedReply: seq(0x11, 48),
			VoucherWriteCap: seq(0x21, 168), VoucherReadCap: seq(0x31, 136), Salt: seq(0x41, 16)}}},
		{"voucher_open_reply", &thin.Response{VoucherOpenReply: &thin.VoucherOpenReply{
			QueryID: q, WhoReply: seq(0x01, 16), Salt: seq(0x11, 16), MutatedMessageWriteCap: seq(0x21, 168)}}},
		{"voucher_derive_stream_reply", &thin.Response{VoucherDeriveStreamReply: &thin.VoucherDeriveStreamReply{
			QueryID: q, VoucherWriteCap: seq(0x21, 168), VoucherReadCap: seq(0x31, 136)}}},
		{"voucher_open_reply_err", &thin.Response{VoucherOpenReply: &thin.VoucherOpenReply{
			QueryID: q, WhoReply: []byte{}, Salt: []byte{}, MutatedMessageWriteCap: []byte{},
			ErrorCode: thin.ThinClientErrorVoucherSealOpenFailed}}},
	}
}

// variant returns the key and value of the one set field of a Request or Response.
func variant(env any) (string, any) {
	blob := must(cbor.Marshal(env))
	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(blob, &m); err != nil {
		panic(err)
	}
	for k, v := range m {
		if !bytes.Equal(v, []byte{0xf6}) {
			return k, v
		}
	}
	panic("no variant set")
}

type vector struct {
	Name  string `json:"name"`
	Key   string `json:"key"`
	Body  string `json:"body"`
	Frame string `json:"frame"`
}

type vectors struct {
	Requests  []vector `json:"requests"`
	Responses []vector `json:"responses"`
}

func toVector[T any](n named[T]) vector {
	k, body := variant(n.msg)
	return vector{n.name, k, hex.EncodeToString(body.(cbor.RawMessage)),
		hex.EncodeToString(must(cbor.Marshal(n.msg)))}
}

func gen(path string) {
	c := newCaps()
	var out vectors
	for _, r := range requests(c) {
		out.Requests = append(out.Requests, toVector(r))
	}
	for _, r := range responses(c) {
		out.Responses = append(out.Responses, toVector(r))
	}
	b := must(json.MarshalIndent(out, "", "  "))
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}

// verify decodes the Lean thin client's request frames and checks that each
// is the request of the same name, by re-encoding both with the daemon's types.
func verify(path string) {
	var in struct {
		Requests []struct {
			Name  string `json:"name"`
			Frame string `json:"frame"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(must(os.ReadFile(path)), &in); err != nil {
		panic(err)
	}
	want := map[string]*thin.Request{}
	for _, r := range requests(newCaps()) {
		want[r.name] = r.msg
	}
	failed := 0
	for _, r := range in.Requests {
		var got thin.Request
		if err := cbor.Unmarshal(must(hex.DecodeString(r.Frame)), &got); err != nil {
			fmt.Printf("FAIL %s: %v\n", r.Name, err)
			failed++
			continue
		}
		w, ok := want[r.Name]
		if !ok {
			fmt.Printf("FAIL %s: no such request\n", r.Name)
			failed++
			continue
		}
		if !bytes.Equal(must(cbor.Marshal(&got)), must(cbor.Marshal(w))) {
			fmt.Printf("FAIL %s: decodes to a different request\n", r.Name)
			failed++
			continue
		}
		fmt.Printf("ok   %s\n", r.Name)
	}
	if failed > 0 || len(in.Requests) != len(want) {
		fmt.Printf("%d of %d requests failed (%d expected)\n", failed, len(in.Requests), len(want))
		os.Exit(1)
	}
	fmt.Printf("all %d requests decode as the daemon's types\n", len(in.Requests))
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gen-vectors gen|verify FILE")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		gen(os.Args[2])
	case "verify":
		verify(os.Args[2])
	default:
		fmt.Fprintln(os.Stderr, "usage: gen-vectors gen|verify FILE")
		os.Exit(2)
	}
}
