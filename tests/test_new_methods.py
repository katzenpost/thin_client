# SPDX-FileCopyrightText: Copyright (C) 2024, 2025 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Unit tests for new ThinClient methods: get_all_couriers, get_distinct_couriers,
pki_document_for_epoch, and blocking_send_message.

These tests mock the PKI document and do not require a running daemon.
"""

import pytest
import hashlib
import cbor2

from katzenpost_thinclient import ThinClient, Config


def blake2_256_sum(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def make_service_node(identity_key: bytes, capability: str, endpoint: str) -> bytes:
    """Create a CBOR-encoded service node descriptor."""
    node = {
        "IdentityKey": identity_key,
        "Kaetzchen": {
            capability: {
                "endpoint": endpoint,
            }
        },
    }
    return cbor2.dumps(node)


def make_pki_doc(service_nodes: list, epoch: int = 1) -> dict:
    """Create a minimal PKI document with the given service nodes."""
    return {
        "Epoch": epoch,
        "ServiceNodes": service_nodes,
        "GatewayNodes": [],
        "Topology": [],
    }


def make_client() -> ThinClient:
    """Create a ThinClient with a minimal config, no daemon connection."""
    from .conftest import get_config_path

    config_path = get_config_path()
    cfg = Config(config_path)
    return ThinClient(cfg)


class TestGetAllCouriers:
    def test_returns_couriers(self):
        client = make_client()
        key1 = b"courier_identity_key_1__________"
        key2 = b"courier_identity_key_2__________"
        nodes = [
            make_service_node(key1, "courier", "courier"),
            make_service_node(key2, "courier", "courier"),
        ]
        client.pki_doc = make_pki_doc(nodes)

        couriers = client.get_all_couriers()

        assert len(couriers) == 2
        assert couriers[0] == (blake2_256_sum(key1), b"courier")
        assert couriers[1] == (blake2_256_sum(key2), b"courier")
        client.socket.close()

    def test_no_couriers_raises(self):
        client = make_client()
        nodes = [
            make_service_node(b"echo_key________________________", "echo", "echo"),
        ]
        client.pki_doc = make_pki_doc(nodes)

        with pytest.raises(Exception, match="service not found"):
            client.get_all_couriers()
        client.socket.close()

    def test_no_pki_doc_raises(self):
        client = make_client()
        client.pki_doc = None

        with pytest.raises(Exception, match="pki doc is nil"):
            client.get_all_couriers()
        client.socket.close()


class TestGetDistinctCouriers:
    def test_returns_n_distinct(self):
        client = make_client()
        keys = [f"courier_key_{i:021d}".encode() for i in range(5)]
        nodes = [make_service_node(k, "courier", "courier") for k in keys]
        client.pki_doc = make_pki_doc(nodes)

        result = client.get_distinct_couriers(3)

        assert len(result) == 3
        # All should be distinct
        hashes = [r[0] for r in result]
        assert len(set(hashes)) == 3
        # All should be valid courier hashes
        valid_hashes = {blake2_256_sum(k) for k in keys}
        for h in hashes:
            assert h in valid_hashes
        client.socket.close()

    def test_not_enough_couriers_raises(self):
        client = make_client()
        nodes = [
            make_service_node(
                b"courier_key_only________________", "courier", "courier"
            ),
        ]
        client.pki_doc = make_pki_doc(nodes)

        with pytest.raises(Exception, match="not enough couriers"):
            client.get_distinct_couriers(3)
        client.socket.close()

    def test_exact_count(self):
        client = make_client()
        keys = [f"courier_key_{i:021d}".encode() for i in range(2)]
        nodes = [make_service_node(k, "courier", "courier") for k in keys]
        client.pki_doc = make_pki_doc(nodes)

        result = client.get_distinct_couriers(2)

        assert len(result) == 2
        assert len(set(r[0] for r in result)) == 2
        client.socket.close()


class TestPkiDocumentForEpoch:
    def test_returns_cached_epoch(self):
        client = make_client()
        doc1 = make_pki_doc([], epoch=10)
        doc2 = make_pki_doc([], epoch=11)

        # Simulate receiving two PKI docs
        client.parse_pki_doc({"payload": cbor2.dumps(doc1)})
        client.parse_pki_doc({"payload": cbor2.dumps(doc2)})

        result = client.pki_document_for_epoch(10)
        assert result["Epoch"] == 10

        result = client.pki_document_for_epoch(11)
        assert result["Epoch"] == 11
        client.socket.close()

    def test_falls_back_to_current(self):
        client = make_client()
        doc = make_pki_doc([], epoch=10)
        client.parse_pki_doc({"payload": cbor2.dumps(doc)})

        # Request an epoch that was never cached
        result = client.pki_document_for_epoch(999)
        assert result["Epoch"] == 10
        client.socket.close()

    def test_no_doc_raises(self):
        client = make_client()

        with pytest.raises(Exception, match="no PKI document available"):
            client.pki_document_for_epoch(1)
        client.socket.close()

    def test_evicts_old_epochs(self):
        client = make_client()

        # Cache 10 epochs to ensure eviction kicks in multiple times
        for epoch in range(1, 11):
            doc = make_pki_doc([], epoch=epoch)
            client.parse_pki_doc({"payload": cbor2.dumps(doc)})

        # Cache should not grow unboundedly
        assert len(client._pki_doc_cache) <= 6
        # Latest epoch must be present
        assert 10 in client._pki_doc_cache
        # Very old epochs must be evicted
        assert 1 not in client._pki_doc_cache
        assert 2 not in client._pki_doc_cache
        assert 3 not in client._pki_doc_cache
        client.socket.close()

    def test_current_doc_updates(self):
        client = make_client()
        doc1 = make_pki_doc([], epoch=1)
        doc2 = make_pki_doc([], epoch=2)

        client.parse_pki_doc({"payload": cbor2.dumps(doc1)})
        assert client.pki_document()["Epoch"] == 1

        client.parse_pki_doc({"payload": cbor2.dumps(doc2)})
        assert client.pki_document()["Epoch"] == 2
        client.socket.close()
