# SPDX-FileCopyrightText: Copyright (C) 2024, 2025 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""
Unit tests for new ThinClient methods: pki_document_for_epoch and
blocking_send_message.

These tests mock the PKI document and do not require a running daemon.
"""

import pytest
import cbor2

from katzenpost_thinclient import ThinClient, Config


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
