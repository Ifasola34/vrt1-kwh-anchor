"""Tests for checkpoint event creation."""

import pytest

from veritas.crypto import OracleKey

from vrt1_kwh_anchor import batch_measurements, build_kwh_checkpoint


class TestBuildKwhCheckpoint:
    def test_creates_valid_event(self, sample_corpus, oracle_key):
        batch = batch_measurements(sample_corpus, epoch=7)
        event = build_kwh_checkpoint(batch, key=oracle_key)
        assert event.kind == 30079
        assert event.pubkey == oracle_key.xonly_pubkey_hex
        assert event.verify()

    def test_event_id_deterministic(self, sample_corpus, oracle_key):
        batch = batch_measurements(sample_corpus, epoch=7)
        e1 = build_kwh_checkpoint(batch, key=oracle_key, ts=1700000000)
        e2 = build_kwh_checkpoint(batch, key=oracle_key, ts=1700000000)
        assert e1.id == e2.id

    def test_content_contains_root(self, sample_corpus, oracle_key):
        import json

        batch = batch_measurements(sample_corpus, epoch=7)
        event = build_kwh_checkpoint(batch, key=oracle_key)
        content = json.loads(event.content)
        assert content["root"] == batch.root_hex

    def test_content_contains_epoch(self, sample_corpus, oracle_key):
        import json

        batch = batch_measurements(sample_corpus, epoch=42)
        event = build_kwh_checkpoint(batch, key=oracle_key)
        content = json.loads(event.content)
        assert content["epoch"] == 42

    def test_content_contains_count(self, sample_corpus, oracle_key):
        import json

        batch = batch_measurements(sample_corpus, epoch=1)
        event = build_kwh_checkpoint(batch, key=oracle_key)
        content = json.loads(event.content)
        assert content["count"] == 5

    def test_no_anchor_txid_when_no_tx(self, sample_corpus, oracle_key):
        import json

        batch = batch_measurements(sample_corpus, epoch=1)
        assert batch.anchor_tx is None
        event = build_kwh_checkpoint(batch, key=oracle_key)
        content = json.loads(event.content)
        assert content["anchor_txid"] is None

    def test_tags_include_root(self, sample_corpus, oracle_key):
        batch = batch_measurements(sample_corpus, epoch=7)
        event = build_kwh_checkpoint(batch, key=oracle_key)
        root_tags = [t for t in event.tags if t[0] == "root"]
        assert len(root_tags) == 1
        assert root_tags[0][1] == batch.root_hex

    def test_tags_include_d_identifier(self, sample_corpus, oracle_key):
        batch = batch_measurements(sample_corpus, epoch=7)
        event = build_kwh_checkpoint(batch, key=oracle_key)
        d_tags = [t for t in event.tags if t[0] == "d"]
        assert len(d_tags) == 1
        assert "7" in d_tags[0][1]

    def test_custom_timestamp(self, sample_corpus, oracle_key):
        batch = batch_measurements(sample_corpus, epoch=1)
        event = build_kwh_checkpoint(batch, key=oracle_key, ts=1234567890)
        assert event.created_at == 1234567890
