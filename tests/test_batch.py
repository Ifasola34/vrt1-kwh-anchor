"""Tests for batch_measurements and BatchResult."""

import pytest

from veritas.anchor import parse_op_return_payload
from veritas.crypto import OracleKey
from veritas.merkle import verify_merkle_proof
from vrt1_kwh.attestation import measurement_digest

from vrt1_kwh_anchor import batch_measurements, BatchResult


class TestBatchMeasurements:
    def test_batch_single_measurement(self, make_signed_measurement):
        corpus = [make_signed_measurement(0)]
        result = batch_measurements(corpus, epoch=1)
        assert isinstance(result, BatchResult)
        assert result.epoch == 1
        assert result.leaf_count == 1
        assert len(result.digests) == 1
        assert len(result.proofs) == 1
        assert len(result.root) == 32

    def test_batch_multiple_measurements(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=7)
        assert result.leaf_count == 5
        assert len(result.proofs) == 5
        assert result.epoch == 7

    def test_all_proofs_verify(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        for proof in result.proofs:
            assert verify_merkle_proof(proof)

    def test_proof_leaves_match_digests(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        for i, proof in enumerate(result.proofs):
            expected_digest = measurement_digest(sample_corpus[i].measurement)
            assert proof.leaf == expected_digest

    def test_all_proofs_share_root(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        for proof in result.proofs:
            assert proof.root == result.root

    def test_op_return_payload_valid(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=42)
        assert len(result.op_return_payload) == 49
        parsed = parse_op_return_payload(result.op_return_payload)
        assert parsed["tag"] == "VRT1"
        assert parsed["version"] == 1
        assert parsed["epoch"] == 42
        assert parsed["leaf_count"] == 5
        assert parsed["merkle_root"] == result.root

    def test_op_return_roundtrip_root(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        parsed = parse_op_return_payload(result.op_return_payload)
        assert parsed["merkle_root"] == result.root

    def test_empty_corpus_raises(self):
        with pytest.raises(ValueError, match="empty"):
            batch_measurements([], epoch=1)

    def test_invalid_signature_rejected(self, make_signed_measurement):
        m = make_signed_measurement(0)
        tampered = type(m)(
            measurement=m.measurement,
            sig="ff" * 64,
        )
        with pytest.raises(ValueError, match="invalid signature"):
            batch_measurements([tampered], epoch=1)

    def test_no_anchor_tx_without_key_and_utxo(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        assert result.anchor_tx is None

    def test_root_hex_property(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        assert result.root_hex == result.root.hex()
        assert len(result.root_hex) == 64

    def test_deterministic_root(self, sample_corpus):
        r1 = batch_measurements(sample_corpus, epoch=1)
        r2 = batch_measurements(sample_corpus, epoch=1)
        assert r1.root == r2.root

    def test_different_epoch_same_root(self, sample_corpus):
        r1 = batch_measurements(sample_corpus, epoch=1)
        r2 = batch_measurements(sample_corpus, epoch=99)
        assert r1.root == r2.root

    def test_different_corpus_different_root(self, make_signed_measurement):
        c1 = [make_signed_measurement(0), make_signed_measurement(1)]
        c2 = [make_signed_measurement(2), make_signed_measurement(3)]
        r1 = batch_measurements(c1, epoch=1)
        r2 = batch_measurements(c2, epoch=1)
        assert r1.root != r2.root

    def test_proof_index_matches_position(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        for i, proof in enumerate(result.proofs):
            assert proof.index == i
            assert proof.size == 5


class TestBatchFromDirectory:
    def test_missing_dir_raises(self, tmp_path):
        from vrt1_kwh_anchor import batch_from_directory

        with pytest.raises(ValueError, match="no measurements"):
            batch_from_directory(tmp_path / "nonexistent", epoch=1)

    def test_empty_dir_raises(self, tmp_path):
        from vrt1_kwh_anchor import batch_from_directory

        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(ValueError, match="no measurements"):
            batch_from_directory(empty, epoch=1)

    def test_loads_and_batches(self, tmp_path, make_signed_measurement):
        import json

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        for i in range(3):
            m = make_signed_measurement(i)
            path = data_dir / f"{i:020d}_test.json"
            path.write_text(m.to_json())

        from vrt1_kwh_anchor import batch_from_directory

        result = batch_from_directory(data_dir, epoch=5)
        assert result.leaf_count == 3
        assert result.epoch == 5
