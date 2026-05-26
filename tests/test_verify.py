"""Tests for verification utilities."""

import pytest

from veritas.anchor import build_op_return_payload
from veritas.crypto import OracleKey
from vrt1_kwh.attestation import measurement_digest

from vrt1_kwh_anchor import batch_measurements, verify_kwh_inclusion, verify_anchor_binding, verify_full_chain


class TestVerifyKwhInclusion:
    def test_valid_inclusion(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        for i, m in enumerate(sample_corpus):
            assert verify_kwh_inclusion(m, result.proofs[i])

    def test_wrong_measurement_fails(self, make_signed_measurement):
        corpus = [make_signed_measurement(i) for i in range(3)]
        result = batch_measurements(corpus, epoch=1)
        wrong = make_signed_measurement(99)
        assert not verify_kwh_inclusion(wrong, result.proofs[0])

    def test_invalid_sig_fails(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        tampered = type(sample_corpus[0])(
            measurement=sample_corpus[0].measurement,
            sig="ff" * 64,
        )
        assert not verify_kwh_inclusion(tampered, result.proofs[0])

    def test_swapped_proof_fails(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        if len(sample_corpus) >= 2:
            assert not verify_kwh_inclusion(sample_corpus[0], result.proofs[1])


class TestVerifyAnchorBinding:
    def test_valid_binding(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=7)
        payload_hex = result.op_return_payload.hex()
        assert verify_anchor_binding(result.proofs[0], payload_hex, expected_epoch=7)

    def test_wrong_epoch_fails(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=7)
        payload_hex = result.op_return_payload.hex()
        assert not verify_anchor_binding(result.proofs[0], payload_hex, expected_epoch=99)

    def test_wrong_root_fails(self, sample_corpus, make_signed_measurement):
        result = batch_measurements(sample_corpus, epoch=1)
        other = batch_measurements([make_signed_measurement(99)], epoch=1)
        payload_hex = other.op_return_payload.hex()
        assert not verify_anchor_binding(result.proofs[0], payload_hex, expected_epoch=1)

    def test_wrong_leaf_count_fails(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        fake_payload = build_op_return_payload(
            merkle_root=result.root,
            epoch=1,
            leaf_count=999,
        )
        assert not verify_anchor_binding(result.proofs[0], fake_payload.hex(), expected_epoch=1)

    def test_malformed_hex_returns_false(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        assert not verify_anchor_binding(result.proofs[0], "not_valid_hex!", expected_epoch=1)

    def test_odd_length_hex_returns_false(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        assert not verify_anchor_binding(result.proofs[0], "abc", expected_epoch=1)

    def test_short_payload_returns_false(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        assert not verify_anchor_binding(result.proofs[0], "aabb", expected_epoch=1)

    def test_fabricated_proof_fails(self, sample_corpus):
        """A proof with matching root/size but invalid siblings must fail."""
        from veritas.merkle import MerkleProof
        result = batch_measurements(sample_corpus, epoch=1)
        fake_proof = MerkleProof(
            leaf=result.proofs[0].leaf,
            siblings=[b"\x00" * 32] * len(result.proofs[0].siblings),
            directions=result.proofs[0].directions,
            root=result.root,
            size=result.leaf_count,
            index=0,
        )
        payload_hex = result.op_return_payload.hex()
        assert not verify_anchor_binding(fake_proof, payload_hex, expected_epoch=1)


class TestVerifyFullChain:
    def test_valid_full_chain(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=7)
        payload_hex = result.op_return_payload.hex()
        for i, m in enumerate(sample_corpus):
            assert verify_full_chain(m, result.proofs[i], payload_hex, expected_epoch=7)

    def test_wrong_measurement_fails(self, sample_corpus, make_signed_measurement):
        result = batch_measurements(sample_corpus, epoch=1)
        payload_hex = result.op_return_payload.hex()
        wrong = make_signed_measurement(99)
        assert not verify_full_chain(wrong, result.proofs[0], payload_hex, expected_epoch=1)

    def test_wrong_epoch_fails(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=7)
        payload_hex = result.op_return_payload.hex()
        assert not verify_full_chain(sample_corpus[0], result.proofs[0], payload_hex, expected_epoch=99)

    def test_malformed_payload_fails(self, sample_corpus):
        result = batch_measurements(sample_corpus, epoch=1)
        assert not verify_full_chain(sample_corpus[0], result.proofs[0], "garbage", expected_epoch=1)


class TestBatchPartialArgs:
    def test_key_without_utxo_raises(self, sample_corpus, oracle_key):
        with pytest.raises(ValueError, match="both key and utxo"):
            batch_measurements(sample_corpus, epoch=1, key=oracle_key)

    def test_utxo_without_key_raises(self, sample_corpus):
        from veritas.anchor import Utxo
        utxo = Utxo(txid="aa" * 32, vout=0, value_sats=10000, pubkey_compressed=b"\x02" + b"\x00" * 32)
        with pytest.raises(ValueError, match="both key and utxo"):
            batch_measurements(sample_corpus, epoch=1, utxo=utxo)


class TestBatchOrdering:
    def test_different_order_different_root(self, make_signed_measurement):
        corpus = [make_signed_measurement(i) for i in range(4)]
        r1 = batch_measurements(corpus, epoch=1)
        r2 = batch_measurements(list(reversed(corpus)), epoch=1)
        assert r1.root != r2.root
