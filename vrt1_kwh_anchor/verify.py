"""Verification utilities for kWh anchor proofs."""

from __future__ import annotations

from veritas.anchor import parse_op_return_payload
from veritas.merkle import MerkleProof, verify_merkle_proof
from vrt1_kwh.attestation import SignedMeasurement, measurement_digest


def verify_kwh_inclusion(
    measurement: SignedMeasurement,
    proof: MerkleProof,
) -> bool:
    """Verify a kWh measurement is included in a Merkle batch.

    Checks:
    1. Measurement signature is valid
    2. Proof leaf matches measurement digest
    3. Merkle proof verifies against claimed root
    """
    if not measurement.verify():
        return False
    digest = measurement_digest(measurement.measurement)
    if digest != proof.leaf:
        return False
    return verify_merkle_proof(proof)


def verify_anchor_binding(
    proof: MerkleProof,
    op_return_payload_hex: str,
    expected_epoch: int,
) -> bool:
    """Verify a Merkle proof is bound to a Bitcoin anchor.

    Checks:
    1. OP_RETURN parses as valid VRT1 payload
    2. Root in payload matches proof root
    3. Leaf count matches proof size
    4. Epoch matches expected
    """
    payload = bytes.fromhex(op_return_payload_hex)
    parsed = parse_op_return_payload(payload)
    if parsed["merkle_root"] != proof.root:
        return False
    if parsed["leaf_count"] != proof.size:
        return False
    if parsed["epoch"] != expected_epoch:
        return False
    return True
