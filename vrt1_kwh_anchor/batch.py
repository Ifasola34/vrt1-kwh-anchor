"""Core batching: kWh measurements → Merkle tree → anchor-ready artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from veritas.anchor import AnchorTx, Utxo, build_anchor_tx, build_op_return_payload
from veritas.crypto import OracleKey, derive_anchor_key
from veritas.merkle import MerkleProof, MerkleTree
from vrt1_kwh.attestation import SignedMeasurement, measurement_digest
from vrt1_kwh.oracle import load_corpus


@dataclass(frozen=True)
class BatchResult:
    epoch: int
    root: bytes
    leaf_count: int
    digests: list[bytes]
    proofs: list[MerkleProof]
    op_return_payload: bytes
    anchor_tx: AnchorTx | None = None

    @property
    def root_hex(self) -> str:
        return self.root.hex()


def batch_measurements(
    measurements: list[SignedMeasurement],
    *,
    epoch: int,
    key: OracleKey | None = None,
    utxo: Utxo | None = None,
    fee_sats: int = 500,
) -> BatchResult:
    """Batch signed kWh measurements into a Merkle tree with optional Bitcoin anchor.

    All measurements must have valid signatures — invalid ones are rejected.
    """
    if not measurements:
        raise ValueError("cannot batch empty measurement list")

    if bool(key) != bool(utxo):
        raise ValueError("both key and utxo must be provided for anchor construction, or neither")

    invalid = [m for m in measurements if not m.verify()]
    if invalid:
        raise ValueError(f"{len(invalid)} measurement(s) have invalid signatures")

    digests = [measurement_digest(m.measurement) for m in measurements]
    tree = MerkleTree(digests)

    proofs = [tree.prove(i) for i in range(len(digests))]

    payload = build_op_return_payload(
        merkle_root=tree.root,
        epoch=epoch,
        leaf_count=len(digests),
    )

    anchor_tx = None
    if key and utxo:
        anchor_privkey = derive_anchor_key(key)
        anchor_tx = build_anchor_tx(
            utxo=utxo,
            privkey=anchor_privkey,
            merkle_root=tree.root,
            epoch=epoch,
            leaf_count=len(digests),
            fee_sats=fee_sats,
        )

    return BatchResult(
        epoch=epoch,
        root=tree.root,
        leaf_count=len(digests),
        digests=digests,
        proofs=proofs,
        op_return_payload=payload,
        anchor_tx=anchor_tx,
    )


def batch_from_directory(
    data_dir: Path,
    *,
    epoch: int,
    key: OracleKey | None = None,
    utxo: Utxo | None = None,
    fee_sats: int = 500,
) -> BatchResult:
    """Load a kWh oracle's output directory and batch all measurements.

    Raises ValueError if any files fail to parse (no silent data loss).
    """
    corpus, errors = load_corpus(data_dir, return_errors=True)
    if errors:
        raise ValueError(f"{len(errors)} file(s) failed to parse in {data_dir}")
    if not corpus:
        raise ValueError(f"no measurements found in {data_dir}")
    return batch_measurements(
        corpus,
        epoch=epoch,
        key=key,
        utxo=utxo,
        fee_sats=fee_sats,
    )
