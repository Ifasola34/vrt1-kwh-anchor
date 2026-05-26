"""Nostr checkpoint event for kWh batches."""

from __future__ import annotations

from veritas.crypto import OracleKey
from veritas.nostr import NostrEvent, build_checkpoint_event

from .batch import BatchResult


def build_kwh_checkpoint(
    batch: BatchResult,
    *,
    key: OracleKey,
    ts: int | None = None,
) -> NostrEvent:
    """Create a signed Nostr checkpoint event for a kWh batch.

    Wraps the standard VRT1 checkpoint builder with kWh batch data.
    """
    anchor_txid = batch.anchor_tx.txid if batch.anchor_tx else None
    return build_checkpoint_event(
        key=key,
        epoch=batch.epoch,
        merkle_root_hex=batch.root_hex,
        leaf_count=batch.leaf_count,
        anchor_txid=anchor_txid,
        ts=ts,
    )
