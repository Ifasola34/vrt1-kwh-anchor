# vrt1-kwh-anchor

Batch kWh attestations from [vrt1-kwh](https://github.com/Ifasola34/vrt1-kwh) through the [VRT1](https://github.com/Ifasola34/vrt1-spec) Merkle/Bitcoin-anchor pipeline.

## What it does

Takes a corpus of signed kWh measurements and:

1. Computes a Merkle tree from their digests (SHA-256d with leaf/internal prefixes)
2. Generates inclusion proofs for every measurement
3. Builds a 49-byte OP_RETURN payload ready for Bitcoin anchoring
4. Optionally builds and signs an anchor transaction
5. Creates a Nostr kind-30079 checkpoint event binding epoch, root, and leaf count

After anchoring, any measurement can independently prove its inclusion via its Merkle proof + the on-chain root.

## Usage

```python
from veritas.crypto import OracleKey
from vrt1_kwh_anchor import batch_measurements, build_kwh_checkpoint
from vrt1_kwh.oracle import load_corpus

key = OracleKey.from_hex("...")
corpus = load_corpus(Path("./kwh-data"))

batch = batch_measurements(corpus, epoch=1)
# batch.root_hex          — Merkle root
# batch.proofs[i]         — inclusion proof for measurement i
# batch.op_return_payload — 49-byte anchor payload

checkpoint = build_kwh_checkpoint(batch, key=key)
# checkpoint.id, checkpoint.sig — signed Nostr event
```

### Verify inclusion

```python
from vrt1_kwh_anchor.verify import verify_kwh_inclusion, verify_anchor_binding

assert verify_kwh_inclusion(corpus[0], batch.proofs[0])
assert verify_anchor_binding(batch.proofs[0], batch.op_return_payload.hex(), expected_epoch=1)
```

## Install

```
pip install git+https://github.com/Ifasola34/vrt1-kwh-anchor.git
```

## License

MIT
