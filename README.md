# attestinfer

**[Status](STATUS.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Issues](https://github.com/SMC17/attestinfer/issues)**

Signed receipts for a model call, in Zig 0.16. A receipt binds five fields:
- the model hash;
- the policy hash;
- a Merkle root over the prompt's salted chunks;
- the Blake3 hash of the output;
- a timestamp.

Any one prompt chunk can be revealed later with a Merkle inclusion proof, and the rest stay
hidden. Zig library, CLI, C API (`libattestinfer`) and Python `ctypes` wrapper.

Status: **unit-tested** (8 Zig tests, plus a Python round trip). This is a prototype.

## Two modes

| Mode | Who can verify | Who can forge | Use when |
| --- | --- | --- | --- |
| **Ed25519** (`signEd25519` / `verifyEd25519`, the CLI) | anyone with the public key | only the holder of the secret seed | a third party must be able to check the receipt |
| HMAC-SHA256 (`signAttestation` / `verifyAttestation`, library and C API only) | holders of the shared key | **any** holder of the shared key | both sides already share a secret and trust each other |

`verifyEd25519` takes the public key you trust as an argument. It never trusts the key that
travels inside the receipt.

## What it is not

- **Not zero-knowledge.** A disclosed chunk is revealed in full, together with its salt and its
  sibling path. The old module name `zk_infer_receipt` survives only as an alias for existing
  imports.
- **Not proof that a model produced the output.** A receipt records what its signer chose to
  sign. Binding it to real execution needs something else, such as hardware attestation.
- **Not enclave-backed.** Nothing here runs in a TEE.

## Use it

```sh
# Zig 0.16.0
zig build test --summary all     # 8/8
zig build -Doptimize=ReleaseFast
B=./zig-out/bin/attestinfer
$B keygen signer.seed            # writes a 0600 seed file (refuses to overwrite); prints the public key
$B sign signer.seed <model_hex> <policy_hex> <prompt_root_hex> "the output"
# {"model_hash":…,"timestamp_ns":…,"public_key":…,"signature":…}
$B verify <public_key_hex> <model_hex> <policy_hex> <prompt_root_hex> "the output" <timestamp_ns> <signature_hex>
# {"valid":true}   (exit 1 and {"valid":false} if any field or the key is wrong)
python3 python/attestinfer.py    # ctypes round trip for both modes
```

Library: `hashChunk(chunk, salt)`, `buildMerkleRoot(alloc, leaves)`,
`merkleProof(alloc, leaves, index)` and `verifyInclusion(leaf, proof, root)`. Leaves are hashed
as `Blake3(0x00 ‖ salt ‖ chunk)` and inner nodes as `Blake3(0x01 ‖ left ‖ right)`, so a leaf
can never be passed off as an inner node. The signed bytes (`receiptMessage`) start with a
version tag, and the timestamp is little-endian on every host.

## Changed on 2026-11-19 ([#2](https://github.com/SMC17/attestinfer/issues/2))

- Added Ed25519 receipts, so third parties can verify. Before, there was only HMAC.
- The CLI no longer has a built-in key. Before, `sign` and `verify` both used the constant
  `0xAB…`, so anyone could forge a CLI receipt.
- The timestamp is encoded as fixed little-endian. Before, it was host-endian.
- Leaves now get a `0x00` domain prefix. **Roots and receipts from v0.1.0 do not verify under
  this version.**
- `merkleProof` is new; before, proofs could be verified but not produced.

## Measured

Apple M2 Max, macOS 26.4, Zig 0.16.0 ReleaseFast, 2026-11-19, `attestinfer bench`, three runs:

| What | Result |
| --- | ---: |
| HMAC tag + verify (5,000 rounds) | 422–439 ns |
| Ed25519 sign (2,000 rounds) | ~42.7 µs |
| Ed25519 verify (2,000 rounds) | ~47 µs |

## License

MIT
