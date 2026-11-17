# attestinfer

**Verifiable Inference Attestations & Selective-Disclosure Blake3 Merkle Proofs.**

Cryptographically binds `(model_hash, policy_hash, prompt_merkle_root, output_hash)` into compact HMAC-SHA256 attestations and verifies prompt/policy chunk inclusion without disclosing private prompt segments.

## Quickstart
```sh
zig build test
zig build -Doptimize=ReleaseFast
./zig-out/bin/attestinfer bench
```
