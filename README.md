# attestinfer

**[Status](STATUS.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Issues](https://github.com/SMC17/attestinfer/issues)**

Tamper-evident receipts for a model call, in Zig 0.16. A receipt binds four hashes (model,
policy, a Merkle root over the prompt's chunks, and the output) and a timestamp under an
HMAC-SHA256 tag. Separately, any single prompt chunk can be revealed later with a Merkle
inclusion proof, without revealing the other chunks. A C API (`libattestinfer`) and a Python
`ctypes` wrapper are included.

Status: **unit-tested** (3 tests). This is a prototype.

## What it is, precisely

- **Integrity between parties who share a key.** If you and the verifier both hold the
  32-byte key, a valid tag shows the four hashes and the timestamp were not changed after
  tagging, by anyone without the key.
- **Selective disclosure by salted commitment.** Each chunk is hashed with a 16-byte salt
  (Blake3), and the chunk hashes form a Merkle tree. To disclose one chunk, you reveal the
  chunk, its salt and its sibling path. The other chunks stay hidden behind their salted
  hashes.

## What it is not

- **Not publicly verifiable.** HMAC is symmetric: anyone who can verify a tag can also forge
  one. A third party gets no assurance from it. That needs a signature, such as Ed25519, with a
  published public key ([#2](https://github.com/SMC17/attestinfer/issues/2)).
- **Not zero-knowledge**, despite the file name `zk_infer_receipt.zig`. Disclosure reveals the
  chunk itself.
- **Not enclave-backed.** `enclave_key` is just a byte array the caller passes in. The `bench`
  CLI uses a built-in constant key.
- **It does not prove the model produced the output.** It records hashes that whoever holds the
  key chose to tag.
- The timestamp is tagged as host-endian bytes of an `i128`, so tags are not portable between
  big- and little-endian hosts.

## Build

```sh
# Zig 0.16.0
zig build test --summary all      # 3/3
zig build -Doptimize=ReleaseFast
./zig-out/bin/attestinfer bench
python3 python/attestinfer.py     # ctypes round trip against zig-out/lib
```

## Measured

Apple M2 Max, macOS 26.4, Zig 0.16.0 ReleaseFast, commit `e5b1862`, 2026-11-19:
`attestinfer bench` reports ~430–450 ns per tag-and-verify round trip, over a fixed
15-byte output.

## License

MIT
