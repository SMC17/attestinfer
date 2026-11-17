"""Python ctypes wrapper for libattestinfer."""

from __future__ import annotations

import ctypes
import platform
from pathlib import Path
from typing import Tuple


def _find_lib_path() -> Path:
    root = Path(__file__).resolve().parent.parent
    ext = "dylib" if platform.system() == "Darwin" else "so"
    lib_path = root / "zig-out" / "lib" / f"libattestinfer.{ext}"
    if not lib_path.exists():
        raise FileNotFoundError(
            f"libattestinfer not found at {lib_path}; run `zig build -Doptimize=ReleaseFast` first."
        )
    return lib_path


_lib = ctypes.CDLL(str(_find_lib_path()))

_c_u8_p = ctypes.POINTER(ctypes.c_uint8)

_lib.attestinfer_sign.argtypes = [
    _c_u8_p,  # model_hash[32]
    _c_u8_p,  # policy_hash[32]
    _c_u8_p,  # prompt_root[32]
    ctypes.c_char_p,  # output_ptr
    ctypes.c_size_t,  # output_len
    ctypes.c_int64,  # timestamp_ns
    _c_u8_p,  # enclave_key[32]
    _c_u8_p,  # out_output_hash[32]
    _c_u8_p,  # out_mac[32]
]
_lib.attestinfer_sign.restype = ctypes.c_int32

_lib.attestinfer_verify.argtypes = [
    _c_u8_p,  # model_hash[32]
    _c_u8_p,  # policy_hash[32]
    _c_u8_p,  # prompt_root[32]
    ctypes.c_char_p,  # output_ptr
    ctypes.c_size_t,  # output_len
    ctypes.c_int64,  # timestamp_ns
    _c_u8_p,  # enclave_key[32]
    _c_u8_p,  # mac[32]
]
_lib.attestinfer_verify.restype = ctypes.c_int32


def _to_buf32(data: bytes, name: str) -> ctypes.Array[ctypes.c_uint8]:
    if len(data) != 32:
        raise ValueError(f"{name} must be 32 bytes, got {len(data)}")
    return (ctypes.c_uint8 * 32).from_buffer_copy(data)


def sign_attestation(
    model_hash: bytes,
    policy_hash: bytes,
    prompt_root: bytes,
    output: bytes,
    timestamp_ns: int,
    enclave_key: bytes,
) -> Tuple[bytes, bytes]:
    """Sign an inference attestation; returns (output_hash, attestation_mac)."""
    out_hash = (ctypes.c_uint8 * 32)()
    out_mac = (ctypes.c_uint8 * 32)()
    rc = _lib.attestinfer_sign(
        _to_buf32(model_hash, "model_hash"),
        _to_buf32(policy_hash, "policy_hash"),
        _to_buf32(prompt_root, "prompt_root"),
        output,
        len(output),
        timestamp_ns,
        _to_buf32(enclave_key, "enclave_key"),
        out_hash,
        out_mac,
    )
    if rc != 0:
        raise RuntimeError(f"attestinfer_sign failed with code {rc}")
    return bytes(out_hash), bytes(out_mac)


def verify_attestation(
    model_hash: bytes,
    policy_hash: bytes,
    prompt_root: bytes,
    output: bytes,
    timestamp_ns: int,
    enclave_key: bytes,
    mac: bytes,
) -> bool:
    """Verify an inference attestation MAC."""
    rc = _lib.attestinfer_verify(
        _to_buf32(model_hash, "model_hash"),
        _to_buf32(policy_hash, "policy_hash"),
        _to_buf32(prompt_root, "prompt_root"),
        output,
        len(output),
        timestamp_ns,
        _to_buf32(enclave_key, "enclave_key"),
        _to_buf32(mac, "mac"),
    )
    if rc < 0:
        raise RuntimeError(f"attestinfer_verify failed with code {rc}")
    return rc == 1


if __name__ == "__main__":
    model_h = b"\x01" * 32
    policy_h = b"\x02" * 32
    prompt_r = b"\x03" * 32
    key = b"\xab" * 32
    output_bytes = b"verified inference output"
    ts = 1700000000000000000

    out_h, mac = sign_attestation(model_h, policy_h, prompt_r, output_bytes, ts, key)
    valid = verify_attestation(model_h, policy_h, prompt_r, output_bytes, ts, key, mac)
    tampered = verify_attestation(model_h, policy_h, prompt_r, b"tampered", ts, key, mac)
    assert valid is True, "expected valid attestation"
    assert tampered is False, "expected tampered attestation to fail"
    print(f"attestinfer.py ok: output_hash={out_h.hex()[:16]}... valid={valid} tampered={tampered}")
