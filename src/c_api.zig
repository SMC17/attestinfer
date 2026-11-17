const std = @import("std");
const zk = @import("zk_infer_receipt.zig");

export fn attestinfer_sign(
    model_hash: *const [32]u8,
    policy_hash: *const [32]u8,
    prompt_root: *const [32]u8,
    output_ptr: ?[*]const u8,
    output_len: usize,
    timestamp_ns: i64,
    enclave_key: *const [32]u8,
    out_output_hash: *[32]u8,
    out_mac: *[32]u8,
) callconv(.c) i32 {
    const output_slice: []const u8 = if (output_len == 0)
        ""
    else if (output_ptr) |p|
        p[0..output_len]
    else
        return -1;

    const att = zk.signAttestation(
        model_hash.*,
        policy_hash.*,
        prompt_root.*,
        output_slice,
        @as(i128, timestamp_ns),
        enclave_key.*,
    );
    out_output_hash.* = att.output_hash;
    out_mac.* = att.attestation_mac;
    return 0;
}

export fn attestinfer_verify(
    model_hash: *const [32]u8,
    policy_hash: *const [32]u8,
    prompt_root: *const [32]u8,
    output_ptr: ?[*]const u8,
    output_len: usize,
    timestamp_ns: i64,
    enclave_key: *const [32]u8,
    mac: *const [32]u8,
) callconv(.c) i32 {
    const output_slice: []const u8 = if (output_len == 0)
        ""
    else if (output_ptr) |p|
        p[0..output_len]
    else
        return -1;

    var out_hash: zk.Hash256 = undefined;
    std.crypto.hash.Blake3.hash(output_slice, &out_hash, .{});

    const att = zk.InferenceAttestation{
        .model_hash = model_hash.*,
        .policy_hash = policy_hash.*,
        .prompt_merkle_root = prompt_root.*,
        .output_hash = out_hash,
        .timestamp_ns = @as(i128, timestamp_ns),
        .attestation_mac = mac.*,
    };
    return if (zk.verifyAttestation(att, enclave_key.*)) 1 else 0;
}

test "c_api sign and verify roundtrip" {
    const model_h = [_]u8{0x01} ** 32;
    const policy_h = [_]u8{0x02} ** 32;
    const root_h = [_]u8{0x03} ** 32;
    const key = [_]u8{0xAB} ** 32;
    const msg = "verified inference output";

    var out_hash: [32]u8 = undefined;
    var mac: [32]u8 = undefined;
    const rc = attestinfer_sign(&model_h, &policy_h, &root_h, msg.ptr, msg.len, 99999, &key, &out_hash, &mac);
    try std.testing.expectEqual(@as(i32, 0), rc);

    const ok = attestinfer_verify(&model_h, &policy_h, &root_h, msg.ptr, msg.len, 99999, &key, &mac);
    try std.testing.expectEqual(@as(i32, 1), ok);

    const bad_msg = "tampered inference output";
    const bad = attestinfer_verify(&model_h, &policy_h, &root_h, bad_msg.ptr, bad_msg.len, 99999, &key, &mac);
    try std.testing.expectEqual(@as(i32, 0), bad);
}
