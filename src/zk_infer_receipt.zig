const std = @import("std");

/// Verifiable Inference Attestation & Selective-Disclosure Merkle Proof Kernel.
/// Cryptographically binds `(model_hash, policy_hash, prompt_commitment, output_hash)`
/// into a compact attestation and allows proving a prompt/output span commitment
/// via a Blake3 Merkle inclusion proof without revealing the full private prompt.
pub const Hash256 = [32]u8;

pub const InferenceAttestation = struct {
    model_hash: Hash256,
    policy_hash: Hash256,
    prompt_merkle_root: Hash256,
    output_hash: Hash256,
    timestamp_ns: i128,
    attestation_mac: [32]u8,
};

pub const MerkleStep = struct {
    sibling: Hash256,
    is_left: bool,
};

pub fn hashChunk(chunk: []const u8, salt: [16]u8) Hash256 {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(&salt);
    h.update(chunk);
    var out: Hash256 = undefined;
    h.final(&out);
    return out;
}

pub fn merkleParent(left: Hash256, right: Hash256) Hash256 {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(&.{0x01});
    h.update(&left);
    h.update(&right);
    var out: Hash256 = undefined;
    h.final(&out);
    return out;
}

pub fn buildMerkleRoot(allocator: std.mem.Allocator, leaves: []const Hash256) !Hash256 {
    if (leaves.len == 0) return [_]u8{0} ** 32;
    var level = try allocator.dupe(Hash256, leaves);
    defer allocator.free(level);

    var n = level.len;
    while (n > 1) {
        var next_n: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 2) {
            if (i + 1 < n) {
                level[next_n] = merkleParent(level[i], level[i + 1]);
            } else {
                level[next_n] = level[i];
            }
            next_n += 1;
        }
        n = next_n;
    }
    return level[0];
}

pub fn verifyInclusion(leaf: Hash256, proof: []const MerkleStep, expected_root: Hash256) bool {
    var cur = leaf;
    for (proof) |step| {
        cur = if (step.is_left) merkleParent(step.sibling, cur) else merkleParent(cur, step.sibling);
    }
    return std.mem.eql(u8, &cur, &expected_root);
}

pub fn signAttestation(
    model_hash: Hash256,
    policy_hash: Hash256,
    prompt_merkle_root: Hash256,
    output_bytes: []const u8,
    timestamp_ns: i128,
    enclave_key: [32]u8,
) InferenceAttestation {
    var out_hash: Hash256 = undefined;
    std.crypto.hash.Blake3.hash(output_bytes, &out_hash, .{});

    var mac_ctx = std.crypto.auth.hmac.sha2.HmacSha256.init(&enclave_key);
    mac_ctx.update(&model_hash);
    mac_ctx.update(&policy_hash);
    mac_ctx.update(&prompt_merkle_root);
    mac_ctx.update(&out_hash);
    mac_ctx.update(std.mem.asBytes(&timestamp_ns));
    var mac: [32]u8 = undefined;
    mac_ctx.final(&mac);

    return .{
        .model_hash = model_hash,
        .policy_hash = policy_hash,
        .prompt_merkle_root = prompt_merkle_root,
        .output_hash = out_hash,
        .timestamp_ns = timestamp_ns,
        .attestation_mac = mac,
    };
}

pub fn verifyAttestation(att: InferenceAttestation, enclave_key: [32]u8) bool {
    var mac_ctx = std.crypto.auth.hmac.sha2.HmacSha256.init(&enclave_key);
    mac_ctx.update(&att.model_hash);
    mac_ctx.update(&att.policy_hash);
    mac_ctx.update(&att.prompt_merkle_root);
    mac_ctx.update(&att.output_hash);
    mac_ctx.update(std.mem.asBytes(&att.timestamp_ns));
    var expected: [32]u8 = undefined;
    mac_ctx.final(&expected);
    return std.crypto.timing_safe.eql([32]u8, att.attestation_mac, expected);
}

test "zk_infer_receipt attests model/policy/output and verifies selective-disclosure Merkle proof" {
    const alloc = std.testing.allocator;
    const salt = [_]u8{0x11} ** 16;
    const leaves = [_]Hash256{
        hashChunk("system: obey policy", salt),
        hashChunk("secret_user_context", salt),
    };
    const root = try buildMerkleRoot(alloc, &leaves);
    const key = [_]u8{0xAB} ** 32;
    const model_h = [_]u8{0x01} ** 32;
    const policy_h = [_]u8{0x02} ** 32;

    const att = signAttestation(model_h, policy_h, root, "verified response", 12345, key);
    try std.testing.expect(verifyAttestation(att, key));

    // Prove chunk 0 was committed in `prompt_merkle_root` without revealing chunk 1 plaintext
    const proof = [_]MerkleStep{.{ .sibling = leaves[1], .is_left = false }};
    try std.testing.expect(verifyInclusion(leaves[0], &proof, att.prompt_merkle_root));
}
