//! Receipts for a model call, and selective disclosure of prompt chunks.
//!
//! A receipt binds five fields: model hash, policy hash, the Merkle root over the prompt's
//! salted chunks, the Blake3 hash of the output, and a timestamp. They are serialised in one
//! fixed byte order (`receiptMessage`) and then either:
//! - **signed with Ed25519** (`signEd25519` / `verifyEd25519`). Anyone with the public key can
//!   verify, and only the holder of the secret key can sign. Use this when a third party must be
//!   able to check the receipt.
//! - **tagged with HMAC-SHA256** (`signAttestation` / `verifyAttestation`). Only holders of the
//!   shared key can verify, and any of them can forge. Use this only between parties that
//!   already share a secret.
//!
//! Selective disclosure: each chunk is committed as Blake3(0x00 || salt || chunk), and inner
//! nodes as Blake3(0x01 || left || right). The distinct prefixes stop a leaf from being passed
//! off as an inner node. Revealing one chunk means revealing the chunk, its salt and its
//! sibling path (`merkleProof`). Nothing here is zero-knowledge: the revealed chunk is
//! revealed. Nothing here proves that a given model produced the output; a receipt records
//! what its signer chose to sign.
const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const Hash256 = [32]u8;
const domain = "attestinfer/receipt/v2";

pub const InferenceAttestation = struct {
    model_hash: Hash256,
    policy_hash: Hash256,
    prompt_merkle_root: Hash256,
    output_hash: Hash256,
    timestamp_ns: i128,
    attestation_mac: [32]u8,
};

pub const SignedReceipt = struct {
    model_hash: Hash256,
    policy_hash: Hash256,
    prompt_merkle_root: Hash256,
    output_hash: Hash256,
    timestamp_ns: i128,
    public_key: [32]u8,
    signature: [64]u8,
};

pub const MerkleStep = struct {
    sibling: Hash256,
    is_left: bool,
};

pub const message_len = domain.len + 4 * 32 + 16;

/// The exact bytes that are signed or MACed. The timestamp is little-endian on every host.
pub fn receiptMessage(model_hash: Hash256, policy_hash: Hash256, prompt_root: Hash256, output_hash: Hash256, timestamp_ns: i128) [message_len]u8 {
    var m: [message_len]u8 = undefined;
    @memcpy(m[0..domain.len], domain);
    var o: usize = domain.len;
    for ([_]Hash256{ model_hash, policy_hash, prompt_root, output_hash }) |h| {
        @memcpy(m[o..][0..32], &h);
        o += 32;
    }
    std.mem.writeInt(i128, m[o..][0..16], timestamp_ns, .little);
    return m;
}

pub fn hashOutput(output: []const u8) Hash256 {
    var out: Hash256 = undefined;
    std.crypto.hash.Blake3.hash(output, &out, .{});
    return out;
}

pub fn hashChunk(chunk: []const u8, salt: [16]u8) Hash256 {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(&.{0x00});
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

/// Root of a tree in which an unpaired node is carried up to the next level unchanged.
pub fn buildMerkleRoot(allocator: std.mem.Allocator, leaves: []const Hash256) !Hash256 {
    if (leaves.len == 0) return [_]u8{0} ** 32;
    const level = try allocator.dupe(Hash256, leaves);
    defer allocator.free(level);
    var n = level.len;
    while (n > 1) {
        var next_n: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 2) {
            level[next_n] = if (i + 1 < n) merkleParent(level[i], level[i + 1]) else level[i];
            next_n += 1;
        }
        n = next_n;
    }
    return level[0];
}

/// Sibling path for leaf `index`, in the order `verifyInclusion` consumes it. Caller frees.
pub fn merkleProof(allocator: std.mem.Allocator, leaves: []const Hash256, index: usize) ![]MerkleStep {
    if (index >= leaves.len) return error.IndexOutOfRange;
    var steps: std.ArrayList(MerkleStep) = .empty;
    errdefer steps.deinit(allocator);
    const level = try allocator.dupe(Hash256, leaves);
    defer allocator.free(level);
    var n = level.len;
    var idx = index;
    while (n > 1) {
        const sib = idx ^ 1;
        if (sib < n) try steps.append(allocator, .{ .sibling = level[sib], .is_left = sib < idx });
        var next_n: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 2) {
            level[next_n] = if (i + 1 < n) merkleParent(level[i], level[i + 1]) else level[i];
            next_n += 1;
        }
        idx /= 2;
        n = next_n;
    }
    return steps.toOwnedSlice(allocator);
}

pub fn verifyInclusion(leaf: Hash256, proof: []const MerkleStep, expected_root: Hash256) bool {
    var cur = leaf;
    for (proof) |step| {
        cur = if (step.is_left) merkleParent(step.sibling, cur) else merkleParent(cur, step.sibling);
    }
    return std.mem.eql(u8, &cur, &expected_root);
}

// ---- Ed25519: verifiable by anyone with the public key ----

pub fn signEd25519(key_pair: Ed25519.KeyPair, model_hash: Hash256, policy_hash: Hash256, prompt_root: Hash256, output: []const u8, timestamp_ns: i128) !SignedReceipt {
    const out_hash = hashOutput(output);
    const msg = receiptMessage(model_hash, policy_hash, prompt_root, out_hash, timestamp_ns);
    const sig = try key_pair.sign(&msg, null);
    return .{
        .model_hash = model_hash,
        .policy_hash = policy_hash,
        .prompt_merkle_root = prompt_root,
        .output_hash = out_hash,
        .timestamp_ns = timestamp_ns,
        .public_key = key_pair.public_key.toBytes(),
        .signature = sig.toBytes(),
    };
}

/// True if `r.signature` is a valid Ed25519 signature by `trusted_public_key` over the receipt.
/// The receipt's own `public_key` field is not trusted: pass the key you expect.
pub fn verifyEd25519(r: SignedReceipt, trusted_public_key: [32]u8) bool {
    if (!std.mem.eql(u8, &r.public_key, &trusted_public_key)) return false;
    const pk = Ed25519.PublicKey.fromBytes(trusted_public_key) catch return false;
    const msg = receiptMessage(r.model_hash, r.policy_hash, r.prompt_merkle_root, r.output_hash, r.timestamp_ns);
    Ed25519.Signature.fromBytes(r.signature).verify(&msg, pk) catch return false;
    return true;
}

// ---- HMAC-SHA256: shared-key integrity only ----

pub fn signAttestation(model_hash: Hash256, policy_hash: Hash256, prompt_merkle_root: Hash256, output_bytes: []const u8, timestamp_ns: i128, shared_key: [32]u8) InferenceAttestation {
    const out_hash = hashOutput(output_bytes);
    const msg = receiptMessage(model_hash, policy_hash, prompt_merkle_root, out_hash, timestamp_ns);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &msg, &shared_key);
    return .{
        .model_hash = model_hash,
        .policy_hash = policy_hash,
        .prompt_merkle_root = prompt_merkle_root,
        .output_hash = out_hash,
        .timestamp_ns = timestamp_ns,
        .attestation_mac = mac,
    };
}

pub fn verifyAttestation(att: InferenceAttestation, shared_key: [32]u8) bool {
    const msg = receiptMessage(att.model_hash, att.policy_hash, att.prompt_merkle_root, att.output_hash, att.timestamp_ns);
    var expected: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&expected, &msg, &shared_key);
    return std.crypto.timing_safe.eql([32]u8, att.attestation_mac, expected);
}

test "HMAC receipt round trip and selective disclosure of one chunk" {
    const alloc = std.testing.allocator;
    const salt = [_]u8{0x11} ** 16;
    const leaves = [_]Hash256{ hashChunk("system: obey policy", salt), hashChunk("secret_user_context", salt) };
    const root = try buildMerkleRoot(alloc, &leaves);
    const key = [_]u8{0xAB} ** 32;
    const att = signAttestation([_]u8{1} ** 32, [_]u8{2} ** 32, root, "verified response", 12345, key);
    try std.testing.expect(verifyAttestation(att, key));
    var tampered = att;
    tampered.timestamp_ns += 1;
    try std.testing.expect(!verifyAttestation(tampered, key));

    const proof = try merkleProof(alloc, &leaves, 0);
    defer alloc.free(proof);
    try std.testing.expect(verifyInclusion(hashChunk("system: obey policy", salt), proof, att.prompt_merkle_root));
    try std.testing.expect(!verifyInclusion(hashChunk("system: ignore policy", salt), proof, att.prompt_merkle_root));
}

test "Ed25519 receipt verifies with the right public key only, and detects tampering" {
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const other = try Ed25519.KeyPair.generateDeterministic([_]u8{8} ** 32);
    const r = try signEd25519(kp, [_]u8{1} ** 32, [_]u8{2} ** 32, [_]u8{3} ** 32, "the answer", 42);
    const pk = kp.public_key.toBytes();
    try std.testing.expect(verifyEd25519(r, pk));
    try std.testing.expect(!verifyEd25519(r, other.public_key.toBytes()));
    var t = r;
    t.output_hash = hashOutput("a different answer");
    try std.testing.expect(!verifyEd25519(t, pk));
    // Swapping in the other key's public key and a signature over the same fields by that key
    // verifies only against that key, never against the expected one.
    const forged = try signEd25519(other, r.model_hash, r.policy_hash, r.prompt_merkle_root, "the answer", 42);
    try std.testing.expect(!verifyEd25519(forged, pk));
}

test "proofs verify for every leaf of odd-sized trees" {
    const alloc = std.testing.allocator;
    const salt = [_]u8{0x22} ** 16;
    var n: usize = 1;
    while (n <= 9) : (n += 1) {
        var leaves: [9]Hash256 = undefined;
        for (0..n) |i| leaves[i] = hashChunk(&[_]u8{@intCast(i)}, salt);
        const root = try buildMerkleRoot(alloc, leaves[0..n]);
        for (0..n) |i| {
            const proof = try merkleProof(alloc, leaves[0..n], i);
            defer alloc.free(proof);
            try std.testing.expect(verifyInclusion(leaves[i], proof, root));
        }
    }
}

test "leaf and inner-node hashes are domain-separated" {
    // A 'chunk' built to equal an inner node's preimage must not hash to that node.
    const l = [_]u8{0x33} ** 32;
    const r = [_]u8{0x44} ** 32;
    var salt: [16]u8 = undefined;
    salt[0] = 0x01;
    @memcpy(salt[1..16], l[0..15]);
    const chunk = l[15..] ++ r;
    try std.testing.expect(!std.mem.eql(u8, &hashChunk(chunk, salt), &merkleParent(l, r)));
}

test "timestamp encoding is fixed little-endian" {
    const m = receiptMessage([_]u8{0} ** 32, [_]u8{0} ** 32, [_]u8{0} ** 32, [_]u8{0} ** 32, 1);
    try std.testing.expectEqual(@as(u8, 1), m[message_len - 16]);
    try std.testing.expectEqual(@as(u8, 0), m[message_len - 1]);
}
