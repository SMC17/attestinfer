//! attestinfer CLI: Ed25519-signed receipts for a model call, verifiable by anyone with the
//! public key. The HMAC (shared-key) mode is library and C API only: a CLI with a shared key
//! would need that key on every verifier, and every verifier could then forge.
const std = @import("std");
pub const receipt = @import("receipt.zig");
/// Deprecated name kept for existing imports. Nothing in this module is zero-knowledge.
pub const zk_infer_receipt = receipt;
pub const c_api = @import("c_api.zig");
const Ed25519 = std.crypto.sign.Ed25519;

const usage =
    \\attestinfer — signed receipts for a model call, with selective disclosure of prompt chunks
    \\
    \\Usage:
    \\  attestinfer keygen <secret_key_file>          write a new Ed25519 seed (hex, mode 0600); print the public key
    \\  attestinfer pubkey <secret_key_file>          print the public key for a seed file
    \\  attestinfer sign <secret_key_file> <model_hex> <policy_hex> <prompt_root_hex> <output_text>
    \\  attestinfer verify <public_key_hex> <model_hex> <policy_hex> <prompt_root_hex> <output_text> <timestamp_ns> <signature_hex>
    \\  attestinfer bench
    \\
;

fn parseHex(comptime n: usize, hex: []const u8) ![n]u8 {
    if (hex.len != 2 * n) return error.InvalidHexLength;
    var out: [n]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

fn loadKeyPair(io: std.Io, alloc: std.mem.Allocator, path: []const u8) !Ed25519.KeyPair {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(4096));
    const seed = try parseHex(32, std.mem.trim(u8, raw, " \t\r\n"));
    return Ed25519.KeyPair.generateDeterministic(seed);
}

pub fn main(init: std.process.Init) !u8 {
    const alloc = init.arena.allocator();
    const io = init.io;
    const stdout = std.Io.File.stdout();
    const args = try init.minimal.args.toSlice(alloc);
    var buf: [1024]u8 = undefined;

    if (args.len >= 3 and std.mem.eql(u8, args[1], "keygen")) {
        const kp = Ed25519.KeyPair.generate(io);
        const seed_hex = std.fmt.bytesToHex(kp.secret_key.seed(), .lower);
        const f = try std.Io.Dir.cwd().createFile(io, args[2], .{ .exclusive = true, .permissions = .fromMode(0o600) });
        defer f.close(io);
        try f.writeStreamingAll(io, &seed_hex);
        try f.writeStreamingAll(io, "\n");
        try stdout.writeStreamingAll(io, try std.fmt.bufPrint(&buf, "{{\"public_key\":\"{s}\"}}\n", .{std.fmt.bytesToHex(kp.public_key.toBytes(), .lower)}));
        return 0;
    }
    if (args.len >= 3 and std.mem.eql(u8, args[1], "pubkey")) {
        const kp = try loadKeyPair(io, alloc, args[2]);
        try stdout.writeStreamingAll(io, try std.fmt.bufPrint(&buf, "{s}\n", .{std.fmt.bytesToHex(kp.public_key.toBytes(), .lower)}));
        return 0;
    }
    if (args.len >= 7 and std.mem.eql(u8, args[1], "sign")) {
        const kp = try loadKeyPair(io, alloc, args[2]);
        const ts: i128 = std.Io.Clock.real.now(io).nanoseconds;
        const r = try receipt.signEd25519(kp, try parseHex(32, args[3]), try parseHex(32, args[4]), try parseHex(32, args[5]), args[6], ts);
        try stdout.writeStreamingAll(io, try std.fmt.bufPrint(&buf,
            "{{\"model_hash\":\"{s}\",\"policy_hash\":\"{s}\",\"prompt_merkle_root\":\"{s}\",\"output_hash\":\"{s}\",\"timestamp_ns\":{d},\"public_key\":\"{s}\",\"signature\":\"{s}\"}}\n",
            .{
                std.fmt.bytesToHex(r.model_hash, .lower),
                std.fmt.bytesToHex(r.policy_hash, .lower),
                std.fmt.bytesToHex(r.prompt_merkle_root, .lower),
                std.fmt.bytesToHex(r.output_hash, .lower),
                r.timestamp_ns,
                std.fmt.bytesToHex(r.public_key, .lower),
                std.fmt.bytesToHex(r.signature, .lower),
            }));
        return 0;
    }
    if (args.len >= 9 and std.mem.eql(u8, args[1], "verify")) {
        const pk = try parseHex(32, args[2]);
        const r = receipt.SignedReceipt{
            .model_hash = try parseHex(32, args[3]),
            .policy_hash = try parseHex(32, args[4]),
            .prompt_merkle_root = try parseHex(32, args[5]),
            .output_hash = receipt.hashOutput(args[6]),
            .timestamp_ns = try std.fmt.parseInt(i128, args[7], 10),
            .public_key = pk,
            .signature = try parseHex(64, args[8]),
        };
        const valid = receipt.verifyEd25519(r, pk);
        try stdout.writeStreamingAll(io, try std.fmt.bufPrint(&buf, "{{\"valid\":{}}}\n", .{valid}));
        return if (valid) 0 else 1;
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], "bench")) {
        // Fixed keys: this measures speed only.
        const salt = [_]u8{0x11} ** 16;
        const leaves = [_]receipt.Hash256{ receipt.hashChunk("system: obey policy", salt), receipt.hashChunk("private_user_prompt", salt) };
        const root = try receipt.buildMerkleRoot(alloc, &leaves);
        const mh = [_]u8{1} ** 32;
        const ph = [_]u8{2} ** 32;
        const hkey = [_]u8{0xAB} ** 32;
        var ok: usize = 0;
        var t = std.Io.Clock.awake.now(io);
        var i: usize = 0;
        while (i < 5000) : (i += 1) {
            const att = receipt.signAttestation(mh, ph, root, "verified output", @intCast(i), hkey);
            if (receipt.verifyAttestation(att, hkey)) ok += 1;
        }
        const hmac_ns = @divTrunc(t.durationTo(std.Io.Clock.awake.now(io)).nanoseconds, 5000);
        const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{7} ** 32);
        const pk = kp.public_key.toBytes();
        t = std.Io.Clock.awake.now(io);
        i = 0;
        while (i < 2000) : (i += 1) _ = try receipt.signEd25519(kp, mh, ph, root, "verified output", @intCast(i));
        const sign_ns = @divTrunc(t.durationTo(std.Io.Clock.awake.now(io)).nanoseconds, 2000);
        const r = try receipt.signEd25519(kp, mh, ph, root, "verified output", 1);
        t = std.Io.Clock.awake.now(io);
        i = 0;
        while (i < 2000) : (i += 1) {
            if (receipt.verifyEd25519(r, pk)) ok += 1;
        }
        const verify_ns = @divTrunc(t.durationTo(std.Io.Clock.awake.now(io)).nanoseconds, 2000);
        std.mem.doNotOptimizeAway(ok);
        try stdout.writeStreamingAll(io, try std.fmt.bufPrint(&buf, "{{\"hmac_tag_and_verify_ns\":{d},\"ed25519_sign_ns\":{d},\"ed25519_verify_ns\":{d}}}\n", .{ hmac_ns, sign_ns, verify_ns }));
        return 0;
    }
    try stdout.writeStreamingAll(io, usage);
    return 2;
}

test {
    std.testing.refAllDecls(@This());
}
