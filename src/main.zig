const std = @import("std");
pub const zk_infer_receipt = @import("zk_infer_receipt.zig");
pub const c_api = @import("c_api.zig");

const DEFAULT_ENCLAVE_KEY = [_]u8{0xAB} ** 32;

fn parseHex32(hex: []const u8) !zk_infer_receipt.Hash256 {
    if (hex.len != 64) return error.InvalidHexLength;
    var out: zk_infer_receipt.Hash256 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

fn formatHex32(bytes: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}

pub fn main(init: std.process.Init) !void {
    const alloc = init.arena.allocator();
    const io = init.io;
    const stdout = std.Io.File.stdout();

    const args = try init.minimal.args.toSlice(alloc);
    if (args.len >= 2 and std.mem.eql(u8, args[1], "bench")) {
        const salt = [_]u8{0x11} ** 16;
        const leaves = [_]zk_infer_receipt.Hash256{
            zk_infer_receipt.hashChunk("system: obey policy", salt),
            zk_infer_receipt.hashChunk("private_user_prompt", salt),
        };
        const root = try zk_infer_receipt.buildMerkleRoot(alloc, &leaves);
        const key = DEFAULT_ENCLAVE_KEY;
        const model_h = [_]u8{0x01} ** 32;
        const policy_h = [_]u8{0x02} ** 32;

        const t0 = std.Io.Clock.awake.now(io);
        var i: usize = 0;
        var ok_count: usize = 0;
        while (i < 5000) : (i += 1) {
            const att = zk_infer_receipt.signAttestation(model_h, policy_h, root, "verified output", @intCast(i), key);
            if (zk_infer_receipt.verifyAttestation(att, key)) ok_count += 1;
        }
        std.mem.doNotOptimizeAway(ok_count);
        const t1 = std.Io.Clock.awake.now(io);
        const attest_ns: i96 = @divTrunc(t0.durationTo(t1).nanoseconds, 5000);

        var buf: [128]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "{{\"attest_verify_ns\":{d}}}\n", .{attest_ns});
        try stdout.writeStreamingAll(io, msg);
        return;
    }

    if (args.len >= 5 and std.mem.eql(u8, args[1], "sign")) {
        const model_h = try parseHex32(args[2]);
        const policy_h = try parseHex32(args[3]);
        const output_text = args[4];
        const prompt_root = [_]u8{0x00} ** 32;
        const ts_ns: i128 = std.Io.Clock.real.now(io).nanoseconds;
        const att = zk_infer_receipt.signAttestation(model_h, policy_h, prompt_root, output_text, ts_ns, DEFAULT_ENCLAVE_KEY);

        var buf: [512]u8 = undefined;
        const msg = try std.fmt.bufPrint(
            &buf,
            "{{\"model_hash\":\"{s}\",\"policy_hash\":\"{s}\",\"prompt_merkle_root\":\"{s}\",\"output_hash\":\"{s}\",\"timestamp_ns\":{d},\"attestation_mac\":\"{s}\"}}\n",
            .{
                formatHex32(att.model_hash),
                formatHex32(att.policy_hash),
                formatHex32(att.prompt_merkle_root),
                formatHex32(att.output_hash),
                att.timestamp_ns,
                formatHex32(att.attestation_mac),
            },
        );
        try stdout.writeStreamingAll(io, msg);
        return;
    }

    if (args.len >= 8 and std.mem.eql(u8, args[1], "verify")) {
        const model_h = try parseHex32(args[2]);
        const policy_h = try parseHex32(args[3]);
        const prompt_root = try parseHex32(args[4]);
        const output_text = args[5];
        const ts_ns = try std.fmt.parseInt(i128, args[6], 10);
        const mac = try parseHex32(args[7]);

        var out_hash: zk_infer_receipt.Hash256 = undefined;
        std.crypto.hash.Blake3.hash(output_text, &out_hash, .{});

        const att = zk_infer_receipt.InferenceAttestation{
            .model_hash = model_h,
            .policy_hash = policy_h,
            .prompt_merkle_root = prompt_root,
            .output_hash = out_hash,
            .timestamp_ns = ts_ns,
            .attestation_mac = mac,
        };
        const valid = zk_infer_receipt.verifyAttestation(att, DEFAULT_ENCLAVE_KEY);
        var buf: [64]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "{{\"valid\":{}}}\n", .{valid});
        try stdout.writeStreamingAll(io, msg);
        if (!valid) std.process.exit(1);
        return;
    }

    try stdout.writeStreamingAll(
        io,
        "attestinfer — Verifiable Inference Attestation & Selective-Disclosure Merkle Proofs\n\nUsage:\n  attestinfer bench\n  attestinfer sign <model_hex> <policy_hex> <output_text>\n  attestinfer verify <model_hex> <policy_hex> <prompt_root_hex> <output_text> <timestamp_ns> <mac_hex>\n",
    );
}

test {
    std.testing.refAllDecls(@This());
}
