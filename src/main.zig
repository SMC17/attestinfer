const std = @import("std");
pub const zk_infer_receipt = @import("zk_infer_receipt.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    if (args.len >= 2 and std.mem.eql(u8, args[1], "bench")) {
        const salt = [_]u8{0x11} ** 16;
        const leaves = [_]zk_infer_receipt.Hash256{
            zk_infer_receipt.hashChunk("system: obey policy", salt),
            zk_infer_receipt.hashChunk("private_user_prompt", salt),
        };
        const root = try zk_infer_receipt.buildMerkleRoot(alloc, &leaves);
        const key = [_]u8{0xAB} ** 32;
        const model_h = [_]u8{0x01} ** 32;
        const policy_h = [_]u8{0x02} ** 32;

        var timer = try std.time.Timer.start();
        var i: usize = 0;
        var ok_count: usize = 0;
        while (i < 5000) : (i += 1) {
            const att = zk_infer_receipt.signAttestation(model_h, policy_h, root, "verified output", @intCast(i), key);
            if (zk_infer_receipt.verifyAttestation(att, key)) ok_count += 1;
        }
        std.mem.doNotOptimizeAway(ok_count);
        const attest_ns = timer.read() / 5000;

        var buf: [128]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "{{\"attest_verify_ns\":{d}}}\n", .{attest_ns});
        try std.fs.File.stdout().writeAll(msg);
        return;
    }

    try std.fs.File.stdout().writeAll("attestinfer — Verifiable Inference Attestation & Selective-Disclosure Merkle Proofs\n\nUsage:\n  attestinfer bench\n");
}

test {
    std.testing.refAllDecls(@This());
}
