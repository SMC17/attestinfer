const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "attestinfer",
        .root_module = root_mod,
    });
    b.installArtifact(exe);

    const c_api_mod = b.createModule(.{
        .root_source_file = b.path("src/c_api.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "attestinfer",
        .root_module = c_api_mod,
    });
    b.installArtifact(lib);

    const tests = b.addTest(.{ .root_module = root_mod });
    const test_step = b.step("test", "Run all attestinfer cryptographic attestation & Merkle proof tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
