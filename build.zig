const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const linenoise = b.addLibrary(.{
        .name = "linenoise",
        .linkage = .static,
        .root_module = b.createModule(.{
            .optimize = optimize,
            .target = target,
        }),
    });
    linenoise.linkLibC();
    linenoise.linkLibCpp();
    linenoise.addCSourceFiles(.{
        .files = &.{
            "linenoise/linenoise.c",
        },
        .flags = &.{},
    });
    linenoise.addIncludePath(b.path("linenoise"));
    linenoise.installHeadersDirectory(b.path("linenoise"), "", .{});

    b.installArtifact(linenoise);

    const spp = b.addExecutable(.{
        .name = "sqlplusplus",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/spp.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    spp.linkLibrary(linenoise);

    b.installArtifact(spp);
}
