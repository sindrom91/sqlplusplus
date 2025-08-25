const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const replxx = b.addLibrary(.{
        .name = "replxx",
        .linkage = .static,
        .root_module = b.createModule(.{
            .optimize = optimize,
            .target = target,
        }),
    });
    replxx.linkLibC();
    replxx.linkLibCpp();
    replxx.addCSourceFiles(.{
        .files = &.{
            "replxx/src/ConvertUTF.cpp",
            "replxx/src/conversion.cxx",
            "replxx/src/escape.cxx",
            "replxx/src/history.cxx",
            "replxx/src/prompt.cxx",
            "replxx/src/replxx.cxx",
            "replxx/src/replxx_impl.cxx",
            "replxx/src/terminal.cxx",
            "replxx/src/util.cxx",
            "replxx/src/wcwidth.cpp",
            "replxx/src/windows.cxx",
        },
        .flags = &.{},
    });
    replxx.addIncludePath(b.path("replxx/src"));
    replxx.addIncludePath(b.path("replxx/include"));
    replxx.root_module.addCMacro("REPLXX_STATIC", "1");
    replxx.installHeadersDirectory(b.path("replxx/include"), "", .{});

    b.installArtifact(replxx);

    const spp = b.addExecutable(.{
        .name = "sqlplusplus",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/spp.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    spp.linkLibrary(replxx);

    b.installArtifact(spp);
}
