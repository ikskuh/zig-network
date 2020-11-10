const std = @import("std");

const pkgs = struct {
    const network = std.build.Pkg{
        .name = "network",
        .path = "network.zig",
    };
};

pub fn build(b: *std.build.Builder) !void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    var test_runner = b.addTest("testsuite.zig");

    const async_example = b.addExecutable("async", "examples/async.zig");
    async_example.setBuildMode(mode);
    async_example.setTarget(target);
    async_example.addPackage(pkgs.network);

    const echo_example = b.addExecutable("echo", "examples/echo.zig");
    echo_example.setBuildMode(mode);
    echo_example.setTarget(target);
    echo_example.addPackage(pkgs.network);

    const test_step = b.step("test", "Runs the test suite.");
    test_step.dependOn(&test_runner.step);

    const examples_step = b.step("examples", "Builds the examples");
    examples_step.dependOn(&b.addInstallArtifact(async_example).step);
    examples_step.dependOn(&b.addInstallArtifact(echo_example).step);
}
