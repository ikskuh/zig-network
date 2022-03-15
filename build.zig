const std = @import("std");

const pkgs = struct {
    const network = std.build.Pkg{
        .name = "network",
        .path = .{ .path = "network.zig" },
    };
};

pub fn build(b: *std.build.Builder) !void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    var test_runner = b.addTest("testsuite.zig");
    test_runner.addPackage(pkgs.network);
    test_runner.setBuildMode(mode);
    test_runner.setTarget(target);

    const async_example = b.addExecutable("async", "examples/async.zig");
    async_example.setBuildMode(mode);
    async_example.setTarget(target);
    async_example.addPackage(pkgs.network);

    const echo_example = b.addExecutable("echo", "examples/echo.zig");
    echo_example.setBuildMode(mode);
    echo_example.setTarget(target);
    echo_example.addPackage(pkgs.network);

    const udp_example = b.addExecutable("udp", "examples/multicast_udp.zig");
    udp_example.setBuildMode(mode);
    udp_example.setTarget(target);
    udp_example.addPackage(pkgs.network);

    const discovery_client = b.addExecutable("discovery_client", "examples/discovery/client.zig");
    discovery_client.setBuildMode(mode);
    discovery_client.setTarget(target);
    discovery_client.addPackage(pkgs.network);

    const discovery_server = b.addExecutable("discovery_server", "examples/discovery/server.zig");
    discovery_server.setBuildMode(mode);
    discovery_server.setTarget(target);
    discovery_server.addPackage(pkgs.network);

    const test_step = b.step("test", "Runs the test suite.");
    test_step.dependOn(&test_runner.step);

    const sync_examples_step = b.step("sync-examples", "Builds the examples");
    sync_examples_step.dependOn(&b.addInstallArtifact(echo_example).step);

    const async_examples_step = b.step("async-examples", "Builds the examples");
    async_examples_step.dependOn(&b.addInstallArtifact(async_example).step);

    const udp_examples_step = b.step("udp-examples", "Builds UDP examples");
    udp_examples_step.dependOn(&b.addInstallArtifact(udp_example).step);

    const discovery_examples_step = b.step("discovery-examples", "Builds UDP/TCP Server Discovery examples");
    discovery_examples_step.dependOn(&b.addInstallArtifact(discovery_client).step);
    discovery_examples_step.dependOn(&b.addInstallArtifact(discovery_server).step);
}
