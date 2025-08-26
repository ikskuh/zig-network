const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const module = b.addModule("network", .{
        .root_source_file = b.path("network.zig"),
    });

    var test_runner = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("testsuite.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_runner.root_module.addImport("network", module);

    const async_example = b.addExecutable(.{
        .name = "async",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/async.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    async_example.root_module.addImport("network", module);

    const echo_example = b.addExecutable(.{
        .name = "echo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/echo.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    echo_example.root_module.addImport("network", module);

    const udp_example = b.addExecutable(.{
        .name = "udp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/multicast_udp.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    udp_example.root_module.addImport("network", module);

    const udp_broadcast_example = b.addExecutable(.{
        .name = "udp_broadcast",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/udp_broadcast.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    udp_broadcast_example.root_module.addImport("network", module);

    const discovery_client = b.addExecutable(.{
        .name = "discovery_client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/discovery/client.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    discovery_client.root_module.addImport("network", module);

    const discovery_server = b.addExecutable(.{
        .name = "discovery_server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/discovery/server.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    discovery_server.root_module.addImport("network", module);

    const ntp_client = b.addExecutable(.{
        .name = "ntp_client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/ntp_client.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    ntp_client.root_module.addImport("network", module);

    const test_step = b.step("test", "Runs the test suite.");
    var run = b.addRunArtifact(test_runner);

    test_step.dependOn(&run.step);

    const sync_examples_step = b.step("sync-examples", "Builds the examples");
    sync_examples_step.dependOn(&b.addInstallArtifact(echo_example, .{}).step);

    const async_examples_step = b.step("async-examples", "Builds the examples");
    async_examples_step.dependOn(&b.addInstallArtifact(async_example, .{}).step);

    const udp_examples_step = b.step("udp-examples", "Builds UDP examples");
    udp_examples_step.dependOn(&b.addInstallArtifact(udp_example, .{}).step);

    const udp_broadcast_step = b.step("udp-broadcast", "Builds UDP broadcast example");
    udp_broadcast_step.dependOn(&b.addInstallArtifact(udp_broadcast_example, .{}).step);

    const discovery_examples_step = b.step("discovery-examples", "Builds UDP/TCP Server Discovery examples");
    discovery_examples_step.dependOn(&b.addInstallArtifact(discovery_client, .{}).step);
    discovery_examples_step.dependOn(&b.addInstallArtifact(discovery_server, .{}).step);

    const ntp_example_step = b.step("ntp-client", "Builds NTP client example");
    ntp_example_step.dependOn(&b.addInstallArtifact(ntp_client, .{}).step);

    const all_examples_step = b.step("examples", "Builds all examples");
    all_examples_step.dependOn(&b.addInstallArtifact(echo_example, .{}).step);
    // TODO: uncomment once async is implemented
    // all_examples_step.dependOn(&b.addInstallArtifact(async_example).step);
    all_examples_step.dependOn(&b.addInstallArtifact(udp_example, .{}).step);
    all_examples_step.dependOn(&b.addInstallArtifact(udp_broadcast_example, .{}).step);
    all_examples_step.dependOn(&b.addInstallArtifact(discovery_client, .{}).step);
    all_examples_step.dependOn(&b.addInstallArtifact(discovery_server, .{}).step);
    all_examples_step.dependOn(&b.addInstallArtifact(ntp_client, .{}).step);
}
