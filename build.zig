const std = @import("std");

pub fn build(b: *std.Build) void {
    // 默认 baseline CPU：跳板机可能很老，不赌指令集扩展（决策 D12）。
    const target = b.standardTargetOptions(.{
        .default_target = .{ .cpu_model = .baseline },
    });
    // 默认 ReleaseSafe：处理不可信网络输入，保留边界与溢出检查（决策 D12）。
    // 不出 Debug 产物——默认即安全基线；确需调试可显式 -Doptimize=Debug。
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Optimization mode (default ReleaseSafe)",
    ) orelse .ReleaseSafe;

    // 公开库模块——别人作依赖时拿到的就是它。
    const mod = b.addModule("smodem", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // 薄可执行——只是把库接到 argv 和退出码上。
    const exe = b.addExecutable(.{
        .name = "smodem",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true, // io 层用 std.c（socket/getaddrinfo/spawn）
            .imports = &.{.{ .name = "smodem", .module = mod }},
        }),
    });
    b.installArtifact(exe);

    // ---- test ----
    const test_step = b.step("test", "Run all tests");

    const mod_tests = b.addTest(.{ .root_module = mod });
    test_step.dependOn(&b.addRunArtifact(mod_tests).step);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

    // 外置测试文件（tests/*.zig），各自 import 库模块。
    const extra_tests = [_][]const u8{
        "tests/encoding_test.zig",
        "tests/tunnel_test.zig",
    };
    for (extra_tests) |path| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "smodem", .module = mod }},
            }),
        });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    // ---- freestanding 红线：core/ 必须能对无 OS 目标编译（设计 §3）----
    const freestanding = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });
    const core_check = b.addObject(.{
        .name = "sansio-freestanding-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sansio.zig"),
            .target = freestanding,
            .optimize = .ReleaseSafe,
        }),
    });
    // 让 test 依赖这次编译：core/ 一旦混进 syscall，这里就编译失败。
    test_step.dependOn(&core_check.step);

    // ---- release：多平台静态 baseline 二进制（决策 D12）----
    const release_step = b.step("release", "Cross-compile static baseline binaries");
    const targets = [_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
        .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
        .{ .cpu_arch = .x86_64, .os_tag = .macos },
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
    };
    for (targets) |q| {
        var query = q;
        query.cpu_model = .baseline;
        const rtarget = b.resolveTargetQuery(query);
        // 每个目标建独立的库模块——模块 target 不能跨平台复用。
        const rmod = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = rtarget,
            .optimize = .ReleaseSafe,
        });
        const rexe = b.addExecutable(.{
            .name = "smodem",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = rtarget,
                .optimize = .ReleaseSafe,
                .strip = true, // release 产物要 scp 到跳板机，去掉调试信息减体积
                .link_libc = true,
                .imports = &.{.{ .name = "smodem", .module = rmod }},
            }),
        });
        const triple = q.zigTriple(b.allocator) catch @panic("oom");
        const install = b.addInstallArtifact(rexe, .{
            .dest_dir = .{ .override = .{ .custom = b.fmt("release/{s}", .{triple}) } },
        });
        release_step.dependOn(&install.step);
    }
}
