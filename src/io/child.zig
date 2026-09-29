//! 拉起传输子进程（默认 ssh）。fork + execvp + 管道，链接 libc。
//! 仅本地模式用；远端 serve 模式直接用 stdin/stdout，不涉及本文件。

const std = @import("std");
const c = std.c;
const net = @import("net.zig");

extern "c" fn fork() c.pid_t;
extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern "c" fn _exit(code: c_int) noreturn;

pub const Child = struct {
    pid: c.pid_t,
    stdin_fd: net.fd_t, // 写给子进程
    stdout_fd: net.fd_t, // 从子进程读
};

pub const SpawnError = error{ PipeFailed, ForkFailed };

/// argv[0] 是可执行名（走 PATH），末尾无需 null——本函数自己补。
pub fn spawn(argv: []const [:0]const u8, buf_argv: [][*:null]const ?[*:0]const u8) SpawnError!Child {
    _ = buf_argv;
    var in_pipe: [2]net.fd_t = undefined;
    var out_pipe: [2]net.fd_t = undefined;
    if (c.pipe(&in_pipe) != 0) return error.PipeFailed;
    if (c.pipe(&out_pipe) != 0) return error.PipeFailed;

    // 组装 argv（[*:null]const ?[*:0]const u8）
    var argv_z: [64]?[*:0]const u8 = undefined;
    var n: usize = 0;
    for (argv) |a| {
        if (n >= argv_z.len - 1) break;
        argv_z[n] = a.ptr;
        n += 1;
    }
    argv_z[n] = null;

    const pid = fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        // 子进程
        _ = c.dup2(in_pipe[0], 0);
        _ = c.dup2(out_pipe[1], 1);
        _ = c.close(in_pipe[0]);
        _ = c.close(in_pipe[1]);
        _ = c.close(out_pipe[0]);
        _ = c.close(out_pipe[1]);
        _ = execvp(argv[0].ptr, @ptrCast(&argv_z));
        _exit(127);
    }
    // 父进程
    _ = c.close(in_pipe[0]);
    _ = c.close(out_pipe[1]);
    net.setNonBlock(in_pipe[1]);
    net.setNonBlock(out_pipe[0]);
    return .{ .pid = pid, .stdin_fd = in_pipe[1], .stdout_fd = out_pipe[0] };
}

/// 终止并回收子进程（避免僵尸）。重连前调用。
pub fn stop(self: Child) void {
    _ = c.kill(self.pid, .TERM);
    var status: c_int = 0;
    _ = c.waitpid(self.pid, &status, 0);
}
