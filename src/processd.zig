const std = @import("std");
const os = std.os;
const print = std.debug.print;
const android = @import("android.zig");

/// Code for interacting with aed_process_worker on the unit
pub const AedProcCmdType = enum(u32) {
    req = 0,
    // Present, but not supported :(
    resp = 1,
    ind = 2,
};

pub const AedProcCmd = enum(u32) {
    class = 1,
    typ = 2,
    process = 3,
    module = 4,
    backtrace = 5,
    detail = 6,
    ind_fatal = 11,
    ind_exp = 12,
    ind_wrn = 13,
    ind_rem = 14,
    ind_log_status = 15,
    ind_log_close = 16,
    coredump = 22,
    userspace_backtrace = 40,
    user_reg = 41,
    user_maps = 42,
    trigger_time = 43,
    fd_info = 44,
    maps_info = 45,
};

pub const AedProcExp = enum(u32) {
    kernel = 0,
    hw_reboot = 2,
    native = 3,
    java = 4,
    swt = 5,
    external = 6,
    resmon = 9,
    modem_warn = 10,
    wtf = 11,
    undef = 12,
    manual_dump = 13,
    kernel_dump = 1000,
    system_dump = 1001,
    system_dump_2 = 1002,
    mrdump = 1003,
    s_reboot = 1004,
    hang = 1005,
    ocp_reboot = 1006,
    sec_reboot = 1007,
    reboot_exception = 1008,
    // TODO: Add more AED EXPs
};

// It seems that, when sending the opening packet,
// seq becomes the pid and len becomes the tid.
// Weird...
pub const AedProcHeader = extern struct {
    cmdtype: u32,
    cmd: u32,
    seq: u32,
    exp: u32,
    len: u32 = 0,
    dbopt: u32 = 0,
};

pub const ProcessClient = struct {
    stream: std.net.Stream,

    pub fn init(stream: std.net.Stream) ProcessClient {
        return .{ .stream = stream };
    }
    pub fn close(self: ProcessClient) void {
        self.stream.close();
    }
    pub fn write(self: ProcessClient, hdr: *AedProcHeader, data: []const u8) !void {
        var iovecs: [2]std.os.iovec_const = .{
            .{
                .iov_base = @as([*]const u8, @ptrCast(hdr)),
                .iov_len = @sizeOf(AedProcHeader),
            },
            .{ .iov_base = @ptrCast(data), .iov_len = data.len },
        };
        _ = try self.stream.writevAll(&iovecs);
    }
    pub fn writev(self: ProcessClient, hdr: *AedProcHeader, iovecs: []std.os.iovec_const) !void {
        _ = try self.stream.writeAll(@as([*]const u8, @ptrCast(hdr))[0..@sizeOf(AedProcHeader)]);
        _ = try self.stream.writevAll(iovecs);
    }
    pub fn read(self: ProcessClient, hdr: *AedProcHeader, data: []u8) !void {
        _ = try self.stream.readAll(@as([*]u8, @ptrCast(hdr))[0..@sizeOf(AedProcHeader)]);
        if (hdr.len > data.len) return std.os.ReadError.InputOutput;
        _ = try self.stream.readAll(data[0..hdr.len]);
    }
};
