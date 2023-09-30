const std = @import("std");
const os = std.os;
const android = @import("android.zig");
const print = std.debug.print;


/// Communicate with RTTD and leak a stack canary!
pub const RTTCmd = enum(u32) {
    clean_dal = 2,
};

pub const RTTPacket = extern struct {
    unk1: i32 = 0,
    cmd: u32,
    pid: i32,
    unk2: i32 = 0,
    unk3: i32 = 0,
    unk4: i32 = 0,
    data: [84]u8 = undefined,
};

pub const RTTClient = struct {
    stream: std.net.Stream,

    pub fn init(stream: std.net.Stream) RTTClient {
        return .{ .stream = stream };
    }
    pub fn close(self: RTTClient) void {
        self.stream.close();
    }
    pub fn write(self: RTTClient, packet: *const RTTPacket) !void {
        return self.stream.writeAll(@as([*]const u8, @ptrCast(packet))[0..@sizeOf(RTTPacket)]);
    }
};
