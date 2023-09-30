const std = @import("std");
const os = std.os;
const print = std.debug.print;
const android = @import("android.zig");

pub const LOGGER_ENTRY_MAX_LEN: usize = @as(usize, 5 * 1024);
pub const rsockname = "/dev/socket/logdr";

/// Code to interact with logd on the device
pub const LogClient = struct {
    stream: std.net.Stream,

    pub fn init(stream: std.net.Stream) LogClient {
        return .{
            .stream = stream,
        };
    }
    pub fn read(self: LogClient, message: []u8) !usize {
        return self.stream.read(message);
    }
    pub fn close(self: LogClient) void {
        self.stream.close();
    }
};
