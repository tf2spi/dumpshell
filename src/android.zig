const std = @import("std");
const os = std.os;
const linux = os.linux;
const AF = linux.AF;
const SOCK = linux.SOCK;
const Stream = std.net.Stream;

/// Connect to both abstract and filesystem sockets on Android
/// which os.connectUnixSocket unfortunately fails to do.
///
/// Android also flips between using dgram and stream sockets
/// so be flexible and do either one.
pub fn connectUnixSocket(path: []const u8, socktype: u32) !Stream {
    var sock = try os.socket(AF.UNIX, socktype, 0);
    errdefer os.closeSocket(sock);
    const un = try std.net.Address.initUnix(path);
    var size = @as(os.socklen_t, @offsetOf(os.sockaddr.un, "path") + path.len);
    if (size > @offsetOf(os.sockaddr.un, "path") and path[0] != 0) size += 1;
    _ = try os.connect(sock, &un.any, size);
    return .{ .handle = sock };
}

/// Convenience functions for creating stream, dgram, and seqpacket sockets.
/// Yes, Android will actually use both dgram and seqpacket sockets
/// because Google hates everyone, especially me.
pub fn connectUnixSocketStream(path: []const u8) !Stream {
    return connectUnixSocket(path, SOCK.STREAM);
}
pub fn connectUnixSocketDgram(path: []const u8) !Stream {
    return connectUnixSocket(path, SOCK.DGRAM);
}
pub fn connectUnixSocketSeqpacket(path: []const u8) !Stream {
    return connectUnixSocket(path, SOCK.SEQPACKET);
}
