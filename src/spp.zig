// TODO: Fix child-process detecting redirection.

const std = @import("std");
const win = std.os.windows;
const c = @cImport({
    @cInclude("windows.h");
    @cInclude("linenoise.h");
});

const ArrayList = std.ArrayList;
const assert = std.debug.assert;
const logd = std.log.debug;
const logi = std.log.info;
const logw = std.log.warn;
const loge = std.log.err;

var child_input_write: win.HANDLE = undefined;
var child_input_read: win.HANDLE = undefined;

var child_output_write: win.HANDLE = undefined;
var child_output_read: win.HANDLE = undefined;

var child_handle: win.HANDLE = undefined;

var stdin: win.HANDLE = undefined;
var stdout: win.HANDLE = undefined;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

var prompt: ArrayList(u8) = .empty;

var logfile: ?std.fs.File = null;
var logmsg: ArrayList(u8) = .empty;

pub const std_options: std.Options = .{ .logFn = log };

pub fn initLogfile() void {
    const print = std.debug.print;

    const temp = std.process.getEnvVarOwned(allocator, "TEMP") catch |err| {
        print("Failed to read %TEMP%: {}\n", .{err});
        return;
    };
    defer allocator.free(temp);

    const path = std.fmt.allocPrint(allocator, "{s}\\{s}", .{ temp, "sqlplusplus.log" }) catch |err| {
        print("Failed to create log file path: {}\n", .{err});
        return;
    };
    defer allocator.free(path);

    logfile = std.fs.openFileAbsolute(path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => std.fs.createFileAbsolute(path, .{ .read = true }) catch |err0| {
            print("Unable to create log file: {s} {}", .{ path, err0 });
            return;
        },
        else => {
            print("Failed to open log file: {s} {}\n", .{ path, err });
            return;
        },
    };

    const stat = logfile.?.stat() catch |err| {
        print("Failed to get stat of log file: {}\n", .{err});
        return;
    };
    logfile.?.seekTo(stat.size) catch |err| {
        print("Failed to seek log file: {}\n", .{err});
        return;
    };
}

pub fn log(
    comptime level: std.log.Level,
    comptime _: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const print = std.debug.print;

    // Disable logging altogether.
    if (logfile == null)
        return;

    var time: c.SYSTEMTIME = undefined;
    c.GetLocalTime(&time);

    const timeformat = "[{d}{d:0>2}{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}]";
    const prefix = timeformat ++ "[" ++ comptime level.asText() ++ "] ";

    defer logmsg.clearRetainingCapacity();
    logmsg.writer(allocator).print(prefix ++ format ++ "\n", .{
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds,
    } ++ args) catch |err| {
        print("Failed to format log message with args: {}\n", .{err});
        return;
    };

    logfile.?.writeAll(logmsg.items) catch |err| {
        print("Failed to write to log file: {}\n", .{err});
    };
}

pub fn createPipes() !void {
    var sa: win.SECURITY_ATTRIBUTES = .{
        .nLength = @sizeOf(win.SECURITY_ATTRIBUTES),
        .bInheritHandle = win.TRUE,
        .lpSecurityDescriptor = null,
    };

    // Creates an anonymous pipe where the first parameter is a handle for
    // reading data from pipe, and the second parameter is a handle for writing
    // data to the pipe.
    //
    // First handle will be used as child process' STDIN.
    // Second handle will be used by us to send data to the child.
    try win.CreatePipe(&child_input_read, &child_input_write, &sa);
    try win.SetHandleInformation(child_input_write, win.HANDLE_FLAG_INHERIT, 0);

    try win.CreatePipe(&child_output_read, &child_output_write, &sa);
    try win.SetHandleInformation(child_output_read, win.HANDLE_FLAG_INHERIT, 0);
}

pub fn closePipes() void {
    win.CloseHandle(child_input_write);
    win.CloseHandle(child_input_read);
    win.CloseHandle(child_output_write);
    win.CloseHandle(child_output_read);
}

pub fn getHistoryFilename() ![:0]const u8 {
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return try std.fmt.allocPrintSentinel(allocator, "{s}\\{s}", .{ home, ".sqlplusplus_history" }, 0);
}

pub fn readHistoryFile() void {
    const path = getHistoryFilename() catch |err| {
        logw("Unable to get history filename: {}", .{err});
        return;
    };
    defer allocator.free(path);

    std.fs.accessAbsolute(path, .{ .mode = .read_write }) catch |err| {
        logw("Unable to access history file: {s} {}", .{ path, err });
        return;
    };

    if (c.linenoiseHistoryLoad(path.ptr) != 0)
        logw("Failed to read history file", .{});
}

pub fn writeHistoryFile() void {
    const path = getHistoryFilename() catch |err| {
        logw("Unable to get history filename: {}", .{err});
        return;
    };
    defer allocator.free(path);

    std.fs.accessAbsolute(path, .{ .mode = .read_write }) catch |err| {
        if (err != std.fs.File.OpenError.FileNotFound) {
            logw("Unable to access history file: {s} {}", .{ path, err });
            return;
        }

        const file = std.fs.createFileAbsolute(path, .{ .read = true }) catch |err0| {
            logw("Unable to create history file: {s} {}", .{ path, err0 });
            return;
        };
        file.close();
    };

    if (c.linenoiseHistorySave(path.ptr) != 0)
        logw("Failed to write history file", .{});
}

pub fn getCommandLine() ![:0]u16 {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // Skip first argument (sqlplusplus.exe itself).
    const skip_progname = args.skip();
    assert(skip_progname == true);

    var cmdln: ArrayList(u8) = .empty;
    defer cmdln.deinit(allocator);

    try cmdln.appendSlice(allocator, "sqlplus.exe");

    while (args.next()) |arg| {
        try cmdln.append(allocator, ' ');
        try cmdln.appendSlice(allocator, arg);
    }

    return try std.unicode.utf8ToUtf16LeAllocZ(allocator, cmdln.items);
}

pub fn sendLine(line: []const u8) !void {
    // Send line to child process.
    var written = win.WriteFile(child_input_write, line, 0) catch |err| {
        loge("Fatal error: WriteFile failed ({s}, {})", .{ line, err });
        return err;
    };
    assert(written == line.len);

    // Send EOL to the child process.
    written = win.WriteFile(child_input_write, "\r\n", 0) catch |err| {
        loge("Fatal error: WriteFile failed (EOL, {})", .{err});
        return err;
    };
    assert(written == 2);

    logd("Line sent to child process: {s}", .{line});
}

fn isInputReady() bool {
    var record: c.INPUT_RECORD = undefined;
    var nread: win.DWORD = undefined;
    while (c.PeekConsoleInputA(stdin, &record, 1, &nread) != 0 and nread > 0) {
        if (record.EventType == c.KEY_EVENT and record.Event.KeyEvent.bKeyDown != 0) {
            return true;
        }
        // Skip useless input (mouse events, window resizing, modifiers and similar).
        _ = c.ReadConsoleInputA(stdin, &record, 1, &nread);
    }
    return false;
}

fn isOutputReady() bool {
    var navailable: win.DWORD = 0;
    if (c.PeekNamedPipe(child_output_read, null, 0, null, &navailable, null) != 0 and navailable > 0) {
        return true;
    }
    return false;
}

// Update standard output with data received from child process.
fn updateOutput() void {
    var navailable: win.DWORD = 0;
    const r = c.PeekNamedPipe(child_output_read, null, 0, null, &navailable, null);
    assert(r != 0);
    assert(navailable > 0);

    var buf: [4096]u8 = undefined;
    var nread_total: usize = 0;
    prompt.clearRetainingCapacity();
    while (navailable > nread_total) {
        const nread = win.ReadFile(child_output_read, &buf, 0) catch unreachable;
        loge("nread: {d}", .{nread});
        loge("last byte: {d}", .{buf[nread - 1]});
        assert(nread > 0);
        const idx = std.mem.lastIndexOf(u8, buf[0..nread], "\n");
        if (idx == null) {
            prompt.appendSlice(allocator, buf[0..nread]) catch unreachable;
        } else {
            const start = idx.? + 1;
            prompt.clearRetainingCapacity();
            prompt.appendSlice(allocator, buf[start..nread]) catch unreachable;

            const bytesWritten = win.WriteFile(stdout, buf[0..start], 0) catch unreachable;
            assert(bytesWritten == start);
        }
        nread_total += nread;
    }
    // Zero-terminate prompt.
    prompt.append(allocator, 0) catch unreachable;
}

fn updatePrompt(ls: *c.linenoiseState) void {
    ls.prompt = prompt.items.ptr;
    // Length without zero-terminator.
    ls.plen = prompt.items.len - 1;

    // Mask password input.
    if (std.mem.indexOf(u8, prompt.items, "password") == null) {
        c.linenoiseMaskModeDisable();
    } else {
        c.linenoiseMaskModeEnable();
    }
}

fn isChildAlive() bool {
    var exit_code: win.DWORD = undefined;
    if (win.kernel32.GetExitCodeProcess(child_handle, &exit_code) != 0)
        return exit_code == c.STILL_ACTIVE;
    return true;
}

fn complete(input: [*c]const u8, lc: ?*c.linenoiseCompletions) callconv(.c) void {
    const completions = [_][:0]const u8{
        "AND ",
        "BITAND(",
        "BETWEEN ",
        "COUNT(",
        "DELETE ",
        "DESC ",
        "DISTINCT ",
        "EXIT",
        "FROM ",
        "GROUP BY ",
        "IN (",
        "LIKE '",
        "LINESIZE ",
        "ORDER BY ",
        "ROWNUM ",
        "PAGESIZE ",
        "SELECT ",
        "SUM(",
        "UPDATE ",
        "WHERE ",
    };
    const input_slice = std.mem.span(input);
    const idx = std.mem.lastIndexOf(u8, input_slice, " ");
    const fixed_part = if (idx) |i| input_slice[0 .. i + 1] else "";
    const last_word = if (idx) |i| input_slice[i + 1 ..] else input_slice;
    const last_word_upper = std.ascii.allocUpperString(allocator, last_word) catch unreachable;
    defer allocator.free(last_word_upper);
    for (completions) |completion| {
        if (std.mem.startsWith(u8, completion, last_word_upper)) {
            const complete_line = std.mem.concat(allocator, u8, &.{ fixed_part, completion }) catch unreachable;
            defer allocator.free(complete_line);
            c.linenoiseAddCompletion(lc, complete_line.ptr);
        }
    }
}

pub fn main() !void {
    defer prompt.deinit(allocator);
    defer logmsg.deinit(allocator);

    initLogfile();
    defer if (logfile) |f| f.close();

    logi("Starting sqlplusplus", .{});
    defer logi("Exiting sqlplusplus", .{});

    // History file has to be read before initializing readline, otherwise the order of entries
    // will be wrong.
    readHistoryFile();
    defer writeHistoryFile();

    createPipes() catch |err| {
        loge("Fatal error: createPipes failed ({})", .{err});
        return;
    };
    defer closePipes();

    stdin = win.GetStdHandle(win.STD_INPUT_HANDLE) catch unreachable;
    stdout = win.GetStdHandle(win.STD_OUTPUT_HANDLE) catch unreachable;

    var sinfo: win.STARTUPINFOW = .{
        .cb = @sizeOf(win.STARTUPINFOW),
        .lpReserved = null,
        .lpDesktop = null,
        .lpTitle = null,
        .dwX = 0,
        .dwY = 0,
        .dwXSize = 0,
        .dwYSize = 0,
        .dwXCountChars = 0,
        .dwYCountChars = 0,
        .dwFillAttribute = 0,
        .dwFlags = win.STARTF_USESTDHANDLES,
        .wShowWindow = 0,
        .cbReserved2 = 0,
        .lpReserved2 = null,
        .hStdInput = child_input_read,
        .hStdOutput = child_output_write,
        .hStdError = child_output_write,
    };
    var pinfo: win.PROCESS_INFORMATION = undefined;

    const wcmdln = getCommandLine() catch unreachable;
    defer allocator.free(wcmdln);

    win.CreateProcessW(null, wcmdln.ptr, null, null, win.TRUE, .{}, null, null, &sinfo, &pinfo) catch |err| {
        loge("Fatal error: CreateProcessW failed ({})", .{err});
        return;
    };
    defer win.CloseHandle(pinfo.hThread);
    defer win.CloseHandle(pinfo.hProcess);

    child_handle = pinfo.hProcess;

    // Initialize prompt with empty zero-terminated string.
    prompt.append(allocator, 0) catch unreachable;

    c.linenoiseSetCompletionCallback(complete);

    while (isChildAlive()) {
        var line: [*c]u8 = null;
        var ls: c.linenoiseState = undefined;
        var buf: [1024]u8 = undefined;
        if (c.linenoiseEditStart(&ls, -1, -1, &buf, buf.len, prompt.items.ptr) < 0) break;
        while (true) {
            if (isInputReady()) {
                line = c.linenoiseEditFeed(&ls);
                if (line != c.linenoiseEditMore) break;
            }
            if (isOutputReady()) {
                c.linenoiseHide(&ls);
                updateOutput();
                updatePrompt(&ls);
                c.linenoiseShow(&ls);
            }
            // In case child process exits, break this loop.
            if (!isChildAlive()) break;
        }
        c.linenoiseEditStop(&ls);
        if (line == null) break;

        _ = c.linenoiseHistoryAdd(line);
        try sendLine(std.mem.span(line));
    }
}
