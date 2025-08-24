// TODO: Fix child-process detecting redirection.

const std = @import("std");
const win = std.os.windows;
const c = @cImport({
    @cInclude("windows.h");
    @cInclude("replxx.h");
});

const ArrayList = std.ArrayList;
const fs = std.fs;
const fmt = std.fmt;
const assert = std.debug.assert;
const sleep = std.time.sleep;
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

var prompt = ArrayList(u8).init(allocator);
var prompt_lock: std.Thread.Mutex = .{};
var is_password_prompt = std.atomic.Value(bool).init(false);
var password = ArrayList(u8).init(allocator);

var logfile: ?fs.File = null;
var logmsg = ArrayList(u8).init(allocator);

pub const std_options: std.Options = .{ .logFn = log };

pub fn initLogfile() void {
    const print = std.debug.print;

    const temp = std.process.getEnvVarOwned(allocator, "TEMP") catch |err| {
        print("Failed to read %TEMP%: {}\n", .{err});
        return;
    };
    defer allocator.free(temp);

    const path = fmt.allocPrint(allocator, "{s}\\{s}", .{ temp, "sqlplusplus.log" }) catch |err| {
        print("Failed to create log file path: {}\n", .{err});
        return;
    };
    defer allocator.free(path);

    logfile = fs.openFileAbsolute(path, .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => fs.createFileAbsolute(path, .{ .read = true }) catch |err0| {
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
    logmsg.writer().print(prefix ++ format ++ "\n", .{
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
    return try fmt.allocPrintZ(allocator, "{s}\\{s}", .{ home, ".sqlplusplus_history" });
}

pub fn readHistoryFile(replxx: ?*c.Replxx) void {
    const path = getHistoryFilename() catch |err| {
        logw("Unable to get history filename: {}", .{err});
        return;
    };
    defer allocator.free(path);

    fs.accessAbsolute(path, .{ .mode = .read_write }) catch |err| {
        logw("Unable to access history file: {s} {}", .{ path, err });
        return;
    };

    if (c.replxx_history_load(replxx, path.ptr) != 0)
        logw("Failed to read history file", .{});

    c.replxx_set_unique_history(replxx, 1);
}

pub fn writeHistoryFile(replxx: ?*c.Replxx) void {
    const path = getHistoryFilename() catch |err| {
        logw("Unable to get history filename: {}", .{err});
        return;
    };
    defer allocator.free(path);

    fs.accessAbsolute(path, .{ .mode = .read_write }) catch |err| {
        if (err != fs.File.OpenError.FileNotFound) {
            logw("Unable to access history file: {s} {}", .{ path, err });
            return;
        }

        const file = fs.createFileAbsolute(path, .{ .read = true }) catch |err0| {
            logw("Unable to create history file: {s} {}", .{ path, err0 });
            return;
        };
        file.close();
    };

    if (c.replxx_history_save(replxx, path.ptr) != 0)
        logw("Failed to write history file", .{});
}

pub fn getCommandLine() ![:0]u16 {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // Skip first argument (sqlplusplus.exe itself).
    const skip_progname = args.skip();
    assert(skip_progname == true);

    var cmdln = ArrayList(u8).init(allocator);
    defer cmdln.deinit();

    try cmdln.appendSlice("sqlplus.exe");

    while (args.next()) |arg| {
        try cmdln.append(' ');
        try cmdln.appendSlice(arg);
    }

    return try std.unicode.utf8ToUtf16LeAllocZ(allocator, cmdln.items);
}

// Read everything from childs STDOUT and write it to our STDOUT.
pub fn syncChildOutput(replxx: ?*c.Replxx) !void {
    var new_prompt = ArrayList(u8).init(allocator);
    defer new_prompt.deinit();

    while (true) {
        var bytes_available: win.DWORD = 0;
        const ret = c.PeekNamedPipe(child_output_read, null, 0, null, &bytes_available, null);
        if (ret != 0 and bytes_available > 0) {
            defer new_prompt.clearRetainingCapacity();

            var total_bytes_read: usize = 0;
            while (bytes_available > total_bytes_read) {
                var buf: [4096]u8 = undefined;
                const bytes_read = win.ReadFile(child_output_read, &buf, 0) catch |err| {
                    loge("Fatal error: ReadFile failed (child_output_read, {})", .{err});
                    std.process.abort();
                };

                const idx = std.mem.lastIndexOf(u8, buf[0..bytes_read], "\n");
                if (idx == null) {
                    new_prompt.appendSlice(buf[0..bytes_read]) catch |err| {
                        loge(
                            "Fatal error: appendSlice for full line failed ({}, {d})",
                            .{ err, bytes_read },
                        );
                        std.process.abort();
                    };
                } else {
                    const start = idx.? + 1;
                    new_prompt.clearRetainingCapacity();
                    new_prompt.appendSlice(buf[start..bytes_read]) catch |err| {
                        loge(
                            "Fatal error: appendSlice for partial line failed ({d}, {d}, {})",
                            .{ bytes_read, start, err },
                        );
                        std.process.abort();
                    };

                    const bytesWritten = win.WriteFile(stdout, buf[0..start], 0) catch |err| {
                        loge("Fatal error: WriteFile failed (STDOUT, {})", .{err});
                        std.process.abort();
                    };
                    assert(bytesWritten == start);
                }
                total_bytes_read += bytes_read;
            }
            assert(total_bytes_read == bytes_available);

            if (!std.mem.eql(u8, prompt.items, new_prompt.items)) {
                prompt_lock.lock();
                prompt.clearRetainingCapacity();
                prompt.appendSlice(new_prompt.items) catch |err| {
                    loge(
                        "Fatal error: appendSlice when copying password failed ({d}, {})",
                        .{ new_prompt.items.len, err },
                    );
                    std.process.abort();
                };
                prompt_lock.unlock();

                const prompt_z = allocator.dupeZ(u8, new_prompt.items) catch |err| {
                    loge("Fatal error: dupeZ failed ({})", .{err});
                    std.process.abort();
                };
                defer allocator.free(prompt_z);
                c.replxx_set_prompt(replxx, prompt_z);

                if (std.mem.indexOf(u8, new_prompt.items, "password") == null) {
                    if (is_password_prompt.load(.monotonic)) {
                        logi("Changing to normal prompt", .{});
                        is_password_prompt.store(false, .monotonic);
                    }
                } else {
                    logi("Changing to password prompt", .{});
                    is_password_prompt.store(true, .monotonic);
                }
            }
        }

        // Check if child is alive before sleep, because child can die during the sleep and
        // we will end up finishing this thread while there is more data in the pipe.
        if (!isChildAlive())
            break;

        sleep(std.time.ns_per_ms * 40);
    }
}

pub fn isChildAlive() bool {
    var exit_code: win.DWORD = 0;
    if (win.kernel32.GetExitCodeProcess(child_handle, &exit_code) != 0)
        return exit_code == c.STILL_ACTIVE;
    return true;
}

pub fn handleKeys(code: c_int, ud: ?*anyopaque) callconv(.C) c.ReplxxActionResult {
    const replxx: *c.Replxx = @ptrCast(ud);
    switch (code) {
        c.REPLXX_KEY_CONTROL('P') => {
            return c.replxx_invoke(replxx, c.REPLXX_ACTION_HISTORY_MOVE_PREVIOUS, 0);
        },
        c.REPLXX_KEY_CONTROL('N') => {
            return c.replxx_invoke(replxx, c.REPLXX_ACTION_HISTORY_MOVE_NEXT, 0);
        },
        c.REPLXX_KEY_CONTROL('J') => {
            return c.REPLXX_ACTION_RESULT_RETURN;
        },
        c.REPLXX_KEY_CONTROL('C'), c.REPLXX_KEY_CONTROL('D') => {
            win.TerminateProcess(child_handle, 0) catch |err| {
                loge("Failed to terminate process: {}", .{err});
                std.process.abort();
            };
            return c.REPLXX_ACTION_RESULT_BAIL;
        },
        else => unreachable,
    }
}

pub fn handleCompletion(input: [*c]const u8, comps: ?*c.replxx_completions, _: ?*c_int, _: ?*anyopaque) callconv(.C) void {
    var words_iter = std.mem.splitBackwardsSequence(u8, std.mem.span(input), " ");
    const last_word = words_iter.next().?;
    // TODO: Is this right? Can I use ascii.upperString on UTF-8 encoded string?
    const last_word_upper = std.ascii.allocUpperString(allocator, last_word) catch |err| {
        logw("Failed to allocate in completion function: {}", .{err});
        return;
    };

    if (last_word_upper.len <= 0)
        return;

    defer allocator.free(last_word_upper);
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
    for (completions) |completion|
        if (std.mem.startsWith(u8, completion, last_word_upper))
            c.replxx_add_completion(comps, completion);
}

pub fn handleModify(input: [*c][*c]u8, _: ?*c_int, _: ?*anyopaque) callconv(.C) void {
    if (is_password_prompt.load(.monotonic)) {
        const line = std.mem.span(input[0]);

        // Modify was called even though nothing was added or deleted. Assert that password is hidden.
        if (password.items.len == line.len) {
            for (line) |character|
                assert(character == '*');
            return;
        }

        // 2 or more characters were added to input since the last call (should not be possible).
        if (password.items.len + 1 < line.len) {
            loge("Fatal error: received more password characters than expected", .{});
            std.process.abort();
        }

        // 2 or more characters were deleted frmo input since the last call (should not be possible).
        if (password.items.len > line.len + 1) {
            loge("Fatal error: deleted more password characters than expected", .{});
            std.process.abort();
        }

        // Character was added.
        if (password.items.len + 1 == line.len) {
            password.append(line[line.len - 1]) catch |err| {
                loge("Fatal error: ArrayList.append failed ({})", .{err});
                std.process.abort();
            };
            line[line.len - 1] = '*';
        }

        // Character was deleted.
        if (password.items.len == line.len + 1) {
            _ = password.pop();
        }
    }
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

pub fn getPrompt(alloc: std.mem.Allocator) ![:0]u8 {
    prompt_lock.lock();
    // Make a local copy of the prompt, because replxx_input() will block.
    const prompt_z = alloc.dupeZ(u8, prompt.items) catch |err| {
        loge("Fatal error: dupeZ failed ({})", .{err});
        return err;
    };
    prompt_lock.unlock();
    return prompt_z;
}

pub fn clearPrompt() void {
    prompt_lock.lock();
    // Clear the old prompt and wait for the new prompt from the child process.
    prompt.clearRetainingCapacity();
    prompt_lock.unlock();
}

pub fn main() !void {
    defer prompt.deinit();
    defer password.deinit();
    defer logmsg.deinit();

    initLogfile();
    defer if (logfile) |f| f.close();

    logi("Starting sqlplusplus", .{});
    defer logi("Exiting sqlplusplus", .{});

    const replxx = c.replxx_init();
    defer c.replxx_end(replxx);

    c.replxx_bind_key(replxx, c.REPLXX_KEY_CONTROL('P'), handleKeys, replxx);
    c.replxx_bind_key(replxx, c.REPLXX_KEY_CONTROL('N'), handleKeys, replxx);
    c.replxx_bind_key(replxx, c.REPLXX_KEY_CONTROL('J'), handleKeys, replxx);
    c.replxx_bind_key(replxx, c.REPLXX_KEY_CONTROL('C'), handleKeys, replxx);
    c.replxx_bind_key(replxx, c.REPLXX_KEY_CONTROL('D'), handleKeys, replxx);

    c.replxx_set_completion_callback(replxx, handleCompletion, null);
    c.replxx_set_modify_callback(replxx, handleModify, null);

    // History file has to be read before initializing readline, otherwise the order of entries
    // will be wrong.
    readHistoryFile(replxx);
    defer writeHistoryFile(replxx);

    createPipes() catch |err| {
        loge("Fatal error: createPipes failed ({})", .{err});
        return;
    };
    defer closePipes();

    stdin = win.GetStdHandle(win.STD_INPUT_HANDLE) catch |err| {
        loge("Fatal error: GetStdHandle failed (STDIN, {})", .{err});
        return;
    };

    stdout = win.GetStdHandle(win.STD_OUTPUT_HANDLE) catch |err| {
        loge("Fatal error: GetStdHandle failed (STDOUT, {})", .{err});
        return;
    };

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

    const wcmdln = getCommandLine() catch |err| {
        loge("Fatal error: getCommandLine failed ({})", .{err});
        return;
    };
    defer allocator.free(wcmdln);

    win.CreateProcessW(null, wcmdln.ptr, null, null, win.TRUE, 0, null, null, &sinfo, &pinfo) catch |err| {
        loge("Fatal error: CreateProcessW failed ({})", .{err});
        return;
    };
    defer win.CloseHandle(pinfo.hThread);
    defer win.CloseHandle(pinfo.hProcess);

    child_handle = pinfo.hProcess;

    var thread = std.Thread.spawn(.{}, syncChildOutput, .{replxx}) catch |err| {
        loge("Fatal error: std.Thread.spawn failed ({})", .{err});
        return;
    };

    while (isChildAlive()) {
        const p = try getPrompt(allocator);
        defer allocator.free(p);

        const line = c.replxx_input(replxx, p);
        if (line == null)
            break;

        clearPrompt();

        if (is_password_prompt.load(.monotonic)) {
            assert(password.items.len == std.mem.len(line));
            for (std.mem.span(line)) |character|
                assert(character == '*');
            try sendLine(password.items);
            password.clearRetainingCapacity();
            is_password_prompt.store(false, .monotonic);
        } else {
            try sendLine(std.mem.span(line));
            if (std.mem.len(line) > 0)
                c.replxx_history_add(replxx, line);
            if (std.mem.eql(u8, std.mem.span(line), "exit"))
                break;
        }

        sleep(std.time.ns_per_ms * 40);
    }

    win.WaitForSingleObjectEx(pinfo.hProcess, win.INFINITE, false) catch |err| {
        loge("WaitForSingleObjectEx failed: {}", .{err});
        return;
    };
    thread.join();
}
