/// Test client for the TCP tunnel - sends valid TigerBeetle-like frames
const std = @import("std");
const net = std.Io.net;
const Io = std.Io;

const header_size: u32 = 256;
const max_frame_size: u32 = 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    // Parse port from args
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next(); // skip program name
    if (args.next()) |port_str| {
        target_port = std.fmt.parseInt(u16, port_str, 10) catch 3000;
    }

    const io = init.io;

    std.debug.print("=== Multi-connection test (port {}) ===\n", .{target_port});

    // Sequential test
    std.debug.print("\n--- Sequential Test ---\n", .{});
    for (0..3) |i| {
        std.debug.print("Client {}: ", .{i});
        if (runClient(allocator, io, 2)) {
            std.debug.print("OK\n", .{});
        } else {
            std.debug.print("FAILED\n", .{});
        }
    }

    // Concurrent test
    std.debug.print("\n--- Concurrent Test ---\n", .{});
    var threads: [3]std.Thread = undefined;
    var results: [3]bool = .{ false, false, false };

    for (0..3) |i| {
        threads[i] = std.Thread.spawn(.{}, runClientThread, .{ allocator, io, i, &results[i] }) catch {
            std.debug.print("Failed to spawn thread {}\n", .{i});
            continue;
        };
    }

    for (threads) |t| {
        t.join();
    }

    std.debug.print("\nConcurrent results:\n", .{});
    for (0..3) |i| {
        std.debug.print("  Client {}: {s}\n", .{ i, if (results[i]) "OK" else "FAILED" });
    }
}

fn runClientThread(allocator: std.mem.Allocator, io: Io, id: usize, result: *bool) void {
    result.* = runClient(allocator, io, 2);
    std.debug.print("Client {}: {s}\n", .{ id, if (result.*) "OK" else "FAILED" });
}

var target_port: u16 = 3000;

fn runClient(allocator: std.mem.Allocator, io: Io, iterations: usize) bool {
    const tunnel_addr = net.IpAddress.parse("127.0.0.1", target_port) catch |err| {
        std.debug.print("Parse error: {}\n", .{err});
        return false;
    };

    const stream = net.IpAddress.connect(tunnel_addr, io, .{ .mode = .stream }) catch |err| {
        std.debug.print("Connect error: {}\n", .{err});
        return false;
    };
    defer stream.close(io);

    var buffer = allocator.alignedAlloc(u8, .@"16", max_frame_size) catch {
        return false;
    };
    defer allocator.free(buffer);

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);

    for (0..iterations) |_| {
        // Initialize a minimal frame (just header)
        @memset(buffer, 0);
        // Set size at offset 96
        const size_ptr: *u32 = @ptrCast(@alignCast(buffer.ptr + 96));
        size_ptr.* = header_size;

        // Send frame using interface
        writer.interface.writeAll(buffer[0..header_size]) catch |err| {
            std.debug.print("Write error: {}\n", .{err});
            return false;
        };
        writer.interface.flush() catch |err| {
            std.debug.print("Flush error: {}\n", .{err});
            return false;
        };

        // Read response header using interface
        reader.interface.readSliceAll(buffer[0..header_size]) catch |err| {
            std.debug.print("Read error: {}\n", .{err});
            return false;
        };

        // Check response size
        const resp_size = size_ptr.*;
        if (resp_size < header_size or resp_size > max_frame_size) {
            std.debug.print("Invalid response size: {}\n", .{resp_size});
            return false;
        }

        // Read body if any
        if (resp_size > header_size) {
            reader.interface.readSliceAll(buffer[header_size..resp_size]) catch |err| {
                std.debug.print("Read body error: {}\n", .{err});
                return false;
            };
        }
    }

    return true;
}
