//! Stress tests for tigertunnel TCP tunnel
//!
//! Tests concurrent connections, high throughput, and connection pool behavior.
//! Run with: zig build stress-test
//!
//! For full integration testing, start the tunnel first:
//!   Terminal 1: zig build run -- server -p :3000,127.0.0.1:3001 -k tmp/server.key
//!   Terminal 2: zig build run -- client -p :4000,127.0.0.1:3000 -k tmp/client.key
//!   Terminal 3: zig build stress-test

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const net = Io.net;
const mem = std.mem;
const Thread = std.Thread;
const Instant = std.time.Instant;

const header_size: u32 = 256;
const max_frame_size: u32 = 1024 * 1024;

// Configuration
const Config = struct {
    // Number of concurrent connections for stress tests
    concurrent_connections: u32 = 50,
    // Number of messages per connection
    messages_per_connection: u32 = 100,
    // Timeout for individual operations (ms)
    timeout_ms: u64 = 5000,
    // Target port (use 3001 for direct mock server, 4000 for through tunnel)
    target_port: u16 = 3001,
    // Whether to use the mock server (true) or real TigerBeetle (false)
    use_mock: bool = true,
};

const config = Config{};

// Test result tracking
const TestResult = struct {
    success: bool = false,
    frames_sent: u64 = 0,
    frames_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    latency_sum_ns: u64 = 0,
    errors: u32 = 0,
    error_message: ?[]const u8 = null,
};

/// Create a TigerBeetle-style frame with the given payload size
fn createFrame(buffer: []u8, payload_size: u32, sequence: u32) u32 {
    const total_size = header_size + payload_size;
    std.debug.assert(total_size <= max_frame_size);
    std.debug.assert(buffer.len >= total_size);

    // Clear header
    @memset(buffer[0..header_size], 0);

    // Set size at offset 96
    mem.writeInt(u32, buffer[96..100], total_size, .little);

    // Set command to 0 (ping)
    buffer[106] = 0;

    // Fill payload with sequence number pattern
    if (payload_size > 0) {
        for (0..payload_size) |i| {
            buffer[header_size + i] = @truncate((sequence +% @as(u32, @intCast(i))) & 0xFF);
        }
    }

    return total_size;
}

/// Verify a received frame matches what we sent
fn verifyFrame(buffer: []const u8, expected_size: u32, sequence: u32) bool {
    if (buffer.len < expected_size) return false;

    // Check size field
    const size = mem.readInt(u32, buffer[96..100], .little);
    if (size != expected_size) return false;

    // Verify payload pattern
    const payload_size = expected_size - header_size;
    for (0..payload_size) |i| {
        const expected: u8 = @truncate((sequence +% @as(u32, @intCast(i))) & 0xFF);
        if (buffer[header_size + i] != expected) return false;
    }

    return true;
}

/// Single client connection that sends and receives frames
fn runClient(
    allocator: mem.Allocator,
    addr: net.IpAddress,
    client_id: u32,
    num_messages: u32,
    result: *TestResult,
) void {
    var io_backend = Io.Threaded.init(allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    const stream = net.IpAddress.connect(addr, io, .{ .mode = .stream }) catch |err| {
        result.error_message = @errorName(err);
        result.errors += 1;
        return;
    };
    defer stream.close(io);

    var buffer: [max_frame_size]u8 = undefined;
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);

    var i: u32 = 0;
    while (i < num_messages) : (i += 1) {
        // Vary payload size: 0, 256, 512, 1024, 4096, etc.
        const payload_sizes = [_]u32{ 0, 256, 512, 1024, 4096, 8192 };
        const payload_size = payload_sizes[i % payload_sizes.len];
        const sequence = client_id * 1000000 + i;

        const frame_size = createFrame(&buffer, payload_size, sequence);
        const start_time = Instant.now() catch {
            result.error_message = "timer unavailable";
            result.errors += 1;
            return;
        };

        // Send frame
        writer.interface.writeAll(buffer[0..frame_size]) catch |err| {
            result.error_message = @errorName(err);
            result.errors += 1;
            return;
        };
        writer.interface.flush() catch |err| {
            result.error_message = @errorName(err);
            result.errors += 1;
            return;
        };

        result.frames_sent += 1;
        result.bytes_sent += frame_size;

        // Read response header
        reader.interface.readSliceAll(buffer[0..header_size]) catch |err| {
            result.error_message = @errorName(err);
            result.errors += 1;
            return;
        };

        // Get response size and read body
        const resp_size = mem.readInt(u32, buffer[96..100], .little);
        if (resp_size < header_size or resp_size > max_frame_size) {
            result.error_message = "invalid response size";
            result.errors += 1;
            return;
        }

        if (resp_size > header_size) {
            reader.interface.readSliceAll(buffer[header_size..resp_size]) catch |err| {
                result.error_message = @errorName(err);
                result.errors += 1;
                return;
            };
        }

        const end_time = Instant.now() catch {
            result.error_message = "timer unavailable";
            result.errors += 1;
            return;
        };
        result.latency_sum_ns += end_time.since(start_time);
        result.frames_received += 1;
        result.bytes_received += resp_size;

        // Verify response matches request
        if (!verifyFrame(buffer[0..resp_size], frame_size, sequence)) {
            result.error_message = "response verification failed";
            result.errors += 1;
            return;
        }
    }

    result.success = true;
}

// ============================================================================
// Stress Test: Concurrent Connections
// ============================================================================

fn stressConcurrentConnections(allocator: mem.Allocator) !void {
    std.debug.print("\n=== Stress Test: Concurrent Connections ===\n", .{});
    std.debug.print("Connections: {}, Messages/conn: {}\n", .{ config.concurrent_connections, config.messages_per_connection });

    const addr = net.IpAddress{ .ip4 = net.Ip4Address.loopback(config.target_port) };

    var threads: []Thread = try allocator.alloc(Thread, config.concurrent_connections);
    defer allocator.free(threads);

    var results: []TestResult = try allocator.alloc(TestResult, config.concurrent_connections);
    defer allocator.free(results);

    // Initialize results
    for (results) |*r| {
        r.* = TestResult{};
    }

    const start_time = try Instant.now();

    // Start all client threads
    for (0..config.concurrent_connections) |i| {
        threads[i] = try Thread.spawn(.{}, runClient, .{
            allocator,
            addr,
            @as(u32, @intCast(i)),
            config.messages_per_connection,
            &results[i],
        });
    }

    // Wait for all threads
    for (threads) |t| {
        t.join();
    }

    const end_time = try Instant.now();
    const elapsed_ns = end_time.since(start_time);
    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;

    // Aggregate results
    var total_success: u32 = 0;
    var total_frames_sent: u64 = 0;
    var total_frames_received: u64 = 0;
    var total_bytes_sent: u64 = 0;
    var total_bytes_received: u64 = 0;
    var total_latency_ns: u64 = 0;
    var total_errors: u32 = 0;

    for (results, 0..) |r, i| {
        if (r.success) {
            total_success += 1;
        } else if (r.error_message) |msg| {
            std.debug.print("  Client {} failed: {s}\n", .{ i, msg });
        }
        total_frames_sent += r.frames_sent;
        total_frames_received += r.frames_received;
        total_bytes_sent += r.bytes_sent;
        total_bytes_received += r.bytes_received;
        total_latency_ns += r.latency_sum_ns;
        total_errors += r.errors;
    }

    const avg_latency_us = if (total_frames_received > 0)
        (total_latency_ns / total_frames_received) / 1000
    else
        0;

    const throughput_msg_per_sec = if (elapsed_ms > 0)
        (total_frames_sent * 1000) / elapsed_ms
    else
        0;

    const throughput_mb_per_sec = if (elapsed_ms > 0)
        @as(f64, @floatFromInt(total_bytes_sent)) / @as(f64, @floatFromInt(elapsed_ms)) / 1000.0
    else
        0;

    std.debug.print("\nResults:\n", .{});
    std.debug.print("  Successful connections: {}/{}\n", .{ total_success, config.concurrent_connections });
    std.debug.print("  Total frames: {} sent, {} received\n", .{ total_frames_sent, total_frames_received });
    std.debug.print("  Total bytes: {} sent, {} received\n", .{ total_bytes_sent, total_bytes_received });
    std.debug.print("  Errors: {}\n", .{total_errors});
    std.debug.print("  Elapsed time: {} ms\n", .{elapsed_ms});
    std.debug.print("  Throughput: {} msg/s, {d:.2} MB/s\n", .{ throughput_msg_per_sec, throughput_mb_per_sec });
    std.debug.print("  Avg latency: {} us\n", .{avg_latency_us});

    // Verify all succeeded
    if (total_success != config.concurrent_connections) {
        return error.TestFailed;
    }
    if (total_frames_sent != total_frames_received) {
        return error.TestFailed;
    }
}

// ============================================================================
// Stress Test: High Throughput (Single Connection)
// ============================================================================

fn stressHighThroughput(allocator: mem.Allocator) !void {
    std.debug.print("\n=== Stress Test: High Throughput ===\n", .{});

    const num_messages: u32 = 1000;
    const payload_size: u32 = 32768; // 32KB payloads

    std.debug.print("Messages: {}, Payload size: {} bytes\n", .{ num_messages, payload_size });

    var io_backend = Io.Threaded.init(allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    const addr = net.IpAddress{ .ip4 = net.Ip4Address.loopback(config.target_port) };
    const stream = net.IpAddress.connect(addr, io, .{ .mode = .stream }) catch |err| {
        std.debug.print("Failed to connect: {}\n", .{err});
        return error.ConnectionFailed;
    };
    defer stream.close(io);

    var buffer = try allocator.alignedAlloc(u8, .@"16", max_frame_size);
    defer allocator.free(buffer);

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);

    var total_bytes: u64 = 0;
    const start_time = try Instant.now();

    var i: u32 = 0;
    while (i < num_messages) : (i += 1) {
        const frame_size = createFrame(buffer, payload_size, i);

        // Send
        writer.interface.writeAll(buffer[0..frame_size]) catch |err| {
            std.debug.print("Write error at message {}: {}\n", .{ i, err });
            return error.WriteFailed;
        };
        writer.interface.flush() catch return error.WriteFailed;

        // Receive
        reader.interface.readSliceAll(buffer[0..header_size]) catch |err| {
            std.debug.print("Read header error at message {}: {}\n", .{ i, err });
            return error.ReadFailed;
        };

        const resp_size = mem.readInt(u32, buffer[96..100], .little);
        if (resp_size > header_size) {
            reader.interface.readSliceAll(buffer[header_size..resp_size]) catch |err| {
                std.debug.print("Read body error at message {}: {}\n", .{ i, err });
                return error.ReadFailed;
            };
        }

        total_bytes += frame_size + resp_size;
    }

    const end_time = try Instant.now();
    const elapsed_ns = end_time.since(start_time);
    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;

    const throughput_msg_per_sec = if (elapsed_ms > 0)
        (num_messages * 1000) / elapsed_ms
    else
        0;

    const throughput_mb_per_sec = if (elapsed_ms > 0)
        @as(f64, @floatFromInt(total_bytes)) / @as(f64, @floatFromInt(elapsed_ms)) / 1000.0
    else
        0;

    std.debug.print("\nResults:\n", .{});
    std.debug.print("  Messages: {} sent and received\n", .{num_messages});
    std.debug.print("  Total bytes: {} ({d:.2} MB)\n", .{ total_bytes, @as(f64, @floatFromInt(total_bytes)) / 1024.0 / 1024.0 });
    std.debug.print("  Elapsed time: {} ms\n", .{elapsed_ms});
    std.debug.print("  Throughput: {} msg/s, {d:.2} MB/s\n", .{ throughput_msg_per_sec, throughput_mb_per_sec });
}

// ============================================================================
// Stress Test: Rapid Connect/Disconnect
// ============================================================================

fn stressRapidConnectDisconnect(allocator: mem.Allocator) !void {
    std.debug.print("\n=== Stress Test: Rapid Connect/Disconnect ===\n", .{});

    const num_cycles: u32 = 100;
    std.debug.print("Connection cycles: {}\n", .{num_cycles});

    var io_backend = Io.Threaded.init(allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    const addr = net.IpAddress{ .ip4 = net.Ip4Address.loopback(config.target_port) };
    var buffer: [header_size]u8 = undefined;

    var successful_cycles: u32 = 0;
    const start_time = try Instant.now();

    var i: u32 = 0;
    while (i < num_cycles) : (i += 1) {
        // Connect
        const stream = net.IpAddress.connect(addr, io, .{ .mode = .stream }) catch {
            continue;
        };

        // Send minimal frame
        @memset(&buffer, 0);
        mem.writeInt(u32, buffer[96..100], header_size, .little);

        var write_buf: [8192]u8 = undefined;
        var writer = stream.writer(io, &write_buf);
        writer.interface.writeAll(&buffer) catch {
            stream.close(io);
            continue;
        };
        writer.interface.flush() catch {
            stream.close(io);
            continue;
        };

        // Receive response
        var read_buf: [8192]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        reader.interface.readSliceAll(&buffer) catch {
            stream.close(io);
            continue;
        };

        // Verify response
        const resp_size = mem.readInt(u32, buffer[96..100], .little);
        if (resp_size == header_size) {
            successful_cycles += 1;
        }

        // Disconnect
        stream.close(io);
    }

    const end_time = try Instant.now();
    const elapsed_ns = end_time.since(start_time);
    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;

    const cycles_per_sec = if (elapsed_ms > 0)
        (num_cycles * 1000) / elapsed_ms
    else
        0;

    std.debug.print("\nResults:\n", .{});
    std.debug.print("  Successful cycles: {}/{}\n", .{ successful_cycles, num_cycles });
    std.debug.print("  Elapsed time: {} ms\n", .{elapsed_ms});
    std.debug.print("  Rate: {} connections/s\n", .{cycles_per_sec});

    if (successful_cycles < num_cycles * 9 / 10) {
        return error.TooManyFailures;
    }
}

// ============================================================================
// Stress Test: Large Payloads
// ============================================================================

fn stressLargePayloads(allocator: mem.Allocator) !void {
    std.debug.print("\n=== Stress Test: Large Payloads ===\n", .{});

    const payload_sizes = [_]u32{ 64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 768 * 1024 };

    var io_backend = Io.Threaded.init(allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    const addr = net.IpAddress{ .ip4 = net.Ip4Address.loopback(config.target_port) };
    const stream = net.IpAddress.connect(addr, io, .{ .mode = .stream }) catch |err| {
        std.debug.print("Failed to connect: {}\n", .{err});
        return error.ConnectionFailed;
    };
    defer stream.close(io);

    var buffer = try allocator.alignedAlloc(u8, .@"16", max_frame_size);
    defer allocator.free(buffer);

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);

    for (payload_sizes, 0..) |payload_size, i| {
        const frame_size = createFrame(buffer, payload_size, @intCast(i));

        std.debug.print("  Testing payload size: {} bytes... ", .{payload_size});

        const start_time = Instant.now() catch {
            std.debug.print("FAILED (timer unavailable)\n", .{});
            return error.TimerUnavailable;
        };

        // Send
        writer.interface.writeAll(buffer[0..frame_size]) catch |err| {
            std.debug.print("FAILED (write: {})\n", .{err});
            return error.WriteFailed;
        };
        writer.interface.flush() catch return error.WriteFailed;

        // Receive
        reader.interface.readSliceAll(buffer[0..header_size]) catch |err| {
            std.debug.print("FAILED (read header: {})\n", .{err});
            return error.ReadFailed;
        };

        const resp_size = mem.readInt(u32, buffer[96..100], .little);
        if (resp_size > header_size) {
            reader.interface.readSliceAll(buffer[header_size..resp_size]) catch |err| {
                std.debug.print("FAILED (read body: {})\n", .{err});
                return error.ReadFailed;
            };
        }

        const end_time = Instant.now() catch {
            std.debug.print("FAILED (timer unavailable)\n", .{});
            return error.TimerUnavailable;
        };
        const latency_us = end_time.since(start_time) / 1000;

        if (resp_size != frame_size) {
            std.debug.print("FAILED (size mismatch: {} vs {})\n", .{ resp_size, frame_size });
            return error.SizeMismatch;
        }

        std.debug.print("OK ({} us)\n", .{latency_us});
    }

    std.debug.print("\nAll large payload tests passed!\n", .{});
}

// ============================================================================
// Stress Test: Burst Traffic
// ============================================================================

fn stressBurstTraffic(allocator: mem.Allocator) !void {
    std.debug.print("\n=== Stress Test: Burst Traffic ===\n", .{});

    const burst_size: u32 = 50;
    const num_bursts: u32 = 10;
    const pause_between_bursts_ms: i64 = 100;

    std.debug.print("Bursts: {}, Messages/burst: {}\n", .{ num_bursts, burst_size });

    var io_backend = Io.Threaded.init(allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    const addr = net.IpAddress{ .ip4 = net.Ip4Address.loopback(config.target_port) };
    const stream = net.IpAddress.connect(addr, io, .{ .mode = .stream }) catch |err| {
        std.debug.print("Failed to connect: {}\n", .{err});
        return error.ConnectionFailed;
    };
    defer stream.close(io);

    var buffer: [max_frame_size]u8 = undefined;
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);

    var total_sent: u32 = 0;
    var total_received: u32 = 0;
    const start_time = try Instant.now();

    var burst: u32 = 0;
    while (burst < num_bursts) : (burst += 1) {
        // Send burst of messages quickly
        var i: u32 = 0;
        while (i < burst_size) : (i += 1) {
            const sequence = burst * burst_size + i;
            const frame_size = createFrame(&buffer, 1024, sequence);

            writer.interface.writeAll(buffer[0..frame_size]) catch return error.WriteFailed;
            total_sent += 1;
        }
        writer.interface.flush() catch return error.WriteFailed;

        // Receive all responses
        i = 0;
        while (i < burst_size) : (i += 1) {
            reader.interface.readSliceAll(buffer[0..header_size]) catch return error.ReadFailed;
            const resp_size = mem.readInt(u32, buffer[96..100], .little);
            if (resp_size > header_size) {
                reader.interface.readSliceAll(buffer[header_size..resp_size]) catch return error.ReadFailed;
            }
            total_received += 1;
        }

        // Pause between bursts
        if (burst < num_bursts - 1) {
            Io.sleep(io, Io.Duration.fromMilliseconds(pause_between_bursts_ms), .awake) catch {};
        }
    }

    const end_time = try Instant.now();
    const elapsed_ns = end_time.since(start_time);
    const elapsed_ms = elapsed_ns / std.time.ns_per_ms;

    std.debug.print("\nResults:\n", .{});
    std.debug.print("  Sent: {}, Received: {}\n", .{ total_sent, total_received });
    std.debug.print("  Elapsed time: {} ms\n", .{elapsed_ms});

    if (total_sent != total_received) {
        return error.MessageMismatch;
    }
}

// ============================================================================
// Mock Echo Server
// ============================================================================

var mock_server_running = std.atomic.Value(bool).init(false);

fn runMockServer(allocator: mem.Allocator) void {
    var io_backend = Io.Threaded.init(allocator, .{});
    defer io_backend.deinit();
    const io = io_backend.io();

    const listen_addr = net.IpAddress{ .ip4 = net.Ip4Address.loopback(config.target_port) };

    var server = net.IpAddress.listen(listen_addr, io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("Mock server failed to bind: {}\n", .{err});
        return;
    };
    defer server.deinit(io);

    mock_server_running.store(true, .release);
    std.debug.print("Mock echo server listening on :{}\n", .{config.target_port});

    while (mock_server_running.load(.acquire)) {
        const stream = server.accept(io) catch continue;

        // Handle each client in a new thread
        _ = Thread.spawn(.{}, handleMockClient, .{ allocator, stream, io }) catch {
            stream.close(io);
            continue;
        };
    }
}

fn handleMockClient(_: mem.Allocator, stream: net.Stream, io: Io) void {
    defer stream.close(io);

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &write_buf);

    var frame_buf: [max_frame_size]u8 = undefined;

    while (mock_server_running.load(.acquire)) {
        // Read header
        reader.interface.readSliceAll(frame_buf[0..header_size]) catch break;

        // Get size
        const size = mem.readInt(u32, frame_buf[96..100], .little);
        if (size < header_size or size > max_frame_size) break;

        // Read body
        if (size > header_size) {
            reader.interface.readSliceAll(frame_buf[header_size..size]) catch break;
        }

        // Echo back
        writer.interface.writeAll(frame_buf[0..size]) catch break;
        writer.interface.flush() catch break;
    }
}

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("========================================\n", .{});
    std.debug.print("   tigertunnel Stress Test Suite\n", .{});
    std.debug.print("========================================\n", .{});
    std.debug.print("Target port: {}\n", .{config.target_port});

    // Start mock server if configured
    if (config.use_mock) {
        _ = try Thread.spawn(.{}, runMockServer, .{allocator});

        // Wait for server to start
        while (!mock_server_running.load(.acquire)) {
            std.posix.nanosleep(0, 10 * std.time.ns_per_ms);
        }
        std.posix.nanosleep(0, 50 * std.time.ns_per_ms); // Extra time for listener
    }

    defer {
        if (config.use_mock) {
            mock_server_running.store(false, .release);
        }
    }

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Run tests
    const TestFn = *const fn (mem.Allocator) anyerror!void;
    const tests = [_]struct { name: []const u8, func: TestFn }{
        .{ .name = "Concurrent Connections", .func = stressConcurrentConnections },
        .{ .name = "High Throughput", .func = stressHighThroughput },
        .{ .name = "Rapid Connect/Disconnect", .func = stressRapidConnectDisconnect },
        .{ .name = "Large Payloads", .func = stressLargePayloads },
        .{ .name = "Burst Traffic", .func = stressBurstTraffic },
    };

    for (tests) |t| {
        t.func(allocator) catch |err| {
            std.debug.print("\n[FAILED] {s}: {}\n", .{ t.name, err });
            failed += 1;
            continue;
        };
        std.debug.print("\n[PASSED] {s}\n", .{t.name});
        passed += 1;
    }

    std.debug.print("\n========================================\n", .{});
    std.debug.print("Summary: {} passed, {} failed\n", .{ passed, failed });
    std.debug.print("========================================\n", .{});

    if (failed > 0) {
        return error.TestsFailed;
    }
}
