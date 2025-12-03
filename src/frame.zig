//! TigerBeetle wire protocol framing.
//!
//! Handles reading and writing TigerBeetle message frames which consist of
//! a 256-byte header followed by a variable-length body (up to 1MB total).

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const Io = std.Io;

pub const header_size: u32 = 256;
pub const max_frame_size: u32 = 1024 * 1024; // 1 MiB
pub const io_buffer_size: usize = 8192;

/// Offset of size field in normal (plaintext) frames.
pub const size_offset_normal: usize = 96;

/// Offset of size field in encrypted frames (after tag only, nonce is implicit).
pub const size_offset_encrypted: usize = 16;

pub const Error = error{
    InvalidSize,
    InvalidCluster,
    EndOfStream,
    ReadFailed,
    WriteFailed,
};

/// TigerBeetle message header - 256 bytes, extern struct matching wire format.
pub const Header = extern struct {
    checksum: u128,
    checksum_padding: u128,
    checksum_body: u128,
    checksum_body_padding: u128,
    nonce_reserved: u128,
    cluster: u128,
    size: u32,
    epoch: u32,
    view: u32,
    release: u32,
    protocol: u16,
    command: u8,
    replica: u8,
    reserved_frame: [12]u8,
    reserved_command: [128]u8,

    comptime {
        assert(@sizeOf(Header) == header_size);
        assert(@offsetOf(Header, "size") == 96);
    }
};

/// Buffer for a complete TigerBeetle frame (header + body).
pub const FrameBuffer = struct {
    data: []align(16) u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator) Allocator.Error!FrameBuffer {
        return .{
            .data = try allocator.alignedAlloc(u8, .@"16", max_frame_size),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FrameBuffer) void {
        self.allocator.free(self.data);
    }

    pub fn header(self: *const FrameBuffer) *const Header {
        return @ptrCast(self.data.ptr);
    }
};

/// Read a complete TigerBeetle frame from the stream into the buffer.
/// Returns the frame size on success.
pub fn readFrame(reader: *Io.Reader, buffer: *FrameBuffer) Error!u32 {
    return readFrameWithOffset(reader, buffer, size_offset_normal);
}

/// Read a complete encrypted frame from the stream into the buffer.
/// Encrypted frames have the size field at offset 16 (after the 16-byte tag).
/// Returns the frame size on success.
pub fn readEncryptedFrame(reader: *Io.Reader, buffer: *FrameBuffer) Error!u32 {
    return readFrameWithOffset(reader, buffer, size_offset_encrypted);
}

fn readFrameWithOffset(reader: *Io.Reader, buffer: *FrameBuffer, size_offset: usize) Error!u32 {
    try reader.readSliceAll(buffer.data[0..header_size]);

    const size = mem.readInt(u32, buffer.data[size_offset..][0..4], .little);
    if (size < header_size or size > max_frame_size) {
        return error.InvalidSize;
    }

    if (size > header_size) {
        try reader.readSliceAll(buffer.data[header_size..size]);
    }

    return size;
}

/// Write frame data to the stream without flushing.
/// Call writer.flush() after writing all frames.
pub fn writeFrameNoFlush(writer: *Io.Writer, data: []const u8) Error!void {
    if (data.len < header_size or data.len > max_frame_size) {
        return error.InvalidSize;
    }
    try writer.writeAll(data);
}

/// Write frame data to the stream and flush.
/// For batch writes, use writeFrameNoFlush() and flush once at the end.
pub fn writeFrame(writer: *Io.Writer, data: []const u8) Error!void {
    try writeFrameNoFlush(writer, data);
    try writer.flush();
}

/// Read the frame body (data after the header) into the buffer.
/// The header must already be read into buffer.data[0..header_size].
/// Returns the total frame size on success.
pub fn readFrameBody(reader: *Io.Reader, buffer: *FrameBuffer, frame_size: u32) Error!u32 {
    if (frame_size < header_size or frame_size > max_frame_size) {
        return error.InvalidSize;
    }

    if (frame_size > header_size) {
        try reader.readSliceAll(buffer.data[header_size..frame_size]);
    }

    return frame_size;
}

/// Validate the cluster ID in a plaintext frame header.
/// If expected_cluster is null, validation is skipped.
/// Returns error.InvalidCluster if the cluster ID doesn't match.
pub fn validateCluster(buffer: *const FrameBuffer, expected_cluster: ?u128) Error!void {
    const cluster = if (expected_cluster) |expected| expected else return;
    const frame_cluster = buffer.header().cluster;
    if (frame_cluster != cluster) {
        return error.InvalidCluster;
    }
}

/// A pool of frame buffers for zero-copy response handling.
/// Uses a lock-free stack for thread-safe buffer acquisition/release.
pub const FrameBufferPool = struct {
    buffers: []FrameBuffer,
    /// Free list implemented as indices into buffers array.
    free_stack: []std.atomic.Value(u32),
    /// Stack top index (atomic for lock-free push/pop).
    stack_top: std.atomic.Value(u32),
    allocator: Allocator,

    /// Initialize a pool with the specified number of frame buffers.
    pub fn init(allocator: Allocator, count: u32) Allocator.Error!FrameBufferPool {
        const buffers = try allocator.alloc(FrameBuffer, count);
        errdefer allocator.free(buffers);

        for (buffers, 0..) |*buf, i| {
            buf.* = try FrameBuffer.init(allocator);
            errdefer {
                for (buffers[0..i]) |*b| b.deinit();
            }
        }

        const free_stack = try allocator.alloc(std.atomic.Value(u32), count);
        for (free_stack, 0..) |*slot, i| {
            slot.* = std.atomic.Value(u32).init(@intCast(i));
        }

        return .{
            .buffers = buffers,
            .free_stack = free_stack,
            .stack_top = std.atomic.Value(u32).init(count),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FrameBufferPool) void {
        for (self.buffers) |*buf| {
            buf.deinit();
        }
        self.allocator.free(self.buffers);
        self.allocator.free(self.free_stack);
    }

    /// Acquire a buffer from the pool. Returns null if pool is exhausted.
    pub fn acquire(self: *FrameBufferPool) ?*FrameBuffer {
        while (true) {
            const top = self.stack_top.load(.acquire);
            if (top == 0) return null;

            const new_top = top - 1;
            if (self.stack_top.cmpxchgWeak(top, new_top, .release, .monotonic)) |_| {
                continue;
            }

            const idx = self.free_stack[new_top].load(.acquire);
            return &self.buffers[idx];
        }
    }

    /// Release a buffer back to the pool.
    pub fn release(self: *FrameBufferPool, buffer: *FrameBuffer) void {
        const idx: u32 = @intCast((@intFromPtr(buffer) - @intFromPtr(self.buffers.ptr)) / @sizeOf(FrameBuffer));

        while (true) {
            const top = self.stack_top.load(.acquire);
            if (top >= self.free_stack.len) {
                @panic("FrameBufferPool: double release detected");
            }

            self.free_stack[top].store(idx, .release);
            if (self.stack_top.cmpxchgWeak(top, top + 1, .release, .monotonic)) |_| {
                continue;
            }
            return;
        }
    }

    /// Get the number of available buffers.
    pub fn available(self: *const FrameBufferPool) u32 {
        return self.stack_top.load(.acquire);
    }
};

test "Header has correct size and layout" {
    try testing.expectEqual(@as(usize, 256), @sizeOf(Header));
    try testing.expectEqual(@as(usize, 96), @offsetOf(Header, "size"));
}

test "FrameBuffer allocation" {
    const allocator = testing.allocator;
    var buf = try FrameBuffer.init(allocator);
    defer buf.deinit();

    try testing.expectEqual(@as(usize, max_frame_size), buf.data.len);
}

test "FrameBufferPool basic operations" {
    const allocator = testing.allocator;
    var pool = try FrameBufferPool.init(allocator, 4);
    defer pool.deinit();

    // Should have 4 available buffers
    try testing.expectEqual(@as(u32, 4), pool.available());

    // Acquire all buffers
    const buf1 = pool.acquire();
    try testing.expect(buf1 != null);
    try testing.expectEqual(@as(u32, 3), pool.available());

    const buf2 = pool.acquire();
    try testing.expect(buf2 != null);
    try testing.expectEqual(@as(u32, 2), pool.available());

    const buf3 = pool.acquire();
    try testing.expect(buf3 != null);
    try testing.expectEqual(@as(u32, 1), pool.available());

    const buf4 = pool.acquire();
    try testing.expect(buf4 != null);
    try testing.expectEqual(@as(u32, 0), pool.available());

    // Pool should be exhausted
    const buf5 = pool.acquire();
    try testing.expect(buf5 == null);

    // Release some buffers
    pool.release(buf2.?);
    try testing.expectEqual(@as(u32, 1), pool.available());

    pool.release(buf4.?);
    try testing.expectEqual(@as(u32, 2), pool.available());

    // Should be able to acquire again
    const buf6 = pool.acquire();
    try testing.expect(buf6 != null);
    try testing.expectEqual(@as(u32, 1), pool.available());

    // Clean up
    pool.release(buf1.?);
    pool.release(buf3.?);
    pool.release(buf6.?);
    try testing.expectEqual(@as(u32, 4), pool.available());
}

test "FrameBufferPool concurrent stress test" {
    const allocator = testing.allocator;
    const pool_size: u32 = 16;
    const num_threads: usize = 8;
    const ops_per_thread: usize = 1000;

    var pool = try FrameBufferPool.init(allocator, pool_size);
    defer pool.deinit();

    const ThreadContext = struct {
        pool: *FrameBufferPool,
        success_count: std.atomic.Value(u64),
        acquire_count: std.atomic.Value(u64),
        release_count: std.atomic.Value(u64),
        thread_counter: std.atomic.Value(u64),
    };

    var ctx = ThreadContext{
        .pool = &pool,
        .success_count = std.atomic.Value(u64).init(0),
        .acquire_count = std.atomic.Value(u64).init(0),
        .release_count = std.atomic.Value(u64).init(0),
        .thread_counter = std.atomic.Value(u64).init(0),
    };

    const worker = struct {
        fn run(context: *ThreadContext) void {
            // Use thread counter as seed for deterministic but varied behavior
            const seed = context.thread_counter.fetchAdd(1, .monotonic);
            var prng = std.Random.DefaultPrng.init(seed);
            const random = prng.random();

            var held_buffers: [4]?*FrameBuffer = .{ null, null, null, null };
            var held_count: usize = 0;

            for (0..ops_per_thread) |_| {
                // Randomly acquire or release
                if (held_count == 0 or (held_count < 4 and random.boolean())) {
                    // Try to acquire
                    if (context.pool.acquire()) |buf| {
                        held_buffers[held_count] = buf;
                        held_count += 1;
                        _ = context.acquire_count.fetchAdd(1, .monotonic);
                    }
                } else {
                    // Release a random buffer
                    const idx = random.uintLessThan(usize, held_count);
                    if (held_buffers[idx]) |buf| {
                        context.pool.release(buf);
                        _ = context.release_count.fetchAdd(1, .monotonic);
                        held_buffers[idx] = held_buffers[held_count - 1];
                        held_buffers[held_count - 1] = null;
                        held_count -= 1;
                    }
                }
            }

            // Release all remaining buffers
            for (0..held_count) |i| {
                if (held_buffers[i]) |buf| {
                    context.pool.release(buf);
                    _ = context.release_count.fetchAdd(1, .monotonic);
                }
            }

            _ = context.success_count.fetchAdd(1, .monotonic);
        }
    }.run;

    // Spawn worker threads
    var threads: [num_threads]std.Thread = undefined;
    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, worker, .{&ctx});
    }

    // Wait for all threads
    for (threads) |t| {
        t.join();
    }

    // Verify all threads completed
    try testing.expectEqual(@as(u64, num_threads), ctx.success_count.load(.acquire));

    // Verify acquire/release counts match
    try testing.expectEqual(ctx.acquire_count.load(.acquire), ctx.release_count.load(.acquire));

    // Verify pool is fully restored
    try testing.expectEqual(pool_size, pool.available());
}

test "FrameBufferPool exhaustion under contention" {
    const allocator = testing.allocator;
    const pool_size: u32 = 4;
    const num_threads: usize = 16;

    var pool = try FrameBufferPool.init(allocator, pool_size);
    defer pool.deinit();

    var acquired_count = std.atomic.Value(u32).init(0);
    var exhaustion_count = std.atomic.Value(u32).init(0);
    var barrier = std.atomic.Value(u32).init(0);

    const worker = struct {
        fn run(p: *FrameBufferPool, acquired: *std.atomic.Value(u32), exhausted: *std.atomic.Value(u32), bar: *std.atomic.Value(u32), n_threads: u32) void {
            // Wait for all threads to start
            _ = bar.fetchAdd(1, .release);
            while (bar.load(.acquire) < n_threads) {
                std.atomic.spinLoopHint();
            }

            // Try to acquire
            if (p.acquire()) |buf| {
                _ = acquired.fetchAdd(1, .release);
                // Hold briefly using spin loop
                var spin: u32 = 0;
                while (spin < 10000) : (spin += 1) {
                    std.atomic.spinLoopHint();
                }
                p.release(buf);
            } else {
                _ = exhausted.fetchAdd(1, .release);
            }
        }
    }.run;

    var threads: [num_threads]std.Thread = undefined;
    for (0..num_threads) |i| {
        threads[i] = try std.Thread.spawn(.{}, worker, .{ &pool, &acquired_count, &exhaustion_count, &barrier, num_threads });
    }

    for (threads) |t| {
        t.join();
    }

    const acquired = acquired_count.load(.acquire);
    const exhausted = exhaustion_count.load(.acquire);

    // Total should equal num_threads
    try testing.expectEqual(@as(u32, num_threads), acquired + exhausted);

    // Should have some exhaustion events (contention)
    try testing.expect(exhausted > 0);

    // Pool should be fully restored
    try testing.expectEqual(pool_size, pool.available());
}
