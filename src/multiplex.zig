//! Connection multiplexing and handshake protocol.
//!
//! Provides:
//! - Multiplexing protocol for routing multiple client sessions over pooled TCP connections
//! - Client/server handshake with PSK authentication and optional KEM key exchange
//! - Connection pool management with health tracking and automatic reconnection

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const Io = std.Io;
const net = Io.net;

const frame = @import("frame.zig");
const crypto = @import("crypto.zig");

const log = std.log.scoped(.multiplex);

/// Multiplexing header prepended to each frame.
/// This is sent over the wire before every TigerBeetle frame.
pub const MuxHeader = extern struct {
    /// Magic number to identify multiplexed protocol
    magic: u32 = magic_value,
    /// Stream identifier - uniquely identifies a client connection
    stream_id: u32,
    /// Frame type
    frame_type: FrameType,
    /// Reserved for future use
    reserved: [3]u8 = .{ 0, 0, 0 },

    pub const size: usize = 12;

    comptime {
        assert(@sizeOf(MuxHeader) == size);
    }
};

pub const magic_value: u32 = 0x5A_4D_55_58; // "ZMUX" in little-endian

pub const FrameType = enum(u8) {
    /// Regular data frame containing a TigerBeetle message
    data = 0,
    /// Stream open notification (client -> server)
    stream_open = 1,
    /// Stream close notification (either direction)
    stream_close = 2,
};

pub const Error = error{
    InvalidMagic,
    InvalidFrameType,
    StreamNotFound,
    StreamAlreadyExists,
    EndOfStream,
    ReadFailed,
    WriteFailed,
    InvalidSize,
    KeyIdMismatch,
    KeyRejected,
    ServerAuthFailed,
    ClientAuthFailed,
};

/// Compute the server authentication hash.
/// hash = SHA256(shared_key || client_random || server_random || cluster_id)
pub fn computeAuthHash(
    shared_key: *const [32]u8,
    client_random: *const [16]u8,
    server_random: *const [16]u8,
    cluster_id: u128,
) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(shared_key);
    hasher.update(client_random);
    hasher.update(server_random);
    hasher.update(&mem.toBytes(cluster_id));
    return hasher.finalResult();
}

/// Read a multiplexing header from the stream.
pub fn readMuxHeader(reader: *Io.Reader) Error!MuxHeader {
    var header: MuxHeader = undefined;
    try reader.readSliceAll(mem.asBytes(&header));

    if (header.magic != magic_value) {
        return error.InvalidMagic;
    }

    // Validate that the frame_type value is a valid enum member
    const frame_type_raw: u8 = @intFromEnum(header.frame_type);
    if (frame_type_raw > @intFromEnum(FrameType.stream_close)) {
        return error.InvalidFrameType;
    }

    return header;
}

/// Read a multiplexing header and frame header together using vectored I/O.
/// Returns the mux header and frame size. The frame header is read into the buffer.
/// This combines two reads into one system call for data frames.
pub fn readMuxHeaderAndFrameHeader(
    reader: *Io.Reader,
    buffer: *frame.FrameBuffer,
    size_offset: usize,
) Error!struct { mux_header: MuxHeader, frame_size: u32 } {
    var mux_header: MuxHeader = undefined;

    var iovecs: [2][]u8 = .{
        mem.asBytes(&mux_header),
        buffer.data[0..frame.header_size],
    };
    reader.readVecAll(&iovecs) catch {
        return error.ReadFailed;
    };

    if (mux_header.magic != magic_value) {
        return error.InvalidMagic;
    }

    const frame_type_raw: u8 = @intFromEnum(mux_header.frame_type);
    if (frame_type_raw > @intFromEnum(FrameType.stream_close)) {
        return error.InvalidFrameType;
    }

    if (mux_header.frame_type != .data) {
        return .{ .mux_header = mux_header, .frame_size = 0 };
    }

    const size = mem.readInt(u32, buffer.data[size_offset..][0..4], .little);
    if (size < frame.header_size or size > frame.max_frame_size) {
        return error.InvalidSize;
    }

    return .{ .mux_header = mux_header, .frame_size = size };
}

/// Write a multiplexing header to the stream.
pub fn writeMuxHeader(writer: *Io.Writer, header: MuxHeader) Error!void {
    writer.writeAll(mem.asBytes(&header)) catch {
        return error.WriteFailed;
    };
}

/// Write a multiplexing header and frame data to the stream using vectored I/O.
/// Does not flush - call writer.flush() after writing all frames.
pub fn writeMuxFrameNoFlush(writer: *Io.Writer, header: MuxHeader, data: []const u8) Error!void {
    var iovecs: [2][]const u8 = .{
        mem.asBytes(&header),
        data,
    };
    writer.writeVecAll(&iovecs) catch {
        return error.WriteFailed;
    };
}

/// Write a multiplexing header and frame data to the stream using vectored I/O.
/// This combines the mux header and frame data into a single system call and flushes.
/// For batch writes, use writeMuxFrameNoFlush() and flush once at the end.
pub fn writeMuxFrame(writer: *Io.Writer, header: MuxHeader, data: []const u8) Error!void {
    try writeMuxFrameNoFlush(writer, header, data);
    writer.flush() catch {
        return error.WriteFailed;
    };
}

/// Protocol version identifier
pub const protocol_version: u8 = 1;

/// Operation types for client hello
pub const Operation = enum(u8) {
    connect = 0,
    kemconnect = 1,
    _,
};

/// Handshake data sent by client
pub const ClientHello = struct {
    version: u8,
    operation: Operation,
    key_id: u64,
    client_random: [16]u8,
    timestamp: u64,
    hash: [32]u8,
};

/// Client hello size: 1 byte version + 1 byte operation + 8 bytes key_id +
/// 16 bytes client_random + 8 bytes timestamp + 32 bytes hash
pub const client_hello_size: usize = 1 + 1 + 8 + 16 + 8 + 32;

/// Context string for PSK client hello hash (domain separation).
const psk_hello_context = "tigertunnel-psk-hello-v1";

/// Context string for KEM client hello hash (domain separation).
const kem_hello_context = "tigertunnel-kem-hello-v1";

/// Compute client hello authentication hash.
/// hash = SHA256(context || version || operation || key_id || client_random || timestamp || key)
pub fn computeClientHelloHash(
    version: u8,
    operation: Operation,
    key_id: u64,
    client_random: *const [16]u8,
    timestamp: u64,
    shared_key: *const [32]u8,
) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(psk_hello_context);
    hasher.update(&[_]u8{version});
    hasher.update(&[_]u8{@intFromEnum(operation)});
    hasher.update(&mem.toBytes(key_id));
    hasher.update(client_random);
    hasher.update(&mem.toBytes(timestamp));
    hasher.update(shared_key);
    return hasher.finalResult();
}

/// Compute KEM client hello authentication hash.
/// hash = SHA256(context || version || operation || key_id || kem_key_id || client_random || timestamp || key)
pub fn computeKemClientHelloHash(
    version: u8,
    operation: Operation,
    key_id: u64,
    kem_key_id: u64,
    client_random: *const [16]u8,
    timestamp: u64,
    shared_key: *const [32]u8,
) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(kem_hello_context);
    hasher.update(&[_]u8{version});
    hasher.update(&[_]u8{@intFromEnum(operation)});
    hasher.update(&mem.toBytes(key_id));
    hasher.update(&mem.toBytes(kem_key_id));
    hasher.update(client_random);
    hasher.update(&mem.toBytes(timestamp));
    hasher.update(shared_key);
    return hasher.finalResult();
}

/// Handshake data sent by server (on success)
pub const ServerHello = struct {
    server_random: [16]u8,
};

/// Handshake data sent by client for KEM-based key exchange (kemconnect operation).
/// This extends the basic ClientHello with KEM ciphertext for forward secrecy.
pub const KemClientHello = struct {
    version: u8,
    operation: Operation,
    key_id: u64,
    kem_key_id: u64,
    client_random: [16]u8,
    timestamp: u64,
    hash: [32]u8,
    kem_ciphertext: [crypto.kem_ciphertext_size]u8,
};

/// Send the key identifier, client random, timestamp, and authentication hash
/// over a newly established connection.
/// This must be called immediately after connection establishment.
/// Returns the client_random that was sent (for key derivation).
pub fn sendClientHello(stream: net.Stream, io: Io, key_id: u64, shared_key: *const [32]u8) Error![16]u8 {
    var write_buf: [frame.io_buffer_size]u8 = undefined;
    var writer = stream.writer(io, &write_buf);

    var buf: [client_hello_size]u8 = undefined;
    buf[0] = protocol_version;
    buf[1] = @intFromEnum(Operation.connect);
    mem.writeInt(u64, buf[2..10], key_id, .little);

    var client_random: [16]u8 = undefined;
    std.crypto.random.bytes(&client_random);
    @memcpy(buf[10..26], &client_random);

    const ts = std.posix.clock_gettime(.REALTIME) catch @panic("clock_gettime failed");
    const timestamp: u64 = @intCast(ts.sec);
    mem.writeInt(u64, buf[26..34], timestamp, .little);

    const hash = computeClientHelloHash(
        protocol_version,
        .connect,
        key_id,
        &client_random,
        timestamp,
        shared_key,
    );
    @memcpy(buf[34..66], &hash);

    writer.interface.writeAll(&buf) catch {
        return error.WriteFailed;
    };
    writer.interface.flush() catch {
        return error.WriteFailed;
    };

    return client_random;
}

/// KEM client hello size: 1 byte version + 1 byte operation + 8 bytes key_id +
/// 8 bytes kem_key_id + 16 bytes random + 8 bytes timestamp + 32 bytes hash + 1120 bytes ciphertext
pub const kem_client_hello_size: usize = 1 + 1 + 8 + 8 + 16 + 8 + 32 + crypto.kem_ciphertext_size;

/// Result of sending a KEM client hello - contains data needed for key derivation
pub const KemClientHelloResult = struct {
    client_random: [16]u8,
    kem_shared_secret: [crypto.kem_shared_secret_size]u8,
};

/// Send a KEM-based client hello with encapsulated secret.
/// This performs KEM encapsulation using the server's public key and sends:
/// - version (1 byte)
/// - operation = kemconnect (1 byte)
/// - key_id (8 bytes) - PSK key identifier
/// - kem_key_id (8 bytes) - KEM key identifier
/// - client_random (16 bytes)
/// - timestamp (8 bytes)
/// - hash (32 bytes)
/// - kem_ciphertext (1120 bytes)
///
/// Returns the client_random and kem_shared_secret for key derivation.
pub fn sendKemClientHello(
    stream: net.Stream,
    io: Io,
    key_id: u64,
    kem_key_id: u64,
    shared_key: *const [32]u8,
    kem_public_key: *const [crypto.kem_public_key_size]u8,
) Error!KemClientHelloResult {
    var write_buf: [frame.io_buffer_size]u8 = undefined;
    var writer = stream.writer(io, &write_buf);

    var buf: [kem_client_hello_size]u8 = undefined;
    buf[0] = protocol_version;
    buf[1] = @intFromEnum(Operation.kemconnect);
    mem.writeInt(u64, buf[2..10], key_id, .little);
    mem.writeInt(u64, buf[10..18], kem_key_id, .little);

    var client_random: [16]u8 = undefined;
    std.crypto.random.bytes(&client_random);
    @memcpy(buf[18..34], &client_random);

    const ts = std.posix.clock_gettime(.REALTIME) catch @panic("clock_gettime failed");
    const timestamp: u64 = @intCast(ts.sec);
    mem.writeInt(u64, buf[34..42], timestamp, .little);

    const hash = computeKemClientHelloHash(
        protocol_version,
        .kemconnect,
        key_id,
        kem_key_id,
        &client_random,
        timestamp,
        shared_key,
    );
    @memcpy(buf[42..74], &hash);

    const public_key = crypto.HybridKem.PublicKey.fromBytes(kem_public_key);
    const encap = public_key.encaps(null) catch {
        log.err("KEM encapsulation failed", .{});
        return error.WriteFailed;
    };
    @memcpy(buf[74..][0..crypto.kem_ciphertext_size], &encap.ciphertext);

    writer.interface.writeAll(&buf) catch {
        return error.WriteFailed;
    };
    writer.interface.flush() catch {
        return error.WriteFailed;
    };

    return .{
        .client_random = client_random,
        .kem_shared_secret = encap.shared_secret,
    };
}

/// Result of reading client hello with operation dispatch.
/// Contains either a standard ClientHello or a KemClientHello based on the operation.
pub const ClientHelloUnion = union(enum) {
    connect: ClientHello,
    kemconnect: KemClientHello,
};

/// Read client hello and dispatch based on operation type.
/// This reads the full message in a single call to avoid buffered I/O issues.
pub fn readClientHelloDispatch(stream: net.Stream, io: Io) Error!ClientHelloUnion {
    var read_buf: [frame.io_buffer_size]u8 = undefined;
    var reader = stream.reader(io, &read_buf);

    // First read version and operation to determine message type
    var header_buf: [2]u8 = undefined;
    try reader.interface.readSliceAll(&header_buf);

    const version = header_buf[0];
    const operation: Operation = @enumFromInt(header_buf[1]);

    switch (operation) {
        .connect => {
            // Read remaining bytes for standard ClientHello (after version + operation)
            var buf: [client_hello_size - 2]u8 = undefined;
            try reader.interface.readSliceAll(&buf);

            return .{ .connect = .{
                .version = version,
                .operation = operation,
                .key_id = mem.readInt(u64, buf[0..8], .little),
                .client_random = buf[8..24].*,
                .timestamp = mem.readInt(u64, buf[24..32], .little),
                .hash = buf[32..64].*,
            } };
        },
        .kemconnect => {
            // Read remaining bytes for KemClientHello (after version + operation)
            var buf: [kem_client_hello_size - 2]u8 = undefined;
            try reader.interface.readSliceAll(&buf);

            return .{ .kemconnect = .{
                .version = version,
                .operation = operation,
                .key_id = mem.readInt(u64, buf[0..8], .little),
                .kem_key_id = mem.readInt(u64, buf[8..16], .little),
                .client_random = buf[16..32].*,
                .timestamp = mem.readInt(u64, buf[32..40], .little),
                .hash = buf[40..72].*,
                .kem_ciphertext = buf[72..][0..crypto.kem_ciphertext_size].*,
            } };
        },
        _ => {
            return error.ReadFailed; // Unknown operation
        },
    }
}

/// Handshake status codes
pub const HandshakeStatus = enum(u8) {
    ok = 0,
    unknown_key = 1,
    server_error = 2,
    unknown_kem_key = 3,
    client_auth_failed = 4,
    timestamp_invalid = 5,
};

/// Maximum allowed timestamp drift (1 hour in seconds)
pub const max_timestamp_drift: u64 = 3600;

/// Validate that a timestamp is within acceptable bounds (±1 hour from current time).
/// Returns true if timestamp is valid, false otherwise.
pub fn validateTimestamp(client_timestamp: u64) bool {
    const ts = std.posix.clock_gettime(.REALTIME) catch return false;
    const server_time: u64 = @intCast(ts.sec);

    // Check if timestamp is too old (more than 1 hour in the past)
    if (client_timestamp < server_time and server_time - client_timestamp > max_timestamp_drift) {
        return false;
    }

    // Check if timestamp is too far in the future (more than 1 hour ahead)
    if (client_timestamp > server_time and client_timestamp - server_time > max_timestamp_drift) {
        return false;
    }

    return true;
}

/// Verify client hello hash using constant-time comparison.
/// Returns true if the hash is valid, false otherwise.
pub fn verifyClientHelloHash(
    client_hello: *const ClientHello,
    shared_key: *const [32]u8,
) bool {
    const expected_hash = computeClientHelloHash(
        client_hello.version,
        client_hello.operation,
        client_hello.key_id,
        &client_hello.client_random,
        client_hello.timestamp,
        shared_key,
    );
    return std.crypto.timing_safe.eql([32]u8, client_hello.hash, expected_hash);
}

/// Verify KEM client hello hash using constant-time comparison.
/// Returns true if the hash is valid, false otherwise.
pub fn verifyKemClientHelloHash(
    kem_client_hello: *const KemClientHello,
    shared_key: *const [32]u8,
) bool {
    const expected_hash = computeKemClientHelloHash(
        kem_client_hello.version,
        kem_client_hello.operation,
        kem_client_hello.key_id,
        kem_client_hello.kem_key_id,
        &kem_client_hello.client_random,
        kem_client_hello.timestamp,
        shared_key,
    );
    return std.crypto.timing_safe.eql([32]u8, kem_client_hello.hash, expected_hash);
}

/// Send handshake acknowledgment from server to client.
/// On success (status == .ok), sends server random and authentication hash.
/// Returns the server_random on success, null on failure.
pub fn sendServerHello(
    stream: net.Stream,
    io: Io,
    status: HandshakeStatus,
    shared_key: *const [32]u8,
    client_random: *const [16]u8,
    cluster_id: u128,
) Error!?[16]u8 {
    var write_buf: [frame.io_buffer_size]u8 = undefined;
    var writer = stream.writer(io, &write_buf);

    if (status == .ok) {
        var server_random: [16]u8 = undefined;
        std.crypto.random.bytes(&server_random);

        const auth_hash = computeAuthHash(shared_key, client_random, &server_random, cluster_id);

        var buf: [49]u8 = undefined;
        buf[0] = @intFromEnum(status);
        @memcpy(buf[1..17], &server_random);
        @memcpy(buf[17..49], &auth_hash);

        writer.interface.writeAll(&buf) catch {
            return error.WriteFailed;
        };
        writer.interface.flush() catch {
            return error.WriteFailed;
        };

        return server_random;
    } else {
        writer.interface.writeAll(&[_]u8{@intFromEnum(status)}) catch {
            return error.WriteFailed;
        };
        writer.interface.flush() catch {
            return error.WriteFailed;
        };
        return null;
    }
}

/// Read handshake acknowledgment from server and verify authentication.
/// Returns the server random on success, or error if rejected or auth failed.
pub fn readServerHello(
    stream: net.Stream,
    io: Io,
    shared_key: *const [32]u8,
    client_random: *const [16]u8,
    cluster_id: u128,
) Error![16]u8 {
    var read_buf: [frame.io_buffer_size]u8 = undefined;
    var reader = stream.reader(io, &read_buf);

    var status_buf: [1]u8 = undefined;
    try reader.interface.readSliceAll(&status_buf);

    if (status_buf[0] > @intFromEnum(HandshakeStatus.timestamp_invalid)) {
        log.err("Invalid handshake status: {}", .{status_buf[0]});
        return error.KeyRejected;
    }
    const status: HandshakeStatus = @enumFromInt(status_buf[0]);

    if (status != .ok) {
        log.err("Handshake rejected with status: {s}", .{@tagName(status)});
        return error.KeyRejected;
    }

    var response_buf: [48]u8 = undefined;
    try reader.interface.readSliceAll(&response_buf);

    const server_random = response_buf[0..16].*;
    const received_hash = response_buf[16..48].*;

    const expected_hash = computeAuthHash(shared_key, client_random, &server_random, cluster_id);
    if (!std.crypto.timing_safe.eql([32]u8, received_hash, expected_hash)) {
        log.err("Server authentication failed: hash mismatch", .{});
        return error.ServerAuthFailed;
    }

    return server_random;
}

/// Result of KEM server hello - contains data needed for key derivation
pub const KemServerHelloResult = struct {
    server_random: [16]u8,
    kem_shared_secret: [crypto.kem_shared_secret_size]u8,
};

/// Send KEM handshake acknowledgment from server to client.
/// This performs KEM decapsulation and includes the result in key derivation.
/// On success (status == .ok), sends server random and authentication hash.
/// Returns the server_random and kem_shared_secret on success, null on failure.
pub fn sendKemServerHello(
    stream: net.Stream,
    io: Io,
    status: HandshakeStatus,
    shared_key: *const [32]u8,
    client_random: *const [16]u8,
    cluster_id: u128,
    kem_ciphertext: *const [crypto.kem_ciphertext_size]u8,
    kem_secret_key: *const [crypto.kem_secret_key_size]u8,
) Error!?KemServerHelloResult {
    var write_buf: [frame.io_buffer_size]u8 = undefined;
    var writer = stream.writer(io, &write_buf);

    if (status == .ok) {
        const secret_key = crypto.HybridKem.SecretKey.fromBytes(kem_secret_key);
        const kem_shared_secret = secret_key.decaps(kem_ciphertext) catch {
            log.err("KEM decapsulation failed", .{});
            writer.interface.writeAll(&[_]u8{@intFromEnum(HandshakeStatus.server_error)}) catch {
                return error.WriteFailed;
            };
            writer.interface.flush() catch {
                return error.WriteFailed;
            };
            return null;
        };

        var server_random: [16]u8 = undefined;
        std.crypto.random.bytes(&server_random);

        // KEM shared secret is mixed in during key derivation, not in the auth hash
        const auth_hash = computeAuthHash(shared_key, client_random, &server_random, cluster_id);

        var buf: [49]u8 = undefined;
        buf[0] = @intFromEnum(status);
        @memcpy(buf[1..17], &server_random);
        @memcpy(buf[17..49], &auth_hash);

        writer.interface.writeAll(&buf) catch {
            return error.WriteFailed;
        };
        writer.interface.flush() catch {
            return error.WriteFailed;
        };

        return .{
            .server_random = server_random,
            .kem_shared_secret = kem_shared_secret,
        };
    } else {
        writer.interface.writeAll(&[_]u8{@intFromEnum(status)}) catch {
            return error.WriteFailed;
        };
        writer.interface.flush() catch {
            return error.WriteFailed;
        };
        return null;
    }
}

/// Response message passed through the queue.
pub const Response = struct {
    data: []u8,
    allocator: Allocator,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.data);
    }
};

/// Queue capacity for responses per stream
const response_queue_capacity = 16;

/// A virtual stream over a multiplexed connection.
/// Represents one logical client connection.
pub const Stream = struct {
    id: u32,
    /// Backend connection for this stream (server-side only)
    backend_stream: ?net.Stream = null,
    /// Response channel using std.Io.Queue for proper async waiting
    response_queue: Io.Queue(Response),
    /// Buffer backing the queue
    queue_buffer: [response_queue_capacity]Response,
    /// Reference count to coordinate ownership across reader/session threads
    ref_count: std.atomic.Value(u32),
    allocator: Allocator,

    pub fn init(allocator: Allocator, id: u32) Stream {
        var self: Stream = .{
            .id = id,
            .response_queue = undefined,
            .queue_buffer = undefined,
            .ref_count = std.atomic.Value(u32).init(1),
            .allocator = allocator,
        };
        self.response_queue = Io.Queue(Response).init(&self.queue_buffer);
        return self;
    }

    pub fn deinit(self: *Stream, io: Io) void {
        if (self.backend_stream) |bs| {
            bs.close(io);
        }
    }

    /// Push a response to the queue (blocks if full)
    pub fn pushResponse(self: *Stream, io: Io, data: []u8) void {
        self.response_queue.putOneUncancelable(io, .{
            .data = data,
            .allocator = self.allocator,
        }) catch |err| switch (err) {
            error.Closed => unreachable, // Queue should never be closed while pushing
        };
    }

    /// Get a response from the queue (blocks if empty)
    pub fn getResponse(self: *Stream, io: Io) (Io.Cancelable || Io.QueueClosedError)!Response {
        return self.response_queue.getOne(io);
    }

    /// Take an additional reference to this stream.
    pub fn retain(self: *Stream) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    /// Release a reference and free when the last owner drops it.
    pub fn release(self: *Stream, io: Io) void {
        const prev = self.ref_count.fetchSub(1, .acq_rel);
        // If prev was 0, something went wrong; keep debug safety in debug builds.
        std.debug.assert(prev > 0);
        if (prev == 1) {
            self.deinit(io);
            self.allocator.destroy(self);
        }
    }
};

/// Stream registry - tracks active streams on a multiplexed connection.
pub const StreamRegistry = struct {
    streams: std.AutoHashMap(u32, *Stream),
    allocator: Allocator,
    next_stream_id: u32 = 1,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: Allocator) StreamRegistry {
        return .{
            .streams = std.AutoHashMap(u32, *Stream).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StreamRegistry, io: Io) void {
        var it = self.streams.valueIterator();
        while (it.next()) |stream_ptr| {
            stream_ptr.*.release(io);
        }
        self.streams.deinit();
    }

    /// Create a new stream with an auto-assigned ID.
    /// Uses linear probing to avoid collisions when the counter wraps.
    pub fn createStream(self: *StreamRegistry) !*Stream {
        self.mutex.lock();
        defer self.mutex.unlock();

        var id = self.next_stream_id;
        while (self.streams.contains(id)) {
            id +%= 1;
            if (id == self.next_stream_id) {
                return error.StreamIdExhausted;
            }
        }
        self.next_stream_id = id +% 1;

        const stream = try self.allocator.create(Stream);
        stream.* = Stream.init(self.allocator, id);

        try self.streams.put(id, stream);
        return stream;
    }

    /// Register a stream with a specific ID (server-side, from client).
    pub fn registerStream(self: *StreamRegistry, id: u32) !*Stream {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.streams.contains(id)) {
            return error.StreamAlreadyExists;
        }

        const stream = try self.allocator.create(Stream);
        stream.* = Stream.init(self.allocator, id);

        try self.streams.put(id, stream);
        return stream;
    }

    /// Get a stream by ID.
    pub fn getStream(self: *StreamRegistry, id: u32) ?*Stream {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.streams.get(id)) |stream| {
            stream.retain();
            return stream;
        }
        return null;
    }

    /// Remove and cleanup a stream.
    pub fn removeStream(self: *StreamRegistry, id: u32, io: Io) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.streams.fetchRemove(id)) |kv| {
            kv.value.release(io);
        }
    }

    pub fn count(self: *StreamRegistry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.streams.count();
    }
};

/// Connection pool for client-side multiplexing.
/// Maintains N persistent connections to the server.
pub const ConnectionPool = struct {
    connections: []PooledConnection,
    allocator: Allocator,
    backend_address: net.IpAddress,
    next_conn_idx: std.atomic.Value(usize),
    /// Key ID for connection validation (null if encryption is disabled)
    key_id: ?u64,
    /// Shared key for authentication (null if encryption is disabled)
    shared_key: ?*const [32]u8,
    /// Cluster ID for authentication
    cluster_id: u128,
    /// KEM key ID (null if KEM is disabled)
    kem_key_id: ?u64 = null,
    /// KEM public key (null if KEM is disabled)
    kem_public_key: ?*const [crypto.kem_public_key_size]u8 = null,

    /// Retry configuration
    pub const RetryConfig = struct {
        /// Maximum number of retries, or null for unlimited (default)
        max_retries: ?u32 = null,
        base_delay_ms: u64 = 100,
        max_delay_ms: u64 = 10_000,

        /// Calculate next delay with exponential backoff
        fn nextDelay(self: RetryConfig, current: i64) i64 {
            return @min(current * 2, @as(i64, @intCast(self.max_delay_ms)));
        }
    };

    pub const PooledConnection = struct {
        stream: ?net.Stream,
        registry: StreamRegistry,
        write_mutex: std.Thread.Mutex = .{},
        running: std.atomic.Value(bool),
        /// Indicates if the connection is healthy
        healthy: std.atomic.Value(bool),
        /// Connection index in the pool (for logging)
        index: usize,
        /// Connection-specific derived keys (from handshake randoms)
        derived_keys: ?crypto.DerivedKeys = null,
        /// Nonce counter for client-to-server encryption (atomic for thread safety)
        c2s_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        /// Nonce counter for server-to-client decryption (used by reader thread)
        s2c_counter_recv: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    };

    /// Initialize connection pool, retrying connections at startup if the server is not yet available.
    /// If key_id is provided, it will be sent immediately after each connection is established.
    /// If kem_config is provided, KEM-based key exchange will be used for forward secrecy.
    pub fn init(
        allocator: Allocator,
        backend_address: net.IpAddress,
        num_connections: u32,
        key_id: ?u64,
        shared_key: ?*const [32]u8,
        cluster_id: u128,
        kem_config: ?KemConfig,
        io: Io,
    ) error{ OutOfMemory, ConnectionRefused, WriteFailed, ServerAuthFailed }!ConnectionPool {
        const config = RetryConfig{};
        const connections = try allocator.alloc(PooledConnection, num_connections);

        for (connections, 0..) |*conn, idx| {
            conn.stream = null;
            conn.registry = StreamRegistry.init(allocator);
            conn.write_mutex = .{};
            conn.running = std.atomic.Value(bool).init(true);
            conn.healthy = std.atomic.Value(bool).init(false);
            conn.index = idx;
            conn.derived_keys = null;
            conn.c2s_counter = std.atomic.Value(u64).init(0);
            conn.s2c_counter_recv = std.atomic.Value(u64).init(0);
        }

        var all_connected = false;
        var attempt: u32 = 0;
        var delay_ms: i64 = @intCast(config.base_delay_ms);
        const kem_suffix: []const u8 = if (kem_config != null) " (KEM)" else "";

        while (!all_connected) {
            if (config.max_retries) |max| {
                if (attempt >= max) break;
            }

            all_connected = true;

            for (connections) |*conn| {
                if (conn.stream != null) continue;

                if (config.max_retries) |max| {
                    log.info("Connection {} attempt {}/{}{s}", .{ conn.index, attempt + 1, max, kem_suffix });
                } else {
                    log.info("Connection {} attempt {}{s}", .{ conn.index, attempt + 1, kem_suffix });
                }

                const stream = net.IpAddress.connect(backend_address, io, .{ .mode = .stream }) catch |err| {
                    log.warn("Connection {} failed to connect: {}", .{ conn.index, err });
                    all_connected = false;
                    continue;
                };

                if (key_id) |kid| {
                    const kem_pk = if (kem_config) |kc| kc.kem_public_key else null;
                    const kem_kid = if (kem_config) |kc| kc.kem_key_id else null;

                    const result = performClientHandshake(stream, io, kid, shared_key.?, cluster_id, kem_pk, kem_kid, conn.index) catch {
                        stream.close(io);
                        all_connected = false;
                        continue;
                    };
                    conn.derived_keys = result.derived_keys;
                }

                conn.stream = stream;
                conn.healthy.store(true, .release);
                log.info("Connection {} established{s}", .{ conn.index, kem_suffix });
            }

            if (!all_connected) {
                log.info("Not all connections established, retrying in {}ms...", .{delay_ms});
                Io.sleep(io, Io.Duration.fromMilliseconds(delay_ms), .awake) catch {};
                delay_ms = config.nextDelay(delay_ms);
            }

            attempt += 1;
        }

        var any_connected = false;
        for (connections) |*conn| {
            if (conn.stream != null) {
                any_connected = true;
                break;
            }
        }

        if (!any_connected) {
            log.err("Failed to establish any connections after {} attempts", .{attempt});
            for (connections) |*conn| {
                conn.registry.deinit(io);
            }
            allocator.free(connections);
            return error.ConnectionRefused;
        }

        var connected_count: usize = 0;
        for (connections) |*conn| {
            if (conn.stream != null) connected_count += 1;
        }
        log.info("Connection pool initialized{s}: {}/{} connections established", .{ kem_suffix, connected_count, num_connections });

        return .{
            .connections = connections,
            .allocator = allocator,
            .backend_address = backend_address,
            .next_conn_idx = std.atomic.Value(usize).init(0),
            .key_id = key_id,
            .shared_key = shared_key,
            .cluster_id = cluster_id,
            .kem_key_id = if (kem_config) |kc| kc.kem_key_id else null,
            .kem_public_key = if (kem_config) |kc| kc.kem_public_key else null,
        };
    }

    /// KEM configuration for connection pool
    pub const KemConfig = struct {
        kem_key_id: u64,
        kem_public_key: *const [crypto.kem_public_key_size]u8,
    };

    /// Result of a successful client handshake
    pub const HandshakeResult = struct {
        derived_keys: crypto.DerivedKeys,
    };

    /// Perform client-side handshake (PSK or KEM mode).
    /// Used by both init() and reconnect() to avoid code duplication.
    fn performClientHandshake(
        stream: net.Stream,
        io: Io,
        key_id: u64,
        shared_key: *const [32]u8,
        cluster_id: u128,
        kem_public_key: ?*const [crypto.kem_public_key_size]u8,
        kem_key_id: ?u64,
        conn_index: usize,
    ) !HandshakeResult {
        if (kem_public_key) |kem_pk| {
            // KEM mode - use hybrid key exchange
            const kem_kid = kem_key_id.?;
            const kem_result = sendKemClientHello(stream, io, key_id, kem_kid, shared_key, kem_pk) catch |err| {
                log.warn("Connection {} failed to send KEM client hello: {}", .{ conn_index, err });
                return err;
            };

            const server_random = readServerHello(stream, io, shared_key, &kem_result.client_random, cluster_id) catch |err| {
                log.warn("Connection {} KEM handshake failed: {}", .{ conn_index, err });
                return err;
            };

            log.debug("Connection {} KEM handshake complete with key ID {}, KEM key ID {}", .{ conn_index, key_id, kem_kid });
            log.debug("Connection {} client_random: {x}", .{ conn_index, kem_result.client_random });
            log.debug("Connection {} server_random: {x}", .{ conn_index, server_random });

            return .{ .derived_keys = crypto.deriveKeysWithKem(shared_key, &kem_result.kem_shared_secret, &kem_result.client_random, &server_random) };
        } else {
            // PSK-only mode
            const client_random = sendClientHello(stream, io, key_id, shared_key) catch |err| {
                log.warn("Connection {} failed to send client hello: {}", .{ conn_index, err });
                return err;
            };

            const server_random = readServerHello(stream, io, shared_key, &client_random, cluster_id) catch |err| {
                log.warn("Connection {} handshake failed: {}", .{ conn_index, err });
                return err;
            };

            log.debug("Connection {} handshake complete with key ID {}", .{ conn_index, key_id });
            log.debug("Connection {} client_random: {x}", .{ conn_index, client_random });
            log.debug("Connection {} server_random: {x}", .{ conn_index, server_random });

            return .{ .derived_keys = crypto.deriveKeys(shared_key, &client_random, &server_random) };
        }
    }

    pub fn deinit(self: *ConnectionPool, io: Io) void {
        for (self.connections) |*conn| {
            conn.running.store(false, .release);
            if (conn.stream) |s| s.close(io);
            conn.registry.deinit(io);
        }
        self.allocator.free(self.connections);
    }

    /// Check if all connections in the pool are healthy.
    pub fn allHealthy(self: *ConnectionPool) bool {
        for (self.connections) |*conn| {
            if (!conn.healthy.load(.acquire) or conn.stream == null) {
                return false;
            }
        }
        return true;
    }

    /// Get the next healthy connection using round-robin load balancing.
    /// Skips unhealthy connections, returning null if all are unhealthy.
    pub fn getConnection(self: *ConnectionPool) ?*PooledConnection {
        const start_idx = self.next_conn_idx.fetchAdd(1, .monotonic) % self.connections.len;

        var attempts: usize = 0;
        while (attempts < self.connections.len) : (attempts += 1) {
            const idx = (start_idx + attempts) % self.connections.len;
            const conn = &self.connections[idx];
            if (conn.healthy.load(.acquire) and conn.stream != null) {
                return conn;
            }
        }

        // All connections unhealthy
        return null;
    }

    /// Mark a connection as unhealthy (e.g., after an error).
    pub fn markUnhealthy(_: *ConnectionPool, conn: *PooledConnection, io: Io) void {
        conn.healthy.store(false, .release);
        if (conn.stream) |s| {
            s.close(io);
            conn.stream = null;
        }
        log.warn("Connection {} marked as unhealthy", .{conn.index});
    }

    /// Attempt to reconnect an unhealthy connection with exponential backoff.
    /// Returns true if reconnection succeeded.
    pub fn reconnect(self: *ConnectionPool, conn: *PooledConnection, io: Io, config: RetryConfig) bool {
        if (conn.healthy.load(.acquire)) return true;

        var delay_ms: i64 = @intCast(config.base_delay_ms);
        var attempt: u32 = 0;

        while (true) {
            if (config.max_retries) |max| {
                if (attempt >= max) {
                    log.err("Connection {} failed to reconnect after {} attempts", .{ conn.index, attempt });
                    return false;
                }
                log.info("Connection {} reconnect attempt {}/{}", .{ conn.index, attempt + 1, max });
            } else {
                log.info("Connection {} reconnect attempt {}", .{ conn.index, attempt + 1 });
            }

            const stream = net.IpAddress.connect(self.backend_address, io, .{ .mode = .stream }) catch |err| {
                log.warn("Connection {} reconnect failed: {}", .{ conn.index, err });
                Io.sleep(io, Io.Duration.fromMilliseconds(delay_ms), .awake) catch {};
                delay_ms = config.nextDelay(delay_ms);
                attempt += 1;
                continue;
            };

            if (self.key_id) |kid| {
                const result = performClientHandshake(stream, io, kid, self.shared_key.?, self.cluster_id, self.kem_public_key, self.kem_key_id, conn.index) catch {
                    stream.close(io);
                    Io.sleep(io, Io.Duration.fromMilliseconds(delay_ms), .awake) catch {};
                    delay_ms = config.nextDelay(delay_ms);
                    attempt += 1;
                    continue;
                };
                conn.derived_keys = result.derived_keys;
                conn.c2s_counter.store(0, .monotonic);
                conn.s2c_counter_recv.store(0, .monotonic);
            }

            conn.stream = stream;
            conn.healthy.store(true, .release);
            log.info("Connection {} reconnected successfully", .{conn.index});
            return true;
        }
    }
};

test "MuxHeader size and layout" {
    try testing.expectEqual(@as(usize, 12), @sizeOf(MuxHeader));
}
