//! Multiplexed session handling for client and server modes.
//!
//! - `ClientMuxSession`: Handles a single client connection, routing it through a pooled connection
//! - `ServerMuxHandler`: Handles a multiplexed server connection, demultiplexing streams to backends

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;
const net = Io.net;

const frame = @import("frame.zig");
const crypto = @import("crypto.zig");
const multiplex = @import("multiplex.zig");

const log = std.log.scoped(.mux_session);
const io_buffer_size = frame.io_buffer_size;

/// Client-side multiplexed session.
/// Handles a single client connection, routing it through a pooled connection.
///
/// Session Affinity: Each session is assigned to exactly one pooled TCP connection
/// at initialization time and uses that same connection for its entire lifetime.
/// This ensures that all frames for a session traverse the same network path,
/// maintaining ordering guarantees and simplifying server-side demultiplexing.
pub const ClientMuxSession = struct {
    client_stream: net.Stream,
    pool: *multiplex.ConnectionPool,
    /// The pooled connection assigned to this session. This is set once at
    /// initialization and never changes - all I/O for this session goes through
    /// this specific connection to maintain session affinity.
    pool_conn: *multiplex.ConnectionPool.PooledConnection,
    /// The multiplexed stream within pool_conn's registry. The stream_id is
    /// unique within this pool_conn and used to route responses back to us.
    stream: *multiplex.Stream,
    allocator: Allocator,
    io: Io,
    session_id: u64,
    cluster_id: ?u128,
    running: std.atomic.Value(bool),
    /// Pointer to the global active session counter
    active_sessions: *std.atomic.Value(u32),

    pub fn init(
        allocator: Allocator,
        io: Io,
        client_stream: net.Stream,
        pool: *multiplex.ConnectionPool,
        pool_conn: *multiplex.ConnectionPool.PooledConnection,
        session_id: u64,
        cluster_id: ?u128,
        active_sessions: *std.atomic.Value(u32),
    ) !ClientMuxSession {
        // Create a stream for this client
        const stream = try pool_conn.registry.createStream();
        stream.retain(); // session holds its own reference

        return .{
            .client_stream = client_stream,
            .pool = pool,
            .pool_conn = pool_conn,
            .stream = stream,
            .allocator = allocator,
            .io = io,
            .session_id = session_id,
            .cluster_id = cluster_id,
            .running = std.atomic.Value(bool).init(true),
            .active_sessions = active_sessions,
        };
    }

    pub fn run(self: *ClientMuxSession) void {
        defer self.cleanup();

        log.info("[{}] Multiplexed client session started (stream {} on pool conn {})", .{
            self.session_id,
            self.stream.id,
            self.pool_conn.index,
        });

        // Send stream open notification
        self.sendMuxFrame(.stream_open, null, 0) catch |err| {
            log.err("[{}] Failed to send stream open: {}", .{ self.session_id, err });
            return;
        };

        // Allocate frame buffer
        var client_buffer = frame.FrameBuffer.init(self.allocator) catch |err| {
            log.err("[{}] Failed to allocate client buffer: {}", .{ self.session_id, err });
            return;
        };
        defer client_buffer.deinit();

        var client_read_buf: [io_buffer_size]u8 = undefined;
        var client_reader = self.client_stream.reader(self.io, &client_read_buf);

        while (self.running.load(.acquire)) {
            // Read plain frame from local client
            const client_frame_size = frame.readFrame(&client_reader.interface, &client_buffer) catch |err| {
                if (err == error.EndOfStream) {
                    log.info("[{}] Client disconnected", .{self.session_id});
                } else {
                    log.warn("[{}] Error reading from client: {}", .{ self.session_id, err });
                }
                break;
            };

            log.debug("[{}] Received {} byte frame from client", .{ self.session_id, client_frame_size });

            // Validate cluster ID if configured
            frame.validateCluster(&client_buffer, self.cluster_id) catch |err| {
                log.warn("[{}] Cluster ID mismatch in client frame: {}", .{ self.session_id, err });
                break;
            };

            // Send to server via pooled connection with mux header
            // (encryption happens inside sendMuxFrame under write mutex for nonce ordering)
            self.sendMuxFrame(.data, client_buffer.data[0..client_frame_size], client_frame_size) catch |err| {
                log.warn("[{}] Error writing to server: {}", .{ self.session_id, err });
                break;
            };

            // Wait for response from the response queue
            const response = self.waitForResponse() catch |err| {
                log.warn("[{}] Error waiting for response: {}", .{ self.session_id, err });
                break;
            };
            defer self.allocator.free(response);

            // Forward response to local client
            self.sendToClient(response) catch |err| {
                log.warn("[{}] Error writing to client: {}", .{ self.session_id, err });
                break;
            };
        }

        log.info("[{}] Multiplexed client session ended (was on pool conn {})", .{ self.session_id, self.pool_conn.index });
    }

    fn sendMuxFrame(self: *ClientMuxSession, frame_type: multiplex.FrameType, data: ?[]u8, frame_size: u32) !void {
        self.pool_conn.write_mutex.lock();
        defer self.pool_conn.write_mutex.unlock();

        const stream = self.pool_conn.stream orelse {
            self.pool.markUnhealthy(self.pool_conn, self.io);
            return error.WriteFailed;
        };

        // Encrypt data frames inside the mutex to ensure encryption order matches send order
        // (required for implicit nonce synchronization with receiver)
        if (frame_type == .data) {
            if (data) |d| {
                if (self.pool_conn.derived_keys) |*keys| {
                    crypto.encryptFrame(d, frame_size, &keys.client_to_server, &self.pool_conn.c2s_counter) catch {
                        self.pool.markUnhealthy(self.pool_conn, self.io);
                        return error.WriteFailed;
                    };
                    log.debug("[{}] Encrypted client frame for server", .{self.session_id});
                }
            }
        }

        var write_buf: [io_buffer_size]u8 = undefined;
        var writer = stream.writer(self.io, &write_buf);

        const mux_header: multiplex.MuxHeader = .{
            .stream_id = self.stream.id,
            .frame_type = frame_type,
        };

        multiplex.writeMuxFrame(&writer.interface, mux_header, data orelse &.{}) catch {
            self.pool.markUnhealthy(self.pool_conn, self.io);
            return error.WriteFailed;
        };
    }

    fn waitForResponse(self: *ClientMuxSession) ![]u8 {
        // Use std.Io.Queue which properly blocks until data is available
        const response = self.stream.getResponse(self.io) catch |err| {
            return switch (err) {
                error.Canceled, error.Closed => error.EndOfStream,
            };
        };
        return response.data;
    }

    fn sendToClient(self: *ClientMuxSession, data: []u8) !void {
        var write_buf: [io_buffer_size]u8 = undefined;
        var writer = self.client_stream.writer(self.io, &write_buf);
        frame.writeFrame(&writer.interface, data) catch return error.WriteFailed;
    }

    fn cleanup(self: *ClientMuxSession) void {
        self.running.store(false, .release);
        self.sendMuxFrame(.stream_close, null, 0) catch {};
        self.client_stream.close(self.io);
        self.pool_conn.registry.removeStream(self.stream.id, self.io);
        self.stream.release(self.io);
        _ = self.active_sessions.fetchSub(1, .release);
    }
};

/// Server-side multiplexed connection handler.
/// Handles a single multiplexed connection from a client, demuxing streams.
pub const ServerMuxHandler = struct {
    mux_stream: net.Stream,
    backend_address: net.IpAddress,
    registry: multiplex.StreamRegistry,
    allocator: Allocator,
    io: Io,
    conn_id: u64,
    /// Derived keys for this connection (set after key negotiation)
    derived_keys: ?crypto.DerivedKeys,
    /// Key store for looking up keys by ID (for multi-key support)
    key_store: ?*const crypto.KeyStore,
    /// KEM secret key store for decapsulation (for KEM-based key exchange)
    kem_secret_key_store: ?*const crypto.KemSecretKeyStore,
    cluster_id: ?u128,
    running: std.atomic.Value(bool),
    write_mutex: std.Thread.Mutex,
    max_sessions: u32,
    /// Nonce counter for server-to-client encryption (atomic for thread safety)
    s2c_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Nonce counter for client-to-server decryption (used by reader loop)
    c2s_counter_recv: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(
        allocator: Allocator,
        io: Io,
        mux_stream: net.Stream,
        backend_address: net.IpAddress,
        conn_id: u64,
        key_store: ?*const crypto.KeyStore,
        kem_secret_key_store: ?*const crypto.KemSecretKeyStore,
        cluster_id: ?u128,
        max_sessions: u32,
    ) ServerMuxHandler {
        return .{
            .mux_stream = mux_stream,
            .backend_address = backend_address,
            .registry = multiplex.StreamRegistry.init(allocator),
            .allocator = allocator,
            .io = io,
            .conn_id = conn_id,
            .derived_keys = null, // Will be set after key negotiation
            .key_store = key_store,
            .kem_secret_key_store = kem_secret_key_store,
            .cluster_id = cluster_id,
            .running = std.atomic.Value(bool).init(true),
            .write_mutex = .{},
            .max_sessions = max_sessions,
        };
    }

    pub fn run(self: *ServerMuxHandler) void {
        defer self.cleanup();

        log.info("[conn {}] Server mux handler started", .{self.conn_id});

        // If key store is configured, read client hello and look up the key
        if (self.key_store) |store| {
            // Read and dispatch based on operation type (uses single reader to avoid buffer issues)
            const client_hello_union = multiplex.readClientHelloDispatch(self.mux_stream, self.io) catch |err| {
                log.err("[conn {}] Failed to read client hello: {}", .{ self.conn_id, err });
                return;
            };

            switch (client_hello_union) {
                .connect => |client_hello| {
                    // Standard PSK-only handshake
                    const shared_key = store.getKey(client_hello.key_id);
                    if (shared_key == null) {
                        log.err("[conn {}] Unknown key ID: {}", .{ self.conn_id, client_hello.key_id });
                        const dummy_key: [32]u8 = .{0} ** 32;
                        _ = multiplex.sendServerHello(self.mux_stream, self.io, .unknown_key, &dummy_key, &client_hello.client_random, self.cluster_id orelse 0) catch {};
                        return;
                    }

                    // Verify client hello hash (constant-time comparison)
                    if (!multiplex.verifyClientHelloHash(&client_hello, shared_key.?)) {
                        log.err("[conn {}] Client authentication failed: hash mismatch", .{self.conn_id});
                        _ = multiplex.sendServerHello(self.mux_stream, self.io, .client_auth_failed, shared_key.?, &client_hello.client_random, self.cluster_id orelse 0) catch {};
                        return;
                    }

                    // Validate timestamp (must be within ±1 hour)
                    if (!multiplex.validateTimestamp(client_hello.timestamp)) {
                        log.err("[conn {}] Client authentication failed: timestamp out of range ({})", .{ self.conn_id, client_hello.timestamp });
                        _ = multiplex.sendServerHello(self.mux_stream, self.io, .timestamp_invalid, shared_key.?, &client_hello.client_random, self.cluster_id orelse 0) catch {};
                        return;
                    }

                    log.debug("[conn {}] Client hello timestamp: {}", .{ self.conn_id, client_hello.timestamp });

                    const server_random = multiplex.sendServerHello(
                        self.mux_stream,
                        self.io,
                        .ok,
                        shared_key.?,
                        &client_hello.client_random,
                        self.cluster_id orelse 0,
                    ) catch |err| {
                        log.err("[conn {}] Failed to send server hello: {}", .{ self.conn_id, err });
                        return;
                    };

                    log.info("[conn {}] Using key ID {} (PSK mode)", .{ self.conn_id, client_hello.key_id });
                    log.debug("[conn {}] client_random: {x}", .{ self.conn_id, client_hello.client_random });
                    log.debug("[conn {}] server_random: {x}", .{ self.conn_id, server_random.? });

                    self.derived_keys = crypto.deriveKeys(shared_key.?, &client_hello.client_random, &server_random.?);
                },
                .kemconnect => |kem_client_hello| {
                    // KEM-based handshake with forward secrecy
                    // Look up PSK
                    const shared_key = store.getKey(kem_client_hello.key_id);
                    if (shared_key == null) {
                        log.err("[conn {}] Unknown key ID: {}", .{ self.conn_id, kem_client_hello.key_id });
                        const dummy_key: [32]u8 = .{0} ** 32;
                        _ = multiplex.sendServerHello(self.mux_stream, self.io, .unknown_key, &dummy_key, &kem_client_hello.client_random, self.cluster_id orelse 0) catch {};
                        return;
                    }

                    // Verify KEM client hello hash (constant-time comparison)
                    if (!multiplex.verifyKemClientHelloHash(&kem_client_hello, shared_key.?)) {
                        log.err("[conn {}] Client authentication failed: hash mismatch", .{self.conn_id});
                        _ = multiplex.sendServerHello(self.mux_stream, self.io, .client_auth_failed, shared_key.?, &kem_client_hello.client_random, self.cluster_id orelse 0) catch {};
                        return;
                    }

                    // Validate timestamp (must be within ±1 hour)
                    if (!multiplex.validateTimestamp(kem_client_hello.timestamp)) {
                        log.err("[conn {}] Client authentication failed: timestamp out of range ({})", .{ self.conn_id, kem_client_hello.timestamp });
                        _ = multiplex.sendServerHello(self.mux_stream, self.io, .timestamp_invalid, shared_key.?, &kem_client_hello.client_random, self.cluster_id orelse 0) catch {};
                        return;
                    }

                    log.debug("[conn {}] KEM client hello timestamp: {}", .{ self.conn_id, kem_client_hello.timestamp });

                    // Look up KEM secret key
                    const kem_store = self.kem_secret_key_store orelse {
                        log.err("[conn {}] Client requested KEM but server has no KEM keys configured", .{self.conn_id});
                        const dummy_key: [32]u8 = .{0} ** 32;
                        _ = multiplex.sendServerHello(self.mux_stream, self.io, .unknown_kem_key, &dummy_key, &kem_client_hello.client_random, self.cluster_id orelse 0) catch {};
                        return;
                    };

                    const kem_secret_key = kem_store.getKey(kem_client_hello.kem_key_id);
                    if (kem_secret_key == null) {
                        log.err("[conn {}] Unknown KEM key ID: {}", .{ self.conn_id, kem_client_hello.kem_key_id });
                        const dummy_key: [32]u8 = .{0} ** 32;
                        _ = multiplex.sendServerHello(self.mux_stream, self.io, .unknown_kem_key, &dummy_key, &kem_client_hello.client_random, self.cluster_id orelse 0) catch {};
                        return;
                    }

                    // Send KEM server hello (performs decapsulation)
                    const kem_result = multiplex.sendKemServerHello(
                        self.mux_stream,
                        self.io,
                        .ok,
                        shared_key.?,
                        &kem_client_hello.client_random,
                        self.cluster_id orelse 0,
                        &kem_client_hello.kem_ciphertext,
                        kem_secret_key.?,
                    ) catch |err| {
                        log.err("[conn {}] Failed to send KEM server hello: {}", .{ self.conn_id, err });
                        return;
                    };

                    if (kem_result == null) {
                        log.err("[conn {}] KEM decapsulation failed", .{self.conn_id});
                        return;
                    }

                    log.info("[conn {}] Using key ID {}, KEM key ID {} (KEM mode)", .{ self.conn_id, kem_client_hello.key_id, kem_client_hello.kem_key_id });
                    log.debug("[conn {}] client_random: {x}", .{ self.conn_id, kem_client_hello.client_random });
                    log.debug("[conn {}] server_random: {x}", .{ self.conn_id, kem_result.?.server_random });

                    // Derive keys using both PSK and KEM shared secret
                    self.derived_keys = crypto.deriveKeysWithKem(shared_key.?, &kem_result.?.kem_shared_secret, &kem_client_hello.client_random, &kem_result.?.server_random);
                },
            }
        }

        var read_buf: [io_buffer_size]u8 = undefined;
        var reader = self.mux_stream.reader(self.io, &read_buf);

        var frame_buffer = frame.FrameBuffer.init(self.allocator) catch |err| {
            log.err("[conn {}] Failed to allocate frame buffer: {}", .{ self.conn_id, err });
            return;
        };
        defer frame_buffer.deinit();

        const incoming_keys: ?*const crypto.DirectionalKey = if (self.derived_keys) |*keys|
            &keys.client_to_server
        else
            null;

        while (self.running.load(.acquire)) {
            // Read mux header
            const mux_header = multiplex.readMuxHeader(&reader.interface) catch |err| {
                if (err == error.EndOfStream) {
                    log.info("[conn {}] Client disconnected", .{self.conn_id});
                } else {
                    log.warn("[conn {}] Error reading mux header: {}", .{ self.conn_id, err });
                }
                break;
            };

            switch (mux_header.frame_type) {
                .stream_open => {
                    self.handleStreamOpen(mux_header.stream_id) catch |err| {
                        log.warn("[conn {}] Failed to open stream {}: {}", .{ self.conn_id, mux_header.stream_id, err });
                    };
                },
                .stream_close => {
                    self.handleStreamClose(mux_header.stream_id);
                },
                .data => {
                    self.handleData(&reader.interface, &frame_buffer, mux_header.stream_id, incoming_keys) catch |err| {
                        log.warn("[conn {}] Error handling data for stream {}: {}", .{ self.conn_id, mux_header.stream_id, err });
                    };
                },
            }
        }

        log.info("[conn {}] Server mux handler ended", .{self.conn_id});
    }

    fn handleStreamOpen(self: *ServerMuxHandler, stream_id: u32) !void {
        log.debug("[conn {}] Opening stream {}", .{ self.conn_id, stream_id });

        // Check session limit
        const current = self.registry.count();
        if (current >= self.max_sessions) {
            log.warn("[conn {}] Max sessions reached ({}/{}), rejecting stream {}", .{
                self.conn_id,
                current,
                self.max_sessions,
                stream_id,
            });
            return error.TooManySessions;
        }

        const stream = try self.registry.registerStream(stream_id);

        // Connect to backend for this stream
        stream.backend_stream = net.IpAddress.connect(self.backend_address, self.io, .{ .mode = .stream }) catch |err| {
            log.err("[conn {}] Failed to connect to backend for stream {}: {}", .{ self.conn_id, stream_id, err });
            self.registry.removeStream(stream_id, self.io);
            return err;
        };

        log.info("[conn {}] Stream {} opened, connected to backend", .{ self.conn_id, stream_id });
    }

    fn handleStreamClose(self: *ServerMuxHandler, stream_id: u32) void {
        log.debug("[conn {}] Closing stream {}", .{ self.conn_id, stream_id });
        self.registry.removeStream(stream_id, self.io);
        log.info("[conn {}] Stream {} closed", .{ self.conn_id, stream_id });
    }

    fn handleData(
        self: *ServerMuxHandler,
        reader: *Io.Reader,
        buffer: *frame.FrameBuffer,
        stream_id: u32,
        incoming_keys: ?*const crypto.DirectionalKey,
    ) !void {
        const stream = self.registry.getStream(stream_id) orelse {
            log.warn("[conn {}] Data for unknown stream {}", .{ self.conn_id, stream_id });
            return error.StreamNotFound;
        };
        defer stream.release(self.io);

        const backend_stream = stream.backend_stream orelse {
            log.warn("[conn {}] No backend connection for stream {}", .{ self.conn_id, stream_id });
            return error.StreamNotFound;
        };

        // Read the frame (encrypted format since it came from client)
        const frame_size = if (incoming_keys != null)
            try frame.readEncryptedFrame(reader, buffer)
        else
            try frame.readFrame(reader, buffer);

        log.debug("[conn {}] Received {} byte frame for stream {}", .{ self.conn_id, frame_size, stream_id });

        if (incoming_keys) |keys| {
            try crypto.decryptFrame(buffer.data, frame_size, keys, &self.c2s_counter_recv, self.cluster_id orelse 0);
            log.debug("[conn {}] Decrypted frame for stream {}", .{ self.conn_id, stream_id });
        }

        var backend_write_buf: [io_buffer_size]u8 = undefined;
        var backend_writer = backend_stream.writer(self.io, &backend_write_buf);
        try frame.writeFrame(&backend_writer.interface, buffer.data[0..frame_size]);

        var backend_read_buf: [io_buffer_size]u8 = undefined;
        var backend_reader = backend_stream.reader(self.io, &backend_read_buf);

        const response_size = try frame.readFrame(&backend_reader.interface, buffer);
        log.debug("[conn {}] Received {} byte response from backend for stream {}", .{ self.conn_id, response_size, stream_id });

        const outgoing_keys: ?*const crypto.DirectionalKey = if (self.derived_keys) |*keys|
            &keys.server_to_client
        else
            null;

        if (outgoing_keys) |keys| {
            crypto.encryptFrame(buffer.data, response_size, keys, &self.s2c_counter) catch |err| {
                log.warn("[conn {}] Invalid padding in backend response for stream {}: {}", .{ self.conn_id, stream_id, err });
                return err;
            };
            log.debug("[conn {}] Encrypted response for stream {}", .{ self.conn_id, stream_id });
        }

        self.sendResponse(stream_id, buffer.data[0..response_size]) catch |err| {
            log.warn("[conn {}] Error sending response for stream {}: {}", .{ self.conn_id, stream_id, err });
            return err;
        };
    }

    fn sendResponse(self: *ServerMuxHandler, stream_id: u32, data: []const u8) !void {
        self.write_mutex.lock();
        defer self.write_mutex.unlock();

        var write_buf: [io_buffer_size]u8 = undefined;
        var writer = self.mux_stream.writer(self.io, &write_buf);

        multiplex.writeMuxFrame(&writer.interface, .{
            .stream_id = stream_id,
            .frame_type = .data,
        }, data) catch return error.WriteFailed;
    }

    fn cleanup(self: *ServerMuxHandler) void {
        self.running.store(false, .release);
        self.mux_stream.close(self.io);
        self.registry.deinit(self.io);
    }
};

/// Reader thread for client-side pooled connection.
/// Reads responses from server and routes them to the correct stream.
/// Also handles reconnection on connection failures.
pub fn clientPoolReaderThread(
    pool: *multiplex.ConnectionPool,
    pool_conn: *multiplex.ConnectionPool.PooledConnection,
    io: Io,
    allocator: Allocator,
) void {
    log.info("Pool connection {} reader started", .{pool_conn.index});

    var frame_buffer = frame.FrameBuffer.init(allocator) catch |err| {
        log.err("Failed to allocate frame buffer for reader: {}", .{err});
        return;
    };
    defer frame_buffer.deinit();

    const retry_config = multiplex.ConnectionPool.RetryConfig{};

    while (pool_conn.running.load(.acquire)) {
        // Ensure we have a valid connection
        const stream = pool_conn.stream orelse {
            // Try to reconnect
            if (!pool.reconnect(pool_conn, io, retry_config)) {
                log.err("Connection {} reader: failed to reconnect, exiting", .{pool_conn.index});
                break;
            }
            continue;
        };

        var read_buf: [io_buffer_size]u8 = undefined;
        var reader = stream.reader(io, &read_buf);

        // Read loop for this connection
        while (pool_conn.running.load(.acquire) and pool_conn.healthy.load(.acquire)) {
            // Use vectored I/O to read mux header and frame header in one call
            const size_offset = if (pool_conn.derived_keys != null)
                frame.size_offset_encrypted
            else
                frame.size_offset_normal;

            const read_result = multiplex.readMuxHeaderAndFrameHeader(
                &reader.interface,
                &frame_buffer,
                size_offset,
            ) catch |err| {
                if (err == error.EndOfStream or err == error.ReadFailed) {
                    log.info("Connection {} server disconnected", .{pool_conn.index});
                } else {
                    log.warn("Connection {} error reading mux header: {}", .{ pool_conn.index, err });
                }
                pool.markUnhealthy(pool_conn, io);
                break;
            };

            if (read_result.mux_header.frame_type != .data) {
                continue; // Only handle data frames
            }

            // Read the frame body (header was already read by readMuxHeaderAndFrameHeader)
            const fs = frame.readFrameBody(&reader.interface, &frame_buffer, read_result.frame_size) catch |err| {
                log.warn("Connection {} error reading frame body: {}", .{ pool_conn.index, err });
                pool.markUnhealthy(pool_conn, io);
                break;
            };

            const mux_header = read_result.mux_header;

            // Decrypt in reader thread to maintain counter synchronization
            // (frames must be decrypted in the order they were encrypted)
            if (pool_conn.derived_keys) |*keys| {
                crypto.decryptFrame(frame_buffer.data, fs, &keys.server_to_client, &pool_conn.s2c_counter_recv, pool.cluster_id) catch |err| {
                    log.warn("Connection {} failed to decrypt server response: {}", .{ pool_conn.index, err });
                    pool.markUnhealthy(pool_conn, io);
                    break;
                };
                log.debug("Connection {} decrypted server response", .{pool_conn.index});
            }

            // Find the stream and queue the response
            if (pool_conn.registry.getStream(mux_header.stream_id)) |mux_stream| {
                defer mux_stream.release(io);

                // Copy data for the queue
                const response_copy = allocator.alloc(u8, fs) catch {
                    log.warn("Failed to allocate response buffer", .{});
                    continue;
                };
                @memcpy(response_copy, frame_buffer.data[0..fs]);

                // Push to the queue - this uses std.Io.Queue which blocks if full
                mux_stream.pushResponse(io, response_copy);
            } else {
                log.warn("Response for unknown stream {}", .{mux_header.stream_id});
            }
        }

        // If we exited the inner loop but still running, try to reconnect
        if (pool_conn.running.load(.acquire) and !pool_conn.healthy.load(.acquire)) {
            log.info("Connection {} attempting reconnection", .{pool_conn.index});
            if (!pool.reconnect(pool_conn, io, retry_config)) {
                log.err("Connection {} failed to reconnect after error", .{pool_conn.index});
                // Continue the outer loop - will try again after a delay
                Io.sleep(io, Io.Duration.fromSeconds(1), .awake) catch {};
            }
        }
    }

    log.info("Pool connection {} reader ended", .{pool_conn.index});
}

/// Entry point for client mux session thread
pub fn runClientMuxSession(session: *ClientMuxSession) void {
    defer session.allocator.destroy(session);
    session.run();
}

/// Entry point for server mux handler thread
pub fn runServerMuxHandler(handler: *ServerMuxHandler) void {
    defer handler.allocator.destroy(handler);
    handler.run();
}
