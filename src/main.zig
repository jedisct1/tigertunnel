//! TCP tunnel/proxy for TigerBeetle with encryption support and connection pooling.
//!
//! Operates in two modes:
//! - Server mode: Accepts encrypted multiplexed connections and forwards decrypted frames to a backend
//! - Client mode: Accepts plain connections and encrypts frames for the server over pooled connections
//!
//! Also provides key generation utilities (keygen, kemgen).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;
const Threaded = Io.Threaded;
const net = Io.net;

const crypto = @import("crypto.zig");
const multiplex = @import("multiplex.zig");
const mux_session = @import("mux_session.zig");

const log = std.log.scoped(.main);

/// Runtime log level, configurable via --log-level
var runtime_log_level: std.log.Level = if (@import("builtin").mode == .Debug) .debug else .info;

pub const std_options = std.Options{
    .log_level = .debug,
    .logFn = logFn,
};

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(level) > @intFromEnum(runtime_log_level)) return;
    std.log.defaultLog(level, scope, format, args);
}

pub const Mode = enum {
    client,
    server,
    keygen,
    kemgen,
};

/// A listen,backend address pair for proxying
pub const ProxyPair = struct {
    listen_address: net.IpAddress,
    backend_address: net.IpAddress,
};

/// Maximum number of proxy pairs supported
const max_proxy_pairs = 16;

const Config = struct {
    mode: Mode,
    /// List of proxy pairs (listen,backend) - at least one required for client/server modes
    proxy_pairs: []const ProxyPair,
    /// Key identifier for client mode (to send to server)
    key_id: ?u64,
    /// Raw shared key for client mode (for server authentication and key derivation)
    shared_key: ?[32]u8,
    /// Key store for server mode (supports multiple keys)
    key_store: ?crypto.KeyStore,
    /// KEM public key for client mode (optional, for hybrid key exchange)
    kem_public_key: ?crypto.KemPublicKeyFile,
    /// KEM secret key store for server mode (optional, supports multiple keys for rotation)
    kem_secret_key_store: ?crypto.KemSecretKeyStore,
    cluster_id: ?u128,
    num_connections: u32,
    max_sessions: u32,
    output_path: ?[]const u8, // For keygen
};

fn parseAddress(arg: []const u8, default_port: u16) !net.IpAddress {
    // Handle ":port" format (listen on all interfaces)
    if (arg.len > 0 and arg[0] == ':') {
        const port = std.fmt.parseInt(u16, arg[1..], 10) catch {
            return error.InvalidPort;
        };
        return .{ .ip4 = net.Ip4Address.unspecified(port) };
    }

    // Try parsing as IP literal with port (e.g., "127.0.0.1:3000")
    if (net.IpAddress.parseLiteral(arg)) |addr| {
        return addr;
    } else |_| {}

    // Find the last colon for host:port split
    if (mem.lastIndexOfScalar(u8, arg, ':')) |colon_idx| {
        const host = arg[0..colon_idx];
        const port_str = arg[colon_idx + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch {
            return error.InvalidPort;
        };

        // Try parsing as IP address
        if (net.IpAddress.parse(host, port)) |addr| {
            return addr;
        } else |_| {
            return error.InvalidAddress;
        }
    }

    // No colon, treat as host with default port
    if (net.IpAddress.parse(arg, default_port)) |addr| {
        return addr;
    } else |_| {
        return error.InvalidAddress;
    }
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    log.err(fmt, args);
    std.process.exit(1);
}

fn printUsage(prog_name: []const u8) noreturn {
    std.debug.print(
        \\Usage: {s} <MODE> [OPTIONS]
        \\
        \\TigerBeetle TCP tunnel/proxy with encryption support and connection pooling.
        \\
        \\Modes:
        \\  client                  Run as a client (connects to encrypted server)
        \\  server                  Run as a server (accepts encrypted connections)
        \\  keygen                  Generate a new symmetric encryption key
        \\  kemgen                  Generate a KEM keypair (ML-KEM-768 + X25519)
        \\
        \\Options:
        \\  -p, --proxy <L,R>       Proxy addresses: listen,backend (e.g., :3000,127.0.0.1:3001)
        \\                          Can be specified multiple times for multiple proxies.
        \\                          Each pair creates its own dedicated connection pool.
        \\  -k, --key <FILE>        Path to key file for encryption
        \\  --kempublic <FILE>      KEM public key file (client mode, optional)
        \\  --kemsecret <FILE>      KEM secret key file (server mode, optional)
        \\  -c, --cluster <ID>      Cluster ID for validation (rejects frames with mismatched ID)
        \\  -n, --num-conns <N>     Number of persistent pool connections per pair (default: 4, client only)
        \\  -m, --max-sessions <N>  Maximum concurrent sessions per pair (default: 1000)
        \\  -o, --output <FILE>     Output file for keygen/kemgen (required for keygen/kemgen)
        \\  --log-level <LEVEL>     Log level: err, warn, info, debug (default: debug/info)
        \\  -h, --help              Show this help message
        \\
        \\Address format: [HOST]:PORT or HOST:PORT
        \\
        \\Key file format (keygen): <key_id>:<hex_key>, one key per line
        \\  key_id   64-bit unsigned integer in decimal format
        \\  hex_key  64-character hex string (32 bytes)
        \\  Comments (lines starting with #) and empty lines are allowed.
        \\  Servers accept connections using any key in the file.
        \\  Clients use the first key in the file.
        \\
        \\KEM key file format (kemgen): creates <path>.pub and <path>.key
        \\  Public key:  <kemkey_id>:<hex_public_key> (1216 bytes)
        \\  Secret key:  <kemkey_id>:<hex_secret_key> (32 bytes), one key per line
        \\  Server secret key files support multiple keys for rotation.
        \\  Comments (lines starting with #) and empty lines are allowed.
        \\
        \\Connection pooling (client mode):
        \\  The client maintains N persistent TCP connections to the server per proxy pair.
        \\  Multiple client sessions are multiplexed over these connections.
        \\
        \\Examples:
        \\
        \\  Generate keys:
        \\    {s} keygen -o secret.key                   Generate symmetric key
        \\    {s} kemgen -o server                       Generate KEM keypair (server.pub + server.key)
        \\
        \\  Basic tunnel (symmetric encryption only):
        \\    {s} server -p :3000,127.0.0.1:3001 -k secret.key
        \\    {s} client -p :4000,server.example.com:3000 -k secret.key
        \\
        \\  Post-quantum secure tunnel (KEM + symmetric):
        \\    {s} server -p :3000,127.0.0.1:3001 -k secret.key --kemsecret server.key
        \\    {s} client -p :4000,server.example.com:3000 -k secret.key --kempublic server.pub
        \\
        \\  Multiple backends (replicas):
        \\    {s} server -p :3000,10.0.0.1:3001 -p :3001,10.0.0.2:3001 -p :3002,10.0.0.3:3001 -k secret.key
        \\    {s} client -p :4000,srv:3000 -p :4001,srv:3001 -p :4002,srv:3002 -k secret.key
        \\
        \\  High-throughput client (more pool connections):
        \\    {s} client -p :4000,server:3000 -k secret.key -n 16 -m 5000
        \\
        \\  With cluster ID validation (rejects mismatched traffic):
        \\    {s} server -p :3000,127.0.0.1:3001 -k secret.key -c 12345
        \\    {s} client -p :4000,server:3000 -k secret.key -c 12345
        \\
        \\  Production (minimal logging):
        \\    {s} server -p :3000,127.0.0.1:3001 -k secret.key --log-level err
        \\
    , .{
        prog_name,
        prog_name,
        prog_name,
        prog_name,
        prog_name,
        prog_name,
        prog_name,
        prog_name,
        prog_name,
        prog_name,
        prog_name,
        prog_name,
        prog_name,
    });
    std.process.exit(0);
}

/// Static buffer for proxy pairs (avoids allocator in arg parsing)
var proxy_pairs_buf: [max_proxy_pairs]ProxyPair = undefined;

fn parseArgs(init_args: std.process.Args, io: Io) Config {
    var proxy_pair_count: usize = 0;
    var key_file: ?[]const u8 = null;
    var kem_public_file: ?[]const u8 = null;
    var kem_secret_file: ?[]const u8 = null;
    var cluster_id: ?u128 = null;
    var mode: ?Mode = null;
    var num_connections: u32 = 4;
    var max_sessions: u32 = 1000;
    var output_path: ?[]const u8 = null;

    var args = std.process.Args.Iterator.init(init_args);
    const prog_name = args.next() orelse "tigertunnel";
    const first_arg = args.next() orelse printUsage(prog_name);

    var current_arg: ?[]const u8 = first_arg;
    while (current_arg) |arg| : (current_arg = args.next()) {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            printUsage(prog_name);
        } else if (mem.eql(u8, arg, "client")) {
            if (mode != null) fatal("Mode already specified", .{});
            mode = .client;
        } else if (mem.eql(u8, arg, "server")) {
            if (mode != null) fatal("Mode already specified", .{});
            mode = .server;
        } else if (mem.eql(u8, arg, "keygen")) {
            if (mode != null) fatal("Mode already specified", .{});
            mode = .keygen;
        } else if (mem.eql(u8, arg, "kemgen")) {
            if (mode != null) fatal("Mode already specified", .{});
            mode = .kemgen;
        } else if (mem.eql(u8, arg, "-p") or mem.eql(u8, arg, "--proxy")) {
            const value = args.next() orelse fatal("Missing value for {s}", .{arg});
            if (proxy_pair_count >= max_proxy_pairs) {
                fatal("Too many proxy pairs (max {})", .{max_proxy_pairs});
            }
            // Parse comma-separated listen,backend addresses
            if (mem.indexOfScalar(u8, value, ',')) |comma_idx| {
                const listen_part = value[0..comma_idx];
                const backend_part = value[comma_idx + 1 ..];
                proxy_pairs_buf[proxy_pair_count] = .{
                    .listen_address = parseAddress(listen_part, 3000) catch fatal("Invalid listen address: {s}", .{listen_part}),
                    .backend_address = parseAddress(backend_part, 3001) catch fatal("Invalid backend address: {s}", .{backend_part}),
                };
                proxy_pair_count += 1;
            } else {
                fatal("Invalid proxy format, expected: listen,backend (e.g., :3000,127.0.0.1:3001)", .{});
            }
        } else if (mem.eql(u8, arg, "-k") or mem.eql(u8, arg, "--key")) {
            key_file = args.next() orelse fatal("Missing value for {s}", .{arg});
        } else if (mem.eql(u8, arg, "-c") or mem.eql(u8, arg, "--cluster")) {
            const value = args.next() orelse fatal("Missing value for {s}", .{arg});
            cluster_id = std.fmt.parseInt(u128, value, 10) catch fatal("Invalid cluster ID: {s}", .{value});
        } else if (mem.eql(u8, arg, "-n") or mem.eql(u8, arg, "--num-conns")) {
            const value = args.next() orelse fatal("Missing value for {s}", .{arg});
            num_connections = std.fmt.parseInt(u32, value, 10) catch fatal("Invalid num-conns: {s}", .{value});
            if (num_connections == 0) fatal("num-conns must be at least 1", .{});
        } else if (mem.eql(u8, arg, "-m") or mem.eql(u8, arg, "--max-sessions")) {
            const value = args.next() orelse fatal("Missing value for {s}", .{arg});
            max_sessions = std.fmt.parseInt(u32, value, 10) catch fatal("Invalid max-sessions: {s}", .{value});
            if (max_sessions == 0) fatal("max-sessions must be at least 1", .{});
        } else if (mem.eql(u8, arg, "-o") or mem.eql(u8, arg, "--output")) {
            output_path = args.next() orelse fatal("Missing value for {s}", .{arg});
        } else if (mem.eql(u8, arg, "--kempublic")) {
            kem_public_file = args.next() orelse fatal("Missing value for {s}", .{arg});
        } else if (mem.eql(u8, arg, "--kemsecret")) {
            kem_secret_file = args.next() orelse fatal("Missing value for {s}", .{arg});
        } else if (mem.eql(u8, arg, "--log-level")) {
            const value = args.next() orelse fatal("Missing value for {s}", .{arg});
            runtime_log_level = std.meta.stringToEnum(std.log.Level, value) orelse
                fatal("Invalid log level: {s} (use: err, warn, info, debug)", .{value});
        } else {
            fatal("Unknown argument: {s}", .{arg});
        }
    }

    if (mode == null) fatal("Mode is required (client, server, keygen, or kemgen)", .{});

    // Load keys if key file is specified (not for keygen/kemgen modes)
    var key_id: ?u64 = null;
    var shared_key: ?[32]u8 = null;
    var key_store: ?crypto.KeyStore = null;
    var kem_public_key: ?crypto.KemPublicKeyFile = null;
    var kem_secret_key_store: ?crypto.KemSecretKeyStore = null;

    if (mode != .keygen and mode != .kemgen) {
        if (key_file) |path| {
            var key_buf: [crypto.key_file_buffer_size]u8 = undefined;
            const store = crypto.loadKeyStoreFromFile(io, path, &key_buf) catch |err| {
                fatal("Failed to load keys from '{s}': {}", .{ path, err });
            };

            if (mode == .client) {
                // Client mode: use the first key for encryption
                // Keys are derived per-connection using handshake randoms
                const first_key = store.getFirstKey().?;
                key_id = first_key.key_id;
                shared_key = first_key.key;
                log.info("Loaded encryption key {} from '{s}'", .{ first_key.key_id, path });
            } else {
                // Server mode: keep the full key store for per-connection key lookup
                key_store = store;
                log.info("Loaded {} encryption key(s) from '{s}'", .{ store.count(), path });
            }
        }

        // Load KEM public key for client mode
        if (kem_public_file) |path| {
            if (mode != .client) {
                fatal("--kempublic is only valid in client mode", .{});
            }
            var buf: [crypto.kem_public_key_file_buffer_size]u8 = undefined;
            kem_public_key = crypto.loadKemPublicKeyFromFile(io, path, &buf) catch |err| {
                fatal("Failed to load KEM public key from '{s}': {}", .{ path, err });
            };
            log.info("Loaded KEM public key {} from '{s}'", .{ kem_public_key.?.key_id, path });
        }

        // Load KEM secret key(s) for server mode
        if (kem_secret_file) |path| {
            if (mode != .server) {
                fatal("--kemsecret is only valid in server mode", .{});
            }
            var buf: [crypto.kem_secret_key_store_buffer_size]u8 = undefined;
            kem_secret_key_store = crypto.loadKemSecretKeyStoreFromFile(io, path, &buf) catch |err| {
                fatal("Failed to load KEM secret key(s) from '{s}': {}", .{ path, err });
            };
            log.info("Loaded {} KEM secret key(s) from '{s}'", .{ kem_secret_key_store.?.count(), path });
        }
    }

    // Validate proxy pairs are provided for client/server modes
    if ((mode == .client or mode == .server) and proxy_pair_count == 0) {
        fatal("At least one proxy pair (-p) is required for {s} mode", .{@tagName(mode.?)});
    }

    return .{
        .mode = mode.?,
        .proxy_pairs = proxy_pairs_buf[0..proxy_pair_count],
        .key_id = key_id,
        .shared_key = shared_key,
        .key_store = key_store,
        .kem_public_key = kem_public_key,
        .kem_secret_key_store = kem_secret_key_store,
        .cluster_id = cluster_id,
        .num_connections = num_connections,
        .max_sessions = max_sessions,
        .output_path = output_path,
    };
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    const config = parseArgs(init.minimal.args, init.io);

    if (config.mode == .keygen) {
        runKeygen(init.io, config);
        return;
    }

    if (config.mode == .kemgen) {
        runKemgen(init.io, config);
        return;
    }

    const io = init.io;

    log.info("Starting tigertunnel in {s} mode with {} proxy pair(s)", .{ @tagName(config.mode), config.proxy_pairs.len });
    for (config.proxy_pairs, 0..) |pair, i| {
        log.info("  Pair {}: {any} -> {any}", .{ i, pair.listen_address, pair.backend_address });
    }
    if (config.mode == .client) {
        log.info("  Encryption: {s}", .{if (config.shared_key != null) "enabled" else "disabled"});
        log.info("  Pool connections per pair: {}", .{config.num_connections});
    } else {
        if (config.key_store) |store| {
            log.info("  Encryption: enabled ({} key(s))", .{store.count()});
        } else {
            log.info("  Encryption: disabled", .{});
        }
    }
    log.info("  Max sessions per pair: {}", .{config.max_sessions});

    if (config.mode == .client) {
        runMuxClient(allocator, io, &config);
    } else {
        runMuxServer(allocator, io, &config);
    }
}

fn runKeygen(io: Io, config: Config) void {
    const output_path = config.output_path orelse {
        fatal("Output path (-o) is required for keygen mode", .{});
    };

    var key_id_bytes: [8]u8 = undefined;
    io.random(&key_id_bytes);
    const key_id = mem.readInt(u64, &key_id_bytes, .little);
    const key = crypto.generateKey(io);

    var buf: [256]u8 = undefined;
    const content = crypto.formatKeyFile(&buf, key_id, &key);

    const file = Io.Dir.cwd().createFile(io, output_path, .{}) catch |err| {
        fatal("Failed to create '{s}': {}", .{ output_path, err });
    };
    defer file.close(io);

    file.writeStreamingAll(io, content) catch |err| {
        fatal("Failed to write to '{s}': {}", .{ output_path, err });
    };

    std.debug.print("Generated key {} -> {s}\n", .{ key_id, output_path });
}

fn runKemgen(io: Io, config: Config) void {
    const output_path = config.output_path orelse {
        fatal("Output path (-o) is required for kemgen mode", .{});
    };

    var key_id_bytes: [8]u8 = undefined;
    io.random(&key_id_bytes);
    const key_id = mem.readInt(u64, &key_id_bytes, .little);
    const keypair = crypto.generateKemKeyPair(io);
    const public_key = keypair.public_key.toBytes();
    const secret_key = keypair.secret_key.toBytes();

    var pub_path_buf: [256]u8 = undefined;
    var sec_path_buf: [256]u8 = undefined;

    const pub_path = std.fmt.bufPrint(&pub_path_buf, "{s}.pub", .{output_path}) catch {
        fatal("Output path too long", .{});
    };
    const sec_path = std.fmt.bufPrint(&sec_path_buf, "{s}.key", .{output_path}) catch {
        fatal("Output path too long", .{});
    };

    var pub_buf: [crypto.kem_public_key_file_buffer_size]u8 = undefined;
    const pub_content = crypto.formatKemPublicKeyFile(&pub_buf, key_id, &public_key);

    const pub_file = Io.Dir.cwd().createFile(io, pub_path, .{}) catch |err| {
        fatal("Failed to create '{s}': {}", .{ pub_path, err });
    };
    defer pub_file.close(io);

    pub_file.writeStreamingAll(io, pub_content) catch |err| {
        fatal("Failed to write to '{s}': {}", .{ pub_path, err });
    };

    var sec_buf: [crypto.kem_secret_key_file_buffer_size]u8 = undefined;
    const sec_content = crypto.formatKemSecretKeyFile(&sec_buf, key_id, &secret_key);

    const sec_file = Io.Dir.cwd().createFile(io, sec_path, .{}) catch |err| {
        fatal("Failed to create '{s}': {}", .{ sec_path, err });
    };
    defer sec_file.close(io);

    sec_file.writeStreamingAll(io, sec_content) catch |err| {
        fatal("Failed to write to '{s}': {}", .{ sec_path, err });
    };

    std.debug.print("Generated KEM keypair {} -> {s}, {s}\n", .{ key_id, pub_path, sec_path });
}

/// Context for a client proxy pair running in its own thread
const ClientProxyContext = struct {
    allocator: Allocator,
    io: Io,
    pair_index: usize,
    listen_address: net.IpAddress,
    backend_address: net.IpAddress,
    key_id: ?u64,
    shared_key: ?*const [32]u8,
    cluster_id: ?u128,
    num_connections: u32,
    max_sessions: u32,
    kem_config: ?multiplex.ConnectionPool.KemConfig,
    /// Per-pair session counter
    active_sessions: std.atomic.Value(u32),
    /// Group for reader tasks (one per pooled connection)
    reader_group: Io.Group = .init,
    /// Group for session tasks (one per client connection)
    session_group: Io.Group = .init,
};

fn runClientProxyPair(ctx: *ClientProxyContext) void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const pair_index = ctx.pair_index;

    log.info("Pair {}: Initializing connection pool with {} connections...", .{ pair_index, ctx.num_connections });

    var pool = multiplex.ConnectionPool.init(
        allocator,
        ctx.backend_address,
        ctx.num_connections,
        ctx.key_id,
        ctx.shared_key,
        ctx.cluster_id orelse 0,
        ctx.kem_config,
        io,
    ) catch |err| {
        log.err("Pair {}: Failed to initialize connection pool: {}", .{ pair_index, err });
        return;
    };
    defer pool.deinit(io);

    // Start listener BEFORE reader threads to avoid race condition on bind failure.
    // If we spawn threads first and bind fails, the defer cleanup closes sockets
    // while threads are blocked on read, causing BADF panic.
    var server = net.IpAddress.listen(ctx.listen_address, io, .{
        .reuse_address = true,
    }) catch |err| {
        log.err("Pair {}: Failed to bind: {}", .{ pair_index, err });
        return;
    };
    defer server.deinit(io);

    for (pool.connections) |*conn| {
        ctx.reader_group.concurrent(io, mux_session.clientPoolReaderThread, .{ &pool, conn, io, allocator }) catch |err| {
            log.err("Pair {}: Failed to spawn reader thread for connection {}: {}", .{ pair_index, conn.index, err });
            return;
        };
    }

    log.info("Pair {}: Connection pool initialized", .{pair_index});
    log.info("Pair {}: Listening...", .{pair_index});

    var session_id: u64 = 0;

    while (true) {
        const stream = server.accept(io) catch |err| {
            log.warn("Pair {}: Accept failed: {}", .{ pair_index, err });
            continue;
        };

        if (!pool.allHealthy()) {
            log.warn("Pair {}: Not all pool connections healthy, rejecting new client", .{pair_index});
            stream.close(io);
            continue;
        }

        const current = ctx.active_sessions.load(.acquire);
        if (current >= ctx.max_sessions) {
            log.warn("Pair {}: Max sessions reached ({}/{}), rejecting new client", .{ pair_index, current, ctx.max_sessions });
            stream.close(io);
            continue;
        }

        session_id += 1;

        const pool_conn = pool.getConnection() orelse {
            log.err("Pair {}: No healthy pool connection available, rejecting connection", .{pair_index});
            stream.close(io);
            continue;
        };

        log.info("Pair {}: Accepted connection (session {} -> pool conn {})", .{ pair_index, session_id, pool_conn.index });

        const session = allocator.create(mux_session.ClientMuxSession) catch |err| {
            log.err("Pair {}: Failed to allocate session: {}", .{ pair_index, err });
            stream.close(io);
            continue;
        };

        session.* = mux_session.ClientMuxSession.init(
            allocator,
            io,
            stream,
            &pool,
            pool_conn,
            session_id,
            ctx.cluster_id,
            &ctx.active_sessions,
        ) catch |err| {
            log.err("Pair {}: Failed to initialize mux session: {}", .{ pair_index, err });
            stream.close(io);
            allocator.destroy(session);
            continue;
        };

        _ = ctx.active_sessions.fetchAdd(1, .release);
        ctx.session_group.concurrent(io, mux_session.runClientMuxSession, .{session}) catch |err| {
            log.err("Pair {}: Failed to spawn session thread: {}", .{ pair_index, err });
            stream.close(io);
            _ = ctx.active_sessions.fetchSub(1, .release);
            allocator.destroy(session);
            continue;
        };
    }
}

fn runMuxClient(
    allocator: Allocator,
    io: Io,
    config: *const Config,
) void {
    // Build KEM config if enabled (shared across all pairs)
    const kem_config: ?multiplex.ConnectionPool.KemConfig = if (config.kem_public_key) |kem_pk| blk: {
        // KEM mode requires encryption to be enabled
        if (config.key_id == null or config.shared_key == null) {
            log.err("KEM mode requires encryption (-k flag)", .{});
            return;
        }
        log.info("Using KEM mode with key ID {}", .{kem_pk.key_id});
        break :blk .{
            .kem_key_id = kem_pk.key_id,
            .kem_public_key = &kem_pk.key,
        };
    } else null;

    var contexts: [max_proxy_pairs]ClientProxyContext = undefined;
    for (config.proxy_pairs, 0..) |pair, i| {
        contexts[i] = .{
            .allocator = allocator,
            .io = io,
            .pair_index = i,
            .listen_address = pair.listen_address,
            .backend_address = pair.backend_address,
            .key_id = config.key_id,
            .shared_key = if (config.shared_key) |*k| k else null,
            .cluster_id = config.cluster_id,
            .num_connections = config.num_connections,
            .max_sessions = config.max_sessions,
            .kem_config = kem_config,
            .active_sessions = std.atomic.Value(u32).init(0),
        };
    }

    var group: Io.Group = .init;
    for (0..config.proxy_pairs.len) |i| {
        group.concurrent(io, runClientProxyPair, .{&contexts[i]}) catch |err| {
            log.err("Pair {}: Failed to spawn proxy pair thread: {}", .{ i, err });
        };
    }
    group.await(io) catch {};
}

/// Context for a server proxy pair running in its own thread
const ServerProxyContext = struct {
    allocator: Allocator,
    io: Io,
    pair_index: usize,
    listen_address: net.IpAddress,
    backend_address: net.IpAddress,
    key_store_ptr: ?*const crypto.KeyStore,
    kem_secret_key_store_ptr: ?*const crypto.KemSecretKeyStore,
    cluster_id: ?u128,
    max_sessions: u32,
    /// Group for handler tasks (one per multiplexed connection)
    handler_group: Io.Group = .init,
};

fn runServerProxyPair(ctx: *ServerProxyContext) void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const pair_index = ctx.pair_index;

    var server = net.IpAddress.listen(ctx.listen_address, io, .{
        .reuse_address = true,
    }) catch |err| {
        log.err("Pair {}: Failed to bind: {}", .{ pair_index, err });
        return;
    };
    defer server.deinit(io);

    log.info("Pair {}: Listening for multiplexed connections...", .{pair_index});

    var conn_id: u64 = 0;

    // Accept loop
    while (true) {
        const stream = server.accept(io) catch |err| {
            log.warn("Pair {}: Accept failed: {}", .{ pair_index, err });
            continue;
        };

        conn_id += 1;
        log.info("Pair {}: Accepted multiplexed connection {}", .{ pair_index, conn_id });

        const handler = allocator.create(mux_session.ServerMuxHandler) catch |err| {
            log.err("Pair {}: Failed to allocate handler: {}", .{ pair_index, err });
            stream.close(io);
            continue;
        };

        handler.* = mux_session.ServerMuxHandler.init(
            allocator,
            io,
            stream,
            ctx.backend_address,
            conn_id,
            ctx.key_store_ptr,
            ctx.kem_secret_key_store_ptr,
            ctx.cluster_id,
            ctx.max_sessions,
        );

        ctx.handler_group.concurrent(io, mux_session.runServerMuxHandler, .{handler}) catch |err| {
            log.err("Pair {}: Failed to spawn handler thread: {}", .{ ctx.pair_index, err });
            stream.close(io);
            continue;
        };
    }
}

fn runMuxServer(
    allocator: Allocator,
    io: Io,
    config: *const Config,
) void {
    const key_store_ptr: ?*const crypto.KeyStore = if (config.key_store) |*ks| ks else null;
    const kem_secret_key_store_ptr: ?*const crypto.KemSecretKeyStore = if (config.kem_secret_key_store) |*kss| kss else null;

    var contexts: [max_proxy_pairs]ServerProxyContext = undefined;
    for (config.proxy_pairs, 0..) |pair, i| {
        contexts[i] = .{
            .allocator = allocator,
            .io = io,
            .pair_index = i,
            .listen_address = pair.listen_address,
            .backend_address = pair.backend_address,
            .key_store_ptr = key_store_ptr,
            .kem_secret_key_store_ptr = kem_secret_key_store_ptr,
            .cluster_id = config.cluster_id,
            .max_sessions = config.max_sessions,
        };
    }

    var group: Io.Group = .init;
    for (0..config.proxy_pairs.len) |i| {
        group.concurrent(io, runServerProxyPair, .{&contexts[i]}) catch |err| {
            log.err("Pair {}: Failed to spawn server proxy pair thread: {}", .{ i, err });
        };
    }
    group.await(io) catch {};
}
