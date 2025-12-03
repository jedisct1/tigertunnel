# tigertunnel

An encrypted tunnel for TigerBeetle with connection pooling and session multiplexing.

## What it does

tigertunnel sits between your TigerBeetle clients and replicas, and/or between TigerBeetle replicas, encrypting all traffic:

```text
[TB Client] → [tigertunnel client] ══encrypted══> [tigertunnel server] → [TB Replica]

[TB Replica] → [tigertunnel client] ══encrypted══> [tigertunnel server] → [TB Replica]
```

TigerBeetle frames are individually encrypted and sent and received over a configurable pool of persistent connections.

## Quickstart: securing connections from TB clients to replicas

### Build

```sh
zig build -Doptimize=ReleaseFast
```

This creates a `zig-out/bin/tigertunnel` executable that can be copied anywhere.

### Generate keys

Create a 256-bit pre-shared key:

```sh
tigertunnel keygen -o secret.key
```

This creates a key file like:
```
1732712345678901234:0123456789abcdef...
```

Copy this file to the tigertunnel clients and servers. The same preshared key must be used everywhere.

Next, on one of the servers, create a KEM key pair:

```sh
tigertunnel kemgen -o server-kem
```

Copy `server-kem.key` to all the servers, and `server-kem.pub` to all the clients.

### Start the servers

On the TigerBeetle replicas, start tigertunnel with the `server` command:

```sh
tigertunnel server -p :3000,127.0.0.1:3001 -k secret.key
```

This listens on port 3000 for tigertunnel clients, and decrypts and forwards the traffic to 127.0.0.1:3001.

### Start the clients

On the TigerBeetle clients, start the tigertunnel with the `client` command:

```sh
tigertunnel client -p :4000,192.168.1.100:3000 -k secret.key
```

This listens for TigerBeetle client traffic on port 4000, and forwards encrypted frames to the remote tigertunnel server.

### Connect your application

Point your TigerBeetle client at `127.0.0.1:4000` instead of connecting directly to replicas.

## Forward Secrecy

Forward secrecy is optional as it may increase CPU usage/latency and may not be a mandatory property given the typical TigerBeetle deployment scenarios.

In order to enable forward secrecy:

Start the tigertunnel servers with the KEM secret key:
```sh
tigertunnel server -p :3000,127.0.0.1:3001 -k secret.key --kemsecret server-kem.key
```

Start the tigertunnel clients with the KEM public key:
```sh
tigertunnel client -p :4000,192.168.1.100:3000 -k secret.key --kempublic server-kem.pub
```

## Key rotation

Server key files support multiple keys for rotation, one per line:

```
# New key (clients should use this)
1732800000000000000:newkey...
# Old key (still accepted during rotation)
1732712345678901234:oldkey...
...
```

This applies both to KEM keys and to preshared keys.

## Multiple backends

Multiple proxy addresses can be specified by repeating the `-p` option, so that a single tigertunnel instance can proxy to all replicas:

```sh
tigertunnel client -p :4000,server1:3000 -p :4001,server2:3000 -k secret.key
```

## Tuning

```sh
# Increase pool connections (default: 4)
tigertunnel client -p :4000,server:3000 -k secret.key -n 8

# Limit concurrent sessions (default: 1000)
tigertunnel server -p :3000,127.0.0.1:3001 -k secret.key -m 500

# Verbose logging
tigertunnel server -p :3000,127.0.0.1:3001 -k secret.key --log-level debug

# Set cluster ID (connections for different clusters will be immediately rejected)
tigertunnel client -p :4000,server:3000 -k secret.key -c 12345
tigertunnel server -p :3000,127.0.0.1:3001 -k secret.key -c 12345
```
