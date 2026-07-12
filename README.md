<div align="center">

# yggmail-ng

</div>

P2P email server over Yggdrasil mesh network rewritten on Rust.

[English](#) | [Русский](README.ru.md)

## How it works

yggmail-ng lets you send and receive email over the Yggdrasil mesh network. No central servers — messages route directly between nodes using Ed25519 public keys as addresses.

Your email address is `hex_pubkey@yggmail`. Standard mail clients (Thunderbird, Outlook) connect via localhost SMTP/IMAP.

## Requirements

To build from source:

- **Rust** stable (1.85+) — install via [rustup](https://rustup.rs)
- **A C compiler** — `rusqlite` bundles SQLite and compiles it from C:
  Linux `gcc`/`clang` + `make`, macOS Xcode Command Line Tools, Windows MSVC build tools
- Yggdrasil-ng is a local path dependency (nothing to install separately)

## Build

```bash
git clone https://github.com/JB-SelfCompany/Yggmail-ng
cd Yggmail-ng
cargo build --release
```

## Quick start

```bash
# Generate configs
./target/release/yggmail --genconf

# Edit yggdrasil.toml — add peers
# Edit yggmail.toml — configure ports if needed

# Start
./target/release/yggmail
```

Mail client settings:
- SMTP: `127.0.0.1:1025` (no auth, no TLS)
- IMAP: `127.0.0.1:1143` (no auth, no TLS)

## CLI

```
yggmail [flags]

  --config, -c FILE        Yggdrasil config (default: yggdrasil.toml)
  --yggmail-config FILE    Yggmail config (default: yggmail.toml)
  --genconf                Generate fresh configs and exit
  --help, -h               Show help
  --version, -V            Show version
```

## Configuration

### yggmail.toml

```toml
db_path = "yggmail.db"    # SQLite database path
smtp_port = 1025           # SMTP listen port (localhost only)
imap_port = 1143           # IMAP listen port (localhost only)
```

### yggdrasil.toml

Standard Yggdrasil-ng config. Key fields:

```toml
private_key = ""           # Ed25519 keypair (128 hex chars)
peers = []                 # Peer URIs: ["tcp://host:port"]
listen = ["tcp://[::]:0"]  # Listen addresses
```

## Architecture

```
MUA (Thunderbird) <──SMTP/IMAP──> yggmail <──YMP──> Yggdrasil network <──> peers
                                       │
                                  SQLite (yggmail.db)
```

### Protocol stack

| Layer | Protocol | Purpose |
|-------|----------|---------|
| Mail client | SMTP + IMAP4rev1 | Thunderbird/Outlook compatibility |
| Wire protocol | YMP (Yggdrasil Mail Protocol) | Fragmentation, ACK, retransmission over PacketConn |
| Encryption | XSalsa20-Poly1305 (ironwood) | End-to-end encrypted transport |
| Routing | Yggdrasil spanning tree | P2P mesh routing via Ed25519 keys |

### YMP packet format

```
Offset  Size  Field
0       1     type        — 0x10=DATA, 0x11=ACK
1       8     msg_id      — big-endian u64
9       2     seq         — segment number
11      2     total        — total segments
13      2     payload_len  — payload length
15      N     payload
```

### Database schema

```sql
-- Mailboxes (INBOX, Outbox, Sent are protected)
CREATE TABLE mailboxes (mailbox TEXT PRIMARY KEY, subscribed BOOLEAN DEFAULT 1);

-- Mails (RFC 5322 blobs with flags)
CREATE TABLE mails (
    mailbox TEXT, id INTEGER, mail BLOB, datetime INTEGER,
    seen BOOLEAN DEFAULT 0, answered BOOLEAN DEFAULT 0,
    flagged BOOLEAN DEFAULT 0, deleted BOOLEAN DEFAULT 0,
    PRIMARY KEY (mailbox, id)
);

-- Outbound queue
CREATE TABLE queue (
    destination TEXT, mailbox TEXT, id INTEGER,
    mail TEXT, rcpt TEXT,
    PRIMARY KEY (destination, mailbox, id)
);
```

## Android library

The `yggmail-mobile` crate provides Kotlin bindings via UniFFI.

### Build

Additional dependencies for the Android cross-build:

- Android NDK, with `ANDROID_NDK_HOME` set to its path
- Rust Android targets and `cargo-ndk`:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
cargo install cargo-ndk
./build-android.sh          # Unix   (build-android.ps1 on Windows)
```

The script builds the `.so` per ABI and generates the UniFFI Kotlin bindings, then
prints where to copy them.

### API

```kotlin
val mobile = YggmailMobile()
mobile.start(YggmailConfig(
    privateKey = "hex...",
    peers = listOf("tcp://peer:1234"),
    listen = listOf("tcp://[::]:0"),
    groupPassword = "",
    databasePath = "/data/data/.../yggmail.db"
))

mobile.sendMail("pubkey@yggmail", "Subject", "Body")
val count = mobile.getInboxCount()
val mails = mobile.getMailSummaries(0u, 20u)
mobile.stop()
```

### Generated files

```
kotlin-bindings/uniffi/yggmail_mobile/yggmail_mobile.kt  → app/src/main/java/
target/<arch>/release/libyggmail_mobile.so                 → app/src/main/jniLibs/<abi>/
```

## Project structure

```
yggmail-ng/
├── crates/
│   ├── yggmail/            # Core server
│   │   └── src/
│   │       ├── ymp/        # Yggdrasil Mail Protocol
│   │       ├── storage/    # SQLite storage
│   │       ├── peer/       # Peer exchange (sender/receiver)
│   │       ├── smtp/       # SMTP server
│   │       └── imap/       # IMAP server
│   └── yggmail-mobile/     # Android/iOS library (UniFFI)
├── Cross.toml              # Android cross-compilation
├── build-android.sh        # Android build script
├── build-android.ps1       # Android build script
├── README.md
└── README.ru.md
```

## Testing

```bash
cargo test -p yggmail
```

## License

MPL