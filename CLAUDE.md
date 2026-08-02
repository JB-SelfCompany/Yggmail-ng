# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```bash
# Debug build (fast iteration)
cargo build -p yggmail

# Release build (LTO, stripped, single codegen unit)
cargo build --release

# Run all tests
cargo test -p yggmail

# Run a single test module
cargo test -p yggmail -- ymp

# Android build (requires NDK, cargo-ndk, Android targets)
./build-android.sh
```

Windows MSVC target uses `rust-lld` via `.cargo/config.toml` (Git Bash shadows the MSVC linker).

## Architecture

```
MUA (Thunderbird) ←SMTP:1025/IMAP:1143→ yggmail ←YMP→ Yggdrasil mesh ←→ peers
                                               │
                                          SQLite (yggmail.db)
```

### Crate layout (2 crates in workspace)

| Crate | Purpose |
|-------|---------|
| `yggmail` | Core server: library + binary (`src/main.rs`) |
| `yggmail-mobile` | UniFFI FFI layer for Android (depends on `yggmail`) |

Both reference `Yggdrasil-ng` at `../../../Yggdrasil-ng/crates/{ironwood,yggdrasil}` — local filesystem dependency, not published crates.

### Key module responsibilities (yggmail crate)

| Module | Role |
|--------|------|
| `ymp/` | Yggdrasil Mail Protocol — fragmentation, ACK, retransmission over `PacketConn` |
| `core_conn.rs` | Adapter that wraps `yggdrasil::Core` as `ironwood::PacketConn` trait |
| `storage/` | SQLite via rusqlite, schema-compatible with yggmail_old |
| `peer/sender.rs` | Background poll loop: reads `queue` table → `YmpSession::send()` |
| `peer/receiver.rs` | Background loop: `YmpSession::recv()` → INBOX |
| `smtp/` | Self-written ESMTP server (~200 lines), localhost:1025 only |
| `imap/` | Self-written IMAP4rev1 server (~500 lines), localhost:1143 only |
| `address.rs` | `hex(pubkey)@yggmail` parse/create |
| `config.rs` | TOML config (db_path, smtp_port, imap_port) |

### YMP protocol (15-byte header)

Wire format: `type(1) | msg_id(8 BE) | seq(2 BE) | total(2 BE) | payload_len(2 BE) | payload`

- `0x10` = DATA, `0x11` = ACK. FRAGMENT_SIZE = 65520. Max message = 32 MiB.
- Per-segment ACK (not cumulative) — Yggdrasil allows out-of-order packet delivery.
- `YmpSession::send()` blocks until all ACKs received or 5 retries exhausted (30s timeout each).
- Background reader spawned in `YmpSession::new()` — single consumer of `Core::read_from()`.

### CoreConn adapter

`Core` doesn't implement `ironwood::PacketConn` directly. `CoreConn` bridges it:
- `read_from`/`write_to` delegate to `Core` (which handles type-byte dispatch: 0x01=traffic, 0x02=proto)
- `is_closed()` stubbed to `false` (Core doesn't expose it)
- YMP is the **sole consumer** of `Core::read_from()` — no competition for the internal mpsc channel

### Storage schema

Tables: `mails`, `mailboxes`, `queue`, `config`. Key details:
- Mail BLOBs stored as raw RFC 5322 with `version byte` prefix (0x00 = plaintext, 0x01 = XChaCha20 encrypted — encryption stub currently)
- `queue.destination` = hex pubkey (not full address)
- Protected mailboxes: INBOX, Outbox, Sent (can't delete/rename)
- `Arc<Mutex<Connection>>` — no writer channel, rusqlite serializes internally

## Design decisions

- **No external SMTP/IMAP libraries.** Self-written over tokio (cumulatively ~700 lines vs adding 30k+ lines of deps). Supports the subset Thunderbird/Outlook need.
- **YMP over QUIC.** Yggdrasil-ng provides only `PacketConn` (no QUIC streams). YMP adds reliability at ~300 lines instead of porting yggquic (~2000+ lines).
- **Ponytail throughout.** Marked with `ponytail:` comments. Examples: no chrono crate (stdlib timestamps), no thiserror in yggmail (manual `impl Display`), encryption stubbed (version byte 0x00), writer channel skipped (rusqlite mutex is enough).
- **Schema compatible with yggmail_old** for migration path.
- **localhost-only** for SMTP/IMAP — rejects non-loopback connections at accept time.
- **rustls форкнут** (`../rustls-yggmail`, подключён через `[patch.crates-io]` в
  корневом `Cargo.toml`) ради одной строки: upstream отвечает фатальным алертом на
  SNI от yggmail-go — одну 64-символьную DNS-метку, превышающую лимит в 63. Без
  этого входящие соединения от узлов 1.8 невозможны. Безопасно именно здесь: SNI не
  используется вообще (один сертификат, аутентификация по ed25519-ключу из
  сертификата). **При обновлении rustls** несовпадение версии заставит cargo молча
  проигнорировать patch — проверять `cargo tree -p yggmail -i rustls`. Подробности —
  в комментарии над `[patch.crates-io]`.

## Testing patterns

- **SQLite tests**: create temp DB per test in `std::env::temp_dir()` with pid-prefixed filenames
- **YMP mock pair**: `ChanPacketConn` uses `mpsc::unbounded_channel` as a bidirectional fake network. **Known limitation**: mpsc scheduling can prevent ACK delivery in integration tests — the `ymp_send_recv_*` tests are `#[ignore]`d pending real Yggdrasil nodes.
- **SMTP/IMAP tests**: bind to `127.0.0.1:0` (random port), spawn handler in tokio task, connect as client, verify responses
- **End-to-end**: `main.rs` contains an `e2e_smtp_imap_roundtrip` test that sends via SMTP and reads back via IMAP

## Integration with Yggdrasil-ng

```rust
let config: yggdrasil::config::Config = toml::from_str(&text)?;
let signing_key = config.signing_key()?;
let core = Core::new(signing_key, config);
core.init_links().await;  // set up TLS/TCP listeners
core.start().await;       // begin peer connections + spanning tree
// then wrap in CoreConn for YMP
```

Key Yggdrasil-ng types used: `Core`, `Config`, `addr_for_key()`, `subnet_for_key()`.

## Current status (Phase implementation)

Most of DESIGN.md Phases 1-7 are complete. Notable gaps:
- At-rest encryption (XChaCha20-Poly1305): version byte plumbing exists, encryption not wired in (`chacha20poly1305` dep commented out in Cargo.toml)
- IMAP IDLE: basic broadcast-based, but sender doesn't notify on delivery yet
- YMP integration tests marked `#[ignore]` — need real Yggdrasil nodes or a proper duplex mock
- Sent mailbox: outbound mail stays in Outbox after delivery (MOVE to Sent not implemented)
