<div align="center">

# yggmail-ng

</div>

P2P почтовый сервер поверх сети Yggdrasil переписанный на Rust.

[English](README.md) | [Русский](#)

## Как работает

yggmail-ng позволяет отправлять и получать почту через mesh-сеть Yggdrasil без центральных серверов. Сообщения маршрутизируются напрямую между узлами по Ed25519 публичным ключам.

Ваш адрес почты: `hex_pubkey@yggmail`. Подключение через локальные SMTP/IMAP — совместимо с Thunderbird и Outlook.

## Требования

Для сборки из исходников:

- **Rust** stable (1.85+) — через [rustup](https://rustup.rs)
- **Компилятор C** — `rusqlite` встраивает SQLite и собирает его из C:
  Linux `gcc`/`clang` + `make`, macOS Xcode Command Line Tools, Windows MSVC build tools
- Yggdrasil-ng — локальная path-зависимость (отдельно ставить не нужно)

## Сборка

```bash
git clone https://github.com/JB-SelfCompany/Yggmail-ng
cd Yggmail-ng
cargo build --release
```

## Быстрый старт

```bash
# Сгенерировать конфиги
./target/release/yggmail --genconf

# Отредактировать yggdrasil.toml — добавить пиров
# Отредактировать yggmail.toml — настроить порты при необходимости

# Запуск
./target/release/yggmail
```

Настройки почтового клиента:
- SMTP: `127.0.0.1:1025` (без аутентификации, без TLS)
- IMAP: `127.0.0.1:1143` (без аутентификации, без TLS)

## CLI

```
yggmail [flags]

  --config, -c FILE        Конфиг Yggdrasil (по умолчанию: yggdrasil.toml)
  --yggmail-config FILE    Конфиг Yggmail (по умолчанию: yggmail.toml)
  --genconf                Сгенерировать новые конфиги и выйти
  --help, -h               Справка
  --version, -V            Версия
```

## Конфигурация

### yggmail.toml

```toml
db_path = "yggmail.db"    # Путь к базе SQLite
smtp_port = 1025           # Порт SMTP (только localhost)
imap_port = 1143           # Порт IMAP (только localhost)
```

### yggdrasil.toml

Стандартный конфиг Yggdrasil-ng. Основные поля:

```toml
private_key = ""           # Ключ Ed25519 (128 hex-символов)
peers = []                 # URI пиров: ["tcp://host:port"]
listen = ["tcp://[::]:0"]  # Адреса прослушивания
```

## Архитектура

```
MUA (Thunderbird) <──SMTP/IMAP──> yggmail <──YMP──> сеть Yggdrasil <──> пиры
                                       │
                                  SQLite (yggmail.db)
```

### Стек протоколов

| Уровень | Протокол | Назначение |
|---------|----------|-----------|
| Почтовый клиент | SMTP + IMAP4rev1 | Совместимость с Thunderbird/Outlook |
| Сетевой протокол | YMP (Yggdrasil Mail Protocol) | Фрагментация, ACK, повторная отправка поверх PacketConn |
| Шифрование | XSalsa20-Poly1305 (ironwood) | Сквозное шифрование транспорта |
| Маршрутизация | Yggdrasil spanning tree | P2P-маршрутизация по ключам Ed25519 |

### Формат пакета YMP

```
Смещ. Размер Поле
0      1     type        — 0x10=DATA, 0x11=ACK
1      8     msg_id      — big-endian u64
9      2     seq         — номер сегмента
11     2     total        — всего сегментов
13     2     payload_len  — длина данных
15     N     payload
```

### Схема базы данных

```sql
-- Почтовые ящики (INBOX, Outbox, Sent защищены)
CREATE TABLE mailboxes (mailbox TEXT PRIMARY KEY, subscribed BOOLEAN DEFAULT 1);

-- Письма (RFC 5322 + флаги)
CREATE TABLE mails (
    mailbox TEXT, id INTEGER, mail BLOB, datetime INTEGER,
    seen BOOLEAN DEFAULT 0, answered BOOLEAN DEFAULT 0,
    flagged BOOLEAN DEFAULT 0, deleted BOOLEAN DEFAULT 0,
    PRIMARY KEY (mailbox, id)
);

-- Очередь исходящих
CREATE TABLE queue (
    destination TEXT, mailbox TEXT, id INTEGER,
    mail TEXT, rcpt TEXT,
    PRIMARY KEY (destination, mailbox, id)
);
```

## Android-библиотека

Крейт `yggmail-mobile` предоставляет Kotlin-биндинги через UniFFI.

### Сборка

Дополнительные зависимости для кросс-сборки под Android:

- Android NDK с заданной `ANDROID_NDK_HOME`
- Rust Android-таргеты и `cargo-ndk`:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
cargo install cargo-ndk
./build-android.sh          # Unix   (build-android.ps1 на Windows)
```

Скрипт собирает `.so` по каждому ABI и генерирует UniFFI Kotlin-биндинги, затем
печатает, куда их скопировать.

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

mobile.sendMail("pubkey@yggmail", "Тема", "Тело письма")
val count = mobile.getInboxCount()
val mails = mobile.getMailSummaries(0u, 20u)
mobile.stop()
```

### Сгенерированные файлы

```
kotlin-bindings/uniffi/yggmail_mobile/yggmail_mobile.kt  → app/src/main/java/
target/<arch>/release/libyggmail_mobile.so                 → app/src/main/jniLibs/<abi>/
```

## Структура проекта

```
yggmail-ng/
├── crates/
│   ├── yggmail/            # Основной сервер
│   │   └── src/
│   │       ├── ymp/        # Yggdrasil Mail Protocol
│   │       ├── storage/    # Хранилище SQLite
│   │       ├── peer/       # Пиринговый обмен
│   │       ├── smtp/       # SMTP сервер
│   │       └── imap/       # IMAP сервер
│   └── yggmail-mobile/     # Библиотека Android/iOS (UniFFI)
├── Cross.toml              # Кросс-компиляция под Android
├── build-android.sh        # Скрипт сборки под Android
├── build-android.ps1       # Скрипт сборки под Android
├── README.md
└── README.ru.md
```

## Тестирование

```bash
cargo test -p yggmail
```

## Лицензия

MPL