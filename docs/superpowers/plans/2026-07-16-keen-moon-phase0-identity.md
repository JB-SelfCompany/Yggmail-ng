# keen-moon Фаза 0 — Стабильная и переносимая identity (issue #39) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Гарантировать, что `@yggmail`-адрес (ed25519 identity) не меняется между рестартами, при смене пароля и при restore — закрыв issue #39 регресс-тестами на **зашифрованном (production) пути** и пересборкой `.so` для всех 4 ABI.

**Architecture:** Продакшн-код identity **уже корректен** — `load_or_migrate_identity` переиспользует персистентный ключ, `SqliteStorage` хранит стабильный data-key (DK) под `KEK=f(password_hash)`, при неверном пароле открытие даёт `Err` (DK не пересоздаётся), смена пароля = `rewrap_data_key` (тот же DK). Реальная причина #39 — релизный `.so` предшествует этому фиксу. **Единственная дыра — нулевое тестовое покрытие зашифрованного пути** (все существующие identity-тесты используют `dk=None`). Этот план добавляет регресс-тесты именно на `dk=Some(...)` и фиксирует релизную пересборку.

**Tech Stack:** Rust, `cargo test -p yggmail-mobile`, rusqlite, ed25519-dalek, `yggmail::storage::{SqliteStorage, crypt}`, XChaCha20-Poly1305 at-rest, UniFFI (Android), cargo-ndk.

---

## Ground truth (прочитано из кода — не менять эти инварианты)

Всё ниже — фактическое поведение текущего исходника, на которое опираются тесты:

- `crates/yggmail-mobile/src/lib.rs`:
  - `start()` (`:135`): открывает `SqliteStorage::open(db, Some(password_hash))` → берёт `storage.at_rest_key` (DK, `Option<[u8;32]>`) → зовёт `load_or_migrate_identity(db_path, dk)`.
  - `load_or_migrate_identity(db_path, dk)` (`:659`): (1) легаси `config.private_key` побеждает и **лечит** `mobile_config`; (2) иначе переиспользует `mobile_config` (расшифровка через `decrypt_stored_key`); (3) иначе минтит новый. Открывает **свою** rusqlite-connection к тому же файлу.
  - `decrypt_stored_key(value, dk)` (`:727`): дискриминация по **длине** — 64 байта = легаси plaintext keypair; иначе `[0x01|nonce24|ct|tag16]` → `aead_decrypt(dk, ...)`; если `dk=None` при зашифрованном блобе → `Err`.
  - `persist_identity(conn, hex_key, dk)` (`:757`): при `dk=Some` пишет `hex::encode(aead_encrypt(dk, hex_key))`, иначе plaintext hex.
  - `parse_signing_key(hex)` (`:~625`): 64-байтный keypair hex → `SigningKey::from_keypair_bytes`.
  - Существующие тесты (`:788+`): `migrates_legacy_config_key_preserving_address`, `legacy_config_key_wins_over_poisoned_mobile_config`, `fresh_install_generates_stable_key` — **все с `dk=None`**. Хелпер `temp_db(tag) -> String` уже есть в `mod tests`.
- `crates/yggmail/src/storage/mod.rs`:
  - `SqliteStorage::open(path, password_hash: Option<&str>) -> Result<Self, rusqlite::Error>` (`:62`). При `Some(hash)`: get-or-create `salt`, `KEK=derive_kek(hash, salt)`, get-or-create `wrapped_dk`. **Unwrap неверным паролем → `Err(InvalidParameterName(...))`, DK не пересоздаётся** (`:138-142`).
  - `at_rest_key: Option<[u8;32]>` (`:41`) — `Copy`.
  - `rewrap_data_key(&self, new_password_hash) -> Result<(), rusqlite::Error>` (`:189`): перезаворачивает **тот же** DK под новый KEK.
- `crates/yggmail/src/storage/crypt.rs`: `VERSION_XCHACHA=0x01`, `derive_kek(pw_hash_hex, salt)`, `aead_encrypt(&[u8;32], &[u8])`, `aead_decrypt(&[u8;32], &[u8]) -> Option<Vec<u8>>`.

**Ключевой факт для тестов:** `password_hash` в `open()`/`derive_kek()` — просто строка, скармливаемая в SHA-256; НЕ валидируется как «настоящий sha256». Значит в тестах можно брать любые различающиеся 64-hex-строки как «пароли» без крейта `sha2`.

---

## File Structure

Единственный модифицируемый файл кода — тестовый модуль в mobile-крейте; продакшн-логика не трогается (она уже корректна).

- **Modify (tests only):** `crates/yggmail-mobile/src/lib.rs` — в существующий `#[cfg(test)] mod tests` добавляются: один хелпер `dk_for(...)` и пять тестов зашифрованного пути.
- **Release (никаких правок кода):** пересборка `libyggmail_mobile.so` для 4 ABI + копирование в `Android/app/src/main/jniLibs/`.

Тесты живут рядом с identity-функциями (тот же модуль) — DRY с существующим `temp_db`, и `super::*` уже даёт в скоуп `SqliteStorage`, `load_or_migrate_identity`, `parse_signing_key`, `ed25519_dalek`, `hex`, `rusqlite`.

---

## Task 1: Хелпер `dk_for` + round-trip зашифрованной identity

Доказать: при `dk=Some` ключ шифруется в `mobile_config` и корректно расшифровывается обратно (тот же адрес). Это база для остальных тестов.

**Files:**
- Modify/Test: `crates/yggmail-mobile/src/lib.rs` (внутри `#[cfg(test)] mod tests`, рядом с существующими identity-тестами)

- [ ] **Step 1: Написать падающий тест + хелпер**

Добавить в `mod tests` (после `use super::*;`):

```rust
    use yggmail::storage::SqliteStorage;

    // Открыть storage с паролем и вернуть выведенный data-key (DK).
    // Storage дропается сразу — load_or_migrate_identity откроет свою connection,
    // ровно как в start(): сперва open() минтит/распечатывает DK, затем identity.
    fn dk_for(db: &str, password_hash: &str) -> Option<[u8; 32]> {
        SqliteStorage::open(db, Some(password_hash))
            .expect("storage open")
            .at_rest_key
    }

    const PW_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const PW_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn encrypted_identity_roundtrips() {
        let p = temp_db("enc-roundtrip");

        // Первый "старт": open минтит DK, load генерит+шифрует identity в mobile_config.
        let dk = dk_for(&p, PW_A);
        assert!(dk.is_some(), "password → DK must be present");
        let (k1, hex1) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();

        // Хранимое значение — зашифрованный блоб, НЕ 128-hex plaintext keypair.
        let conn = rusqlite::Connection::open(&p).unwrap();
        let stored: String = conn
            .query_row(
                "SELECT value FROM mobile_config WHERE key = 'private_key'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let raw = hex::decode(&stored).expect("stored value is hex");
        assert_ne!(raw.len(), 64, "encrypted blob must not be a 64-byte keypair");
        assert_eq!(raw.first(), Some(&0x01u8), "encrypted blob starts with VERSION_XCHACHA");
        assert_ne!(stored, hex1, "stored form must be ciphertext, not plaintext hex");

        // Второй load с тем же DK возвращает тот же адрес (расшифровка сработала).
        let (k2, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
        assert_eq!(
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
            "encrypted identity must round-trip to the same @yggmail address"
        );

        let _ = std::fs::remove_file(&p);
    }
```

- [ ] **Step 2: Запустить — убедиться, что падает (или компилируется и проходит, если инфра готова)**

Run: `cargo test -p yggmail-mobile encrypted_identity_roundtrips -- --nocapture`
Expected: сперва может не компилироваться, если `SqliteStorage` не был импортирован — тогда ошибка компиляции `unresolved import`. После добавления `use` — тест должен **пройти** (продакшн-код уже корректен). Это regression-lock: тест фиксирует существующее верное поведение.

> NB: у части задач тут «тест сразу зелёный» — это **характеризационные (regression) тесты** на уже-рабочий код. Красная фаза = «до добавления теста поведение не проверялось». Если тест падает — это найденный баг, останавливаемся и чиним по systematic-debugging.

- [ ] **Step 3: Если тест красный — диагностировать, не «подгонять»**

Если `encrypted_identity_roundtrips` падает — значит зашифрованный путь реально сломан (в отличие от plaintext). Зафиксировать факт, применить systematic-debugging, чинить **продакшн** `decrypt_stored_key`/`persist_identity`/`load_or_migrate_identity`, а не тест.

- [ ] **Step 4: Запустить — зелёный**

Run: `cargo test -p yggmail-mobile encrypted_identity_roundtrips`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/yggmail-mobile/src/lib.rs
git commit -m "test(identity): cover encrypted mobile_config round-trip (issue #39)"
```

---

## Task 2: Стабильность адреса через N рестартов (зашифрованный путь)

Прямой регресс на симптом #39: «рестарт → новый адрес». Моделируем N циклов open→load с одним паролем.

**Files:**
- Test: `crates/yggmail-mobile/src/lib.rs` (`mod tests`)

- [ ] **Step 1: Написать тест**

```rust
    #[test]
    fn encrypted_identity_stable_across_restarts() {
        let p = temp_db("enc-restarts");

        // Первый старт фиксирует адрес.
        let first = {
            let dk = dk_for(&p, PW_A);
            let (k, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
            k.verifying_key().to_bytes()
        };

        // Ещё 5 "рестартов": каждый заново открывает storage (распечатывает тот же DK
        // из wrapped_dk) и загружает identity. Адрес обязан остаться прежним.
        for i in 0..5 {
            let dk = dk_for(&p, PW_A);
            let (k, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
            assert_eq!(
                k.verifying_key().to_bytes(),
                first,
                "restart #{i} rotated the @yggmail address — issue #39 regression"
            );
        }

        let _ = std::fs::remove_file(&p);
    }
```

- [ ] **Step 2: Запустить**

Run: `cargo test -p yggmail-mobile encrypted_identity_stable_across_restarts`
Expected: PASS (фиксация корректного поведения). Красный → баг в персистентности DK/identity, чинить продакшн.

- [ ] **Step 3: Commit**

```bash
git add crates/yggmail-mobile/src/lib.rs
git commit -m "test(identity): address stable across N encrypted restarts (issue #39)"
```

---

## Task 3: Неверный пароль → `Err`, БЕЗ ротации; верный пароль восстанавливает

Гарантия «нет тихой потери identity»: неверный пароль (в т.ч. после Keystore-recovery) обязан дать ошибку открытия, а не пересоздать ключ; при возврате верного пароля адрес тот же.

**Files:**
- Test: `crates/yggmail-mobile/src/lib.rs` (`mod tests`)

- [ ] **Step 1: Написать тест**

```rust
    #[test]
    fn wrong_password_errors_and_never_rotates_identity() {
        let p = temp_db("enc-wrongpw");

        // Установить identity под паролем A.
        let original = {
            let dk = dk_for(&p, PW_A);
            let (k, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
            k.verifying_key().to_bytes()
        };

        // Открытие под НЕВЕРНЫМ паролем B → hard error (DK не распечатывается),
        // wrapped_dk НЕ перезаписывается новым ключом.
        let bad = SqliteStorage::open(&p, Some(PW_B));
        assert!(bad.is_err(), "wrong password must fail open, never mint a new DK");

        // Возврат к верному паролю A → тот же DK, тот же адрес (ничего не потеряно).
        let dk = dk_for(&p, PW_A);
        let (k, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
        assert_eq!(
            k.verifying_key().to_bytes(),
            original,
            "correct password must recover the exact same @yggmail address"
        );

        let _ = std::fs::remove_file(&p);
    }
```

- [ ] **Step 2: Запустить**

Run: `cargo test -p yggmail-mobile wrong_password_errors_and_never_rotates_identity`
Expected: PASS. Красный (напр. `open` под чужим паролем вернул `Ok` и пересоздал DK) → критический баг потери данных, чинить продакшн `SqliteStorage::open`.

- [ ] **Step 3: Commit**

```bash
git add crates/yggmail-mobile/src/lib.rs
git commit -m "test(identity): wrong password errors without rotating identity (issue #39)"
```

---

## Task 4: Смена пароля (`rewrap_data_key`) сохраняет адрес — доказательство restore-под-новым-паролем

Закрывает residual «restore под новым паролем»: identity привязана к DK, а не к паролю; `rewrap_data_key` меняет только обёртку DK. Значит restore, за которым следует смена пароля, адрес сохраняет.

**Files:**
- Test: `crates/yggmail-mobile/src/lib.rs` (`mod tests`)

- [ ] **Step 1: Написать тест**

```rust
    #[test]
    fn password_change_preserves_identity_address() {
        let p = temp_db("enc-rewrap");

        // Identity под паролем A.
        let (before, _) = {
            let dk = dk_for(&p, PW_A);
            load_or_migrate_identity(&p, dk.as_ref()).unwrap()
        };

        // Смена пароля A→B: тот же DK перезаворачивается под KEK(B). Identity/mail не трогаются.
        {
            let s = SqliteStorage::open(&p, Some(PW_A)).unwrap();
            s.rewrap_data_key(PW_B).unwrap();
        }

        // Теперь открытие под НОВЫМ паролем B распечатывает тот же DK → тот же адрес.
        let dk_b = dk_for(&p, PW_B);
        let (after, _) = load_or_migrate_identity(&p, dk_b.as_ref()).unwrap();
        assert_eq!(
            after.verifying_key().to_bytes(),
            before.verifying_key().to_bytes(),
            "password change must preserve the @yggmail address (restore-under-new-password path)"
        );

        // И старый пароль A после rewrap больше не открывает БД (обёртка сменилась).
        assert!(
            SqliteStorage::open(&p, Some(PW_A)).is_err(),
            "old password must stop working after rewrap"
        );

        let _ = std::fs::remove_file(&p);
    }
```

- [ ] **Step 2: Запустить**

Run: `cargo test -p yggmail-mobile password_change_preserves_identity_address`
Expected: PASS. Красный → `rewrap_data_key` ломает доступ к identity, чинить продакшн.

- [ ] **Step 3: Commit**

```bash
git add crates/yggmail-mobile/src/lib.rs
git commit -m "test(identity): password change preserves address via DK rewrap (issue #39)"
```

---

## Task 5: Миграция легаси-1.8-ключа под шифрованием (`dk=Some`) — лечит и шифрует

Существующий `legacy_config_key_wins_over_poisoned_mobile_config` покрывает только `dk=None`. Здесь — тот же приоритет+лечение, но с реальным DK: адрес легаси-ключа сохраняется, а вылеченный `mobile_config` хранится **в зашифрованном** виде.

**Files:**
- Test: `crates/yggmail-mobile/src/lib.rs` (`mod tests`)

- [ ] **Step 1: Написать тест**

```rust
    #[test]
    fn legacy_migration_under_encryption_heals_and_encrypts() {
        let p = temp_db("enc-legacy");

        // 1.8 DB: легаси `config` держит реальный ключ; сначала создаём его.
        let real = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let real_hex = hex::encode(real.to_keypair_bytes());
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch(
                "CREATE TABLE config (key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(key));",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('private_key', ?1)",
                rusqlite::params![&real_hex],
            )
            .unwrap();
        }

        // Открытие storage с паролем создаёт at_rest/DK поверх той же БД.
        let dk = dk_for(&p, PW_A);
        let (loaded, loaded_hex) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();

        // Легаси-адрес сохранён.
        assert_eq!(
            loaded.verifying_key().to_bytes(),
            real.verifying_key().to_bytes(),
            "1.8→1.9 migration must keep the @yggmail address under encryption"
        );
        assert_eq!(loaded_hex, real_hex);

        // mobile_config вылечен И зашифрован (не 64-байтный plaintext keypair).
        let conn = rusqlite::Connection::open(&p).unwrap();
        let stored: String = conn
            .query_row(
                "SELECT value FROM mobile_config WHERE key = 'private_key'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let raw = hex::decode(&stored).unwrap();
        assert_eq!(raw.first(), Some(&0x01u8), "healed mobile_config must be encrypted");
        assert_ne!(stored, real_hex, "must not store legacy key in plaintext");

        // Следующий старт под тем же паролем даёт тот же адрес.
        let dk2 = dk_for(&p, PW_A);
        let (again, _) = load_or_migrate_identity(&p, dk2.as_ref()).unwrap();
        assert_eq!(again.verifying_key().to_bytes(), real.verifying_key().to_bytes());

        let _ = std::fs::remove_file(&p);
    }
```

- [ ] **Step 2: Запустить**

Run: `cargo test -p yggmail-mobile legacy_migration_under_encryption_heals_and_encrypts`
Expected: PASS. Красный → миграция под шифрованием теряет/не шифрует ключ, чинить продакшн.

- [ ] **Step 3: Прогнать весь модуль identity-тестов**

Run: `cargo test -p yggmail-mobile`
Expected: PASS — новые 5 тестов + 3 существующих зелёные.

- [ ] **Step 4: Commit**

```bash
git add crates/yggmail-mobile/src/lib.rs
git commit -m "test(identity): legacy 1.8 migration heals+encrypts under DK (issue #39)"
```

---

## Task 6: Релиз — пересборка `.so` для всех 4 ABI (главная причина #39)

Код-фикс уже в исходнике; #39 в проде живёт потому, что релизный `.so` его предшествует. Эта задача — **выпустить** фикс. Команды выполняет пользователь (workflow «no build/commit by Claude»); ниже — точный чеклист.

**Files:**
- Rebuild: `crates/yggmail-mobile` → `libyggmail_mobile.so` ×4 ABI
- Copy to: `Android/app/src/main/jniLibs/{armeabi-v7a,arm64-v8a,x86,x86_64}/libyggmail_mobile.so`
- Regenerate: `Android/app/src/main/java/uniffi/yggmail_mobile/yggmail_mobile.kt` (если менялся `.udl` — здесь НЕ менялся, шаг проверочный)

- [ ] **Step 1: Полный прогон тестов на релизном профиле**

Run: `cargo test -p yggmail-mobile --release`
Expected: все identity-тесты PASS.

- [ ] **Step 2: Собрать AAR/`.so` для всех 4 ABI**

Run (из `Librarys/Yggmail-ng`): `./build-android.sh`
Expected: собраны `.so` под `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64` (cargo-ndk). Убедиться, что **ни один ABI не пропущен** — иначе часть устройств останется на старом коде (ровно причина #39).

- [ ] **Step 3: Скопировать `.so` в Android и (если нужно) регенерировать UniFFI-биндинги**

- Скопировать каждый `libyggmail_mobile.so` в соответствующий `Android/app/src/main/jniLibs/{abi}/`.
- `.udl` в этом плане не менялся → Kotlin-биндинги регенерировать не требуется; сверить, что `uniffi/yggmail_mobile/yggmail_mobile.kt` не устарел относительно `.so`.

- [ ] **Step 4: Смоук на устройстве — регресс #39**

Ручной сценарий (Android): свежая установка → онбординг → записать `@yggmail`-адрес → бэкап → **рестарт сервиса** → адрес **тот же**. Затем: смена пароля → рестарт → адрес тот же. Затем: restore `.tyrbackup` → адрес тот же.
Expected: адрес не меняется ни в одном сценарии.

- [ ] **Step 5: Commit (Android-репо, отдельный)**

```bash
git add app/src/main/jniLibs
git commit -m "chore: ship identity-stability fix (rebuilt .so, all 4 ABI) — fixes #39"
```

---

## Вне объёма этого плана (отдельные follow-up)

Не тащим сюда (YAGNI / отдельные подсистемы):

1. **Kotlin BackupManager verification** — проверить, что `.tyrbackup` бэкапит **весь** `yggmail.db` включая таблицу `at_rest` (salt + wrapped_dk), а restore не рассинхронивает пароль. Если restore под новым паролем — Kotlin должен вызвать смену пароля (которая внутри зовёт `SqliteStorage::rewrap_data_key`, проверить, что `set_password`/`hotReloadPassword` это делает). Это Android-подсистема с device-тестами → отдельный план.
2. **Проверка, что `set_password` (lib.rs:~616) вызывает `storage.rewrap_data_key`** — если только обновляет in-memory hash без rewrap, смена пароля сломает открытие после рестарта. Мелкий, но отдельный фикс/тест; всплывёт в Kotlin-плане.
3. **Фазы 1-3 keen-moon** (QUIC-оверлей) — отдельные планы, как решено.

---

## Self-Review

**Spec coverage** (против `android-keen-moon.md` Фаза 0 «Фикс»):
- «Гарантировать наличие `load_or_migrate_identity` в релизной сборке; пересобрать `.so` для всех 4 ABI» → Task 6. ✓
- «identity стабильна через N рестартов» → Task 2. ✓
- «restore под новым паролем сохраняет адрес» → Task 4 (доказано через `rewrap_data_key`; спецовский «отдельный identity-field» оказался не нужен — DK-модель уже это даёт; расхождение со спекой намеренное, обосновано в Ground truth). ✓
- «1.8→1.9 миграция сохраняет адрес» → Task 5 (под шифрованием; plaintext уже покрыт существующим тестом). ✓
- «На Keystore-recovery не терять identity» → Task 3 (неверный/пропавший пароль → `Err`, не ротация; identity восстановима верным паролем). ✓

**Placeholder scan:** код в каждом шаге полный, команды точные, ожидания заданы. Нет TBD/«handle edge cases». ✓

**Type consistency:** `dk_for(&str,&str)->Option<[u8;32]>`, `load_or_migrate_identity(&str, Option<&[u8;32]>)`, `SqliteStorage::open(&str, Option<&str>)`, `rewrap_data_key(&str)`, `at_rest_key: Option<[u8;32]>` — согласованы с прочитанным исходником. `PW_A`/`PW_B`/`temp_db`/`OsRng`/`hex`/`ed25519_dalek` — в скоупе `mod tests` через `use super::*` + добавленный `use yggmail::storage::SqliteStorage`. ✓

**Характеризационные тесты:** Tasks 1-5 фиксируют уже-корректное поведение (красная фаза = «не проверялось»). Если любой падает — это найденный баг: остановка + systematic-debugging + правка **продакшн**-кода, не теста.

## Verification (пользователь)
1. `cargo test -p yggmail-mobile` — 8 identity-тестов (3 старых + 5 новых) зелёные.
2. `cargo test -p yggmail-mobile --release` — то же на релизе.
3. `./build-android.sh` — `.so` под все 4 ABI, скопированы в `jniLibs/`.
4. Device-смоук: адрес не меняется через рестарт / смену пароля / restore (Task 6 Step 4).
