//! Почтовый оверлей: emersion-совместимый SMTP по одному QUIC-стриму, который
//! quinn везёт поверх Yggdrasil-mesh. Байт-совместим с транспортом yggquic из
//! yggmail-go, поэтому Tyr снова работает в общей сети yggmail.
//!
//! Заменяет слой надёжности YMP (`crate::ymp`); оба стоят над одним и тем же
//! ключ-адресуемым датаграммным стыком `ironwood::PacketConn`.
//!
//! Не путать с `yggdrasil::transport::quic` — то слой ПИРИНГА (как узел
//! подключается к хабу, рядом с `tcp://`), он `pub(crate)` и не переиспользуется.

mod addr_table;
mod smtp_overlay;
mod transport;
mod udp_adapter;

pub use transport::{QuicMailError, QuicMailTransport};

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ironwood::types::PacketConn;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig,
};
use rustls::pki_types::CertificateDer;
use yggdrasil::transport::tls;

use addr_table::AddrTable;
use udp_adapter::CoreUdpSocket;

/// Верхняя граница датаграммы у quinn.
const QUINN_MAX_DATAGRAM: u64 = 65527;

/// Размер пакета, который шлёт Tyr 1.8 (`InitialPacketSize: 1200` в
/// `internal/transport/yggdrasil.go`). Отправляем ровно столько же.
const OVERLAY_PACKET_BYTES: u16 = 1200;

/// Один endpoint quinn поверх mesh — и дозванивается до пиров, и принимает
/// входящую почту через единственный `CoreUdpSocket`, как в yggquic.
pub(crate) struct QuicOverlay {
    endpoint: Endpoint,
    table: Arc<AddrTable>,
}

/// Параметры QUIC под Tyr 1.8: простой 30 минут, фиксированные пакеты 1200,
/// без path-MTU discovery. (У пиринг-QUIC простой 60 с; почта держит дольше,
/// чтобы пережить окна Doze на Android.)
fn overlay_transport_config() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(
        Duration::from_secs(1800).try_into().expect("valid idle timeout"),
    ));
    // Держим соединение живым в фоне — та же роль, что у KeepAlivePeriod в 1.8.
    t.keep_alive_interval(Some(Duration::from_secs(60)));
    t.initial_mtu(OVERLAY_PACKET_BYTES);
    t.min_mtu(OVERLAY_PACKET_BYTES);
    t.mtu_discovery_config(None);
    Arc::new(t)
}

impl QuicOverlay {
    pub(crate) fn new(conn: Arc<dyn PacketConn>, signing_key: &SigningKey) -> Result<Self, String> {
        // Сколько байт мы готовы ПРИНЯТЬ. Upstream yggquic шлёт по
        // `InitialPacketSize: uint16(ygg.MTU())`, а не 1200 (1200 — это
        // переопределение именно Tyr 1.8), поэтому занижать нельзя.
        let max_datagram = conn
            .mtu()
            .min(QUINN_MAX_DATAGRAM)
            .max(OVERLAY_PACKET_BYTES as u64) as u16;

        let table = Arc::new(AddrTable::default());
        let socket = CoreUdpSocket::new(conn, table.clone());

        // Переиспользуем отгруженный ed25519 self-signed / accept-all TLS.
        // Ключ сертификата = наша mesh-identity — это требование Go-стороны:
        // она сверяет ключ из серта с адресом источника датаграмм.
        let material = tls::generate_self_signed_cert(signing_key)?;
        let server_rustls = tls::create_server_config(material.cert_chain(), material.private_key()?)?;
        let client_rustls = tls::create_client_config(material.cert_chain(), material.private_key()?)?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_rustls).map_err(|e| format!("quic server crypto: {e}"))?,
        ));
        server_config.transport_config(overlay_transport_config());

        let mut client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_rustls).map_err(|e| format!("quic client crypto: {e}"))?,
        ));
        client_config.transport_config(overlay_transport_config());

        let mut endpoint_config = EndpointConfig::default();
        endpoint_config
            .max_udp_payload_size(max_datagram)
            .map_err(|e| format!("quic max_udp_payload_size: {e}"))?;

        let mut endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|e| format!("quic endpoint: {e}"))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint, table })
    }

    /// Дозвон до пира по 32-байтному ключу.
    ///
    /// `ServerName` инертен: обе стороны включают `InsecureSkipVerify`
    /// (у нас — `AcceptAllVerifier`), проверка идёт по ключу сертификата.
    /// yggquic кладёт туда свой ключ; мы кладём ключ назначения — на провод
    /// это уходит как SNI, который Go-сторона игнорирует.
    ///
    /// Отклонение от брифа: `rustls::pki_types::ServerName::try_from` требует
    /// валидное DNS-имя и режет метки длиннее 63 байт (`server_name.rs`,
    /// `MAX_LABEL_LENGTH`), а `hex::encode(dest)` — это одна 64-символьная
    /// метка без точек, поэтому `endpoint.connect` падал с
    /// `ConnectError::InvalidServerName` ещё до первого пакета на проводе.
    /// crypto/tls на Go-стороне такой проверки не делает, отсюда расхождение
    /// проявилось только здесь. Раз содержимое SNI не участвует в протоколе
    /// (проверка — по ключу сертификата, см. `peer_key`), делим hex ровно
    /// пополам точкой — 32+32 символа, обе метки укладываются в лимит, а
    /// ключ назначения по-прежнему виден в строке для отладки.
    pub(crate) async fn connect(&self, dest: [u8; 32]) -> Result<Connection, String> {
        let addr = self.table.addr_for_key(dest);
        let hex = hex::encode(dest);
        let sni = format!("{}.{}", &hex[..32], &hex[32..]);
        self.endpoint
            .connect(addr, &sni)
            .map_err(|e| format!("quic connect: {e}"))?
            .await
            .map_err(|e| format!("quic handshake: {e}"))
    }

    /// Принять следующее входящее соединение; `None` — endpoint закрыт.
    pub(crate) async fn accept(&self) -> Option<Result<Connection, String>> {
        let incoming = self.endpoint.accept().await?;
        Some(incoming.await.map_err(|e| format!("quic accept: {e}")))
    }
}

/// Достать ed25519-ключ пира из его TLS-сертификата.
///
/// На уровне TLS сертификат принимается любой (CA у узлов нет, доверие строится
/// на ключах), поэтому аутентификация выполняется здесь и обязательна: `None`
/// означает, что пир не прислал сертификат или прислал не-ed25519 — такое
/// соединение отвергается вызывающим.
pub(crate) fn peer_key(conn: &Connection) -> Option<[u8; 32]> {
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    tls::extract_ed25519_pubkey_from_cert(certs.first()?.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_conn::testutil::MemPacketConn;
    use ed25519_dalek::SigningKey;
    // ponytail: quinn's SendStream/RecvStream have their own inherent
    // read_exact/write_all — tokio::io::{AsyncReadExt, AsyncWriteExt} from the
    // brief's test text aren't needed and trip unused-import warnings.

    /// Спайк: handshake quinn проходит поверх mesh-адаптера, bidi-стрим носит
    /// байты в обе стороны, и каждая сторона пинит ed25519-ключ другой.
    #[tokio::test]
    async fn quic_handshake_and_key_pinning_over_mesh() {
        let key_a = SigningKey::from_bytes(&[9u8; 32]);
        let key_b = SigningKey::from_bytes(&[10u8; 32]);
        let pub_a = key_a.verifying_key().to_bytes();
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let server = QuicOverlay::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();
        let client = QuicOverlay::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();

        let (srv_conn, cli_conn) = tokio::join!(
            async {
                let c = server.accept().await.expect("incoming").expect("accepted");
                let (mut send, mut recv) = c.accept_bi().await.unwrap();
                let mut b = [0u8; 5];
                recv.read_exact(&mut b).await.unwrap();
                send.write_all(&b).await.unwrap();
                send.finish().unwrap();
                c
            },
            async {
                let c = client.connect(pub_b).await.expect("connect");
                let (mut send, mut recv) = c.open_bi().await.unwrap();
                send.write_all(b"hello").await.unwrap();
                send.finish().unwrap();
                let mut back = [0u8; 5];
                recv.read_exact(&mut back).await.unwrap();
                assert_eq!(&back, b"hello");
                c
            },
        );

        assert_eq!(peer_key(&srv_conn), Some(pub_a), "server must pin client key");
        assert_eq!(peer_key(&cli_conn), Some(pub_b), "client must pin server key");
    }
}
