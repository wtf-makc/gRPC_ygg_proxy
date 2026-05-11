/// ygg-grpc-proxy
///
/// CLIENT mode:
///   Listens on one or more local TCP ports. Each port maps to a remote Yggdrasil
///   peer URI (tcp:// or tls://). When Yggdrasil connects to that port, the client
///   opens a gRPC bidirectional stream to the server and passes the target URI in
///   the first frame. All subsequent bytes are proxied transparently.
///
/// SERVER mode:
///   Accepts gRPC streams. Reads the target URI from the first frame, dials the
///   real Yggdrasil peer (TCP or TLS), and splices traffic in both directions.
///
/// Usage examples:
///
///   Server (on VPS):
///     ygg-grpc-proxy --server --port 9999
///
///   Client (local machine) — maps two local ports to two remote peers:
///     ygg-grpc-proxy --client \
///       --server-url http://vps.example.com:9999 \
///       --map 7777=tls://peer1.ygg.example.com:1234 \
///       --map 7778=tcp://peer2.ygg.example.com:5678
///
///   yggdrasil.conf:
///     Peers: ["tcp://127.0.0.1:7777", "tcp://127.0.0.1:7778"]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use log::{error, info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status, Streaming};

// TLS deps for dialing tls:// peers on the server side
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio_rustls::TlsConnector;

pub mod tunnel {
    tonic::include_proto!("tunnel");
}

use tunnel::tunnel_client::TunnelClient;
use tunnel::tunnel_server::{Tunnel, TunnelServer};
use tunnel::Frame;

// ─────────────────────────────────────────────
// AsyncStream trait (fix E0225)
// ─────────────────────────────────────────────

/// Combined trait so we can box async read+write streams.
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

// ─────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "ygg-grpc-proxy", about = "gRPC obfuscation proxy for Yggdrasil peers")]
struct Args {
    /// Run in server mode (on VPS)
    #[arg(long, group = "mode")]
    server: bool,

    /// Run in client mode (local machine)
    #[arg(long, group = "mode")]
    client: bool,

    /// gRPC listen port (server mode)
    #[arg(long, default_value = "9999")]
    port: u16,

    /// gRPC server URL (client mode), e.g. http://vps.example.com:9999
    #[arg(long)]
    server_url: Option<String>,

    /// Port-to-peer mappings (client mode): LOCAL_PORT=PEER_URI
    /// Example: --map 7777=tls://peer.example.com:1234
    #[arg(long = "map", value_name = "PORT=URI")]
    maps: Vec<String>,
}

// ─────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────

const BUF_SIZE: usize = 65536;
// First frame on every new gRPC stream carries the target URI as UTF-8,
// prefixed with a single 0x00 byte to distinguish it from data frames.
const CONTROL_PREFIX: u8 = 0x00;

fn encode_control(target: &str) -> Vec<u8> {
    let mut v = vec![CONTROL_PREFIX];
    v.extend_from_slice(target.as_bytes());
    v
}

fn decode_control(data: &[u8]) -> Option<&str> {
    if data.first() == Some(&CONTROL_PREFIX) {
        std::str::from_utf8(&data[1..]).ok()
    } else {
        None
    }
}

/// Splice two async read/write halves until either side closes.
async fn splice<R1, W1, R2, W2>(
    mut r1: R1, mut w1: W1,
    mut r2: R2, mut w2: W2,
) where
    R1: AsyncReadExt + Unpin + Send + 'static,
    W1: AsyncWriteExt + Unpin + Send + 'static,
    R2: AsyncReadExt + Unpin + Send + 'static,
    W2: AsyncWriteExt + Unpin + Send + 'static,
{
    let t1 = tokio::spawn(async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            match r1.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if w2.write_all(&buf[..n]).await.is_err() { break; }
                }
            }
        }
        let _ = w2.shutdown().await;
    });
    let t2 = tokio::spawn(async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            match r2.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if w1.write_all(&buf[..n]).await.is_err() { break; }
                }
            }
        }
        let _ = w1.shutdown().await;
    });
    let _ = tokio::join!(t1, t2);
}

// ─────────────────────────────────────────────
// SERVER
// ─────────────────────────────────────────────

#[derive(Default)]
struct TunnelService;

#[tonic::async_trait]
impl Tunnel for TunnelService {
    // FIX E0592: renamed Connect→Pipe in proto, so the associated type is PipeStream
    type PipeStream = ReceiverStream<Result<Frame, Status>>;

    async fn pipe(
        &self,
        req: Request<Streaming<Frame>>,
    ) -> Result<Response<Self::PipeStream>, Status> {
        let mut in_stream = req.into_inner();

        // Read first frame — must be control frame with target URI
        let first = in_stream
            .message()
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::invalid_argument("Empty stream"))?;

        let target = decode_control(&first.data)
            .ok_or_else(|| Status::invalid_argument("First frame must be control frame with target URI"))?
            .to_string();

        info!("New tunnel request → {}", target);

        // FIX E0282: explicit type annotation on peer_stream
        let peer_stream: Box<dyn AsyncStream> = dial_peer(&target)
            .await
            // FIX E0282: explicit closure parameter type
            .map_err(|e: anyhow::Error| {
                error!("Failed to dial {}: {}", target, e);
                Status::unavailable(e.to_string())
            })?;

        // FIX E0282: split gives concrete typed halves, no inference ambiguity
        let (peer_reader, peer_writer) = tokio::io::split(peer_stream);

        // Channel: peer→gRPC outbound
        let (tx, rx) = mpsc::channel::<Result<Frame, Status>>(256);

        // Task: peer → gRPC client
        let tx2 = tx.clone();
        tokio::spawn(async move {
            let mut reader = peer_reader;
            let mut buf = vec![0u8; BUF_SIZE];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx2.send(Ok(Frame { data: buf[..n].to_vec() })).await.is_err() {
                            break;
                        }
                    }
                }
            }
            info!("Peer→gRPC task ended for {}", target);
        });

        // Task: gRPC client → peer
        let mut peer_writer = peer_writer;
        tokio::spawn(async move {
            while let Ok(Some(frame)) = in_stream.message().await {
                if peer_writer.write_all(&frame.data).await.is_err() {
                    break;
                }
            }
            let _ = peer_writer.shutdown().await;
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Dial a peer URI. Supports:
///   tcp://host:port
///   tls://host:port
// FIX E0225: use Box<dyn AsyncStream> instead of Box<dyn AsyncRead + AsyncWrite + ...>
async fn dial_peer(uri: &str) -> Result<Box<dyn AsyncStream>> {
    if let Some(rest) = uri.strip_prefix("tcp://") {
        let stream = TcpStream::connect(rest)
            .await
            .with_context(|| format!("TCP connect to {}", rest))?;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    } else if let Some(rest) = uri.strip_prefix("tls://") {
        // Parse host:port
        let (host, _port) = rest.rsplit_once(':')
            .with_context(|| format!("Invalid tls:// URI: {}", uri))?;

        let tcp = TcpStream::connect(rest)
            .await
            .with_context(|| format!("TCP connect for TLS to {}", rest))?;
        tcp.set_nodelay(true)?;

        // Build TLS client config with system roots
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        };
        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(host.to_string())
            .with_context(|| format!("Invalid server name: {}", host))?;

        let tls_stream = connector.connect(server_name, tcp)
            .await
            .with_context(|| format!("TLS handshake with {}", host))?;

        Ok(Box::new(tls_stream))
    } else {
        bail!("Unsupported URI scheme (use tcp:// or tls://): {}", uri)
    }
}

async fn run_server(port: u16) -> Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    info!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(TunnelServer::new(TunnelService::default()))
        .serve(addr)
        .await?;

    Ok(())
}

// ─────────────────────────────────────────────
// CLIENT
// ─────────────────────────────────────────────

/// Parse "7777=tls://peer.example.com:1234" → (7777, "tls://peer.example.com:1234")
fn parse_map(s: &str) -> Result<(u16, String)> {
    let (port_str, uri) = s.split_once('=')
        .with_context(|| format!("Invalid --map value '{}', expected PORT=URI", s))?;
    let port = port_str.trim().parse::<u16>()
        .with_context(|| format!("Invalid port in --map: {}", port_str))?;
    Ok((port, uri.trim().to_string()))
}

async fn run_client(server_url: String, maps: Vec<String>) -> Result<()> {
    if maps.is_empty() {
        bail!("Client mode requires at least one --map PORT=URI");
    }

    let server_url = Arc::new(server_url);

    for map in maps {
        let (local_port, target_uri) = parse_map(&map)?;
        let server_url = server_url.clone();

        tokio::spawn(async move {
            if let Err(e) = listen_and_forward(local_port, target_uri.clone(), server_url).await {
                error!("Listener for port {} ({}): {}", local_port, target_uri, e);
            }
        });
    }

    // Keep main alive
    tokio::signal::ctrl_c().await?;
    info!("Shutting down");
    Ok(())
}

async fn listen_and_forward(local_port: u16, target_uri: String, server_url: Arc<String>) -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port))
        .await
        .with_context(|| format!("Bind 127.0.0.1:{}", local_port))?;

    info!("Listening on 127.0.0.1:{} → {}", local_port, target_uri);

    loop {
        let (ygg_stream, peer_addr) = listener.accept().await?;
        ygg_stream.set_nodelay(true)?;
        info!("Yggdrasil connected from {} on port {}", peer_addr, local_port);

        let target_uri = target_uri.clone();
        let server_url = server_url.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_ygg_connection(ygg_stream, target_uri.clone(), server_url).await {
                warn!("Connection to {} ended: {}", target_uri, e);
            }
        });
    }
}

async fn handle_ygg_connection(
    ygg_stream: TcpStream,
    target_uri: String,
    server_url: Arc<String>,
) -> Result<()> {
    // Connect to gRPC server with retry
    let channel = tokio::time::timeout(
        Duration::from_secs(10),
        tonic::transport::Endpoint::from_shared((*server_url).clone())?
            .connect(),
    )
    .await
    .context("gRPC connect timeout")?
    .context("gRPC connect failed")?;

    let mut client = TunnelClient::new(channel);

    // Channel for Yggdrasil→gRPC outbound frames
    let (tx, rx) = mpsc::channel::<Frame>(256);

    // First frame: control frame with target URI
    tx.send(Frame { data: encode_control(&target_uri) }).await
        .context("Failed to send control frame")?;

    // Task: Yggdrasil → gRPC
    let (mut ygg_reader, mut ygg_writer) = tokio::io::split(ygg_stream);
    let tx2 = tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            match ygg_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx2.send(Frame { data: buf[..n].to_vec() }).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let request = Request::new(ReceiverStream::new(rx));
    // FIX E0592: renamed from .connect() to .pipe() to match proto
    let mut response_stream = client.pipe(request).await?.into_inner();

    // gRPC → Yggdrasil
    while let Ok(Some(frame)) = response_stream.message().await {
        if ygg_writer.write_all(&frame.data).await.is_err() {
            break;
        }
    }

    let _ = ygg_writer.shutdown().await;
    Ok(())
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    if args.server {
        run_server(args.port).await
    } else if args.client {
        let url = args.server_url
            .context("--server-url is required in client mode")?;
        run_client(url, args.maps).await
    } else {
        bail!("Either --server or --client is required");
    }
}
