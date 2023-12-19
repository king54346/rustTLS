use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;

use argh::FromArgs;
use rustls::{OwnedTrustAnchor, ServerName};
use rustls_pemfile::certs;
use tokio::io::{copy, split, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Tokio Rustls client example
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, short = 'p', default = "443")]
    port: u16,

    /// domain
    #[argh(option, short = 'd')]
    domain: Option<String>,

    /// cafile
    #[argh(option, short = 'c')]
    cafile: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let options: Options = argh::from_env();

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    
    let domain = options.domain.unwrap_or(options.host);
    let content = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n",domain);

    let mut root_cert_store = rustls::RootCertStore::empty();

    let cert_file = File::open("/home/socks5-main/domain.crt")?;
    
    let mut reader = BufReader::new(cert_file);
  
    root_cert_store.add_parsable_certificates(&certs(&mut reader)?);
    
    
    // root_cert_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
    //     OwnedTrustAnchor::from_subject_spki_name_constraints(
    //         ta.subject,
    //         ta.spki,
    //         ta.name_constraints,
    //     )
    // }));

    let config = rustls::ClientConfig::builder().with_safe_defaults().with_root_certificates(root_cert_store).with_no_client_auth();

    
    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(&addr).await?;

    let (mut stdin, mut stdout) = (tokio_stdin(), tokio_stdout());
    
    let dnsname = ServerName::try_from("www.domain.com").unwrap();


    let mut stream = connector.connect(dnsname, stream).await?;
    
    //所有数据都被写入到操作系统的输出缓冲区
    stream.write_all(content.as_bytes()).await?;
    
    // 输出缓冲区中的数据被发送到网络
    stream.flush().await?; 

    // 关闭流的写入部分
    stream.shutdown().await?;

    // 读取响应并输出到控制台
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await?;
    println!("Response: {}", String::from_utf8_lossy(&buffer));

    Ok(())
}