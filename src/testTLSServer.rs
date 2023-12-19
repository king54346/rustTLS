use std::fs::File;
use std::io::{self, BufReader, Read, Cursor, Seek};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use argh::FromArgs;

use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::{CertifiedKey, self};
use rustls::{PrivateKey, ServerConfig, Certificate};
use rustls_pemfile::{certs, rsa_private_keys, pkcs8_private_keys, ec_private_keys};
use tokio::io::{copy, sink, split, AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Tokio Rustls server example
#[derive(FromArgs)]
struct Options {
    /// bind addr
    #[argh(positional)]
    addr: String,

    /// cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// key file
    #[argh(option, short = 'k')]
    key: PathBuf,

    /// echo mode
    #[argh(switch, short = 'e')]
    echo_mode: bool,
}
// //这个函数用于加载 TLS 证书
// pub fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
//     certs(&mut BufReader::new(File::open(path)?))
//         .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
//         .map(|mut certs| certs.drain(..).map(Certificate).collect())
// }

// //这个函数用于加载私钥
// pub fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
//     let file = &mut BufReader::new(File::open(path)?);
//     let mut data = Vec::new();
//     file.read_to_end(&mut data)?;

//     let mut cursor = Cursor::new(data);

//     let parsers = [rsa_private_keys, pkcs8_private_keys, ec_private_keys];

//     for parser in &parsers {
//         if let Ok(mut key) = parser(&mut cursor) {
//             if !key.is_empty() {
//                 return Ok(key.drain(..).map(PrivateKey).collect());
//             }
//         }
//         cursor.set_position(0);
//     }

//     Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
// }
fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

// 函数：从路径加载私钥
fn load_private_key(path: &Path) -> io::Result<PrivateKey> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // 尝试读取 RSA 私钥
    if let Ok(keys) = rsa_private_keys(&mut reader) {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKey(key));
        }
    }
    // 重置读取器到文件开始
    reader.seek(io::SeekFrom::Start(0))?;

    // 尝试读取 PKCS8 私钥
    if let Ok(keys) = pkcs8_private_keys(&mut reader) {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKey(key));
        }
    }

    Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}

fn make_signing_key(priv_key: PrivateKey) -> Result<Arc<dyn sign::SigningKey>, Box<dyn std::error::Error>> {
    // 检查密钥类型并进行相应的转换
    if let Ok(rsa_key) = sign::RsaSigningKey::new(&priv_key) {
        Ok(Arc::new(rsa_key))
    } else {
        Err("Unsupported private key type".into())
    }
}


#[tokio::main]
async fn main() -> io::Result<()> {
    let options: Options = argh::from_env();

   
    // let certs  = match load_certs(Path::new(&options.cert)) {
    //     Ok(v) => v,
    //     Err(err) => {
    //         Vec::new()
    //     }
    // };

    // let mut keys  = match load_keys(Path::new(&options.key)) {
    //     Ok(v) => v,
    //     Err(err) => {
    //         Vec::new()
    //     }
    // };

    let certs  = load_certs(Path::new(&options.cert)).unwrap();
    let keys  =  load_private_key(Path::new(&options.key)).unwrap();

    let addr = &options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;

    


    let flag_echo = options.echo_mode;


    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();


    // 加载证书和私钥
    let a = keys;
    // 确保至少有一个私钥
    let priv_key = make_signing_key(a).unwrap();

    
    let certified_key = CertifiedKey::new(certs, priv_key);

    let certs2  = load_certs(Path::new("/home/socks5-main/domain.crt")).unwrap();
    let keys2  =  load_private_key(Path::new("/home/socks5-main/domain.key")).unwrap();    

    let priv_key2 = make_signing_key(keys2).unwrap();

    let certified_key2 = CertifiedKey::new(certs2, priv_key2);

    // 将域名、证书和密钥添加到解析器
    let _ = resolver.add("example.com", certified_key);
    let _ = resolver.add("domain.com",  certified_key2.clone());
    let _ = resolver.add("www.domain.com", certified_key2.clone());


    let mut config = ServerConfig::builder()
                                    .with_safe_defaults()
                                    .with_no_client_auth()
                                    // .with_single_cert(certs, a).unwrap();
                                    .with_cert_resolver(Arc::new(resolver)); //ResolvesServerCertUsingSni允许服务器根据客户端的服务器名称指示（SNI）字段选择合适的证书



    // Tls   
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // 创建并绑定一个 TCP 监听器到指定的地址 
    let listener = TcpListener::bind(&addr).await?;
        
    
    loop {
        // 每当接受一个新的 TCP 连接时，它将启动一个新的异步任务来处理这个连接
        let (stream, peer_addr) = listener.accept().await?;
        // 在异步环境中共享 TlsAcceptor 实例
        let acceptor = acceptor.clone();

        let fut = async move {
            // 对于每个接收到的 TCP 连接进行 TLS 握手
            let mut stream = acceptor.accept(stream).await?;
            
            //用来获取 TLS 握手过程中客户端
            let sni_hostname = stream.get_ref().1.server_name().unwrap();
            println!("{}",sni_hostname);
            
            println!("TLS 握手成功");
            let mut buffer = [0; 1024];
            let bytes_read = stream.read(&mut buffer).await?;
            if bytes_read == 0 {
                return Ok(());
            }
  

            // 假设请求是一个简单的 HTTP 请求
            let request_str = String::from_utf8_lossy(&buffer[..bytes_read]);
            if let Some(host_line) = request_str.split('\n').find(|line| line.starts_with("Host:")) {
                let host = host_line.trim().strip_prefix("Host:").unwrap().trim();
                println!("Received request for domain: {}", host);
            }


            // 服务器要么回显接收到的数据，要么发送一个简单的 HTTP 响应
            if flag_echo {
                let (mut reader, mut writer) = split(stream);
                let n = copy(&mut reader, &mut writer).await?;
                writer.flush().await?;
                println!("Echo: {} - {}", peer_addr, n);
            } else {
                stream
                    .write_all(
                        &b"HTTP/1.0 200 ok\r\n\
                    Connection: close\r\n\
                    Content-length: 12\r\n\
                    \r\n\
                    Hello world!"[..],
                    )
                    .await?;                    
                stream.shutdown().await?;
                println!("Hello: {}", peer_addr);
            }

            Ok(()) as io::Result<()>
        };
        // 处理单个连接
        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}