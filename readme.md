虚拟主机支持： 在同一个IP地址上可以托管多个网站，这称为虚拟主机。客户端通过发送包含目标域名的HTTP请求（通过HTTP头部的“Host”字段），可以访问托管在同一服务器上的特定网站。
负载均衡和故障转移： 域名可以映射到多个IP地址，允许在多个服务器之间分配流量，实现负载均衡和故障转移。

服务名称指示（SNI）支持： SNI 是TLS协议的一个扩展，允许客户端在初始握手阶段向服务器发送目标服务器的名称。这对于在同一个IP地址上托管多个TLS保护的域名（虚拟主机）非常重要。




openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out csr.pem
openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem -extfile v3.ext




 <!-- cargo run --bin testTLSServer localhost:8002 -c /home/rustTLS/cert.pem  -k /home/rustTLS/key.pem -->