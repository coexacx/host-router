# Host Router

使用 Rust 编写的 TCP / QUIC 域名分流内核，附带中文终端管理菜单。

同一个监听端口可以按域名转发到不同后端。TCP 识别 TLS SNI 或 HTTP Host；UDP 识别 QUIC v1 / v2 的 ClientHello SNI。规则支持精确域名、通配域名和默认目标。

**普通 UDP 默认拒绝。** 它通常没有域名信息，不能套用 HTTP/TLS 的分流方法。本项目不将普通 UDP 自动送往默认目标。

## 安装

适用于采用 systemd 的常见 Linux 发行版。提供 amd64、arm64 的静态二进制；运行时无需 Go、Rust、Python 或数据库。

需要 Bash、curl、CA 证书、sha256sum、flock 和 useradd。Debian/Ubuntu 可先执行：

```bash
sudo apt update
sudo apt install -y curl ca-certificates passwd util-linux
```

下载脚本到本地后安装：

```bash
curl -fL https://github.com/coexacx/host-router/releases/latest/download/hostip.sh -o hostip.sh
sudo bash hostip.sh install
sudo bash hostip.sh
```

备用脚本地址：<https://pay.vistart.art/hostip.sh>。

安装器验证二进制 SHA256；后续更新还会验证发布清单的 Ed25519 签名。服务以专用的 hostrouter 用户运行，只授予绑定低端口所需的能力。

## 菜单与规则

菜单顶部显示内核版本、运行状态、生效规则数、TCP/UDP 监听地址数和 DDNS 刷新间隔。一个端口同时监听 IPv4、IPv6 时，计为两个监听地址。

单个监听端口批量添加时，每行填写：

```text
app.example.com home.example.net 443
api.example.com 192.0.2.20 8443
*.example.org 2001:db8::20 443
```

选择逐行指定监听端口时，每行填写：

```text
443 app.example.com home.example.net 443
8443 api.example.com 192.0.2.20 8443
```

新规则默认同时启用 TCP、UDP。UDP 仍须通过 QUIC 域名识别，普通数据报不会因为存在 `*` 规则而被放行。

匹配优先级：精确域名 → 最长的通配域名后缀 → `*` 默认目标。`*.example.com` 匹配子域名，不包含 `example.com` 本身。

规则变更采用事务：整批校验，先绑定新增端口，全部成功后才提交配置。冲突、无效编号或并发修改会使整批操作失败，保留原配置。规则热加载不主动切断已有 TCP 连接；移除 UDP 监听会关闭该监听上的会话。

## 命令行

```bash
host-router -c /etc/host-router/config.json list
host-router -c /etc/host-router/config.json check
host-router -c /etc/host-router/config.json status
host-router -c /etc/host-router/config.json add-batch --listen 443 --file rules.txt
host-router -c /etc/host-router/config.json delete 2 5 8
host-router -c /etc/host-router/config.json set --dns-refresh 30
```

服务运行时默认通过本机私有控制套接字提交变更。服务已停止时，可明确添加 `--offline`；随后启动服务才会绑定监听端口。资源上限字段变更需要停止服务后修改并重启。

配置文件位于 `/etc/host-router/config.json`，二进制位于 `/usr/local/bin/host-router`。日志通过 `journalctl -u host-router` 查看。

## DDNS

目标可以使用域名。内核调用系统解析器，本地解析缓存默认 30 秒，可设置 1–3600 秒。缓存到期后由新连接触发重新查询；系统或上游 DNS 的缓存仍受其 TTL 影响。

- TCP 新连接使用最新解析结果，已经建立的连接保持原目标。
- QUIC 会话固定后端地址到空闲超时，新会话使用最新解析结果。
- 不会在正在传输的 QUIC 会话中强行替换目标 IP。
- TCP 会在连接超时预算内尝试解析到的多个地址；UDP 套接字建立成功不代表远端服务已响应。

## 真实客户端 IP

本版保持后端配置不变、业务数据原样透传，不插入 PROXY protocol 或 HTTP 头。**后端看到的来源仍是转发机 IP。**

保留原始源 IP 的透明代理需要后端回包经过转发机，通常涉及回程路由或隧道。后端应用、系统路由均不能修改时，无法仅通过入口脚本实现这一点。本项目不会自动更改系统路由、防火墙或启用源 IP 伪装。

## QUIC 边界

- 支持 QUIC v1 / v2 Initial 解析、CRYPTO 分片/乱序重组及已观察到的连接 ID 路由。
- 兼容 QUIC Bit GREASE；不解密后续业务流量，不终止 TLS。
- TCP 使用 Linux splice 零拷贝；UDP 使用 GRO/GSO 批量收发，不支持 GSO 时按原数据报边界回退。
- 缺少可读 SNI、未知 QUIC 版本和普通 UDP 不建立转发会话。
- ECH 隐藏的内部域名无法由透传入口识别。
- 初始同一个 UDP 源端口访问多个域名有覆盖测试；任意连接迁移、地址改变，以及多个会话同时使用未观察到的加密轮换 CID，不能保证继续分流。出现歧义时丢弃，避免送往错误后端。
- UDP 空闲默认 60 秒，可调整。需要更长空闲连接时，应设置应用保活或增大超时。

## 更新与旧版迁移

```bash
sudo bash hostip.sh check-update
sudo bash hostip.sh update
```

更新来源固定为 `coexacx/host-router` 的 GitHub Release。普通启动不会自动升级。只有主动选择更新才安装新版。

旧版 Go 迁移说明见 [docs/迁移与部署.md](docs/迁移与部署.md)。升级会保存原规则，缺少协议字段的旧规则自动补为 TCP+UDP。内核替换需要短暂重启，现有连接可能重连；规则和目标地址会保留。

## 构建与验证

Rust 1.89 或更新版本；发布构建使用 Cargo.lock 固定依赖。

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
bash build.sh x86_64-unknown-linux-musl
```

发布版的静态编译需要对应的 musl 工具链和 C 编译器。功能测试使用独立的 Python aioquic 实现生成 TLS/QUIC 流量，见 `tests/`。生产运行不依赖这些测试工具。

性能和安全测试范围见 [docs/验收报告.md](docs/验收报告.md)。进程 RSS 不包含内核 socket/pipe 内存；回环压测结果不等于公网链路带宽。

MIT License。
