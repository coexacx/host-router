//! Human-readable terminal views; machine-readable commands keep their original output.
use crate::config::{Config, Protocol};
use serde_json::Value;
pub fn rules(cfg: &Config) {
    println!("  共 {} 条转发规则\n", cfg.rules.len());
    if cfg.rules.is_empty() {
        println!("  还没有规则，选择「添加规则」开始。");
        return;
    }
    for (i, r) in cfg.rules.iter().enumerate() {
        let protocol = match r.protocol {
            Protocol::Both => "TCP + QUIC",
            Protocol::Tcp => "TCP",
            Protocol::Udp => "QUIC",
        };
        println!("  {:>3}  {}  ·  {}", i + 1, r.domain, protocol);
        println!("       {}  →  {}", r.listen, r.target);
        if !r.note.is_empty() {
            println!("       备注：{}", r.note)
        }
        println!();
    }
}
fn n(v: &Value, p: &str) -> u64 {
    v.pointer(p).and_then(Value::as_u64).unwrap_or(0)
}
fn f(v: &Value, p: &str) -> f64 {
    v.pointer(p).and_then(Value::as_f64).unwrap_or(0.0)
}
fn text<'a>(v: &'a Value, p: &str) -> &'a str {
    v.pointer(p).and_then(Value::as_str).unwrap_or("-")
}
fn bytes(b: u64) -> String {
    if b >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", b as f64 / (1024. * 1024. * 1024.))
    } else if b >= 1024 * 1024 {
        format!("{:.1} MiB", b as f64 / (1024. * 1024.))
    } else {
        format!("{:.1} KiB", b as f64 / 1024.)
    }
}
pub fn status(v: &Value) {
    let mode = if text(v, "/capacity/mode") == "auto" {
        "自动调整"
    } else {
        "固定上限"
    };
    let pressure = match text(v, "/capacity/pressure") {
        "normal" | "manual" => "正常",
        "cpu" => "CPU 繁忙，已收紧新连接",
        "memory" => "内存紧张，已收紧新连接",
        "memory_critical" => "内存不足，暂停新连接",
        "sensor_unavailable" => "资源检测异常，暂停新连接",
        "recovering" => "负载回落，逐步恢复额度",
        _ => "-",
    };
    println!("  运行概况\n");
    println!("  内核版本    {}", text(v, "/version"));
    println!("  生效规则    {} 条", n(v, "/rules"));
    println!("  容量模式    {mode}");
    println!("  保护状态    {pressure}");
    println!("\n  当前使用 / 有效上限\n");
    println!(
        "  TCP 连接    {} / {}",
        n(v, "/tcp_active"),
        n(v, "/capacity/effective/tcp")
    );
    println!(
        "  QUIC 会话   {} / {}",
        n(v, "/udp_active"),
        n(v, "/capacity/effective/udp")
    );
    println!(
        "  路由握手    {} / {}",
        n(v, "/pending_handshakes"),
        n(v, "/capacity/effective/pending")
    );
    println!(
        "  UDP 队列    {} / {}",
        bytes(n(v, "/queued_udp_bytes")),
        bytes(n(v, "/capacity/effective/queue_bytes"))
    );
    println!("\n  服务器资源\n");
    println!(
        "  可用 CPU    {:.2} 核",
        f(v, "/capacity/resources/cpu_cores")
    );
    println!(
        "  内存余量    {} / {}",
        bytes(n(v, "/capacity/resources/memory_available_bytes")),
        bytes(n(v, "/capacity/resources/memory_total_bytes"))
    );
    println!(
        "  系统 CPU    {:.1}%",
        f(v, "/capacity/resources/system_cpu_percent")
    );
    println!(
        "  转发 CPU    {:.1}%（按可用工作线程计算）",
        f(v, "/capacity/resources/process_cpu_percent")
    );
    println!(
        "  文件上限    {}",
        n(v, "/capacity/resources/fd_soft_limit")
    );
    if n(v, "/tcp_failed") > 0 {
        println!("\n  累计连接异常\n");
        for (key, label) in [
            ("admission_rejected", "接入受限"),
            ("socket_error", "套接字异常"),
            ("handshake_timeout", "握手超时"),
            ("handshake_rejected", "握手中断或无效"),
            ("route_missing", "未匹配规则"),
            ("dns_error", "目标解析失败"),
            ("connect_timeout", "目标连接超时"),
            ("connect_error", "目标连接失败"),
            ("relay_error", "传输中断"),
        ] {
            let count = n(v, &format!("/tcp_failure_reasons/{key}"));
            if count > 0 {
                println!("  {label:<10} {count}");
            }
        }
        println!("\n  传输中断也包含客户端或目标主动重置连接。");
    }
    println!("\n  TCP 与 QUIC 共用资源预算，两项上限不能相加。");
}
