#!/usr/bin/env bash
# host-router Rust edition — legacy SetNoDelay is implemented by Rust set_nodelay(true).
set -Eeuo pipefail
umask 077
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VERSION=0.1.1
REPO=coexacx/host-router
AMD64_SHA=0d9133597f9d7b07c24d1ee912f4e50e24a541e2f48a0f46dcdb95218799f1e2
ARM64_SHA=9de814353fce8d9bdc4ef34ba421f78cf965e8839399b51fd9e8eb93035605af
BIN="${HOST_ROUTER_BIN:-/usr/local/bin/host-router}"
CFG="${HOST_ROUTER_CONFIG:-/etc/host-router/config.json}"
SERVICE=host-router
UNIT=/etc/systemd/system/host-router.service
die() { printf '错误：%s\n' "$*" >&2; exit 1; }
need_root() { [[ ${EUID} -eq 0 ]] || die "此操作需要 root"; }
run_cli() { [[ -x "$BIN" ]] || die "请先安装内核"; "$BIN" -c "$CFG" "$@"; }
mode_args() { OFFLINE=(); [[ -S "${CFG%.*}.sock" ]] || OFFLINE=(--offline); }
fetch() { curl --proto '=https' --tlsv1.2 -fL --retry 2 --connect-timeout 10 --max-time 180 "$1" -o "$2"; }
digest_ok() { [[ "$(sha256sum -- "$1" | awk '{print $1}')" == "$2" ]]; }

install_router() (
  set -Eeuo pipefail
  need_root
  [[ "$BIN" == /usr/local/bin/host-router && "$CFG" == /etc/host-router/config.json ]] || die "服务安装使用固定路径；自定义路径请使用 cli"
  command -v systemctl >/dev/null || die "需要采用 systemd 的 Linux"
  command -v flock >/dev/null || die "需要 util-linux 的 flock"
  [[ ! -L /run/host-router-update ]] || die "更新锁目录不能是符号链接"
  install -d -m 0700 -o root -g root /run/host-router-update
  exec 9>/run/host-router-update/lock
  flock -n 9 || die "已有安装或更新任务正在执行"
  command -v sha256sum >/dev/null || die "需要 sha256sum"
  local_arch="$(uname -m)"
  case "$local_arch" in x86_64) arch=amd64; expected="$AMD64_SHA";; aarch64|arm64) arch=arm64; expected="$ARM64_SHA";; *) die "支持 amd64/arm64；其他架构请从源码构建";; esac
  work="$(mktemp -d /tmp/host-router-install.XXXXXX)"
  modified=0
  old_running=0
  old_enabled=0
  # Invoked indirectly by the ERR trap.
  # shellcheck disable=SC2317
  rollback() {
    local code=$?
    trap - ERR
    if [[ "$modified" == 1 ]]; then
      printf '安装失败，正在恢复原内核、规则和服务配置。\n' >&2
      systemctl stop "$SERVICE" >/dev/null 2>&1 || true
      if [[ -f "$work/bin" ]]; then install -m 0755 "$work/bin" "$BIN"; else rm -f -- "$BIN"; fi
      if [[ -f "$work/unit" ]]; then cp -p -- "$work/unit" "$UNIT"; else rm -f -- "$UNIT"; fi
      if [[ -d "$work/config" ]]; then
        # Restore only this application's directory; never remove parent paths.
        rm -rf -- /etc/host-router
        cp -a -- "$work/config" /etc/host-router
      fi
      systemctl daemon-reload
      if [[ "$old_enabled" == 1 ]]; then systemctl enable "$SERVICE" >/dev/null 2>&1 || true
      else systemctl disable "$SERVICE" >/dev/null 2>&1 || true; fi
      if [[ "$old_running" == 1 ]]; then systemctl start "$SERVICE" || true; fi
    fi
    exit "$code"
  }
  trap rollback ERR
  trap 'rm -rf -- "$work"' EXIT
  candidate="$work/host-router"
  if [[ -f "$SCRIPT_DIR/bin/host-router-linux-$arch" ]]; then
    cp -- "$SCRIPT_DIR/bin/host-router-linux-$arch" "$candidate"
  else
    command -v curl >/dev/null || die "需要 curl（Debian/Ubuntu: apt install curl ca-certificates）"
    fetch "https://github.com/$REPO/releases/download/v$VERSION/host-router-linux-$arch" "$candidate"
  fi
  digest_ok "$candidate" "$expected" || die "内核 SHA256 校验失败，尚未修改服务"
  chmod 0755 "$candidate"; "$candidate" --version
  [[ ! -L /etc/host-router && ! -L "$CFG" && ! -L "$BIN" && ! -L "$UNIT" ]] || die "应用路径不能是符号链接"
  if [[ -e "$CFG" ]]; then "$candidate" -c "$CFG" check; fi
  if [[ -f "$BIN" ]]; then cp -p -- "$BIN" "$work/bin"; fi
  if [[ -f "$UNIT" ]]; then cp -p -- "$UNIT" "$work/unit"; fi
  if [[ -d /etc/host-router ]]; then cp -a -- /etc/host-router "$work/config"; fi
  if systemctl is-active --quiet "$SERVICE"; then old_running=1; fi
  if systemctl is-enabled --quiet "$SERVICE"; then old_enabled=1; fi
  # Save a private recovery copy before changing anything.
  recovery="/var/backups/host-router/$(date -u +%Y%m%dT%H%M%SZ)-$$"
  install -d -m 0700 "$recovery"
  cp -a -- "$work/." "$recovery/"
  command -v useradd >/dev/null || die "系统缺少 useradd（shadow/passwd 软件包）"
  if ! id hostrouter >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin hostrouter
  fi
  modified=1
  install -d -m 0750 -o hostrouter -g hostrouter /etc/host-router
  if [[ ! -e "$CFG" ]]; then "$candidate" -c "$CFG" init; fi
  chown hostrouter:hostrouter /etc/host-router
  "$candidate" -c "$CFG" prepare-config --user hostrouter
  cat > "$work/service" <<'UNIT'
[Unit]
Description=Host Router Rust TCP and QUIC
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=hostrouter
Group=hostrouter
# The old updater restores a root-owned config after installation. Open without
# following symlinks, validate it, then repair ownership before privilege dropping.
ExecStartPre=+/usr/local/bin/host-router -c /etc/host-router/config.json prepare-config --user hostrouter
ExecStart=/usr/local/bin/host-router -c /etc/host-router/config.json serve
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
TasksMax=256
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/host-router
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native

UNIT
  "$candidate" capacity-plan --systemd >> "$work/service"
  cat >> "$work/service" <<'UNIT'

[Install]
WantedBy=multi-user.target
UNIT
  stage="$(mktemp /usr/local/bin/.host-router.XXXXXX)"
  install -m 0755 "$candidate" "$stage"; mv -f -- "$stage" "$BIN"
  install -m 0644 "$work/service" "$UNIT"
  systemctl daemon-reload
  systemctl enable "$SERVICE"
  systemctl restart "$SERVICE"
  sleep 2
  systemctl is-active --quiet "$SERVICE"
  run_cli status
  modified=0
  printf '已安装 Rust %s。原规则已保留并补全 TCP+UDP。恢复备份：%s\n' "$VERSION" "$recovery"
)

update_router() (
  set -Eeuo pipefail
  need_root
  command -v curl >/dev/null || die "需要 curl"
  [[ -x "$BIN" ]] || die "请先安装"
  work="$(mktemp -d)"
  trap 'rm -rf -- "$work"' EXIT
  fetch "https://github.com/$REPO/releases/latest/download/manifest.json" "$work/manifest.json"
  fetch "https://github.com/$REPO/releases/latest/download/manifest.sig" "$work/manifest.sig"
  read -r state version digest url < <(run_cli verify-release --manifest "$work/manifest.json" --signature "$work/manifest.sig" --asset hostip.sh)
  [[ -n "${state:-}" && -n "${digest:-}" ]] || die "更新信息未通过签名验证"
  if [[ "$state" != new ]]; then printf '当前内核已是最新稳定版：%s\n' "$version"; exit 0; fi
  printf '发现新版 %s，当前 %s。升级需要短暂重启。\n' "$version" "$VERSION"
  if [[ "${1:-}" == check ]]; then exit 0; fi
  fetch "$url" "$work/hostip.sh"
  digest_ok "$work/hostip.sh" "$digest" || die "脚本校验失败"
  bash -n "$work/hostip.sh"
  bash "$work/hostip.sh" install
  # Update this script only after the new service passed startup checks.
  destination="$(readlink -f -- "${BASH_SOURCE[0]}")"
  [[ -f "$destination" ]] || die "请将脚本保存为普通文件后再更新"
  install -m 0755 "$work/hostip.sh" "$destination"
  printf '更新完成，请重新打开菜单。\n'
)

input_batch() (
  local listen line tmp
  read -r -p '监听端口（如 443；逐行指定不同端口请填 -）：' listen
  [[ -n "$listen" ]] || exit 0
  tmp="$(mktemp)"; trap 'rm -f -- "$tmp"' EXIT
  if [[ "$listen" == - ]]; then printf '格式：监听端口 域名 目标地址 目标端口\n'
  else printf '格式：域名 目标地址 目标端口\n'; fi
  printf '一行一条，支持多行粘贴；空行提交。\n'
  while IFS= read -r line && [[ -n "$line" ]]; do printf '%s\n' "$line" >> "$tmp"; done
  [[ -s "$tmp" ]] || exit 0
  mode_args
  if [[ "$listen" == - ]]; then run_cli add-batch --file "$tmp" --protocol both "${OFFLINE[@]}"
  else run_cli add-batch --file "$tmp" --listen "$listen" --protocol both "${OFFLINE[@]}"; fi
)
delete_batch() {
  local line id confirm
  local -a ids=()
  run_cli list
  read -r -p '删除编号（空格分隔，留空返回）：' line
  [[ -n "$line" ]] || return 0
  read -r -a ids <<< "$line"
  for id in "${ids[@]}"; do [[ "$id" =~ ^[1-9][0-9]*$ ]] || { printf '编号无效\n'; return 1; }; done
  read -r -p "删除 ${#ids[@]} 条规则？输入 DELETE 确认：" confirm
  [[ "$confirm" == DELETE ]] || return 0
  mode_args; run_cli delete "${ids[@]}" "${OFFLINE[@]}"
}
edit_rule() {
  local id listen domain target
  run_cli list
  read -r -p '规则编号：' id
  [[ "$id" =~ ^[1-9][0-9]*$ ]] || return 0
  read -r -p '监听端口 / IP:端口：' listen
  read -r -p '匹配域名：' domain
  read -r -p '目标地址:端口：' target
  mode_args; run_cli edit "$id" --listen "$listen" --domain "$domain" --target "$target" "${OFFLINE[@]}"
}
settings() {
  local n action tmp editor
  printf '1. DDNS 刷新间隔\n2. 默认目标端口\n3. 编辑配置\n4. 容量与负载详情\n0. 返回\n'
  read -r -p '选择：' action
  mode_args
  case "$action" in
    1) read -r -p '刷新秒数（1–3600）：' n; run_cli set --dns-refresh "$n" "${OFFLINE[@]}";;
    2) read -r -p '默认目标端口：' n; run_cli set --default-port "$n" "${OFFLINE[@]}";;
    3) tmp="$(mktemp)"; cp -- "$CFG" "$tmp"; editor="${EDITOR:-vi}"
       "$editor" "$tmp" && run_cli apply --file "$tmp" "${OFFLINE[@]}"
       rm -f -- "$tmp";;
    4) run_cli status;;
  esac
}
service_menu() {
  local action confirm
  printf '1. 启动\n2. 停止\n3. 重启\n4. 卸载（保留规则）\n0. 返回\n'
  read -r -p '选择：' action
  need_root
  case "$action" in
    1) systemctl start "$SERVICE";;
    2) systemctl stop "$SERVICE";;
    3) systemctl restart "$SERVICE";;
    4) read -r -p '输入 REMOVE 卸载服务，保留配置：' confirm
       [[ "$confirm" == REMOVE ]] || return 0
       systemctl disable --now "$SERVICE" || return 1
       rm -f -- "$BIN" "$UNIT"; systemctl daemon-reload;;
  esac
}
header() {
  local state=stopped version=未安装 count=0 tcp=0 udp=0 dns=30 line mode=- ta=0 tc=0 ua=0 uc=0
  if [[ -x "$BIN" && -f "$CFG" ]]; then
    line="$(run_cli summary 2>/dev/null || true)"
    if [[ -n "$line" ]]; then read -r state version count tcp udp dns mode ta tc ua uc <<< "$line"; fi
  fi
  [[ "$state" != running ]] || state=运行中
  [[ "$state" != stopped ]] || state=已停止
  printf '\n  Host Router\n  ─────────────────────────────────────────\n'
  printf '  内核 %-10s  状态 %s\n' "$version" "$state"
  printf '  规则 %-10s  TCP %s · UDP %s\n' "$count" "$tcp" "$udp"
  printf '  DDNS %s 秒        UDP 仅 QUIC\n' "$dns"
  if [[ "$mode" == auto || "$mode" == manual ]]; then
    [[ "$mode" != auto ]] || mode=自动
    [[ "$mode" != manual ]] || mode=手动
    printf '  容量 %s · TCP %s/%s · QUIC %s/%s\n' "$mode" "$ta" "$tc" "$ua" "$uc"
  fi
  printf '  ─────────────────────────────────────────\n'
}
menu() {
  local choice
  while true; do
    header
    printf '  1  规则列表         2  添加 / 批量添加\n  3  修改规则         4  删除 / 批量删除\n  5  转发设置         6  服务管理\n  7  运行日志         8  检查并更新\n  9  安装内核         0  退出\n\n'
    read -r -p '  选择：' choice || return 0
    case "$choice" in
      1) run_cli list || true;;
      2) input_batch || true;;
      3) edit_rule || true;;
      4) delete_batch || true;;
      5) settings || true;;
      6) service_menu || true;;
      7) journalctl -u "$SERVICE" -n 50 --no-pager || true;;
      8) bash "${BASH_SOURCE[0]}" update || true;;
      9) bash "${BASH_SOURCE[0]}" install || true;;
      0) return 0;;
      *) printf '  无效选项\n';;
    esac
    read -r -p '  回车继续…' _ || return 0
  done
}
case "${1:-menu}" in
  install) install_router;;
  update) update_router;;
  check-update) update_router check;;
  menu) menu;;
  cli) shift; run_cli "$@";;
  *) printf '用法：bash hostip.sh [menu|install|update|check-update|cli ...]\n' >&2; exit 2;;
esac
