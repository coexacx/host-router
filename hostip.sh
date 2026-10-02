#!/usr/bin/env bash
# host-router Rust edition — legacy SetNoDelay is implemented by Rust set_nodelay(true).
set -Eeuo pipefail
umask 077
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VERSION=0.1.1
REPO=coexacx/host-router
AMD64_SHA=622cb499eff87567e1135c8936d43f92f758b2ca0eb14f6755ffa9e122c3c21b
ARM64_SHA=3308206fd81314581006e852416439fe5094192ad332714d67d81d6f755d063a
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
  run_cli status --human
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


# Terminal presentation. Keep redirected output and NO_COLOR plain.
UI_ACCENT='' UI_DIM='' UI_GOOD='' UI_RESET=''
UI_SCRIPT="${BASH_SOURCE[0]}"
if [[ -t 1 && "${TERM:-dumb}" != dumb && -z "${NO_COLOR+x}" ]]; then
  UI_ACCENT=$'\033[1;36m'; UI_DIM=$'\033[2m'
  UI_GOOD=$'\033[32m'; UI_RESET=$'\033[0m'
fi
ui_clear() { if [[ -t 1 && "${TERM:-dumb}" != dumb ]]; then printf '\033[H\033[2J'; fi; }
ui_line() { printf '  %s────────────────────────────────────%s\n' "$UI_DIM" "$UI_RESET"; }
ui_page() { ui_clear; printf '\n  %s%s%s\n' "$UI_ACCENT" "$1" "$UI_RESET"; ui_line; printf '\n'; }
view_rules() { run_cli list --human 2>/dev/null || run_cli list; }
view_status() { run_cli status --human 2>/dev/null || run_cli status; }
prompt_validated() {
  local label="$1" kind="$2" hint="$3" current="${4:-}"
  printf '  %s\n' "$hint"
  [[ -z "$current" ]] || printf '  当前：%s（回车保留）\n' "$current"
  while true; do
    read -r -p "  $label：" INPUT_VALUE || return 1
    if [[ -z "$INPUT_VALUE" ]]; then
      [[ -n "$current" ]] || return 1
      INPUT_VALUE="$current"
    fi
    if run_cli validate-input "$kind" -- "$INPUT_VALUE" >/dev/null 2>&1; then return 0; fi
    printf '  格式不正确，请按示例重新填写；留空取消。\n'
  done
}
submit_rules() {
  local file="$1" listen="${2:-}" confirm
  local -a batch_args=(add-batch --file "$file" --protocol both)
  [[ -z "$listen" ]] || batch_args+=(--listen "$listen")
  ui_page '确认添加'
  if ! run_cli "${batch_args[@]}" --check-only; then
    printf '\n  检查未通过，请检查格式、重复域名和入口端口。\n'
    return 1
  fi
  printf '  新规则同时用于 TCP 与 QUIC。\n\n'
  read -r -p '  确认保存并启用？[y/N]：' confirm || return 0
  [[ "$confirm" == y || "$confirm" == Y ]] || { printf '  已取消，未添加规则。\n'; return 0; }
  mode_args
  if run_cli "${batch_args[@]}" "${OFFLINE[@]}" >/dev/null; then
    printf '\n  %s规则已保存。%s\n' "$UI_GOOD" "$UI_RESET"
    [[ ${#OFFLINE[@]} == 0 ]] || printf '  启动转发服务后生效。\n'
  else printf '\n  保存失败，请检查端口是否已被其他程序占用。\n'; return 1; fi
}
input_single() (
  local listen domain target port tmp
  ui_page '添加规则 · 1/4 入口端口'
  printf '  入口是客户端连接这台转发机时使用的端口。\n  各步骤留空均可取消。\n\n'
  prompt_validated '入口端口' listen '  例如：443，也可填写 0.0.0.0:443' || exit 0; listen="$INPUT_VALUE"
  ui_page '添加规则 · 2/4 匹配域名'
  printf '  根据客户端请求的域名选择转发目标。\n\n'
  prompt_validated '匹配域名' domain '  例如：app.example.com；支持 *.example.com' || exit 0; domain="$INPUT_VALUE"
  ui_page '添加规则 · 3/4 目标地址'
  printf '  只填后端 IP 或域名，端口在下一步填写。\n  动态域名会按解析间隔刷新。\n\n'
  prompt_validated '目标地址' target '  例如：192.0.2.10 或 home.example.net' || exit 0; target="$INPUT_VALUE"
  ui_page '添加规则 · 4/4 目标端口'
  prompt_validated '目标端口' port '  例如：443 或 8443' || exit 0; port="$INPUT_VALUE"
  tmp="$(mktemp)"; trap 'rm -f -- "$tmp"' EXIT
  printf '%s %s %s\n' "$domain" "$target" "$port" > "$tmp"
  submit_rules "$tmp" "$listen"
)
input_batch() (
  local kind="${1:-same}" listen='' line tmp confirm total
  local -a batch_args
  while true; do
    ui_page '批量添加规则'
    if [[ "$kind" == same ]]; then
      prompt_validated '共用入口端口' listen '每条规则都使用此入口，例如：443；留空返回。' || exit 0
      listen="$INPUT_VALUE"
      printf '\n  每行：域名 目标地址 目标端口\n'
      printf '  例如：app.example.com 192.0.2.10 443\n'
    else
      printf '  每行：入口端口 域名 目标地址 目标端口\n'
      printf '  例如：8443 app.example.com 192.0.2.10 443\n'
    fi
    printf '\n  可粘贴多行；最后输入空行进入确认。\n\n'
    tmp="$(mktemp)"; trap 'rm -f -- "$tmp"' EXIT; total=0
    while IFS= read -r line && [[ -n "$line" ]]; do
      total=$((total + ${#line} + 1))
      (( total <= 1048576 )) || { printf '  输入过长，请分批添加。\n'; exit 1; }
      printf '%s\n' "$line" >> "$tmp"
    done
    [[ -s "$tmp" ]] || exit 0
    batch_args=(add-batch --file "$tmp" --protocol both --check-only)
    [[ -z "$listen" ]] || batch_args+=(--listen "$listen")
    if run_cli "${batch_args[@]}" >/dev/null; then submit_rules "$tmp" "$listen"; exit $?; fi
    printf '\n  格式或规则有误，整批尚未保存。\n'
    read -r -p '  重新填写？[y/N]：' confirm || exit 0
    [[ "$confirm" == y || "$confirm" == Y ]] || exit 0
    rm -f -- "$tmp"
  done
)
add_menu() {
  local action
  ui_page '添加规则'
  printf '  1  添加一条规则\n  2  批量添加 · 共用一个入口端口\n  3  批量添加 · 每条指定入口端口\n\n  0  返回主菜单\n\n'
  read -r -p '  请选择：' action || return 0
  case "$action" in 1) input_single;; 2) input_batch same;; 3) input_batch separate;; 0|'') PAUSE=0;; *) printf '  请输入 0–3。\n';; esac
}
delete_batch() {
  local line id confirm
  local -a ids=()
  ui_page '删除规则'; view_rules || return 1
  printf '  可填写多个编号，例如：2 5 8。\n\n'
  read -r -p '  规则编号（留空返回）：' line || return 0
  [[ -n "$line" ]] || return 0
  read -r -a ids <<< "$line"
  for id in "${ids[@]}"; do [[ "$id" =~ ^[1-9][0-9]*$ ]] || { printf '  请输入有效的规则编号。\n'; return 1; }; done
  read -r -p '  确认删除选中的规则？[y/N]：' confirm || return 0
  case "$confirm" in y|Y|DELETE) ;; *) printf '  已取消。\n'; return 0;; esac
  mode_args
  if run_cli delete "${ids[@]}" "${OFFLINE[@]}" >/dev/null; then printf '\n  选中的规则已删除。\n'
  else printf '\n  删除失败，请检查编号。\n'; return 1; fi
}
edit_rule() {
  local id listen domain target confirm row
  ui_page '修改规则'; view_rules || return 1
  read -r -p '  规则编号（留空返回）：' id || return 0
  [[ -n "$id" ]] || return 0
  [[ "$id" =~ ^[1-9][0-9]*$ ]] || { printf '  请输入有效的规则编号。\n'; return 1; }
  row="$(run_cli list | awk -v selected="$id" '$1 == selected {print $2, $4, $5; exit}')"
  [[ -n "$row" ]] || { printf '  找不到此规则编号。\n'; return 1; }
  read -r listen domain target <<< "$row"
  printf '\n  只修改需要调整的项目；回车保留原值。\n\n'
  prompt_validated '入口端口' listen '  例如：443' "$listen" || return 0; listen="$INPUT_VALUE"
  prompt_validated '匹配域名' domain '  例如：app.example.com' "$domain" || return 0; domain="$INPUT_VALUE"
  prompt_validated '目标地址:端口' target '  例如：192.0.2.10:443；IPv6 为 [IPv6]:端口' "$target" || return 0; target="$INPUT_VALUE"
  printf '\n  待保存：%s\n  %s → %s\n\n' "$domain" "$listen" "$target"
  read -r -p '  确认修改？[y/N]：' confirm || return 0
  [[ "$confirm" == y || "$confirm" == Y ]] || { printf '  已取消。\n'; return 0; }
  mode_args
  if run_cli edit "$id" --listen "$listen" --domain "$domain" --target "$target" "${OFFLINE[@]}" >/dev/null; then
    printf '\n  修改已保存。\n'
  else printf '\n  保存失败，请检查编号、重复域名或端口占用。\n'; return 1; fi
}
edit_config() (
  local tmp editor
  printf '\n  保存退出后会校验并应用配置。\n  手动修改连接上限需要先停止服务。\n\n'
  tmp="$(mktemp)"; trap 'rm -f -- "$tmp"' EXIT
  cp -- "$CFG" "$tmp"; editor="${EDITOR:-vi}"
  "$editor" "$tmp" || exit 1
  mode_args; run_cli apply --file "$tmp" "${OFFLINE[@]}" >/dev/null || exit 1
  printf '\n  配置已保存。\n'
)
settings() {
  local n action
  ui_page '转发设置'
  printf '  1  域名解析间隔   DDNS 更新频率\n  2  默认目标端口\n  3  连接容量与资源\n  4  编辑完整配置\n\n  0  返回主菜单\n\n'
  read -r -p '  请选择：' action || return 0
  mode_args
  case "$action" in
    1) read -r -p '  刷新间隔，单位秒（1–3600）：' n || return 0
       run_cli set --dns-refresh "$n" "${OFFLINE[@]}" >/dev/null && printf '\n  解析间隔已保存。\n';;
    2) prompt_validated '默认目标端口' port '  例如：443' || return 0
       run_cli set --default-port "$INPUT_VALUE" "${OFFLINE[@]}" >/dev/null && printf '\n  默认端口已保存。\n';;
    3) printf '\n'; view_status;;
    4) edit_config;;
    0|'') PAUSE=0;;
    *) printf '  请输入 0–4。\n';;
  esac
}
service_menu() {
  local action confirm
  ui_page '服务管理'
  printf '  1  启动转发\n  2  停止转发\n  3  重启内核\n  4  卸载内核     保留规则\n\n  0  返回主菜单\n\n'
  read -r -p '  请选择：' action || return 0
  case "$action" in 0|'') PAUSE=0; return 0;; esac
  need_root
  case "$action" in
    1) systemctl start "$SERVICE" && printf '\n  转发服务已启动。\n';;
    2|3) read -r -p '  当前连接将断开，继续？[y/N]：' confirm || return 0
         [[ "$confirm" == y || "$confirm" == Y ]] || { printf '  已取消。\n'; return 0; }
         if [[ "$action" == 2 ]]; then systemctl stop "$SERVICE" && printf '\n  转发服务已停止。\n'
         else systemctl restart "$SERVICE" && printf '\n  内核已重启。\n'; fi;;
    4) read -r -p '  输入 REMOVE 确认卸载内核：' confirm || return 0
       [[ "$confirm" == REMOVE ]] || { printf '  已取消。\n'; return 0; }
       systemctl disable --now "$SERVICE" || return 1
       rm -f -- "$BIN" "$UNIT"; systemctl daemon-reload
       printf '\n  内核已卸载，规则保存在 %s。\n' "$CFG";;
    *) printf '  请输入 0–4。\n';;
  esac
}
monitor_menu() {
  local action
  ui_page '运行状态与日志'
  printf '  1  连接与服务器资源\n  2  最近运行日志\n\n  0  返回主菜单\n\n'
  read -r -p '  请选择：' action || return 0
  case "$action" in
    1) printf '\n'; view_status;;
    2) printf '\n'; journalctl -u "$SERVICE" -n 40 --no-pager -o short-iso;;
    0|'') PAUSE=0;;
    *) printf '  请输入 0–2。\n';;
  esac
}
update_menu() {
  local action
  ui_page '版本更新'
  printf '  更新来源：GitHub · coexacx/host-router\n\n'
  printf '  1  检查最新版本\n  2  下载并安装更新\n\n  0  返回主菜单\n\n'
  read -r -p '  请选择：' action || return 0
  case "$action" in
    1) bash "$UI_SCRIPT" check-update;;
    2) bash "$UI_SCRIPT" update;;
    0|'') PAUSE=0;;
    *) printf '  请输入 0–2。\n';;
  esac
}
header() {
  local state=stopped version=未安装 count=0 tcp=0 udp=0 dns=30 line mode=- ta=0 tc=0 ua=0 uc=0 color=''
  if [[ -x "$BIN" && -f "$CFG" ]]; then
    line="$(run_cli summary 2>/dev/null || true)"
    if [[ -n "$line" ]]; then read -r state version count tcp udp dns mode ta tc ua uc <<< "$line"; fi
  fi
  if [[ "$state" == running ]]; then state=运行中; color="$UI_GOOD"; else state=已停止; fi
  [[ "$version" != 未安装 ]] || state=待安装
  ui_clear
  printf '\n  %sHost Router%s  ·  转发管理\n' "$UI_ACCENT" "$UI_RESET"
  printf '  %s   %s%s%s   %s 条规则\n' "$version" "$color" "$state" "$UI_RESET" "$count"
  ui_line
  if [[ "$mode" == auto || "$mode" == manual ]]; then
    [[ "$mode" != auto ]] || mode=自动调整
    [[ "$mode" != manual ]] || mode=固定上限
    printf '  TCP   %s / %s    QUIC  %s / %s\n' "$ta" "$tc" "$ua" "$uc"
    printf '  容量%s · DDNS %s 秒\n' "$mode" "$dns"
  else
    printf '  监听地址  TCP %s · UDP %s\n' "$tcp" "$udp"
  fi
  printf '\n'
}
menu() {
  local choice PAUSE install_label confirm
  while true; do
    header
    printf '  %s转发规则           运行维护%s\n' "$UI_DIM" "$UI_RESET"
    printf '  %s1%s  查看规则        %s5%s  转发设置\n' "$UI_ACCENT" "$UI_RESET" "$UI_ACCENT" "$UI_RESET"
    printf '  %s2%s  添加规则        %s6%s  服务管理\n' "$UI_ACCENT" "$UI_RESET" "$UI_ACCENT" "$UI_RESET"
    printf '  %s3%s  修改规则        %s7%s  状态与日志\n' "$UI_ACCENT" "$UI_RESET" "$UI_ACCENT" "$UI_RESET"
    printf '  %s4%s  删除规则        %s8%s  版本更新\n' "$UI_ACCENT" "$UI_RESET" "$UI_ACCENT" "$UI_RESET"
    install_label=安装内核; [[ ! -x "$BIN" ]] || install_label=重新安装
    printf '\n  %s9%s  %s        %s0%s  退出\n' "$UI_ACCENT" "$UI_RESET" "$install_label" "$UI_ACCENT" "$UI_RESET"
    ui_line
    printf '  %sUDP 支持 QUIC；普通 UDP 不转发。%s\n\n' "$UI_DIM" "$UI_RESET"
    read -r -p '  请选择 [0–9]：' choice || return 0
    PAUSE=1
    case "$choice" in
      1) ui_page '转发规则'; view_rules || true;;
      2) add_menu || true;;
      3) edit_rule || true;;
      4) delete_batch || true;;
      5) settings || true;;
      6) service_menu || true;;
      7) monitor_menu || true;;
      8) update_menu || true;;
      9) ui_page "$install_label"
         confirm=y
         if [[ -x "$BIN" ]]; then read -r -p '  将保留规则并重启内核，继续？[y/N]：' confirm || return 0; fi
         if [[ "$confirm" == y || "$confirm" == Y ]]; then bash "$UI_SCRIPT" install || true
         else printf '  已取消。\n'; fi;;
      0) printf '\n'; return 0;;
      '') continue;;
      *) printf '\n  请输入菜单中的数字。\n';;
    esac
    if [[ "$PAUSE" == 1 ]]; then
      printf '\n'; read -r -p '  按回车返回主菜单…' _ || return 0
    fi
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
