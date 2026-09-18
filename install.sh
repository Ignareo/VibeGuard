#!/usr/bin/env bash
set -euo pipefail

# VibeGuard installer script (bilingual strings; comments in English)
#
# Features:
# - Install vibeguard binary (prefer Release binaries; fallback to source build; then go install)
# - Export ("download") the CA certificate to a file
# - Optional: install CA into system trust store (may invoke sudo)
#
# Usage:
#   bash install.sh
#
# Notes:
#   By default, this script does not modify your shell config. For global access, use --path auto|add to write PATH.
#   For autostart background service, use --autostart auto|add (macOS LaunchAgent / Linux systemd --user).

SCRIPT_LANG=""     # zh|en
SCRIPT_LANG_SET="0"
TRUST_MODE_SET="0"
DO_EXPORT_SET="0"

to_lower() {
  # macOS default bash 3.2 does not support ${var,,}
  echo "${1:-}" | tr '[:upper:]' '[:lower:]'
}

normalize_lang() {
  local v
  v="$(to_lower "${1:-}")"
  case "${v}" in
    zh|zh-cn|zh_cn|cn|chinese|中文) echo "zh" ;;
    en|en-us|en_us|english) echo "en" ;;
    *) echo "" ;;
  esac
}

t() {
  # Usage: t "Chinese" "English"
  if [[ "${SCRIPT_LANG}" == "zh" ]]; then
    printf "%s" "$1"
  else
    printf "%s" "$2"
  fi
}

say() {
  echo ""
  echo "==> $(t "$1" "$2")"
}

persist_lang_best_effort() {
  # Persist the selected language to ~/.vibeguard/lang (used as default by the admin UI and uninstall script).
  # Best-effort: do not fail installation if writing fails.
  [[ -n "${HOME:-}" ]] || return 0
  local dir="${HOME}/.vibeguard"
  local f="${dir}/lang"
  mkdir -p "${dir}" >/dev/null 2>&1 || return 0
  ( umask 077; printf "%s\n" "${SCRIPT_LANG}" >"${f}" ) >/dev/null 2>&1 || true
}

die() {
  echo ""
  echo "$(t "错误：$1" "Error: $2")" >&2
  exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

need() {
  have "$1" || die "缺少依赖：$1" "Missing dependency: $1"
}

in_repo() {
  [[ -f "go.mod" && -f "cmd/vibeguard/main.go" ]]
}

normalize_version() {
  # Allow 0.2.0 / v0.2.0 / latest
  local v="${1:-}"
  v="$(echo "${v}" | tr -d '[:space:]')"
  if [[ -z "${v}" || "${v}" == "latest" ]]; then
    echo "latest"
    return 0
  fi
  case "${v}" in
    v*) echo "${v}" ;;
    *) echo "v${v}" ;;
  esac
}

detect_goos() {
  local os_name
  os_name="$(uname -s 2>/dev/null || true)"
  case "${os_name}" in
    Darwin) echo "darwin" ;;
    Linux) echo "linux" ;;
    *) echo "" ;;
  esac
}

detect_goarch() {
  local arch
  arch="$(uname -m 2>/dev/null || true)"
  case "${arch}" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *) echo "" ;;
  esac
}

download_file() {
  local url="${1:-}"
  local out="${2:-}"
  [[ -n "${url}" && -n "${out}" ]] || return 1
  if have curl; then
    curl -fsSL "${url}" -o "${out}"
  elif have wget; then
    wget -qO "${out}" "${url}"
  else
    return 1
  fi
}

sha256_file() {
  local p="${1:-}"
  [[ -f "${p}" ]] || return 1
  if have sha256sum; then
    sha256sum "${p}" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "${p}" | awk '{print $1}'
  elif have openssl; then
    openssl dgst -sha256 "${p}" | awk '{print $2}'
  else
    return 1
  fi
}

install_vibeguard_from_release() {
  local install_dir="${1:-}"
  local repo="${2:-inkdust2021/VibeGuard}"
  local version="${3:-latest}"
  local verify="${4:-1}" # 1|0
  local variant="${5:-lite}" # lite|full

  [[ -n "${install_dir}" ]] || return 1
  version="$(normalize_version "${version}")"
  variant="$(to_lower "${variant}")"

  local goos
  goos="$(detect_goos)"
  local goarch
  goarch="$(detect_goarch)"

  if [[ -z "${goos}" || -z "${goarch}" ]]; then
    return 1
  fi

  if [[ "${goos}" != "darwin" && "${goos}" != "linux" ]]; then
    return 1
  fi

  if [[ "${goarch}" != "amd64" && "${goarch}" != "arm64" ]]; then
    return 1
  fi

  local base="https://github.com/${repo}/releases"
  local dl_base=""
  if [[ "${version}" == "latest" ]]; then
    dl_base="${base}/latest/download"
  else
    dl_base="${base}/download/${version}"
  fi

  local suffix=""
  case "${variant}" in
    full) suffix="_full" ;;
    lite|"") suffix="" ;;
    *) suffix="" ;;
  esac

  local asset="vibeguard_${goos}_${goarch}${suffix}.tar.gz"
  local url_asset="${dl_base}/${asset}"
  local url_sum="${dl_base}/checksums.txt"

  say "安装 vibeguard（Release 预编译）" "Installing vibeguard (Release binary)"
  echo "$(t "仓库：" "Repo: ")${repo}"
  echo "$(t "版本：" "Version: ")${version}"
  echo "$(t "平台：" "Platform: ")${goos}/${goarch}"
  echo "$(t "变体：" "Variant: ")${variant}"

  if [[ "${verify}" == "1" ]]; then
    if ! (have sha256sum || have shasum || have openssl); then
      say "未检测到 sha256 校验工具：将跳过校验" "No sha256 tool found: verification will be skipped"
      verify="0"
    fi
  fi

  (
    set -euo pipefail
    tmp="$(mktemp -d -t vibeguard-install.XXXXXX 2>/dev/null || mktemp -d "/tmp/vibeguard-install.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT

    need tar

    if ! download_file "${url_asset}" "${tmp}/${asset}"; then
      echo "$(t "下载失败：" "Download failed: ")${url_asset}" >&2
      exit 2
    fi

    if [[ "${verify}" == "1" ]]; then
      if ! download_file "${url_sum}" "${tmp}/checksums.txt"; then
        echo "$(t "下载校验文件失败：" "Failed to download checksums: ")${url_sum}" >&2
        exit 3
      fi

      expected="$(grep -E "[[:space:]]${asset}$" "${tmp}/checksums.txt" | awk '{print $1}' | head -n 1 || true)"
      if [[ -z "${expected}" ]]; then
        echo "$(t "校验文件中未找到条目：" "Checksums entry not found: ")${asset}" >&2
        exit 4
      fi

      actual="$(sha256_file "${tmp}/${asset}" || true)"
      if [[ -z "${actual}" || "${actual}" != "${expected}" ]]; then
        echo "$(t "sha256 校验失败（可能被篡改或下载损坏）" "sha256 verification failed (possible tampering or corrupted download)")" >&2
        echo "  expected=${expected}" >&2
        echo "  actual=${actual}" >&2
        exit 5
      fi
    fi

    tar -xzf "${tmp}/${asset}" -C "${tmp}"
    if [[ ! -f "${tmp}/vibeguard" ]]; then
      echo "$(t "解压后未找到 vibeguard 二进制" "vibeguard binary not found after extraction")" >&2
      exit 6
    fi

    mkdir -p "${install_dir}"
    if have install; then
      install -m 0755 "${tmp}/vibeguard" "${install_dir}/vibeguard"
    else
      cp -f "${tmp}/vibeguard" "${install_dir}/vibeguard"
      chmod 0755 "${install_dir}/vibeguard" >/dev/null 2>&1 || true
    fi
  )
}

# Interactivity detection:
# - When piped (curl | bash), stdin is not a TTY, but /dev/tty is often available.
# - After parsing args, we try to open /dev/tty as FD=3 (VG_TTY_FD=3) to continue prompting.
is_tty() {
  if [[ "${VG_TTY_OK:-0}" == "1" ]]; then
    return 0
  fi
  [[ -t 0 && -t 1 ]]
}

can_prompt() {
  [[ "${NON_INTERACTIVE:-0}" == "0" ]] || return 1
  is_tty
}

prompt() {
  # Usage: prompt "Prompt: " "default"
  local msg="${1:-}"
  local def="${2:-}"
  local ans=""

  if [[ "${NON_INTERACTIVE:-0}" == "1" ]]; then
    echo "${def}"
    return 0
  fi

  if [[ -n "${VG_TTY_FD:-}" ]]; then
    printf "%s" "${msg}" >&${VG_TTY_FD}
    IFS= read -r ans <&${VG_TTY_FD} || true
  else
    read -r -p "${msg}" ans || true
  fi

  if [[ -z "${ans}" ]]; then
    ans="${def}"
  fi
  echo "${ans}"
}

run_with_tty() {
  # In curl | bash mode, bind child stdin to /dev/tty (if available) to avoid reading pipe EOF.
  if [[ -n "${VG_TTY_FD:-}" ]]; then
    "$@" <&${VG_TTY_FD}
  else
    "$@"
  fi
}

docker_container_exists() {
  local name="${1:-}"
  [[ -n "${name}" ]] || return 1
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Fxq "${name}"
}

docker_container_running() {
  local name="${1:-}"
  [[ -n "${name}" ]] || return 1
  docker ps --format '{{.Names}}' 2>/dev/null | grep -Fxq "${name}"
}

trust_ca_darwin_user() {
  local cert_path="${1:-}"
  [[ -f "${cert_path}" ]] || return 1
  have security || return 1

  local args=("add-trusted-cert" "-r" "trustRoot")
  if [[ -n "${HOME:-}" ]]; then
    local login_kc="${HOME}/Library/Keychains/login.keychain-db"
    if [[ -f "${login_kc}" ]]; then
      args+=("-k" "${login_kc}")
    fi
  fi
  args+=("${cert_path}")

  security "${args[@]}" >/dev/null 2>&1
}

trust_ca_darwin_system() {
  local cert_path="${1:-}"
  [[ -f "${cert_path}" ]] || return 1
  have security || return 1
  have sudo || return 1

  # System trust install requires sudo + an interactive TTY.
  if [[ "${NON_INTERACTIVE:-0}" == "1" ]]; then
    return 1
  fi
  if [[ "${VG_TTY_OK:-0}" != "1" ]]; then
    return 1
  fi

  run_with_tty sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "${cert_path}" >/dev/null 2>&1
}

trust_ca_linux_system() {
  local cert_path="${1:-}"
  [[ -f "${cert_path}" ]] || return 1

  local dest_dir="/usr/local/share/ca-certificates"
  local dest_path="${dest_dir}/vibeguard-ca.crt"

  if [[ ! -d "${dest_dir}" ]]; then
    local alt_dirs=("/etc/ssl/certs" "/etc/pki/ca-trust/source/anchors")
    local d
    for d in "${alt_dirs[@]}"; do
      if [[ -d "${d}" ]]; then
        dest_dir="${d}"
        dest_path="${d}/vibeguard-ca.crt"
        break
      fi
    done
  fi

  if ! cp -f "${cert_path}" "${dest_path}" >/dev/null 2>&1; then
    have sudo || return 1
    run_with_tty sudo cp -f "${cert_path}" "${dest_path}" >/dev/null 2>&1
  fi

  if have update-ca-certificates; then
    if ! update-ca-certificates >/dev/null 2>&1; then
      have sudo || return 1
      run_with_tty sudo update-ca-certificates >/dev/null 2>&1
    fi
    return 0
  fi
  if have update-ca-trust; then
    if ! update-ca-trust extract >/dev/null 2>&1; then
      have sudo || return 1
      run_with_tty sudo update-ca-trust extract >/dev/null 2>&1
    fi
    return 0
  fi

  return 1
}

trust_ca_file() {
  local cert_path="${1:-}"
  local mode="${2:-auto}"
  [[ -f "${cert_path}" ]] || return 1

  mode="$(to_lower "${mode}")"
  local os_name
  os_name="$(uname -s 2>/dev/null || true)"

  case "${os_name}" in
    Darwin)
      case "${mode}" in
        user)
          trust_ca_darwin_user "${cert_path}"
          ;;
        system)
          trust_ca_darwin_system "${cert_path}"
          ;;
        auto)
          if trust_ca_darwin_user "${cert_path}"; then
            return 0
          fi
          trust_ca_darwin_system "${cert_path}"
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    Linux)
      case "${mode}" in
        system|auto)
          trust_ca_linux_system "${cert_path}"
          ;;
        user)
          return 1
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    *)
      return 1
      ;;
  esac
}

ensure_shell_helper_in_rc() {
  local rc="${1:-}"
  local func_name="${2:-vibeguard}"
  local proxy_url="${3:-http://127.0.0.1:28657}"
  local ca_cert_path="${4:-}"
  local container_name="${5:-vibeguard}"
  local docker_dir="${6:-}"
  local marker="# VibeGuard SHELL"

  [[ -n "${rc}" && -n "${func_name}" ]] || return 1

  if [[ -f "${rc}" ]]; then
    if grep -Fqs "${marker}" "${rc}"; then
      return 0
    fi
  fi

  {
    echo ""
    echo "${marker}"
    echo "# Docker-only helper: admin commands run in the container; assistant commands run on the host and inject proxy+CA for this process only."
    if [[ -n "${docker_dir}" ]]; then
      echo "export VIBEGUARD_DOCKER_DIR=\"${docker_dir}\""
    fi
    echo "export VIBEGUARD_PROXY_URL=\"${proxy_url}\""
    if [[ -n "${ca_cert_path}" ]]; then
      echo "export VIBEGUARD_CA_CERT=\"${ca_cert_path}\""
    fi
    echo "export VIBEGUARD_DOCKER_CONTAINER=\"${container_name}\""
    echo ""
    echo "${func_name}() {"
    cat <<'EOF'
  local sub="${1:-}"
  if [ -z "$sub" ]; then
    if [ -n "${VIBEGUARD_DOCKER_DIR:-}" ] && [ -f "${VIBEGUARD_DOCKER_DIR}/docker-compose.yml" ]; then
      (cd "$VIBEGUARD_DOCKER_DIR" && docker compose exec -T vibeguard vibeguard --help) || \
      (cd "$VIBEGUARD_DOCKER_DIR" && docker-compose exec -T vibeguard vibeguard --help) || true
      return
    fi
    docker exec -i "${VIBEGUARD_DOCKER_CONTAINER:-vibeguard}" vibeguard --help || true
    return
  fi
  shift || true
  case "$sub" in
    claude|codex|gemini|opencode|qwen|kimi)
      if [ -n "${VIBEGUARD_CA_CERT:-}" ] && [ -f "$VIBEGUARD_CA_CERT" ]; then
        HTTPS_PROXY="$VIBEGUARD_PROXY_URL" HTTP_PROXY="$VIBEGUARD_PROXY_URL" \
        https_proxy="$VIBEGUARD_PROXY_URL" http_proxy="$VIBEGUARD_PROXY_URL" \
        NO_PROXY="127.0.0.1,localhost" no_proxy="127.0.0.1,localhost" \
        NODE_EXTRA_CA_CERTS="$VIBEGUARD_CA_CERT" \
        "$sub" "$@"
      else
        HTTPS_PROXY="$VIBEGUARD_PROXY_URL" HTTP_PROXY="$VIBEGUARD_PROXY_URL" \
        https_proxy="$VIBEGUARD_PROXY_URL" http_proxy="$VIBEGUARD_PROXY_URL" \
        NO_PROXY="127.0.0.1,localhost" no_proxy="127.0.0.1,localhost" \
        "$sub" "$@"
      fi
      ;;
    run)
      if [ -n "${VIBEGUARD_CA_CERT:-}" ] && [ -f "$VIBEGUARD_CA_CERT" ]; then
        HTTPS_PROXY="$VIBEGUARD_PROXY_URL" HTTP_PROXY="$VIBEGUARD_PROXY_URL" \
        https_proxy="$VIBEGUARD_PROXY_URL" http_proxy="$VIBEGUARD_PROXY_URL" \
        NO_PROXY="127.0.0.1,localhost" no_proxy="127.0.0.1,localhost" \
        NODE_EXTRA_CA_CERTS="$VIBEGUARD_CA_CERT" \
        "$@"
      else
        HTTPS_PROXY="$VIBEGUARD_PROXY_URL" HTTP_PROXY="$VIBEGUARD_PROXY_URL" \
        https_proxy="$VIBEGUARD_PROXY_URL" http_proxy="$VIBEGUARD_PROXY_URL" \
        NO_PROXY="127.0.0.1,localhost" no_proxy="127.0.0.1,localhost" \
        "$@"
      fi
      ;;
    *)
      if [ -n "${VIBEGUARD_DOCKER_DIR:-}" ] && [ -f "${VIBEGUARD_DOCKER_DIR}/docker-compose.yml" ]; then
        (cd "$VIBEGUARD_DOCKER_DIR" && docker compose exec -T vibeguard vibeguard "$sub" "$@") || \
        (cd "$VIBEGUARD_DOCKER_DIR" && docker-compose exec -T vibeguard vibeguard "$sub" "$@") || true
        return
      fi
      docker exec -i "${VIBEGUARD_DOCKER_CONTAINER:-vibeguard}" vibeguard "$sub" "$@"
      ;;
  esac
}
EOF
  } >>"${rc}"
}

docker_install() {
  need docker

  local image="ghcr.io/inkdust2021/vibeguard:latest"
  local name="vibeguard"
  local volume="vibeguard-data"
  local host_port="${VIBEGUARD_DOCKER_PORT:-28657}"
  local admin_url="http://127.0.0.1:${host_port}/manager/"
  local proxy_url="http://127.0.0.1:${host_port}"
  local ca_in_container="/root/.vibeguard/ca.crt"

  say "Docker 部署" "Docker install"

  if ! docker info >/dev/null 2>&1; then
    die "Docker 未运行或不可用（请先启动 Docker Desktop / dockerd）" "Docker does not seem to be running (start Docker Desktop / dockerd first)"
  fi

  say "拉取镜像：${image}" "Pulling image: ${image}"
  docker pull "${image}" >/dev/null

  docker volume create "${volume}" >/dev/null 2>&1 || true

  if docker_container_exists "${name}"; then
    say "检测到已存在容器：${name}" "Existing container found: ${name}"
    if can_prompt; then
      echo ""
      ans="$(prompt "$(t "是否重建容器（会删除旧容器，但保留数据卷 ${volume}）？[y/N]: " "Recreate container (remove old container, keep volume ${volume})? [y/N]: ")" "N")"
      ans="$(to_lower "${ans:-n}")"
      if [[ "${ans}" == "y" || "${ans}" == "yes" ]]; then
        docker rm -f "${name}" >/dev/null 2>&1 || true
      fi
    fi
  fi

  if ! docker_container_exists "${name}"; then
    say "启动容器" "Starting container"
    docker run -d \
      --name "${name}" \
      --restart unless-stopped \
      -p "127.0.0.1:${host_port}:28657" \
      -v "${volume}:/root/.vibeguard" \
      -e "VIBEGUARD_LANG=${SCRIPT_LANG}" \
      "${image}" >/dev/null
  else
    if ! docker_container_running "${name}"; then
      say "启动已有容器" "Starting existing container"
      docker start "${name}" >/dev/null
    fi
  fi

  say "等待服务就绪（生成 CA）" "Waiting for service (generating CA)"
  for _ in $(seq 1 60); do
    if docker exec "${name}" test -f "${ca_in_container}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done

  local tmp_ca=""
  tmp_ca="$(mktemp -t vibeguard-ca.XXXXXX.crt 2>/dev/null || mktemp "/tmp/vibeguard-ca.XXXXXX.crt")"
  if docker exec "${name}" test -f "${ca_in_container}" >/dev/null 2>&1; then
    if ! docker cp "${name}:${ca_in_container}" "${tmp_ca}" >/dev/null 2>&1; then
      rm -f "${tmp_ca}" >/dev/null 2>&1 || true
      tmp_ca=""
      say "导出 CA 证书失败（你仍可在管理页下载）" "Failed to export CA (you can still download it from the admin UI)"
    fi
  else
    rm -f "${tmp_ca}" >/dev/null 2>&1 || true
    tmp_ca=""
    say "未检测到 CA 证书（你可以稍后重试导出/信任）" "CA certificate not found yet (retry export/trust later)"
  fi

  # Optional: export CA to a file (for manual install/debugging)
  if [[ -n "${tmp_ca}" && -f "${tmp_ca}" ]]; then
    if [[ "${DO_EXPORT_SET}" == "0" ]] && can_prompt; then
      echo ""
      ans="$(prompt "$(t "是否导出（下载）CA 证书到文件（便于排查/手动安装）？[y/N]: " "Export CA certificate to a file (for debugging/manual install)? [y/N]: ")" "N")"
      ans="$(to_lower "${ans:-n}")"
      if [[ "${ans}" == "y" || "${ans}" == "yes" ]]; then
        DO_EXPORT="1"
      fi
    fi

    if [[ "${DO_EXPORT}" == "1" ]]; then
      export_path=""
      if [[ -d "${HOME:-}/Downloads" ]]; then
        export_path="${HOME}/Downloads/vibeguard-ca.crt"
      else
        export_path="$(pwd)/vibeguard-ca.crt"
      fi

      if [[ -f "${export_path}" ]] && can_prompt; then
        echo ""
        ans="$(prompt "$(t "检测到已存在 ${export_path}，是否覆盖？[y/N]: " "File exists at ${export_path}. Overwrite? [y/N]: ")" "N")"
        ans="$(to_lower "${ans:-n}")"
        if [[ "${ans}" != "y" && "${ans}" != "yes" ]]; then
          export_path=""
        fi
      fi

      if [[ -n "${export_path}" ]]; then
        cp -f "${tmp_ca}" "${export_path}"
        say "已导出（下载）CA 证书：${export_path}" "Exported CA certificate: ${export_path}"
      fi
    fi
  fi

  # Also export a stable copy to ~/.vibeguard (for shell helper / NODE_EXTRA_CA_CERTS); do not overwrite ~/.vibeguard/ca.crt.
  local stable_ca=""
  if [[ -n "${HOME:-}" ]]; then
    stable_ca="${HOME}/.vibeguard/vibeguard-docker-ca.crt"
    if [[ -n "${tmp_ca}" && -f "${tmp_ca}" ]]; then
      mkdir -p "${HOME}/.vibeguard" >/dev/null 2>&1 || true
      if cp -f "${tmp_ca}" "${stable_ca}" >/dev/null 2>&1; then
        chmod 0644 "${stable_ca}" >/dev/null 2>&1 || true
      else
        stable_ca=""
      fi
    fi
  fi

  # Optional: install into the HOST trust store (required for HTTPS MITM)
  if [[ "${TRUST_MODE_SET}" == "0" && -n "${tmp_ca}" && -f "${tmp_ca}" ]] && can_prompt; then
    echo ""
    ans="$(prompt "$(t "是否将 CA 安装到“宿主机”信任库（HTTPS MITM 必需，推荐）？[Y/n]: " "Install CA into the HOST trust store (required for HTTPS MITM, recommended)? [Y/n]: ")" "Y")"
    ans="$(to_lower "${ans:-y}")"
    if [[ "${ans}" == "n" || "${ans}" == "no" ]]; then
      TRUST_MODE="skip"
    else
      TRUST_MODE="auto"
    fi
  fi

  case "${TRUST_MODE}" in
    skip)
      say "跳过宿主机信任库安装" "Skipping host trust store install"
      ;;
    user|system|auto)
      if [[ -z "${tmp_ca}" || ! -f "${tmp_ca}" ]]; then
        say "未导出 CA，无法自动安装信任（你可在管理页下载 ca.crt 后手动安装）" "CA not exported; cannot auto-install trust (download ca.crt from admin UI and install manually)"
      else
        if trust_ca_file "${tmp_ca}" "${TRUST_MODE}"; then
          say "已完成宿主机信任证书安装" "Host trust store updated"
        else
          say "自动安装信任证书失败：请手动安装（或改用本机安装方式）" "Failed to update trust store automatically; install manually (or use native install)"
          echo "  macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <ca.crt>"
          echo "  Linux: sudo cp <ca.crt> /usr/local/share/ca-certificates/vibeguard-ca.crt && sudo update-ca-certificates"
        fi
      fi
      ;;
    *)
      die "无效的 --trust：${TRUST_MODE}" "Invalid --trust: ${TRUST_MODE}"
      ;;
  esac

  # Optional: write a shell helper (vibeguard function) for Docker-only mode:
  # run a host helper while injecting proxy + CA into the current process only.
  if can_prompt; then
    rc_file="$(detect_shell_rc || true)"
    if [[ -z "${rc_file}" ]]; then
      say "未识别你的 Shell：跳过写入 shell helper（可按 README 手动添加）" "Shell not recognized: skipping shell helper (add it manually via README)"
    else
      local docker_dir=""
      if in_repo && [[ -f "./docker-compose.yml" ]]; then
        docker_dir="$(pwd)"
      fi

      local existing_bin=""
      existing_bin="$(command -v vibeguard 2>/dev/null || true)"
      default_func="vibeguard"
      if [[ -n "${existing_bin}" ]]; then
        default_func="vibeguard_docker"
        say "检测到宿主机已存在 vibeguard：${existing_bin}" "Host vibeguard already exists: ${existing_bin}"
      fi

      echo ""
      ans="$(prompt "$(t "是否写入 Docker-only shell helper 到 ${rc_file}（提供 ${default_func} 命令）？[Y/n]: " "Write Docker-only shell helper to ${rc_file} (adds ${default_func})? [Y/n]: ")" "Y")"
      ans="$(to_lower "${ans:-y}")"
      if [[ "${ans}" == "y" || "${ans}" == "yes" ]]; then
        func_name="${default_func}"
        if [[ -n "${existing_bin}" ]]; then
          echo ""
          echo "$(t "选择函数名（避免覆盖宿主机的 vibeguard）：" "Choose function name (avoid shadowing host vibeguard):")"
          echo "  1) vibeguard_docker ($(t "推荐" "Recommended"))"
          echo "  2) vibeguard ($(t "覆盖同名命令" "Shadow host command"))"
          choice="$(prompt "$(t "选择 [1]: " "Choose [1]: ")" "1")"
          case "${choice}" in
            2) func_name="vibeguard" ;;
            *) func_name="vibeguard_docker" ;;
          esac
        fi

        ensure_shell_helper_in_rc "${rc_file}" "${func_name}" "${proxy_url}" "${stable_ca}" "${name}" "${docker_dir}"
        say "已写入 shell helper：${rc_file}" "Shell helper written: ${rc_file}"
        say "请执行：source \"${rc_file}\"（或重开终端）" "Run: source \"${rc_file}\" (or restart your terminal)"
      else
        say "已跳过写入 shell helper" "Skipped shell helper"
      fi
    fi
  fi

  if [[ -n "${tmp_ca}" ]]; then
    rm -f "${tmp_ca}" >/dev/null 2>&1 || true
  fi

  say "Docker 部署完成" "Docker install done"
  echo ""
  echo "$(t "下一步：" "Next steps:")"
  echo "  1) $(t "打开管理页" "Open admin UI"): ${admin_url}"
  echo "  2) $(t "在系统/应用中将代理设置为" "Set your system/app proxy to"): ${proxy_url}"
  echo "  3) $(t "如需“进程级代理”（仅对某个命令生效），可用：" "For process-only proxy, use:")"
  echo "     HTTPS_PROXY=${proxy_url} HTTP_PROXY=${proxy_url} <command>"
}

default_install_dir() {
  if [[ -n "${HOME:-}" && -d "${HOME}/.local/bin" ]]; then
    echo "${HOME}/.local/bin"
  else
    echo "${HOME}/.local/bin"
  fi
}

expand_user_path() {
  local p="${1:-}"
  if [[ -z "${HOME:-}" ]]; then
    echo "${p}"
    return
  fi
  case "${p}" in
    "~") echo "${HOME}" ;;
    "~/"*) echo "${HOME}/${p#~/}" ;;
    *) echo "${p}" ;;
  esac
}

path_has_dir() {
  local dir="${1:-}"
  [[ -n "${dir}" ]] || return 1
  case ":${PATH}:" in
    *":${dir}:"*) return 0 ;;
    *) return 1 ;;
  esac
}

detect_shell_rc() {
  local shell_name
  shell_name="$(basename "${SHELL:-}")"
  case "${shell_name}" in
    zsh)
      echo "${HOME}/.zshrc"
      return 0
      ;;
    bash)
      if [[ -f "${HOME}/.bash_profile" ]]; then
        echo "${HOME}/.bash_profile"
      else
        echo "${HOME}/.bashrc"
      fi
      return 0
      ;;
    fish)
      return 1
      ;;
    *)
      echo "${HOME}/.profile"
      return 0
      ;;
  esac
}

ensure_path_in_rc() {
  local rc="${1:-}"
  local dir="${2:-}"
  local marker="# VibeGuard PATH"

  [[ -n "${rc}" && -n "${dir}" ]] || return 1

  if [[ -f "${rc}" ]]; then
    if grep -Fqs "${marker}" "${rc}"; then
      return 0
    fi
    if grep -Fqs "PATH=\"${dir}:" "${rc}" || grep -Fqs "PATH='${dir}:" "${rc}"; then
      return 0
    fi
  fi

  {
    echo ""
    echo "${marker}"
    echo "export PATH=\"${dir}:\$PATH\""
  } >>"${rc}"
}

ensure_assistant_aliases_in_rc() {
  # Add convenience aliases so `kimi`/`opencode` run through the proxy automatically.
  # Idempotent via the marker: existing VibeGuard alias blocks are not duplicated.
  local rc="${1:-}"
  local marker="# VibeGuard ALIASES"

  [[ -n "${rc}" ]] || return 1

  if [[ -f "${rc}" ]]; then
    if grep -Fqs "${marker}" "${rc}"; then
      return 0
    fi
  fi

  {
    echo ""
    echo "${marker}"
    echo "alias kimi='vibeguard kimi'"
    echo "alias opencode='vibeguard opencode'"
  } >>"${rc}"
}

detect_listen_from_config() {
  local cfg="${1:-}"
  [[ -f "${cfg}" ]] || return 1
  awk '
    /^[[:space:]]*proxy:[[:space:]]*$/ { inproxy=1; next }
    inproxy && /^[A-Za-z_][A-Za-z0-9_]*:[[:space:]]*$/ { inproxy=0 }
    inproxy && /^[[:space:]]*listen:[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*listen:[[:space:]]*/, "", line)
      sub(/[[:space:]]+#.*/, "", line)
      gsub(/^["'\'']/, "", line)
      gsub(/["'\'']$/, "", line)
      print line
      exit
    }
  ' "${cfg}"
}

proxy_hostport_from_listen() {
  local listen="${1:-}"
  listen="$(echo "${listen}" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if [[ -z "${listen}" ]]; then
    echo "127.0.0.1:28657"
    return 0
  fi

  # Common: 0.0.0.0:28657 -> 127.0.0.1:28657 (more reasonable for clients)
  if [[ "${listen}" == 0.0.0.0:* ]]; then
    echo "127.0.0.1:${listen#0.0.0.0:}"
    return 0
  fi
  # Port-only form: :28657
  if [[ "${listen}" == :* ]]; then
    echo "127.0.0.1${listen}"
    return 0
  fi
  echo "${listen}"
}

proxy_url_from_listen() {
  echo "http://$(proxy_hostport_from_listen "${1:-}")"
}

install_launch_agent() {
  local label="com.vibeguard.proxy"
  local plist_dir="${HOME}/Library/LaunchAgents"
  local plist_path="${plist_dir}/${label}.plist"

  mkdir -p "${plist_dir}"

  cat >"${plist_path}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
      <string>${VG}</string>
      <string>start</string>
      <string>--foreground</string>
      <string>--config</string>
      <string>${CONFIG_FILE}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${CONFIG_DIR}/launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>${CONFIG_DIR}/launchd.err.log</string>
  </dict>
</plist>
EOF

  echo "${plist_path}"
}

enable_launch_agent() {
  local plist_path="${1:-}"
  local label="com.vibeguard.proxy"
  local uid
  uid="$(id -u)"
  local domain="gui/${uid}"
  local svc="${domain}/${label}"

  have launchctl || return 1

  # Clean up existing service first (avoid duplicate registration)
  launchctl bootout "${domain}" "${plist_path}" >/dev/null 2>&1 || true

  if ! launchctl bootstrap "${domain}" "${plist_path}" >/dev/null 2>&1; then
    return 1
  fi
  launchctl enable "${svc}" >/dev/null 2>&1 || true
  if ! launchctl kickstart -k "${svc}" >/dev/null 2>&1; then
    return 1
  fi
}

install_systemd_user_service() {
  local unit_dir="${HOME}/.config/systemd/user"
  local unit_path="${unit_dir}/vibeguard.service"

  mkdir -p "${unit_dir}"

  cat >"${unit_path}" <<EOF
[Unit]
Description=VibeGuard MITM HTTPS proxy
After=network-online.target

[Service]
Type=simple
ExecStart=${VG} start --foreground --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=2
Environment=VIBEGUARD_LANG=${SCRIPT_LANG}

[Install]
WantedBy=default.target
EOF

  echo "${unit_path}"
}

enable_systemd_user_service() {
  have systemctl || return 1
  if ! systemctl --user daemon-reload >/dev/null 2>&1; then
    return 1
  fi
  if ! systemctl --user enable --now vibeguard.service >/dev/null 2>&1; then
    return 1
  fi
}

INSTALL_DIR="$(default_install_dir)"
TRUST_MODE="system"   # system|user|auto|skip
DO_EXPORT="0"
PATH_MODE="auto"      # auto|add|skip
AUTOSTART_MODE="auto" # auto|add|skip
NON_INTERACTIVE="0"
INSTALL_METHOD="auto" # auto|native|docker
INSTALL_VERSION="latest"
VERIFY_RELEASE="1"
INSTALL_VARIANT="auto" # auto|lite|full

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      INSTALL_DIR="${2:-}"; shift 2;;
    --method)
      INSTALL_METHOD="${2:-}"; shift 2;;
    --version)
      INSTALL_VERSION="${2:-}"; shift 2;;
    --variant)
      INSTALL_VARIANT="${2:-}"; shift 2;;
    --trust)
      TRUST_MODE="${2:-}"; TRUST_MODE_SET="1"; shift 2;;
    --export)
      DO_EXPORT="1"; DO_EXPORT_SET="1"; shift 1;;
    --lang|--language)
      SCRIPT_LANG="${2:-}"; SCRIPT_LANG_SET="1"; shift 2;;
    --path)
      PATH_MODE="${2:-}"; shift 2;;
    --autostart)
      AUTOSTART_MODE="${2:-}"; shift 2;;
    --no-verify)
      VERIFY_RELEASE="0"; shift 1;;
    --non-interactive)
      NON_INTERACTIVE="1"; shift 1;;
    -h|--help)
      cat <<'EOF'
VibeGuard 安装脚本 / Installer

参数 / Options:
  --dir DIR              安装目录 / Install dir (default: $HOME/.local/bin)
  --method METHOD        auto|native|docker (default: auto)
  --version VERSION      安装版本：latest|vX.Y.Z（native 会优先下载 Release） / Version: latest|vX.Y.Z (native prefers Release)
  --variant VARIANT      auto|lite|full (default: auto; full includes SQLite audit persistence)
  --trust MODE           system|user|auto|skip (default: system)
  --export               导出 CA 证书到文件 / Export CA cert to a file
  --lang LANG            zh|en (default: auto)
  --path MODE            auto|add|skip (default: auto)
  --autostart MODE       auto|add|skip (default: auto)
  --no-verify            跳过 Release 下载的 sha256 校验（不推荐） / Skip sha256 verification (not recommended)
  --non-interactive      非交互模式（尽量使用默认值） / Non-interactive (use defaults)

示例 / Examples:
  bash install.sh
EOF
      exit 0;;
    *)
      die "未知参数：$1" "Unknown option: $1";;
  esac
done

# Interactive input: try /dev/tty first (works even with curl | bash)
VG_TTY_OK="0"
VG_TTY_FD=""
if exec 3<>/dev/tty 2>/dev/null; then
  VG_TTY_OK="1"
  VG_TTY_FD="3"
elif [[ -t 0 && -t 1 ]]; then
  VG_TTY_OK="1"
  VG_TTY_FD=""
fi

# If not interactive and the user did not explicitly specify, switch to non-interactive mode.
if [[ "${NON_INTERACTIVE}" == "0" && "${VG_TTY_OK}" != "1" ]]; then
  NON_INTERACTIVE="1"
fi

# In non-interactive mode, skip trust store install by default (avoid sudo/system trust failures without a TTY).
if [[ "${TRUST_MODE_SET}" == "0" && "${NON_INTERACTIVE}" == "1" ]]; then
  TRUST_MODE="skip"
fi

# Language selection: --lang > VIBEGUARD_LANG > infer from locale; if interactive, prompt once at startup.
if [[ "${SCRIPT_LANG_SET}" == "1" ]]; then
  SCRIPT_LANG="$(normalize_lang "${SCRIPT_LANG}")"
  [[ -n "${SCRIPT_LANG}" ]] || die "无效的 --lang（请用 zh 或 en）" "Invalid --lang (use zh or en)"
else
  SCRIPT_LANG="$(normalize_lang "${VIBEGUARD_LANG:-}")"
fi

if [[ -z "${SCRIPT_LANG}" ]]; then
  loc="$(to_lower "${LC_ALL:-${LANG:-}}")"
  if [[ "${loc}" == zh* || "${loc}" == *zh* ]]; then
    SCRIPT_LANG="zh"
  else
    SCRIPT_LANG="en"
  fi
fi

if [[ "${SCRIPT_LANG_SET}" == "0" && -z "${VIBEGUARD_LANG:-}" ]] && can_prompt; then
  echo ""
  echo "请选择语言 / Choose language:"
  echo "  1) 中文"
  echo "  2) English"
  if [[ "${SCRIPT_LANG}" == "zh" ]]; then
    choice="$(prompt "选择 [1]: " "1")"
  else
    choice="$(prompt "Choose [2]: " "2")"
  fi
  case "${choice}" in
    1) SCRIPT_LANG="zh" ;;
    2) SCRIPT_LANG="en" ;;
    *) : ;;
  esac
fi

persist_lang_best_effort

case "$(to_lower "${PATH_MODE}")" in
  auto|add|skip) ;;
  *) die "无效的 --path（可选：auto|add|skip）" "Invalid --path (expected: auto|add|skip)" ;;
esac
PATH_MODE="$(to_lower "${PATH_MODE}")"

case "$(to_lower "${AUTOSTART_MODE}")" in
  auto|add|skip) ;;
  *) die "无效的 --autostart（可选：auto|add|skip）" "Invalid --autostart (expected: auto|add|skip)" ;;
esac
AUTOSTART_MODE="$(to_lower "${AUTOSTART_MODE}")"

case "$(to_lower "${INSTALL_METHOD}")" in
  auto|native|docker) ;;
  *) die "无效的 --method（可选：auto|native|docker）" "Invalid --method (expected: auto|native|docker)" ;;
esac
INSTALL_METHOD="$(to_lower "${INSTALL_METHOD}")"

case "$(to_lower "${INSTALL_VARIANT}")" in
  auto|lite|full) ;;
  *) die "无效的 --variant（可选：auto|lite|full）" "Invalid --variant (expected: auto|lite|full)" ;;
esac
INSTALL_VARIANT="$(to_lower "${INSTALL_VARIANT}")"

# Install method selection (supports curl | bash):
# - auto: prompt if interactive; otherwise auto-select based on environment
if [[ "${INSTALL_METHOD}" == "auto" ]]; then
  if can_prompt; then
    say "选择安装方式" "Choose install method"
    echo "  1) $(t "Docker 部署（推荐，不需要 Go）" "Docker (recommended, no Go required)")"
    echo "  2) $(t "本机安装（需要 Go，提供 vibeguard CLI）" "Native (requires Go, installs vibeguard CLI)")"
    echo "  3) $(t "退出" "Quit")"
    default_choice="1"
    if in_repo; then
      default_choice="2"
    fi
    choice="$(prompt "$(t "选择 [${default_choice}]: " "Choose [${default_choice}]: ")" "${default_choice}")"
    case "${choice}" in
      1|"") INSTALL_METHOD="docker" ;;
      2) INSTALL_METHOD="native" ;;
      3)
        say "已取消" "Cancelled"
        exit 0
        ;;
      *)
        say "无效选项，已使用默认值" "Invalid choice; using default"
        INSTALL_METHOD="docker"
        ;;
    esac
  else
	    # Non-interactive: choose the most likely workable option.
	    if have docker && ! have go; then
      INSTALL_METHOD="docker"
    else
      INSTALL_METHOD="native"
    fi
  fi
fi

if [[ "${INSTALL_METHOD}" == "docker" ]]; then
  docker_install
  exit 0
fi

if [[ "${INSTALL_VARIANT}" == "auto" ]]; then
  if can_prompt; then
    say "选择安装变体" "Choose install variant"
    echo "  1) $(t "Lite（默认，不含 SQLite 审计持久化，体积更小）" "Lite (default, no SQLite audit persistence, smaller)")"
    echo "  2) $(t "Full（包含 SQLite 审计持久化，体积更大）" "Full (includes SQLite audit persistence, larger)")"
    choice="$(prompt "$(t "选择 [1]: " "Choose [1]: ")" "1")"
    case "${choice}" in
      2) INSTALL_VARIANT="full" ;;
      1|"") INSTALL_VARIANT="lite" ;;
      *) INSTALL_VARIANT="lite" ;;
    esac
  else
    INSTALL_VARIANT="lite"
  fi
fi

INSTALL_DIR="$(expand_user_path "${INSTALL_DIR}")"
mkdir -p "${INSTALL_DIR}"

say "安装目录：${INSTALL_DIR}" "Install dir: ${INSTALL_DIR}"

release_repo="${VG_INSTALL_REPO:-inkdust2021/VibeGuard}"
if ! in_repo; then
  # Not in a source tree: prefer GitHub Release binaries (no Go required)
  if ! install_vibeguard_from_release "${INSTALL_DIR}" "${release_repo}" "${INSTALL_VERSION}" "${VERIFY_RELEASE}" "${INSTALL_VARIANT}"; then
    say "Release 安装失败：将回退到 go install（需要 Go）" "Release install failed: falling back to go install (requires Go)"
    need go
    if [[ "${INSTALL_VARIANT}" == "full" ]]; then
      GOBIN="${INSTALL_DIR}" go install -tags vibeguard_full github.com/inkdust2021/vibeguard/cmd/vibeguard@latest
    else
      GOBIN="${INSTALL_DIR}" go install github.com/inkdust2021/vibeguard/cmd/vibeguard@latest
    fi
  fi
else
  # In a source tree: build locally by default (better for dev/debug)
  need go
  say "检测到仓库源码：从源码构建并安装" "Repo detected: build from source"
  tmp="$(mktemp -d -t vibeguard-build.XXXXXX 2>/dev/null || mktemp -d "/tmp/vibeguard-build.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  if [[ "${INSTALL_VARIANT}" == "full" ]]; then
    go build -tags vibeguard_full -o "${tmp}/vibeguard" ./cmd/vibeguard
  else
    go build -o "${tmp}/vibeguard" ./cmd/vibeguard
  fi
  if have install; then
    install -m 0755 "${tmp}/vibeguard" "${INSTALL_DIR}/vibeguard"
  else
    cp -f "${tmp}/vibeguard" "${INSTALL_DIR}/vibeguard"
    chmod 0755 "${INSTALL_DIR}/vibeguard" >/dev/null 2>&1 || true
  fi
fi

VG="${INSTALL_DIR}/vibeguard"
if [[ ! -x "${VG}" ]] && have vibeguard; then
  VG="$(command -v vibeguard)"
fi

if [[ ! -x "${VG}" ]]; then
  die "vibeguard 未找到或不可执行：${VG}" "vibeguard not found or not executable: ${VG}"
fi

say "vibeguard 路径：${VG}" "vibeguard path: ${VG}"

CONFIG_DIR="${HOME}/.vibeguard"
CA_CERT="${CONFIG_DIR}/ca.crt"
CA_KEY="${CONFIG_DIR}/ca.key"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"

# Optional: add install dir to PATH (persistent)
resolved="$(command -v vibeguard 2>/dev/null || true)"
need_path="0"
reason=""
if [[ "${resolved}" == "${VG}" ]]; then
  need_path="0"
else
  need_path="1"
  if [[ -z "${resolved}" ]]; then
    reason="not_found"
  else
    reason="different"
  fi
fi

if [[ "${PATH_MODE}" != "skip" && "${need_path}" == "1" ]]; then
  rc_file="$(detect_shell_rc || true)"
  if [[ -z "${rc_file}" ]]; then
    say "未识别你的 Shell，无法自动写入 PATH（请手动添加）" "Shell not recognized; cannot auto-update PATH (please add it manually)"
  else
    prompt_zh=""
    prompt_en=""
    if [[ "${reason}" == "not_found" ]]; then
      prompt_zh="检测到 vibeguard 可能无法全局调用，是否将 ${INSTALL_DIR} 写入 PATH（${rc_file}）？[Y/n]: "
      prompt_en="vibeguard may not be on PATH. Add ${INSTALL_DIR} to PATH via ${rc_file}? [Y/n]: "
    else
      say "检测到 PATH 中已有 vibeguard：${resolved}（不是本次安装版本）" "Found existing vibeguard on PATH: ${resolved} (not the one just installed)"
      prompt_zh="是否让本次安装版本优先生效（将 ${INSTALL_DIR} 写入 PATH / ${rc_file}）？[Y/n]: "
      prompt_en="Prefer the newly installed one (prepend ${INSTALL_DIR} via ${rc_file})? [Y/n]: "
    fi

	    if [[ "${PATH_MODE}" == "add" ]]; then
	      ensure_path_in_rc "${rc_file}" "${INSTALL_DIR}"
	      say "已写入 PATH：${rc_file}" "PATH updated: ${rc_file}"
	      say "请执行：source \"${rc_file}\"（或重开终端）" "Run: source \"${rc_file}\" (or restart your terminal)"
	    elif [[ "${PATH_MODE}" == "auto" ]]; then
	      if can_prompt; then
	        echo ""
	        ans="$(prompt "$(t "${prompt_zh}" "${prompt_en}")" "Y")"
	        if [[ "${ans}" == "Y" || "${ans}" == "y" ]]; then
	          ensure_path_in_rc "${rc_file}" "${INSTALL_DIR}"
	          say "已写入 PATH：${rc_file}" "PATH updated: ${rc_file}"
	          say "请执行：source \"${rc_file}\"（或重开终端）" "Run: source \"${rc_file}\" (or restart your terminal)"
	        else
	          say "已跳过 PATH 写入" "Skipped PATH update"
	        fi
	      else
	        say "非交互模式：未写入 PATH（你可以手动添加）" "Non-interactive: PATH not modified (you can add it manually)"
	      fi
	    fi
	  fi
	fi

say "检查 CA 证书" "Checking CA certificate"
if [[ ! -f "${CA_CERT}" ]]; then
  if [[ -f "${CONFIG_FILE}" ]]; then
    say "已存在配置但未找到 CA：请运行 vibeguard init 生成 CA" "Config exists but CA missing: run vibeguard init to generate CA"
  else
	    say "未找到 CA：将运行 vibeguard init 生成 CA（不覆盖已有配置）" "CA not found: running vibeguard init to generate CA"
	    if [[ "${NON_INTERACTIVE}" == "1" ]]; then
	      # Choose default config + generate CA + skip init's built-in trust (handled by this script).
	      printf '\n\n\n\n3\n' | VIBEGUARD_LANG="${SCRIPT_LANG}" "${VG}" init || true
	    else
	      VIBEGUARD_LANG="${SCRIPT_LANG}" run_with_tty "${VG}" init || true
	    fi
	  fi
	fi

if [[ -f "${CA_CERT}" ]]; then
  say "CA 证书已就绪：${CA_CERT}" "CA certificate ready: ${CA_CERT}"
else
  say "仍未找到 CA 证书：跳过证书步骤" "CA certificate still missing: skipping cert steps"
  TRUST_MODE="skip"
  DO_EXPORT="0"
fi

	if [[ "${DO_EXPORT_SET}" == "0" && -f "${CA_CERT}" ]] && can_prompt; then
	  echo ""
	  ans="$(prompt "$(t "是否导出（下载）CA 证书到文件（便于排查/手动安装）？[y/N]: " "Export CA certificate to a file (for debugging/manual install)? [y/N]: ")" "N")"
	  ans="$(to_lower "${ans:-n}")"
	  if [[ "${ans}" == "y" || "${ans}" == "yes" ]]; then
	    DO_EXPORT="1"
	  fi
	fi

if [[ "${DO_EXPORT}" == "1" && -f "${CA_CERT}" ]]; then
  export_path=""
  if [[ -d "${HOME}/Downloads" ]]; then
    export_path="${HOME}/Downloads/vibeguard-ca.crt"
  else
    export_path="$(pwd)/vibeguard-ca.crt"
  fi
  cp -f "${CA_CERT}" "${export_path}"
  say "已导出（下载）CA 证书：${export_path}" "Exported CA certificate: ${export_path}"
fi

	if [[ "${TRUST_MODE_SET}" == "0" && -f "${CA_CERT}" ]] && can_prompt; then
	  echo ""
	  ans="$(prompt "$(t "是否安装信任证书（HTTPS MITM 必需，推荐）？[Y/n]: " "Install trusted CA (required for HTTPS MITM, recommended)? [Y/n]: ")" "Y")"
	  ans="$(to_lower "${ans:-y}")"
	  if [[ "${ans}" == "n" || "${ans}" == "no" ]]; then
	    TRUST_MODE="skip"
	  else
	    TRUST_MODE="auto"
	  fi
	fi

case "${TRUST_MODE}" in
  skip)
    say "跳过信任库安装" "Skipping trust store install";;
  system|user|auto)
    if [[ ! -f "${CA_CERT}" ]]; then
      die "未找到 CA 证书，无法安装信任" "CA certificate missing, cannot install trust"
    fi

    if [[ "${TRUST_MODE}" == "system" ]]; then
      say "将安装到系统信任库（可能需要 sudo）" "Installing to SYSTEM trust store (may require sudo)"
    else
      say "将安装到信任库：${TRUST_MODE}" "Installing to trust store: ${TRUST_MODE}"
    fi

	    if [[ "${TRUST_MODE}" == "system" ]] && can_prompt; then
	      echo ""
	      ans="$(prompt "$(t "继续安装系统信任证书？[Y/n]: " "Continue? [Y/n]: ")" "Y")"
	      if [[ "${ans}" != "Y" && "${ans}" != "y" ]]; then
	        say "已取消" "Cancelled"
	        TRUST_MODE="skip"
	      fi
	    fi
	
	    if [[ "${TRUST_MODE}" != "skip" ]]; then
	      VIBEGUARD_LANG="${SCRIPT_LANG}" run_with_tty "${VG}" trust --mode "${TRUST_MODE}"
	    fi
	    ;;
  *)
    die "无效的 --trust：${TRUST_MODE}" "Invalid --trust: ${TRUST_MODE}";;
esac

# Infer proxy address from current config (for env vars and output hints)
listen_addr="$(detect_listen_from_config "${CONFIG_FILE}" || true)"
proxy_hostport="$(proxy_hostport_from_listen "${listen_addr}")"
proxy_url="http://${proxy_hostport}"
admin_url="http://${proxy_hostport}/manager/"

# Optional: autostart background service (user-level)
autostart_enabled="0"
if [[ "${AUTOSTART_MODE}" != "skip" ]]; then
  do_autostart="0"
  if [[ "${AUTOSTART_MODE}" == "add" ]]; then
    do_autostart="1"
	  elif [[ "${AUTOSTART_MODE}" == "auto" ]]; then
	    if can_prompt; then
	      echo ""
	      ans="$(prompt "$(t "是否启用开机自启并后台运行（推荐）？[Y/n]: " "Enable autostart + background service (recommended)? [Y/n]: ")" "Y")"
	      if [[ "${ans}" == "Y" || "${ans}" == "y" ]]; then
	        do_autostart="1"
	      fi
	    fi
	  fi

  if [[ "${do_autostart}" == "1" ]]; then
    os_name="$(uname -s || true)"
    case "${os_name}" in
      Darwin)
        say "配置开机自启（macOS LaunchAgent）" "Setting up autostart (macOS LaunchAgent)"
        plist_path="$(install_launch_agent)"
        if enable_launch_agent "${plist_path}"; then
          autostart_enabled="1"
          say "已启用开机自启：${plist_path}" "Autostart enabled: ${plist_path}"
        else
          say "启用 LaunchAgent 失败（你可稍后手动启动）：${VG} start" "Failed to enable LaunchAgent (you can start manually): ${VG} start"
        fi
        ;;
      Linux)
        say "配置开机自启（Linux systemd --user）" "Setting up autostart (Linux systemd --user)"
        if have systemctl; then
          unit_path="$(install_systemd_user_service)"
          if enable_systemd_user_service; then
            autostart_enabled="1"
            say "已启用开机自启：${unit_path}" "Autostart enabled: ${unit_path}"
          else
            say "启用 systemd 用户服务失败（你可稍后手动启动）：${VG} start" "Failed to enable systemd user service (you can start manually): ${VG} start"
          fi
        else
          say "未检测到 systemctl：跳过开机自启（你的发行版可能不是 systemd）" "systemctl not found; skipping autostart (your distro may not use systemd)"
        fi
        ;;
      *)
        say "当前系统暂不支持自动配置开机自启（你可手动启动）：${VG} start" "Autostart not supported on this OS (start manually): ${VG} start"
        ;;
    esac
  fi
fi

# If autostart is not enabled but proxy env vars were set, start the background proxy now to avoid "proxy set but port not listening".
say "启动后台代理" "Starting proxy in background"
if ! VIBEGUARD_LANG="${SCRIPT_LANG}" "${VG}" start; then
  say "后台代理启动失败（你可稍后手动运行：vibeguard start --foreground）" "Failed to start proxy (you can run: vibeguard start --foreground)"
fi

# Optional: shell aliases so common CLI assistants run through VibeGuard (native install only).
if can_prompt; then
  rc_file="$(detect_shell_rc || true)"
  if [[ -z "${rc_file}" ]]; then
    say "未识别你的 Shell：跳过 alias 写入（可手动添加：alias kimi='vibeguard kimi'）" "Shell not recognized: skipping alias setup (add manually: alias kimi='vibeguard kimi')"
  else
    echo ""
    ans="$(prompt "$(t "是否为常用 CLI 助手创建 alias（kimi='vibeguard kimi'、opencode='vibeguard opencode'）到 ${rc_file}？[y/N]: " "Create aliases for common CLI assistants (kimi='vibeguard kimi', opencode='vibeguard opencode') in ${rc_file}? [y/N]: ")" "N")"
    ans="$(to_lower "${ans:-n}")"
    if [[ "${ans}" == "y" || "${ans}" == "yes" ]]; then
      ensure_assistant_aliases_in_rc "${rc_file}"
      say "已写入 alias：${rc_file}" "Aliases written: ${rc_file}"
      say "请执行：source \"${rc_file}\"（或重开终端）" "Run: source \"${rc_file}\" (or restart your terminal)"
    else
      say "已跳过 alias 写入" "Skipped alias setup"
    fi
  fi
fi

say "安装完成" "Done"
echo ""
echo "$(t "下一步：" "Next steps:")"
if [[ "${autostart_enabled}" == "1" ]]; then
  echo "  1) $(t "代理已设置为后台自启（登录后自动运行）" "Proxy runs in background on login")"
else
  echo "  1) $(t "启动代理（后台）" "Start proxy (background)"): ${VG} start"
fi
echo "  2) $(t "打开管理页" "Open admin"): ${admin_url}"
echo "  3) $(t "CLI 助手推荐用 VibeGuard 启动（仅该进程生效）：" "For CLI assistants, launch via VibeGuard (process-only):")"
echo "     vibeguard codex [args...]"
echo "     vibeguard claude [args...]"
echo "     vibeguard gemini [args...]"
echo "     vibeguard opencode [args...]"
echo "     vibeguard qwen [args...]"
echo "     vibeguard kimi [args...]"
echo "     vibeguard run <command> [args...]"
echo "  4) $(t "IDE/GUI（如 Cursor）在软件设置里把代理地址填为" "For IDE/GUI apps (Cursor, etc), set the proxy URL to"): ${proxy_url}"
