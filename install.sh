#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="yuanzhangdck"
REPO_NAME="oracle-panel"
BRANCH="main"
INSTALL_DIR="${INSTALL_DIR:-/opt/oracle-panel}"
PORT="${PORT:-3001}"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

as_root() {
  if [ "$(id -u)" = "0" ]; then
    bash -lc "$*"
    return
  fi
  if need_cmd sudo; then
    sudo bash -lc "$*"
    return
  fi
  echo "This installer needs root (or sudo) to install dependencies and write to $INSTALL_DIR."
  exit 1
}

detect_pm() {
  if need_cmd apt-get; then echo "apt"; return; fi
  if need_cmd dnf; then echo "dnf"; return; fi
  if need_cmd yum; then echo "yum"; return; fi
  if need_cmd apk; then echo "apk"; return; fi
  if need_cmd pacman; then echo "pacman"; return; fi
  echo "unknown"
}

install_deps() {
  pm="$(detect_pm)"
  case "$pm" in
    apt)
      as_root "apt-get update -y"
      as_root "apt-get install -y ca-certificates curl tar gzip openssl git python3 make g++"
      if ! need_cmd node || ! need_cmd npm; then
        as_root "curl -fsSL https://deb.nodesource.com/setup_22.x | bash -"
        as_root "apt-get install -y nodejs"
      fi
      ;;
    dnf)
      as_root "dnf install -y ca-certificates curl tar gzip openssl git python3 make gcc-c++"
      if ! need_cmd node || ! need_cmd npm; then
        as_root "curl -fsSL https://rpm.nodesource.com/setup_22.x | bash -"
        as_root "dnf install -y nodejs"
      fi
      ;;
    yum)
      as_root "yum install -y ca-certificates curl tar gzip openssl git python3 make gcc-c++"
      if ! need_cmd node || ! need_cmd npm; then
        as_root "curl -fsSL https://rpm.nodesource.com/setup_22.x | bash -"
        as_root "yum install -y nodejs"
      fi
      ;;
    apk)
      as_root "apk add --no-cache bash ca-certificates curl tar gzip openssl git python3 make g++ nodejs npm"
      ;;
    pacman)
      as_root "pacman -Sy --noconfirm ca-certificates curl tar gzip openssl git python3 base-devel nodejs npm"
      ;;
    *)
      echo "Unsupported system: no known package manager found."
      echo "Install dependencies manually: bash, curl, tar, openssl, nodejs, npm, build tools."
      exit 1
      ;;
  esac
}

download_release() {
  tmp="$(mktemp -d)"
  url="https://codeload.github.com/${REPO_OWNER}/${REPO_NAME}/tar.gz/refs/heads/${BRANCH}"
  echo "Downloading $url" >&2
  curl -fsSL "$url" | tar -xz -C "$tmp"
  src="$tmp/${REPO_NAME}-${BRANCH}"
  if [ ! -d "$src" ]; then
    echo "Failed to download or extract source." >&2
    exit 1
  fi
  echo "$src"
}

sync_dir() {
  src="$1"
  as_root "mkdir -p \"$INSTALL_DIR\""

  # Preserve runtime data if exists.
  as_root "mkdir -p \"$INSTALL_DIR/data\" \"$INSTALL_DIR/uploads\""

  as_root "rm -rf \"$INSTALL_DIR/.new\" && mkdir -p \"$INSTALL_DIR/.new\""
  as_root "cp -a \"$src/.\" \"$INSTALL_DIR/.new/\""

  # Keep existing runtime data.
  as_root "rm -rf \"$INSTALL_DIR/.new/data\" \"$INSTALL_DIR/.new/uploads\""
  as_root "cp -a \"$INSTALL_DIR/data\" \"$INSTALL_DIR/.new/data\" 2>/dev/null || true"
  as_root "cp -a \"$INSTALL_DIR/uploads\" \"$INSTALL_DIR/.new/uploads\" 2>/dev/null || true"

  as_root "rm -rf \"$INSTALL_DIR/.old\" && [ -d \"$INSTALL_DIR\" ] && cp -a \"$INSTALL_DIR\" \"$INSTALL_DIR/.old\" 2>/dev/null || true"
  as_root "rm -rf \"$INSTALL_DIR\"/*"
  as_root "cp -a \"$INSTALL_DIR/.new/.\" \"$INSTALL_DIR/\""
  as_root "rm -rf \"$INSTALL_DIR/.new\""
}

main() {
  if ! need_cmd curl; then
    echo "curl not found. Install curl first, then run:"
    echo "bash <(curl -fsSL https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}/install.sh)"
    exit 1
  fi

echo "[1/4] Installing dependencies..."
  install_deps

  echo "[2/4] Downloading panel..."
  src="$(download_release)"
  sync_dir "$src"

  echo "[3/4] Deploying..."
  if need_cmd systemctl && [ -d /run/systemd/system ]; then
    as_root "cd \"$INSTALL_DIR\" && PORT=\"$PORT\" bash deploy.sh --systemd --port \"$PORT\""
  else
    as_root "cd \"$INSTALL_DIR\" && PORT=\"$PORT\" bash deploy.sh --background --port \"$PORT\""
  fi

  echo "[4/4] Done."
  # deploy.sh already prints the final Login URL + password; keep a short summary here.
  echo "Installed at: $INSTALL_DIR"
}

main \"$@\"
