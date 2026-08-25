#!/usr/bin/env bash
#
# MINTER — one-command install on a headless Linux VPS.
#
#   curl -fsSL https://raw.githubusercontent.com/MaxBetov-pdd/Minter-rs-v2/main/deploy/linux/install.sh | sudo bash
#
# Downloads the prebuilt binary from GitHub Releases (no Rust toolchain, no
# 10-minute compile), installs it as a systemd service behind a private noVNC
# desktop, and prints how to connect.
#
# Supported: Debian 12+, Ubuntu 22.04+, Fedora 36+, RHEL/Rocky/Alma 9+, Arch and
# their derivatives.
# The hard floor is webkit2gtk **4.1** (Tauri v2 will not run on 4.0) and glibc
# 2.34, which is what the release binary is linked against. Ubuntu 20.04 and
# Debian 11 ship only webkit 4.0, so they cannot be supported at all.
#
# noVNC is bound to 127.0.0.1 on purpose: classic VNC auth uses only the first
# 8 characters of the password, which is nowhere near enough in front of a
# wallet GUI. Reach it through an SSH tunnel — see minter-connect.
set -Eeuo pipefail

REPO="${MINTER_REPO:-MaxBetov-pdd/Minter-rs-v2}"
# Named for this script rather than `VERSION`: sourcing /etc/os-release below
# defines VERSION as the distribution's own — "24.04.4 LTS (Noble Numbat)" on
# Ubuntu — and the release URL built from it is not a URL at all. Every install
# on a distro that sets it died at "cannot reach the GitHub release API".
WANT_RELEASE="${MINTER_VERSION:-latest}"
INSTALL_DIR="/opt/minter"
DATA_DIR="/var/lib/minter"
SERVICE="minter-vps"
RUN_USER="minter"
# Measured from the published artifact, not assumed from the builder's own
# glibc: the release binary's highest required symbol is GLIBC_2.34, which is
# lower than Ubuntu 22.04's 2.35 and therefore also clears RHEL/Rocky/Alma 9.
# Re-check with `objdump -T minter-desktop | grep -o 'GLIBC_[0-9.]*' | sort -Vu`
# if the build base ever changes.
GLIBC_FLOOR="2.34"

die()  { printf '\n\033[1;31merror:\033[0m %s\n\n' "$*" >&2; exit 1; }
say()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || die "run as root:  curl -fsSL <url> | sudo bash"
[ "$(uname -m)" = "x86_64" ] || die "only x86_64 is published today (this machine is $(uname -m))"
command -v systemctl >/dev/null || die "this installer needs systemd"

# ── Identify the distribution ────────────────────────────────────────────────
. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"

pm=""
case " $DISTRO_ID $DISTRO_LIKE " in
  *" debian "*|*" ubuntu "*) pm="apt" ;;
  *" fedora "*|*" rhel "*)   pm="dnf" ;;
  *" arch "*)                pm="pacman" ;;
esac
[ -n "$pm" ] || {
  command -v apt-get >/dev/null && pm="apt"
  command -v dnf     >/dev/null && pm="dnf"
  command -v pacman  >/dev/null && pm="pacman"
}
[ -n "$pm" ] || die "unsupported distribution: $DISTRO_NAME (no apt/dnf/pacman found)"

say "Detected $DISTRO_NAME (package manager: $pm)"

# Known-impossible releases: webkit2gtk 4.1 simply is not packaged for them.
case "$DISTRO_ID:${VERSION_ID:-}" in
  ubuntu:20.04|ubuntu:18.04|debian:11|debian:10)
    die "$DISTRO_NAME ships only webkit2gtk 4.0; MINTER needs 4.1. Use Ubuntu 22.04+ or Debian 12+."
    ;;
esac

# ── glibc floor ──────────────────────────────────────────────────────────────
# Checked before anything is installed: a too-old glibc makes the binary refuse
# to start, and finding that out after a full package install is a waste.
# NB: no `| head -1` anywhere in this script. Under `set -o pipefail` head closes
# the pipe early, the producer dies of SIGPIPE, and the whole pipeline reports
# failure — which silently appended "0" to the detected version and rejected a
# perfectly good glibc 2.39. awk consumes all input, so it cannot misfire.
ldd_out="$(ldd --version 2>/dev/null || true)"
sys_glibc="$(printf '%s\n' "$ldd_out" |
  awk 'NR==1 { for (i = NF; i > 0; i--) if ($i ~ /^[0-9]+\.[0-9]+$/) { print $i; exit } }')"
[ -n "$sys_glibc" ] || sys_glibc="0"
oldest="$(printf '%s\n%s\n' "$GLIBC_FLOOR" "$sys_glibc" | sort -V | sed -n 1p)"
if [ "$oldest" != "$GLIBC_FLOOR" ]; then
  die "glibc $sys_glibc is older than the required $GLIBC_FLOOR ($DISTRO_NAME).
       Ubuntu 20.04 and Debian 11 (glibc 2.31) are below it — build from source there."
fi
ok "glibc $sys_glibc (need >= $GLIBC_FLOOR)"

# ── VNC password ─────────────────────────────────────────────────────────────
# Piping into bash consumes stdin, so read from the terminal explicitly.
VNC_PASSWORD="${MINTER_VNC_PASSWORD:-}"
if [ -z "$VNC_PASSWORD" ] && [ -r /dev/tty ]; then
  printf 'VNC password (8+ chars; the VNC protocol only uses the first 8): '
  read -rs VNC_PASSWORD < /dev/tty || true
  printf '\n'
fi
if [ -z "$VNC_PASSWORD" ]; then
  VNC_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12)"
  GENERATED_PASSWORD=1
fi
[ ${#VNC_PASSWORD} -ge 8 ] || die "password must be at least 8 characters"

# ── Packages ─────────────────────────────────────────────────────────────────
say "Installing runtime packages"
case "$pm" in
  apt)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      ca-certificates curl jq tar iproute2 \
      libwebkit2gtk-4.1-0 libxdo3 libayatana-appindicator3-1 librsvg2-2 \
      xvfb xauth x11-utils x11vnc openbox dbus-x11 novnc websockify \
      xdg-utils xdg-desktop-portal xdg-desktop-portal-gtk fonts-dejavu-core >/dev/null
    ;;
  dnf)
    # --refresh forces a metadata sync. Without it dnf trusts its cache until
    # metadata_expire (48h on Fedora), so a fresh cloud image with an empty or
    # stale cache fails with "No match for argument" on packages that do exist.
    dnf install -y -q --refresh \
      ca-certificates curl jq tar iproute \
      webkit2gtk4.1 xdotool libappindicator-gtk3 librsvg2 \
      xorg-x11-server-Xvfb xorg-x11-xauth xdpyinfo x11vnc openbox dbus-x11 \
      novnc python3-websockify xdg-utils xdg-desktop-portal-gtk \
      dejavu-sans-fonts >/dev/null
    ;;
  pacman)
    # -Syu, not -Sy. Refreshing the database and installing without upgrading
    # is the partial-upgrade case Arch explicitly does not support: the new
    # package is built against current libraries while the rest of the system
    # stays behind, and dependencies break. On Arch there is no safe way to
    # install from a freshly synced database except to upgrade with it.
    warn "Arch: doing a full system upgrade (-Syu) — partial upgrades are unsupported there"
    pacman -Syu --needed --noconfirm \
      ca-certificates curl jq tar iproute2 \
      webkit2gtk-4.1 xdotool libappindicator-gtk3 librsvg \
      xorg-server-xvfb xorg-xauth xorg-xdpyinfo x11vnc openbox dbus \
      novnc python-websockify xdg-utils xdg-desktop-portal-gtk \
      ttf-dejavu >/dev/null
    ;;
esac
ok "packages installed"

# ── Download the release ─────────────────────────────────────────────────────
say "Fetching MINTER ($WANT_RELEASE) from $REPO"
api="https://api.github.com/repos/$REPO/releases/latest"
[ "$WANT_RELEASE" = "latest" ] || api="https://api.github.com/repos/$REPO/releases/tags/$WANT_RELEASE"

meta="$(curl -fsSL "$api")" || die "cannot reach the GitHub release API"
tag="$(printf '%s' "$meta" | jq -r '.tag_name // empty')"
[ -n "$tag" ] || die "no release found in $REPO (has one been published yet?)"
url="$(printf '%s' "$meta" |
  jq -r '[.assets[]?.browser_download_url | select(endswith("linux-x64.tar.gz"))] | first // empty')"
[ -n "$url" ] || die "release $tag has no linux-x64 asset"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/minter.tar.gz"

sum_url="$(printf '%s' "$meta" |
  jq -r '[.assets[]?.browser_download_url | select(endswith("linux-x64.tar.gz.sha256"))] | first // empty')"
if [ -n "$sum_url" ]; then
  curl -fsSL "$sum_url" -o "$tmp/minter.sha256"
  want="$(awk '{print $1}' "$tmp/minter.sha256")"
  got="$(sha256sum "$tmp/minter.tar.gz" | awk '{print $1}')"
  [ "$want" = "$got" ] || die "checksum mismatch — refusing to install
       expected $want
       got      $got"
  ok "checksum verified"
else
  warn "no published checksum for $tag; skipping verification"
fi

tar -xzf "$tmp/minter.tar.gz" -C "$tmp"
src="$(find "$tmp" -maxdepth 1 -type d -name 'minter-desktop-*-linux-x64' -print -quit)"
[ -n "$src" ] || die "unexpected archive layout"
ok "downloaded $tag"

# ── Verify the binary can actually resolve its libraries ─────────────────────
# Package names differ per distro and drift between releases, so trusting the
# list above is not enough. Ask the loader instead: anything still unresolved
# is reported by name so the operator knows exactly what to install.
say "Checking shared libraries"
missing="$(ldd "$src/minter-desktop" 2>/dev/null | awk '/not found/ {print "    " $1}' || true)"
if [ -n "$missing" ]; then
  die "the binary is missing shared libraries on $DISTRO_NAME:

$missing

       Install the packages providing them and re-run. On Debian/Ubuntu try:
         apt-get install libwebkit2gtk-4.1-0 libayatana-appindicator3-1 librsvg2-2 libxdo3"
fi
ok "all libraries resolve"

for tool in Xvfb x11vnc openbox websockify xdpyinfo; do
  command -v "$tool" >/dev/null || warn "$tool not on PATH — the desktop may fail to start"
done
novnc_web=""
for d in /usr/share/novnc /usr/share/webapps/novnc /usr/share/noVNC; do
  [ -f "$d/vnc.html" ] && novnc_web="$d" && break
done
[ -n "$novnc_web" ] || die "noVNC web assets not found (looked in /usr/share/novnc and friends)"
ok "noVNC assets at $novnc_web"

# ── Stop a running instance before replacing the binary ──────────────────────
if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
  recent="$(find "$DATA_DIR/logs" -maxdepth 1 -name 'mint_*.log' -mmin -5 -print -quit 2>/dev/null || true)"
  if [ -n "$recent" ] && [ -z "${MINTER_FORCE:-}" ]; then
    die "a mint looks active (recent log: $recent).
       Re-run with MINTER_FORCE=1 to replace the binary anyway."
  fi
  say "Stopping the running service"
  systemctl stop "$SERVICE"
fi

# ── Install ──────────────────────────────────────────────────────────────────
say "Installing to $INSTALL_DIR"
id -u "$RUN_USER" >/dev/null 2>&1 || \
  useradd --system --home-dir "$DATA_DIR" --create-home --shell /usr/sbin/nologin "$RUN_USER" 2>/dev/null || \
  useradd --system --home-dir "$DATA_DIR" --create-home --shell /sbin/nologin "$RUN_USER"

install -d -m 0755 "$INSTALL_DIR" "$INSTALL_DIR/backups"
install -d -o "$RUN_USER" -g "$RUN_USER" -m 0700 "$DATA_DIR" "$DATA_DIR/.vnc" "$DATA_DIR/imports"

# Keep the previous binary — a bad release should be one command from a rollback.
if [ -f "$INSTALL_DIR/minter-desktop" ]; then
  cp -a "$INSTALL_DIR/minter-desktop" \
        "$INSTALL_DIR/backups/minter-desktop.bak-$(date -u +%Y%m%d-%H%M%S)"
fi
install -m 0755 "$src/minter-desktop"      "$INSTALL_DIR/minter-desktop"
install -m 0755 "$src/start-minter-vnc.sh" "$INSTALL_DIR/start-minter-vnc.sh"
install -m 0644 "$src/minter-vps.service"  "/etc/systemd/system/$SERVICE.service"

# The runner defaults to /usr/share/novnc; point it at whatever this distro uses.
if [ "$novnc_web" != "/usr/share/novnc" ]; then
  mkdir -p "/etc/systemd/system/$SERVICE.service.d"
  printf '[Service]\nEnvironment=MINTER_NOVNC_WEB=%s\n' "$novnc_web" \
    > "/etc/systemd/system/$SERVICE.service.d/novnc-path.conf"
  ok "noVNC path override written"
fi

x11vnc -storepasswd "${VNC_PASSWORD:0:8}" "$DATA_DIR/.vnc/passwd" >/dev/null 2>&1
chown "$RUN_USER:$RUN_USER" "$DATA_DIR/.vnc/passwd"
chmod 0600 "$DATA_DIR/.vnc/passwd"
ok "binary and service installed"

systemctl daemon-reload
systemctl enable --now "$SERVICE" >/dev/null 2>&1
ok "service enabled"

# ── Wait for it to come up ───────────────────────────────────────────────────
say "Waiting for noVNC"
up=0
for _ in $(seq 1 30); do
  sleep 1
  if ss -ltn 2>/dev/null | grep -q '127.0.0.1:3021'; then up=1; break; fi
done
[ "$up" = 1 ] || die "noVNC did not come up.
       Look at:  journalctl -u $SERVICE -n 50 --no-pager"
ok "listening on 127.0.0.1:3021"

# ── How to connect ───────────────────────────────────────────────────────────
ip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
[ -n "$ip" ] || ip="<your-server-ip>"
sshuser="${SUDO_USER:-root}"

cat <<BANNER

  ────────────────────────────────────────────────────────────────
   MINTER $tag is installed and running on $DISTRO_NAME.
  ────────────────────────────────────────────────────────────────

  Port 3021 is bound to localhost on purpose — nothing is exposed
  to the Internet. Reach the GUI through an SSH tunnel.

  EASY WAY — from Windows:
    1. Get minter-connect:
       https://github.com/MaxBetov-pdd/minter-connect
    2. Run connect.ps1 and enter when asked:
           server:  $ip
           user:    $sshuser
    It creates the SSH key, opens the tunnel and the browser.

  MANUAL WAY — any OS with an ssh client:
    ssh -N -L 3021:127.0.0.1:3021 $sshuser@$ip
    then open  http://127.0.0.1:3021/vnc.html?autoconnect=1&resize=scale

BANNER

if [ -n "${GENERATED_PASSWORD:-}" ]; then
  cat <<PWD
  VNC password (generated — save it now, it is stored nowhere else):

      $VNC_PASSWORD

PWD
fi

cat <<OPS
  Service:   systemctl status $SERVICE
  Logs:      journalctl -u $SERVICE -f
  Data:      $DATA_DIR   (keys.vault, config.json, logs, results)
  Rollback:  ls $INSTALL_DIR/backups

OPS
