#!/bin/sh
# =============================================================================
#  alpine-docker-setup.sh — hardened Docker + mDNS for an Alpine home server
# -----------------------------------------------------------------------------
#  Run once after a fresh install (see the answerfile); safe to re-run.
#
#  What it does:
#    1. Preflight: root, Alpine >= 3.18, real host (not a container)
#    2. Packages: docker, compose, buildx, nftables, dbus, avahi, avahi-tools
#    3. Docker (Alpine's standard service), hardened:
#         - userns-remap: container root is an unprivileged uid on the host
#         - no-new-privileges, icc off, live-restore, capped logs
#         - nobody in the root-equivalent 'docker' group; admins use doas
#    4. Firewall in its own nftables table, never touching Docker's rules:
#         - inbound default-deny; SSH, mDNS and --ports from LAN only
#         - published container ports reachable from the LAN only
#         - global IPv6 blocked (often public even behind CGNAT)
#         - automatic rollback if you lose your SSH session
#    5. mDNS: <hostname>.local announced on the LAN, info leaks off
#    6. SSH: no root login; password login off once you have a key
#    7. Starts everything and runs a self-test (docker run hello-world)
#
#  Usage:
#    doas sh alpine-docker-setup.sh [options]
#
#  Options:
#    --admin USER        Admin user for doas/SSH checks (default: first wheel member)
#    --lan CIDRS         LAN IPv4 ranges, comma list (default: auto-detected)
#    --ssh-port N        SSH port to allow from LAN (default: 22)
#    --ports LIST        Extra HOST service ports for LAN, e.g. "9100/tcp,51820/udp"
#                        (Docker-published ports are LAN-reachable automatically)
#    --iface NAME        LAN interface (default: the default-route interface)
#    --no-mdns           Skip Avahi/D-Bus
#    --no-firewall       Skip the firewall
#    --no-ssh-hardening  Leave sshd_config alone
#    --no-upgrade        Skip `apk upgrade`
#    --no-test           Skip the hello-world self-test
#    --yes               Non-interactive (no prompts, no firewall rollback timer)
#    --check             Preflight only, change nothing
#    -h, --help          Show this help
#
#  Day-to-day:
#    doas docker ps                      doas docker compose up -d
#    rc-service docker status|restart    tail -f /var/log/docker.log
#    rc-service host-firewall reload     doas nft list table inet host_fw
#    avahi-browse -at                    (list mDNS hosts on the LAN)
# =============================================================================

set -eu
# shellcheck disable=SC3040
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
umask 022

MIN_ALPINE="3.18"
FW_FILE="/etc/host-firewall.nft"
FW_SVC="host-firewall"
DOCKER_LOG="/var/log/docker.log"

ADMIN_USER="${ADMIN_USER:-}"
LAN_CIDRS="${LAN_CIDRS:-}"
SSH_PORT="${SSH_PORT:-22}"
HOST_PORTS="${HOST_PORTS:-}"
LAN_IFACE="${LAN_IFACE:-}"
DO_MDNS=1; DO_FIREWALL=1; DO_SSH=1; DO_UPGRADE=1; DO_TEST=1
ASSUME_YES=0; CHECK_ONLY=0; NEED_REBOOT=0
CURRENT_STEP="init"; TCP_PORTS=""; UDP_PORTS=""

# ---------- output -----------------------------------------------------------
if [ -t 1 ]; then
    C_B='\033[1m'; C_G='\033[32m'; C_Y='\033[33m'; C_R='\033[31m'; C_0='\033[0m'
else
    C_B=''; C_G=''; C_Y=''; C_R=''; C_0=''
fi
step() { CURRENT_STEP="$*"; printf '%b==>%b %s\n' "$C_B" "$C_0" "$*"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %b✓%b %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '    %b!%b %s\n' "$C_Y" "$C_0" "$*" >&2; }
die()  { printf '%bERROR:%b %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

on_exit() {
    rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '%bFailed during:%b %s (exit %s). Fix the cause and re-run; the script is idempotent.\n' \
            "$C_R" "$C_0" "$CURRENT_STEP" "$rc" >&2
    fi
}
trap on_exit EXIT

usage() { awk '/^#  Usage:/{f=1} f&&/^# =====/{exit} f{sub(/^# ?/,"");print}' "$0"; exit 0; }

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ -t 0 ] || die "Need confirmation for: $1 (use --yes when non-interactive)"
    printf '%s [y/N] ' "$1"
    read -r ans || ans=""
    case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

backup() {  # backup FILE — once per run, timestamped
    [ -f "$1" ] && cp -p "$1" "$1.bak.$(date +%Y%m%d%H%M%S)"
    return 0
}

# ---------- arguments --------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --admin)            ADMIN_USER="${2:?--admin needs a value}"; shift 2 ;;
        --lan)              LAN_CIDRS="${2:?--lan needs a value}"; shift 2 ;;
        --ssh-port)         SSH_PORT="${2:?--ssh-port needs a value}"; shift 2 ;;
        --ports)            HOST_PORTS="${2:?--ports needs a value}"; shift 2 ;;
        --iface)            LAN_IFACE="${2:?--iface needs a value}"; shift 2 ;;
        --no-mdns)          DO_MDNS=0; shift ;;
        --no-firewall)      DO_FIREWALL=0; shift ;;
        --no-ssh-hardening) DO_SSH=0; shift ;;
        --no-upgrade)       DO_UPGRADE=0; shift ;;
        --no-test)          DO_TEST=0; shift ;;
        --yes|-y)           ASSUME_YES=1; shift ;;
        --check)            CHECK_ONLY=1; shift ;;
        -h|--help)          usage ;;
        *)                  die "Unknown option: $1 (see --help)" ;;
    esac
done

# ---------- validation -------------------------------------------------------
is_port()   { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
is_cidr4()  { printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$'; }
is_iface()  { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9_.:-]{1,15}$'; }
version_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n | head -n1)" = "$2" ]; }
user_home() { awk -F: -v u="$1" '$1==u{print $6}' /etc/passwd; }

parse_ports() {
    [ -n "$HOST_PORTS" ] || return 0
    for p in $(printf '%s' "$HOST_PORTS" | tr ',' ' '); do
        num="${p%/*}"; proto="tcp"
        [ "$num" != "$p" ] && proto="${p#*/}"
        is_port "$num" || die "Invalid port in --ports: $p"
        case "$proto" in
            tcp) TCP_PORTS="${TCP_PORTS:+$TCP_PORTS, }$num" ;;
            udp) UDP_PORTS="${UDP_PORTS:+$UDP_PORTS, }$num" ;;
            *)   die "Invalid protocol in --ports: $p (tcp|udp)" ;;
        esac
    done
}

# ---------- 1. preflight -----------------------------------------------------
preflight() {
    step "Preflight checks"
    [ "$(id -u)" -eq 0 ] || die "Run as root:  doas sh $0   (or from a root shell: su -)"
    [ -f /etc/alpine-release ] || die "This script only supports Alpine Linux"
    ver="$(cut -d. -f1,2 /etc/alpine-release)"
    case "$ver" in
        *_*) warn "Alpine $(cat /etc/alpine-release) (edge) — supported, less tested" ;;
        *)   version_ge "$ver" "$MIN_ALPINE" || die "Alpine $ver is too old (need >= $MIN_ALPINE)" ;;
    esac
    ok "Alpine $(cat /etc/alpine-release), $(uname -m), kernel $(uname -r)"

    if [ -f /.dockerenv ] || grep -qa 'container=' /proc/1/environ 2>/dev/null; then
        die "Running inside a container; run this on the host"
    fi
    command -v rc-service >/dev/null 2>&1 || die "OpenRC not found"

    exec 9>/run/alpine-docker-setup.lock
    flock -n 9 || die "Another instance is already running"

    is_port "$SSH_PORT" || die "Invalid --ssh-port: $SSH_PORT"
    parse_ports

    # LAN interface: the one carrying the default route
    if [ -z "$LAN_IFACE" ]; then
        LAN_IFACE="$(ip -4 route show default 2>/dev/null \
            | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
    fi
    [ -n "$LAN_IFACE" ] || die "No default route found — is the network up? (or pass --iface eth0)"
    is_iface "$LAN_IFACE" || die "Invalid interface: $LAN_IFACE"
    [ -e "/sys/class/net/$LAN_IFACE" ] || die "Interface $LAN_IFACE does not exist"
    ok "LAN interface: $LAN_IFACE"

    if [ "$DO_FIREWALL" -eq 1 ]; then
        if [ -z "$LAN_CIDRS" ]; then
            LAN_CIDRS="$(ip -4 route show dev "$LAN_IFACE" scope link 2>/dev/null \
                | awk '$1 ~ /\// {print $1}' | sort -u | tr '\n' ',' | sed 's/,$//')"
        fi
        [ -n "$LAN_CIDRS" ] || die "Could not detect the LAN subnet; pass --lan 192.168.1.0/24"
        for c in $(printf '%s' "$LAN_CIDRS" | tr ',' ' '); do
            is_cidr4 "$c" || die "Invalid CIDR in --lan: $c"
        done
        ok "LAN subnet(s): $LAN_CIDRS"
    fi

    # Admin user (for doas + SSH key checks)
    if [ -z "$ADMIN_USER" ]; then
        ADMIN_USER="$(awk -F: '$1=="wheel"{print $4}' /etc/group | tr ',' '\n' \
            | grep -vx root | grep -v '^$' | head -n1 || true)"
    fi
    if [ -n "$ADMIN_USER" ]; then
        id "$ADMIN_USER" >/dev/null 2>&1 || die "Admin user '$ADMIN_USER' does not exist"
        ok "Admin user: $ADMIN_USER"
    else
        warn "No admin user found (no non-root member of 'wheel'). Create one with: setup-user -a NAME"
    fi

    if [ "$DO_MDNS" -eq 1 ]; then
        hn="$(hostname)"
        case "$hn" in
            localhost|localhost.*) warn "Hostname is '$hn'; set a unique one first: setup-hostname NAME && rc-service hostname restart" ;;
        esac
        printf '%s' "${hn%%.*}" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$' \
            || warn "Hostname '$hn' is not a valid DNS label; the .local name may be mangled"
    fi

    if grep -Eq '^[^#]*http://' /etc/apk/repositories 2>/dev/null; then
        warn "Some apk repositories use plain http:// — consider https://"
    fi
}

# ---------- 2. leftovers from the earlier rootless script --------------------
cleanup_rootless() {
    found=0
    if [ -f /etc/init.d/docker-rootless ]; then
        found=1
        rc-service docker-rootless stop >/dev/null 2>&1 || true
        rc-update del docker-rootless default >/dev/null 2>&1 || true
        rm -f /etc/init.d/docker-rootless /etc/conf.d/docker-rootless /etc/logrotate.d/docker-rootless
    fi
    if [ -f /etc/nftables.nft ] && grep -q 'setup-docker-rootless' /etc/nftables.nft; then
        found=1
        rc-update del nftables default >/dev/null 2>&1 || true
        mv /etc/nftables.nft /etc/nftables.nft.rootless-old
        [ -f /usr/share/nftables/nftables.nft ] && cp /usr/share/nftables/nftables.nft /etc/nftables.nft
    fi
    rm -f /etc/modules-load.d/docker-rootless.conf /etc/sysctl.d/90-docker-rootless.conf
    if [ "$found" -eq 1 ]; then
        step "Removed leftovers from the rootless setup"
        info "Its data (user 'dockeruser', ~/.local/share/docker) was left in place; remove with: deluser --remove-home dockeruser"
    fi
}

# ---------- 3. packages ------------------------------------------------------
ensure_community_repo() {
    grep -Eq '^[^#]*/community/?$' /etc/apk/repositories && return 0
    main_line="$(grep -E '^[^#]*/main/?$' /etc/apk/repositories | head -n1)"
    [ -n "$main_line" ] || die "No 'main' repository in /etc/apk/repositories (run setup-apkrepos -c)"
    printf '%s/community\n' "${main_line%/main*}" >> /etc/apk/repositories
    ok "Enabled the community repository"
}

kernel_pkgs() { apk info -vv 2>/dev/null | grep -E '^linux-(lts|virt|edge|rpi)-[0-9]' || true; }

install_packages() {
    step "Installing packages"
    ensure_community_repo
    apk update --quiet
    if [ "$DO_UPGRADE" -eq 1 ]; then
        before="$(kernel_pkgs)"
        apk upgrade --quiet
        [ "$before" = "$(kernel_pkgs)" ] || { warn "Kernel upgraded — reboot when done"; NEED_REBOOT=1; }
    fi
    pkgs="docker docker-cli-compose docker-cli-buildx doas ca-certificates"
    [ "$DO_FIREWALL" -eq 1 ] && pkgs="$pkgs nftables"
    [ "$DO_MDNS" -eq 1 ] && pkgs="$pkgs dbus avahi avahi-tools"
    # shellcheck disable=SC2086
    apk add --quiet $pkgs
    ok "Installed: $pkgs"
}

# ---------- 4. kernel: cgroups + sysctl --------------------------------------
setup_kernel() {
    step "Kernel settings"
    if grep -Eq '^[[:space:]]*rc_cgroup_mode=' /etc/rc.conf; then
        if ! grep -Eq '^[[:space:]]*rc_cgroup_mode="?unified"?' /etc/rc.conf; then
            sed -i 's/^[[:space:]]*rc_cgroup_mode=.*/rc_cgroup_mode="unified"/' /etc/rc.conf
            NEED_REBOOT=1
        fi
    else
        printf 'rc_cgroup_mode="unified"\n' >> /etc/rc.conf
        [ -f /sys/fs/cgroup/cgroup.controllers ] || NEED_REBOOT=1
    fi
    rc-update add cgroups boot >/dev/null 2>&1 || true
    ok "cgroup v2 (unified) configured"

    cat > /etc/sysctl.d/90-hardening.conf <<'EOF'
# Managed by alpine-docker-setup.sh — compatible with Docker networking
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
net.ipv4.tcp_syncookies = 1
# loose reverse-path filtering (strict mode can break container traffic)
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
# ip_forward is left to Docker, which enables it for container networking
EOF
    rc-update add sysctl boot >/dev/null 2>&1 || true
    sysctl -q -p /etc/sysctl.d/90-hardening.conf >/dev/null 2>&1 \
        || warn "Some sysctl values could not be applied now (they apply at boot)"
    ok "sysctl hardening applied"
}

# ---------- 5. Docker --------------------------------------------------------
setup_userns() {
    step "User-namespace remapping (container root ≠ host root)"
    if ! id dockremap >/dev/null 2>&1; then
        addgroup -S dockremap 2>/dev/null || true
        adduser -S -D -H -h /nonexistent -s /sbin/nologin -G dockremap dockremap
        ok "Created system user 'dockremap'"
    fi
    for f in /etc/subuid /etc/subgid; do
        touch "$f"; chmod 644 "$f"
        if grep -q '^dockremap:' "$f"; then ok "$f: dockremap range present"; continue; fi
        start="$(awk -F: 'BEGIN{m=100000} {e=$2+$3; if (e>m) m=e} END{print m}' "$f")"
        printf 'dockremap:%s:65536\n' "$start" >> "$f"
        ok "$f: dockremap:$start:65536"
    done
}

write_daemon_json() {
    step "Writing /etc/docker/daemon.json"
    install -d -m 755 /etc/docker
    cfg=/etc/docker/daemon.json
    new="$(mktemp)"
    cat > "$new" <<'EOF'
{
  "userns-remap": "dockremap",
  "no-new-privileges": true,
  "icc": false,
  "live-restore": true,
  "log-driver": "local",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "features": { "buildkit": true },
  "experimental": false
}
EOF
    if [ -f "$cfg" ] && cmp -s "$new" "$cfg"; then
        rm -f "$new"; ok "Unchanged"; return 0
    fi
    backup "$cfg"
    mv "$new" "$cfg"; chmod 644 "$cfg"
    ok "userns-remap, no-new-privileges, icc off, live-restore, logs capped at 3×10 MB"
}

lock_docker_group() {
    members="$(awk -F: '$1=="docker"{print $4}' /etc/group)"
    if [ -n "$members" ]; then
        warn "'docker' group members ($members) effectively have root. Remove with: delgroup USER docker"
    fi
}

setup_doas() {
    [ -n "$ADMIN_USER" ] || return 0
    step "doas access for '$ADMIN_USER'"
    if ! id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx wheel; then
        addgroup "$ADMIN_USER" wheel
        warn "Added $ADMIN_USER to 'wheel' — log out and back in for it to apply"
    fi
    if grep -Eqs '^[[:space:]]*permit[^#]*:wheel' /etc/doas.conf /etc/doas.d/*.conf; then
        ok "doas rule for :wheel already present"
    else
        install -d -m 755 /etc/doas.d
        printf 'permit persist :wheel\n' > /etc/doas.d/20-wheel.conf
        chmod 0400 /etc/doas.d/20-wheel.conf
        doas -C /etc/doas.d/20-wheel.conf 2>/dev/null || true
        ok "Added /etc/doas.d/20-wheel.conf (permit persist :wheel)"
    fi
}

# ---------- 6. SSH -----------------------------------------------------------
harden_ssh() {
    [ "$DO_SSH" -eq 1 ] || return 0
    [ -f /etc/ssh/sshd_config ] || { info "OpenSSH not installed — skipping SSH hardening"; return 0; }
    step "Hardening SSH"
    grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
        || { backup /etc/ssh/sshd_config; sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config; }
    install -d -m 755 /etc/ssh/sshd_config.d

    has_key=0
    if [ -n "$ADMIN_USER" ]; then
        ak="$(user_home "$ADMIN_USER")/.ssh/authorized_keys"
        grep -Eqs '^(ssh-|ecdsa-|sk-)' "$ak" && has_key=1
    fi

    conf=/etc/ssh/sshd_config.d/10-hardening.conf
    {
        echo "# Managed by alpine-docker-setup.sh"
        if [ -n "$ADMIN_USER" ]; then echo "PermitRootLogin no"; else echo "PermitRootLogin prohibit-password"; fi
        if [ "$has_key" -eq 1 ]; then
            echo "PasswordAuthentication no"
            echo "KbdInteractiveAuthentication no"
        fi
        echo "PermitEmptyPasswords no"
        echo "MaxAuthTries 3"
        echo "LoginGraceTime 30"
        echo "X11Forwarding no"
        echo "ClientAliveInterval 300"
        echo "ClientAliveCountMax 2"
    } > "$conf.new"
    if ! sshd -t -f /etc/ssh/sshd_config 2>/dev/null; then
        rm -f "$conf.new"; warn "Existing sshd config is invalid; skipping SSH hardening"; return 0
    fi
    [ -f "$conf" ] && cp -p "$conf" "$conf.prev"
    mv "$conf.new" "$conf"
    if sshd -t 2>/dev/null; then
        rc-service sshd reload >/dev/null 2>&1 || rc-service sshd restart >/dev/null 2>&1 || true
        rm -f "$conf.prev"
        ok "Root login off$([ "$has_key" -eq 1 ] && echo ", password login off (key found)")"
        [ "$has_key" -eq 1 ] || warn "No SSH key for $ADMIN_USER yet — passwords still allowed. Add one with ssh-copy-id, then re-run."
    else
        if [ -f "$conf.prev" ]; then mv "$conf.prev" "$conf"; else rm -f "$conf"; fi
        warn "sshd rejected the hardening drop-in; reverted"
    fi
}

# ---------- 7. mDNS ----------------------------------------------------------
setup_mdns() {
    [ "$DO_MDNS" -eq 1 ] || return 0
    step "mDNS: announcing $(hostname).local on $LAN_IFACE"
    conf=/etc/avahi/avahi-daemon.conf
    grep -qs 'Managed by alpine-docker-setup.sh' "$conf" || backup "$conf"
    cat > "$conf" <<EOF
# Managed by alpine-docker-setup.sh
[server]
use-ipv4=yes
use-ipv6=yes
# Only the LAN NIC — never Docker bridges or veth interfaces
allow-interfaces=$LAN_IFACE
enable-dbus=yes
disallow-other-stacks=yes
ratelimit-interval-usec=1000000
ratelimit-burst=1000

[wide-area]
enable-wide-area=no

[publish]
publish-addresses=yes
publish-domain=yes
# Don't advertise OS/CPU details or a workstation service
publish-hinfo=no
publish-workstation=no

[reflector]
enable-reflector=no

[rlimits]
rlimit-core=0
rlimit-data=8388608
rlimit-fsize=0
rlimit-nofile=768
rlimit-stack=8388608
rlimit-nproc=3
EOF
    chmod 644 "$conf"
    rc-update add dbus default >/dev/null 2>&1 || true
    rc-update add avahi-daemon default >/dev/null 2>&1 || true
    rc-service dbus start >/dev/null 2>&1 || true
    rc-service avahi-daemon restart >/dev/null 2>&1 || rc-service avahi-daemon start \
        || die "avahi-daemon failed to start (see: tail /var/log/messages)"
    ok "dbus + avahi-daemon running and enabled at boot"
}

# ---------- 8. firewall ------------------------------------------------------
write_firewall_rules() {
    lan4="$(printf '%s' "$LAN_CIDRS" | sed 's/,/, /g')"
    # shellcheck disable=SC2016  # $LAN4/$LAN6 below are nft variables
    {
        cat <<EOF
#!/usr/sbin/nft -f
# Managed by alpine-docker-setup.sh — loaded by the '$FW_SVC' service.
# Lives in its own table, so Docker's own iptables/nft rules are never touched.
# An accept here does not override Docker; a drop here does (both must pass).

define LAN4 = { $lan4 }
define LAN6 = { fe80::/10, fc00::/7 }

# Idempotent reload: create-if-missing, delete, recreate
table inet host_fw
delete table inet host_fw

table inet host_fw {
    chain input {
        type filter hook input priority filter; policy drop;

        ct state established,related accept
        ct state invalid drop
        iif "lo" accept

        # ICMP / ICMPv6 essentials (PMTU, neighbour discovery), rate-limited ping
        ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
        ip protocol icmp icmp type echo-request limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
        ip6 nexthdr icmpv6 icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
        ip6 saddr fe80::/10 icmpv6 type mld-listener-query accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 5/second accept

        # DHCP / DHCPv6 client replies
        udp sport 67 udp dport 68 accept
        ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept

        # SSH from LAN only, throttled
        ip saddr \$LAN4 tcp dport $SSH_PORT ct state new limit rate 15/minute accept
        ip6 saddr \$LAN6 tcp dport $SSH_PORT ct state new limit rate 15/minute accept
EOF
        if [ "$DO_MDNS" -eq 1 ]; then
            printf '\n        # mDNS (Avahi) from LAN only\n'
            printf '        ip saddr $LAN4 udp dport 5353 accept\n'
            printf '        ip6 saddr $LAN6 udp dport 5353 accept\n'
        fi
        if [ -n "$TCP_PORTS" ]; then
            printf '\n        # Host services (TCP) from LAN\n'
            printf '        ip saddr $LAN4 tcp dport { %s } accept\n' "$TCP_PORTS"
            printf '        ip6 saddr $LAN6 tcp dport { %s } accept\n' "$TCP_PORTS"
        fi
        if [ -n "$UDP_PORTS" ]; then
            printf '\n        # Host services (UDP) from LAN\n'
            printf '        ip saddr $LAN4 udp dport { %s } accept\n' "$UDP_PORTS"
            printf '        ip6 saddr $LAN6 udp dport { %s } accept\n' "$UDP_PORTS"
        fi
        cat <<'EOF'

        counter comment "dropped inbound"
    }

    chain forward {
        # Filters container traffic. Docker publishes ports with DNAT, so they
        # pass through here instead of 'input' — this is where they get LAN-only.
        type filter hook forward priority filter; policy drop;

        ct state established,related accept
        ct state invalid drop

        # Containers may reach the internet, the LAN and each other
        iifname "docker0" accept
        iifname "br-*" accept

        # Published container ports: LAN clients only
        ct status dnat ip saddr $LAN4 accept

        counter comment "dropped forward"
    }
}
EOF
    } > "$1"
}

install_firewall_service() {
    cat > "/etc/init.d/$FW_SVC" <<EOF
#!/sbin/openrc-run
# Managed by alpine-docker-setup.sh
description="Host firewall (own nftables table; leaves Docker's rules alone)"
extra_started_commands="reload"

depend() {
    before net docker
}

start() {
    ebegin "Loading $FW_FILE"
    nft -f "$FW_FILE"
    eend \$?
}

reload() {
    ebegin "Reloading $FW_FILE"
    nft -f "$FW_FILE"
    eend \$?
}

stop() {
    ebegin "Removing host firewall table"
    nft delete table inet host_fw 2>/dev/null
    eend 0
}
EOF
    chmod 755 "/etc/init.d/$FW_SVC"
}

setup_firewall() {
    [ "$DO_FIREWALL" -eq 1 ] || return 0
    step "Firewall (nftables table 'inet host_fw')"

    # Alpine's stock 'nftables' service runs 'flush ruleset', which would wipe
    # Docker's rules. Our own service only touches its own table.
    if rc-update show default 2>/dev/null | grep -qw nftables; then
        rc-update del nftables default >/dev/null 2>&1 || true
        warn "Disabled the stock 'nftables' service (its 'flush ruleset' breaks Docker)"
    fi
    for svc in iptables ip6tables awall ufw; do
        rc-update show 2>/dev/null | grep -qw "$svc" \
            && warn "Service '$svc' is enabled; it may conflict — consider: rc-update del $svc"
    done

    new="$FW_FILE.new"
    write_firewall_rules "$new"
    nft -c -f "$new" || die "Generated rules failed validation: $new"
    ok "Rules validated"

    had_old=0
    if [ -f "$FW_FILE" ]; then had_old=1; cp -p "$FW_FILE" "$FW_FILE.prev"; fi
    mv "$new" "$FW_FILE"; chmod 600 "$FW_FILE"
    install_firewall_service
    nft -f "$FW_FILE"

    # Anti-lockout: over SSH + interactive, require confirmation within 60s
    if [ -n "${SSH_CONNECTION:-}" ] && [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ]; then
        warn "Firewall is live. If this SSH session still responds, type 'yes' within 60s:"
        ans=""
        # shellcheck disable=SC3045  # BusyBox ash supports read -t
        read -r -t 60 ans || true
        if [ "$ans" != "yes" ]; then
            if [ "$had_old" -eq 1 ]; then
                mv "$FW_FILE.prev" "$FW_FILE"; nft -f "$FW_FILE" || nft delete table inet host_fw 2>/dev/null || true
            else
                nft delete table inet host_fw 2>/dev/null || true; rm -f "$FW_FILE"
            fi
            die "No confirmation — firewall rolled back. Check --lan ($LAN_CIDRS) / --ssh-port and retry."
        fi
    fi
    rm -f "$FW_FILE.prev"
    rc-update add "$FW_SVC" default >/dev/null 2>&1 || true
    rc-service --ifstopped "$FW_SVC" start >/dev/null 2>&1 || true
    rc-service "$FW_SVC" status >/dev/null 2>&1 || rc-service "$FW_SVC" start >/dev/null 2>&1 || true
    ok "Firewall active, loads at boot before Docker"
}

# ---------- 9. start Docker & verify ----------------------------------------
show_docker_log() {
    printf '\n%b--- last 40 lines of %s ---%b\n' "$C_Y" "$DOCKER_LOG" "$C_0" >&2
    tail -n 40 "$DOCKER_LOG" 2>/dev/null >&2 || echo "(no log yet)" >&2
    printf '%b--- end ---%b\n\n' "$C_Y" "$C_0" >&2
}

start_docker() {
    step "Starting Docker"
    rc-update add docker default >/dev/null 2>&1 || true
    if rc-service docker status >/dev/null 2>&1; then
        rc-service docker restart >/dev/null 2>&1 || { show_docker_log; die "Docker failed to restart"; }
    else
        rc-service docker start >/dev/null 2>&1 || { show_docker_log; die "Docker failed to start"; }
    fi
    i=0
    until docker info >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -le 30 ] || { show_docker_log; die "Docker did not become ready within 30s"; }
        sleep 1
    done
    ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) is running, enabled at boot"
}

verify() {
    step "Self-test"
    sec="$(docker info --format '{{range .SecurityOptions}}{{.}} {{end}}' 2>/dev/null)"
    case "$sec" in *userns*) ok "User-namespace remapping active" ;; *) warn "userns-remap NOT active: $sec" ;; esac
    ok "Compose $(docker compose version --short 2>/dev/null || echo '?'), Buildx $(docker buildx version 2>/dev/null | awk '{print $2}')"

    if [ "$DO_TEST" -eq 1 ]; then
        if docker run --rm hello-world >/dev/null 2>&1; then
            ok "docker run hello-world succeeded"
        else
            warn "hello-world failed (no internet? Docker Hub down?). Try: doas docker run --rm hello-world"
        fi
    fi
    if [ "$DO_MDNS" -eq 1 ]; then
        if out="$(timeout 5 avahi-resolve-host-name -4 "$(hostname).local" 2>/dev/null)" && [ -n "$out" ]; then
            ok "mDNS: $out"
        else
            warn "Could not self-resolve $(hostname).local yet; check: rc-service avahi-daemon status"
        fi
    fi
    if [ "$DO_FIREWALL" -eq 1 ]; then
        if nft list table inet host_fw >/dev/null 2>&1; then ok "Firewall table loaded"; else warn "Firewall table missing"; fi
    fi
}

summary() {
    printf '\n%bDone.%b\n' "$C_G" "$C_0"
    cat <<EOF
  Use Docker   : doas docker run --rm -p 8080:80 nginx   (no 'docker' group)
  Logs         : $DOCKER_LOG
  Config       : /etc/docker/daemon.json
EOF
    if [ "$DO_MDNS" -eq 1 ]; then
        echo "  Hostname     : $(hostname).local  (from other LAN devices)"
    fi
    if [ "$DO_FIREWALL" -eq 1 ]; then
        echo "  Firewall     : LAN $LAN_CIDRS → ssh/$SSH_PORT$([ "$DO_MDNS" -eq 1 ] && echo ', mDNS')${TCP_PORTS:+, tcp $TCP_PORTS}${UDP_PORTS:+, udp $UDP_PORTS}"
        echo "                 Published container ports: LAN only. Rules: $FW_FILE"
    fi
    cat <<'EOF'
  userns note  : container root maps to a high host uid. For bind mounts the
                 container must write to, chown the host dir to that uid
                 (see /etc/subuid), or set  userns_mode: "host"  per service.
EOF
    if [ "$DO_SSH" -eq 1 ] && [ -n "${SSH_CONNECTION:-}" ]; then
        printf '  %bSSH%b          : keep this session open and test a NEW login first.\n' "$C_Y" "$C_0"
    fi
    if [ "$NEED_REBOOT" -eq 1 ]; then
        printf '\n  %bReboot recommended%b (kernel / cgroup change):  doas reboot\n' "$C_Y" "$C_0"
    fi
}

# ---------- main -------------------------------------------------------------
main() {
    preflight
    if [ "$CHECK_ONLY" -eq 1 ]; then ok "Preflight passed (--check: nothing changed)"; exit 0; fi
    info "Will set up: Docker (hardened)$([ "$DO_FIREWALL" -eq 1 ] && echo ', firewall')$([ "$DO_MDNS" -eq 1 ] && echo ', mDNS')$([ "$DO_SSH" -eq 1 ] && echo ', SSH hardening')"
    confirm "Proceed?" || die "Aborted"

    cleanup_rootless
    install_packages
    setup_kernel
    setup_userns
    write_daemon_json
    lock_docker_group
    setup_doas
    harden_ssh
    setup_mdns
    setup_firewall
    start_docker
    verify
    summary
}

main
