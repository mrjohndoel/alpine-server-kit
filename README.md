# Alpine server kit

Unattended Alpine Linux install plus a post-install script that sets up hardened
Docker (with Compose and Buildx), an nftables firewall, mDNS (`<hostname>.local`)
and SSH hardening, for a home server behind NAT/CGNAT.

| File | Purpose |
|---|---|
| `answerfile` | Input for `setup-alpine -f`: disk, network, user, SSH, repos, timezone |
| `alpine-docker-setup.sh` | Post-install: Docker + firewall + Avahi + SSH; idempotent |
| `SHA256SUMS` | Checksums; verify before running anything |

## 1. Configure and publish

Edit the `CHANGE ME` lines in `answerfile`: hostname, admin user, SSH public key
(or `https://github.com/<you>.keys`), target disk. Then:

```sh
shasum -a 256 answerfile alpine-docker-setup.sh > SHA256SUMS   # macOS
git init -b main && git add -A && git commit -m "Alpine server kit"
gh repo create alpine-server-kit --public --source=. --push
git rev-parse HEAD   # use this hash below; never fetch from a branch
```

Re-run the `shasum` line and commit again after every edit.

## 2. Install (Alpine Standard ISO, logged in as root)

```sh
ip link set eth0 up && udhcpc -i eth0
B=https://raw.githubusercontent.com/<you>/alpine-server-kit/<commit-hash>
for f in answerfile alpine-docker-setup.sh SHA256SUMS; do wget -q "$B/$f"; done
sha256sum -c SHA256SUMS
setup-alpine -f answerfile        # asks for passwords + disk-erase confirmation
reboot
```

TLS error from `wget`? Fix the clock first: `ntpd -dnq -p pool.ntp.org`.

## 3. Post-install (on the installed system)

```sh
B=https://raw.githubusercontent.com/<you>/alpine-server-kit/<commit-hash>
for f in alpine-docker-setup.sh SHA256SUMS; do wget -q "$B/$f"; done
sha256sum -c SHA256SUMS --ignore-missing
doas sh alpine-docker-setup.sh --check   # preflight only
doas sh alpine-docker-setup.sh
```

`sh alpine-docker-setup.sh --help` lists options (`--ports`, `--lan`, `--iface`,
`--no-mdns`, `--no-firewall`, `--no-ssh-hardening`, `--yes`, …).

## What it hardens

- **Docker:** `userns-remap` (container root is an unprivileged host uid),
  `no-new-privileges`, `icc` off, `live-restore`, capped logs, nobody in the
  `docker` group; use `doas docker`.
- **Firewall:** its own `inet host_fw` table, loaded by the `host-firewall`
  service before Docker; it never flushes Docker's rules. Inbound is
  default-deny; SSH, mDNS and `--ports` are allowed from the LAN only.
  Published container ports are LAN-only, and global IPv6 is dropped.
  60-second rollback if you lose SSH.
- **mDNS:** Avahi on the LAN interface only; no host info, no reflector, no
  wide-area.
- **SSH:** no root login; password login turns off once your key is present.

## Notes

- With `userns-remap`, bind-mounted host folders a container writes to must be
  owned by the remapped uid (see `/etc/subuid`), or set `userns_mode: "host"`
  for that service.
- The Alpine host itself can't resolve *other* `.local` names with
  `ping`/`curl` (musl has no NSS); use `avahi-resolve -n name.local`.
- Never commit private keys, tokens or passwords; `.gitignore` blocks the
  common ones.
