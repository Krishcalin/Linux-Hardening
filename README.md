# Linux-Hardening

Operating System Security Hardening for Linux Distributions.

---

## Table of Contents

- [RHEL 8 Hardening Script](#rhel-8-hardening-script)
- [RHEL 9 Hardening Script](#rhel-9-hardening-script)
- [RHEL 8 vs RHEL 9 — Key Differences](#rhel-8-vs-rhel-9--key-differences)
- [Disclaimer](#disclaimer)

---

## RHEL 8 Hardening Script

A comprehensive, automated hardening script for **Red Hat Enterprise Linux 8** and compatible derivatives.

Aligned with the **CIS Red Hat Enterprise Linux 8 Benchmark v3.0**.

### Supported Distributions

| Distribution | Version |
|---|---|
| Red Hat Enterprise Linux | 8.x |
| CentOS Stream | 8 |
| AlmaLinux | 8.x |
| Rocky Linux | 8.x |

### Prerequisites

- Must be run as **root** (or via `sudo`)
- Active internet / yum repository access (for package removal)
- `authselect`, `update-crypto-policies`, `nmcli` available (standard on RHEL 8)

### Usage

```bash
sudo bash "RHEL8 Hardening Script"
```

Audit artefacts (backups and findings) are written to `/tmp/<hostname>_audit/`.

> **Important:** Reboot the host after the script completes to apply all kernel module, sysctl, and crypto-policy changes.

---

### What the Script Hardens

#### 1. Legacy Filesystems & Protocols
- Disables unused filesystems: `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `squashfs`, `vfat`, `udf`
- Disables unused network protocols: `dccp`, `sctp`, `rds`, `tipc`
- Disables USB storage (`usb-storage`)

#### 2. Package Removal
- Removes GCC compiler toolchain
- Removes legacy services: `rsh`, `ypserv`, `tftp`, `talk`, `telnet-server`, `xinetd`
- Removes LDAP server/client packages
- Removes `bind`, `vsftpd`, `dovecot`, `samba`, `squid`, `net-snmp`

#### 3. Service Hardening
- Disables unnecessary services: `dhcpd`, `avahi-daemon`, `cups`, `nfslock`, `rpcgssd`, `rpcbind`, `rpcidmapd`, `rpcsvcgssd`
- Daemon umask set to `027`

#### 4. Password Quality (CIS 5.4.1)
- `minlen = 14`, `dcredit = -1`, `ucredit = -1`, `ocredit = -1`, `lcredit = -1`
- `retry = 3`, `maxrepeat = 3`
- Configured via `/etc/security/pwquality.conf`

#### 5. Logging & Auditing (CIS 4.x)
- Enables and configures `auditd` with log rotation (`max_log_file=50`, `num_logs=5`)
- Configures `journald`: persistent storage, compression, syslog forwarding
- Configures `rsyslog` with correct `auth,authpriv.*` facility rules and `0640` file permissions
- Audit rules cover:
  - Time changes, identity file modifications, network/locale changes
  - Login/session events, permission and ownership changes
  - Unsuccessful file access attempts, mount/unmount events, file deletions
  - sudo/sudoers changes, kernel module operations, SELinux MAC policy
  - Privileged command execution (`passwd`, `sudo`, `su`, `chage`, `newgrp`, `chsh`)
  - Power/shutdown events via `systemctl`
- Audit buffer set to **8192** (production-grade)

#### 6. Cron (CIS 5.1)
- Installs `cronie-anacron`, enables `crond`
- Sets `root:root` ownership and restrictive permissions (`600`/`700`) on all cron directories and files
- Creates `/etc/at.allow` and `/etc/cron.allow`; removes `.deny` files

#### 7. SSH Hardening (CIS 5.2)
- Disables `X11Forwarding`, `HostbasedAuthentication`, `PermitRootLogin`, `PermitEmptyPasswords`, `PermitUserEnvironment`
- Disables `AllowTcpForwarding`, `AllowAgentForwarding`, `GatewayPorts`
- `MaxAuthTries 4`, `ClientAliveInterval 300`, `ClientAliveCountMax 0`, `LoginGraceTime 60`
- `LogLevel VERBOSE`, `PrintLastLog yes`, `TCPKeepAlive no`
- Strong **Ciphers**: `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm`, `aes256-ctr`, `aes192-ctr`, `aes128-ctr`
- Strong **MACs** (ETM preferred): `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `hmac-sha2-512`, `hmac-sha2-256`
- Modern **KexAlgorithms**: `curve25519-sha256`, `ecdh-sha2-nistp521/384/256`, `diffie-hellman-group16/18-sha512`
- Validates config with `sshd -t` before restarting — prevents lockout
- Sets `root:root 600` on `/etc/ssh/sshd_config`
- Configures login banner in `/etc/issue.net` and `/etc/motd`

#### 8. Kernel & Network Parameters (CIS 1.x, 3.x)
Applied via `/etc/sysctl.d/99-CIS.conf` and loaded immediately with `sysctl --system`:

| Parameter | Value | Purpose |
|---|---|---|
| `kernel.randomize_va_space` | `2` | Full ASLR |
| `kernel.kptr_restrict` | `2` | Hide kernel pointers |
| `kernel.dmesg_restrict` | `1` | Restrict dmesg to root |
| `kernel.yama.ptrace_scope` | `1` | Restrict ptrace |
| `kernel.perf_event_paranoid` | `3` | Restrict perf events |
| `kernel.sysrq` | `0` | Disable magic SysRq |
| `fs.suid_dumpable` | `0` | No core dumps from setuid |
| `fs.protected_hardlinks` | `1` | Protect hard links |
| `fs.protected_symlinks` | `1` | Protect symbolic links |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood protection |
| `net.ipv4.conf.all.rp_filter` | `1` | Reverse path filtering |
| `net.ipv4.conf.all.log_martians` | `1` | Log martian packets |
| `net.ipv6.conf.all.disable_ipv6` | `1` | Disable IPv6 |

#### 9. IPv6 Disable
- Disables IPv6 via sysctl, `/etc/sysconfig/network`, and kernel module (`modprobe.d/ipv6.conf`)

#### 10. Wireless (CIS 3.7)
- Disables all wireless interfaces via `nmcli radio all off`

#### 11. PAM / Faillock (CIS 5.4.2)
- Enables `with-faillock` feature via `authselect`

#### 12. System-Wide Crypto Policy (CIS 1.11)
- Sets policy to `FUTURE` via `update-crypto-policies`

#### 13. su Restriction (CIS 5.6)
- Restricts `su` to members of the `wheel` group via `pam_wheel.so`
- Adds `root` to `wheel`

#### 14. User Defaults (CIS 5.4.4, 5.4.5)
- Default umask `027` in `/etc/bashrc`, `/etc/profile`, and `/etc/profile.d/CIS-umask.sh`
- `HISTSIZE=10000`, `HISTTIMEFORMAT`, `HISTCONTROL=ignoredups:ignorespace`
- Inactive account lock after 30 days (`useradd -D -f 30`)
- `/etc/login.defs`: `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 7`, `PASS_WARN_AGE 7`, `UID_MIN 1000`

#### 15. File Permissions (CIS 6.1)
- `/etc/passwd 644`, `/etc/shadow 000`, `/etc/gshadow 000`, `/etc/group 644`
- `/boot/grub2/grub.cfg 600` (BIOS) and `/boot/efi/EFI/redhat/grub.cfg 600` (EFI)
- `/etc/rsyslog.conf 600`
- Sticky bit applied to all world-writable directories

#### 16. Audit Reports Generated (informational only)
The following findings are logged to `$AUDITDIR` for manual review — the script does **not** auto-remediate these:

- World-writable files
- Un-owned and un-grouped files
- SUID / SGID executables
- Empty password fields
- Home directory permissions and ownership
- Dot-file permissions
- `.netrc`, `.rhosts`, and `.forward` file presence
- Duplicate UIDs, GIDs, usernames, and group names
- Groups referenced in `/etc/passwd` but missing from `/etc/group`
- Accounts with reserved UIDs that are not standard system accounts
- root PATH integrity (empty entries, trailing colons, group/other-writable dirs)

### Audit Artefact Location (RHEL 8)

All backups and findings are written to `/tmp/<hostname>_audit/`.

| File | Contents |
|---|---|
| `sshd_config_<timestamp>.bak` | SSH config backup |
| `auditd.conf_<timestamp>.bak` | auditd config backup |
| `sysctl.conf_<timestamp>.bak` | sysctl backup |
| `service_remove_<timestamp>.log` | Package removal output |
| `audit_<timestamp>.log` | User/group integrity findings |
| `suid_exec_<timestamp>.log` | SUID executables found |
| `sgid_exec_<timestamp>.log` | SGID executables found |
| `world_writable_files_<timestamp>.log` | World-writable files |
| `home_permission_<timestamp>.log` | Home directory permission issues |

---

## RHEL 9 Hardening Script

A comprehensive, automated hardening script for **Red Hat Enterprise Linux 9** and compatible derivatives.

Aligned with the **CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0**.

### Supported Distributions

| Distribution | Version |
|---|---|
| Red Hat Enterprise Linux | 9.x |
| AlmaLinux | 9.x |
| Rocky Linux | 9.x |

### Prerequisites

- Must be run as **root** (or via `sudo`)
- Active internet / dnf repository access (for package installation and removal)
- `authselect`, `update-crypto-policies`, `nmcli`, `nft` available (standard on RHEL 9)

### Usage

```bash
sudo bash "RHEL9 Hardening Script"
```

Audit artefacts (backups and findings) are written to `/tmp/<hostname>_audit/`.

> **Important:** Reboot the host after the script completes to apply all kernel module, sysctl, crypto-policy, and IPv6 disable changes.

---

### What the Script Hardens

#### 1. Legacy Filesystems & Protocols (CIS 1.1.1, 3.4)
- Disables unused filesystems: `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `squashfs`, `udf`
- **Note:** `vfat` is intentionally left enabled — RHEL 9 requires it for the EFI System Partition
- Disables unused network protocols: `dccp`, `sctp`, `rds`, `tipc`
- Disables USB storage (`usb-storage`) via `modprobe.d`

#### 2. Package Removal (CIS 2.x)
- Removes GCC/make/autoconf compiler toolchain
- Removes legacy services: `rsh`, `ypserv`, `tftp`, `talk`, `telnet-server`, `xinetd`
- Removes LDAP server/client packages
- Removes `bind`, `vsftpd`, `dovecot`, `samba`, `squid`, `net-snmp`, `sendmail`, `postfix`, `xorg-x11-server`
- Each package removal is tolerant of packages already absent — script does not abort

#### 3. Security Package Installation (CIS 1.3, 1.7, 1.9, 4.1, 4.2)
Installs the following security packages if not already present:

| Package | CIS Control | Purpose |
|---|---|---|
| `aide` | CIS 1.3.1 | Host-based file integrity monitoring |
| `fapolicyd` | CIS 1.7 | Application allowlisting |
| `usbguard` | CIS 1.1.1.8 | USB device policy enforcement |
| `dnf-automatic` | CIS 1.9 | Automatic security-only updates |
| `nftables` | CIS 3.5 | Stateful packet filtering firewall |
| `audit` | CIS 4.1 | Kernel audit daemon |
| `rsyslog` | CIS 4.2 | System event logging |
| `chrony` | CIS 2.1.2 | NTP time synchronisation |
| `libpwquality` | CIS 5.4 | Password complexity enforcement |

#### 4. DNF Package Manager Hardening (CIS 1.2)
- `gpgcheck=1` and `localpkg_gpgcheck=1` enforced in `/etc/dnf/dnf.conf`
- `clean_requirements_on_remove=true` to avoid orphaned packages
- All `.repo` files scanned and `gpgcheck=0` entries corrected to `gpgcheck=1`

#### 5. Automatic Security Updates (CIS 1.9)
- `dnf-automatic` configured for **security-only** updates
- `apply_updates=yes` — patches applied automatically
- Timer unit enabled: `dnf-automatic.timer`

#### 6. Service Hardening (CIS 2.1)
- Disables unnecessary services: `dhcpd`, `avahi-daemon`, `cups`, `nfslock`, `rpcgssd`, `rpcbind`, `rpcidmapd`, `rpcsvcgssd`, `bluetooth`, `autofs`, `nfs-server`, `nis`, `kdump`
- Daemon umask set to `027`

#### 7. NTP / Chrony (CIS 2.1.2)
- `cmddeny all` — restricts chrony management queries
- `cmdallow 127.0.0.1` — permits local management only
- chrony daemon runs as the unprivileged `chrony` user

#### 8. Password Quality (CIS 5.4.1)
- Written to drop-in `/etc/security/pwquality.conf.d/CIS.conf` (RHEL 9 native approach)
- `minlen=14`, `dcredit=-1`, `ucredit=-1`, `ocredit=-1`, `lcredit=-1`
- `retry=3`, `maxrepeat=3`, `difok=8`, `gecoscheck=1`

#### 9. Faillock / PAM (CIS 5.4.2)
- Configured via `/etc/security/faillock.conf`: `deny=5`, `unlock_time=900`, `fail_interval=900`
- Applied via `authselect select sssd --force` + `enable-feature with-faillock`

#### 10. Journald (CIS 4.2.2)
- Persistent storage, compression enabled, forwarding to syslog

#### 11. Core Dump Restriction (CIS 1.5.1)
- `* hard core 0` set in `/etc/security/limits.conf`
- `Storage=none` and `ProcessSizeMax=0` set in `/etc/systemd/coredump.conf`
- Combined with `fs.suid_dumpable=0` via sysctl

#### 12. Rsyslog (CIS 4.2.1)
- `auth,authpriv.*` → `/var/log/secure`
- `kern.*`, `daemon.*`, `syslog.*` → `/var/log/messages`
- `*.emerg` → broadcast to all logged-in users
- File create mode set to `0640`

#### 13. Auditd (CIS 4.1)
- `max_log_file=50`, `num_logs=5`, log rotation set to `keep_logs`
- `space_left_action=email`, `admin_space_left_action=halt`
- `log_format=ENRICHED` — structured enriched event format (new in RHEL 9)
- Audit rules cover:
  - Time changes, identity file modifications, network/locale changes
  - Login/session events including `/run/faillock/` (RHEL 9 faillock directory)
  - Permission and ownership changes, unsuccessful file access
  - Mount events, file deletions
  - sudo/sudoers and `/etc/sudoers.d/` changes
  - Kernel module operations including `finit_module` syscall
  - SELinux MAC policy and `/usr/share/selinux/`
  - Extended privileged command set: `passwd`, `sudo`, `su`, `chage`, `newgrp`, `chsh`, `chfn`, `gpasswd`, `usermod`, `useradd`, `userdel`
  - Power/shutdown via `systemctl`
  - fapolicyd policy directory `/etc/fapolicyd/`
- Audit buffer: **8192**; failure mode: **2** (panic on loss)

#### 14. Cron (CIS 5.1)
- Installs `cronie`, enables `crond`
- `root:root` ownership and `600`/`700` permissions on all cron files and directories
- `/etc/at.allow` and `/etc/cron.allow` created; `.deny` files removed

#### 15. Login Banner (CIS 1.7)
- Legal warning written to `/etc/issue.net` and `/etc/motd`
- `/etc/issue` symlinked to `/etc/issue.net`
- Banner path referenced in SSH drop-in config

#### 16. SSH Hardening (CIS 5.2)
RHEL 9 uses the **drop-in directory** approach. All settings are written to `/etc/ssh/sshd_config.d/50-CIS-hardening.conf` rather than editing the main `sshd_config` directly.

Authentication & session controls:

| Setting | Value |
|---|---|
| `PermitRootLogin` | `no` |
| `PermitEmptyPasswords` | `no` |
| `PermitUserEnvironment` | `no` |
| `HostbasedAuthentication` | `no` |
| `IgnoreRhosts` | `yes` |
| `MaxAuthTries` | `4` |
| `LoginGraceTime` | `60` |
| `ClientAliveInterval` | `300` |
| `ClientAliveCountMax` | `0` |
| `MaxStartups` | `10:30:60` |
| `TCPKeepAlive` | `no` |
| `AllowTcpForwarding` | `no` |
| `AllowAgentForwarding` | `no` |
| `GatewayPorts` | `no` |
| `X11Forwarding` | `no` |
| `LogLevel` | `VERBOSE` |
| `SyslogFacility` | `AUTHPRIV` |

Cryptographic settings:

| Setting | Algorithms |
|---|---|
| `Ciphers` | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes192-ctr`, `aes128-ctr` |
| `MACs` | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512`, `hmac-sha2-256` |
| `KexAlgorithms` | `curve25519-sha256`, `curve25519-sha256@libssh.org`, `diffie-hellman-group16/18-sha512`, `ecdh-sha2-nistp521/384/256` |

- Config validated with `sshd -t` before restart — prevents SSH lockout

#### 17. Kernel & Network Parameters (CIS 1.x, 3.x)
Applied via `/etc/sysctl.d/99-CIS.conf`:

| Parameter | Value | Purpose |
|---|---|---|
| `kernel.randomize_va_space` | `2` | Full ASLR |
| `kernel.kptr_restrict` | `2` | Hide kernel symbol addresses |
| `kernel.dmesg_restrict` | `1` | Restrict dmesg to root |
| `kernel.yama.ptrace_scope` | `2` | Restrict ptrace to parent only |
| `kernel.perf_event_paranoid` | `3` | Restrict perf events |
| `kernel.sysrq` | `0` | Disable magic SysRq |
| `fs.suid_dumpable` | `0` | No core dumps from setuid |
| `fs.protected_hardlinks` | `1` | Protect hard links |
| `fs.protected_symlinks` | `1` | Protect symbolic links |
| `fs.protected_fifos` | `2` | Protect FIFOs (RHEL 9) |
| `fs.protected_regular` | `2` | Protect regular files (RHEL 9) |
| `user.max_user_namespaces` | `0` | Disable unprivileged user namespaces |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood protection |
| `net.ipv4.conf.all.rp_filter` | `1` | Reverse path filtering |
| `net.ipv4.conf.all.log_martians` | `1` | Log martian packets |
| `net.ipv6.conf.all.disable_ipv6` | `1` | Disable IPv6 |

> **Container hosts:** Review `user.max_user_namespaces=0` — container runtimes (Podman, Docker) may require a value greater than `0`.

#### 18. IPv6 Disable (CIS 3.1.2)
- Disabled via sysctl (`net.ipv6.conf.*.disable_ipv6=1`)
- `options ipv6 disable=1` written to `/etc/modprobe.d/ipv6.conf`

#### 19. Firewall — nftables (CIS 3.5)
- `nftables` installed and enabled; `firewalld`, `iptables`, `ip6tables` disabled to prevent conflicts
- Default-deny stateful ruleset written to `/etc/nftables/main.nft`:
  - Loopback traffic accepted
  - Invalid packets dropped
  - Established/related connections accepted
  - ICMP/ICMPv6 rate-limited (10/second)
  - SSH (port 22) accepted for new connections
  - All other inbound traffic logged and dropped
  - Outbound traffic accepted by default

> **Review required:** Open only the ports your workload actually needs. Edit `/etc/nftables/main.nft` before production deployment.

#### 20. Wireless (CIS 3.1.2)
- All wireless interfaces disabled via `nmcli radio all off`

#### 21. Crypto Policy (CIS 1.10)
- System-wide policy set to `FUTURE` via `update-crypto-policies`
- RHEL 9 `DEFAULT` policy already disables SHA-1; `FUTURE` additionally removes DH groups below 3072-bit and further restricts TLS

#### 22. su Restriction (CIS 5.6)
- `pam_wheel.so use_uid` enforced in `/etc/pam.d/su` (idempotent — removes duplicates before inserting)
- `root` added to `wheel` group

#### 23. Sudo Hardening (CIS 5.3)
- `Defaults requiretty` — sudo requires a real terminal
- `Defaults logfile="/var/log/sudo.log"` — all sudo commands logged
- `Defaults timestamp_timeout=0` — password required for every sudo invocation (no cached token)

#### 24. User Defaults (CIS 5.4.4, 5.4.5)
- Default umask `027` in `/etc/bashrc`, `/etc/profile`, and `/etc/profile.d/CIS-umask.sh`
- `HISTSIZE=10000`, `HISTTIMEFORMAT`, `HISTCONTROL=ignoredups:ignorespace`
- Inactive account lock after 30 days (`useradd -D -f 30`)
- `/etc/login.defs`: `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 7`, `PASS_WARN_AGE 7`, `UID_MIN 1000`
- `ENCRYPT_METHOD SHA512`, `SHA_CRYPT_MIN_ROUNDS 5000`

#### 25. File Permissions (CIS 6.1)
- `/etc/passwd 644`, `/etc/shadow 000`, `/etc/gshadow 000`, `/etc/group 644`
- BIOS: `/boot/grub2/grub.cfg 600`
- EFI: `/boot/efi/EFI/redhat/grub.cfg`, `/boot/efi/EFI/almalinux/grub.cfg`, `/boot/efi/EFI/rocky/grub.cfg` all `600`
- `/etc/rsyslog.conf 600`
- Sticky bit applied to all world-writable directories

#### 26. AIDE — File Integrity (CIS 1.3.1)
- AIDE database initialised at `/var/lib/aide/aide.db.gz`
- Daily integrity check scheduled via `/etc/cron.daily/aide`
- Check results emailed to `root`

#### 27. fapolicyd — Application Allowlisting (CIS 1.7)
- Trust database regenerated with `fagenrules --load`
- `fapolicyd` service enabled and started
- Policy changes audited via audit rule on `/etc/fapolicyd/`

#### 28. USBGuard — USB Device Control (CIS 1.1.1.8)
- Policy auto-generated from currently connected devices (`usbguard generate-policy`)
- Policy written to `/etc/usbguard/rules.conf` with `600` permissions
- `usbguard` service enabled and started

#### 29. Audit Reports Generated (informational only)
Findings written to `$AUDITDIR` for manual review:

- World-writable files
- Un-owned and un-grouped files
- SUID / SGID executables
- Empty password fields
- Home directory existence and ownership (UID ≥ 1000)
- Dot-file permissions (group/other-writable)
- `.netrc`, `.rhosts`, `.forward` file presence
- Duplicate UIDs, GIDs, usernames, and group names
- Groups referenced in `/etc/passwd` but missing from `/etc/group`
- NIS `+:` entries in `/etc/passwd`, `/etc/shadow`, `/etc/group`
- UID-0 accounts other than root

### Audit Artefact Location (RHEL 9)

All backups and findings are written to `/tmp/<hostname>_audit/`.

| File | Contents |
|---|---|
| `sshd_config_<timestamp>.bak` | Main SSH config backup |
| `sshd_drop_<timestamp>.bak` | SSH drop-in backup |
| `auditd.conf_<timestamp>.bak` | auditd config backup |
| `faillock.conf_<timestamp>.bak` | faillock config backup |
| `sysctl.conf_<timestamp>.bak` | sysctl backup |
| `dnf.conf_<timestamp>.bak` | DNF config backup |
| `chrony.conf_<timestamp>.bak` | chrony config backup |
| `nftables_<timestamp>.bak` | nftables ruleset backup |
| `pkg_remove_<timestamp>.log` | Package removal output |
| `pkg_install_<timestamp>.log` | Package installation output |
| `aide_init_<timestamp>.log` | AIDE database initialisation log |
| `svc_restart_<timestamp>.log` | Service restart output |
| `user_group_audit_<timestamp>.log` | User/group integrity findings |
| `suid_exec_<timestamp>.log` | SUID executables found |
| `sgid_exec_<timestamp>.log` | SGID executables found |
| `world_writable_files_<timestamp>.log` | World-writable files |

### Post-Run Actions Required (RHEL 9)

The script prints these reminders on completion:

1. Replace `YOUR_COMPANY_NAME` in `/etc/issue.net` and `/etc/motd`
2. Review `/etc/nftables/main.nft` — open only ports required by this server's workload
3. If this is a **container host**, review `user.max_user_namespaces=0` in `/etc/sysctl.d/99-CIS.conf`
4. Verify `fapolicyd` policy does not block legitimate application workloads
5. **Reboot** to apply kernel module, sysctl, crypto-policy, and IPv6 disable changes

---

## RHEL 8 vs RHEL 9 — Key Differences

| Area | RHEL 8 Script | RHEL 9 Script |
|---|---|---|
| **CIS Benchmark** | v3.0.0 | v2.0.0 |
| **Package manager** | `yum` | `dnf` |
| **SSH config method** | Edit `/etc/ssh/sshd_config` directly | Drop-in `/etc/ssh/sshd_config.d/50-CIS-hardening.conf` |
| **Password quality config** | `/etc/security/pwquality.conf` | Drop-in `/etc/security/pwquality.conf.d/CIS.conf` |
| **Faillock config** | `authselect` only | `authselect` + `/etc/security/faillock.conf` |
| **Firewall** | Services disabled | Active **nftables** default-deny ruleset |
| **Application allowlisting** | Not present | **fapolicyd** enabled |
| **File integrity** | Not present | **AIDE** initialised + daily cron check |
| **USB control** | Module blacklist only | **USBGuard** policy + service |
| **Automatic updates** | Not present | **dnf-automatic** security-only updates |
| **NTP** | Not configured | **chrony** hardened |
| **Audit log format** | Default | `ENRICHED` (structured) |
| **`vfat` module** | Disabled | Left enabled (required for EFI) |
| **`fs.protected_fifos`** | Not set | `2` |
| **`fs.protected_regular`** | Not set | `2` |
| **`user.max_user_namespaces`** | Not set | `0` (disable unprivileged namespaces) |
| **`kernel.yama.ptrace_scope`** | `1` | `2` (stricter) |
| **sudo hardening** | Not configured | `requiretty`, `logfile`, `timestamp_timeout=0` |
| **login.defs** | Basic password aging | + `ENCRYPT_METHOD SHA512`, `SHA_CRYPT_MIN_ROUNDS 5000` |
| **Audit: finit_module** | Not audited | Audited |
| **Audit: faillock dir** | Not audited | `/run/faillock/` audited |
| **Audit: fapolicyd dir** | Not present | `/etc/fapolicyd/` audited |

---

## Disclaimer

These scripts make **system-wide changes** including service removal, SSH restart, kernel parameter modification, and firewall rule deployment. Before running in production:

1. **Test** in a non-production or staging environment first
2. **Ensure out-of-band console access** (IPMI/iDRAC/iLO) before running — SSH will be restarted
3. **Review environment-specific settings:**
   - `vfat` disable (RHEL 8) may break EFI-only systems
   - nftables rules (RHEL 9) must be adapted to open the ports your workload requires
   - `user.max_user_namespaces=0` (RHEL 9) will break Podman/Docker on container hosts
   - `fapolicyd` (RHEL 9) may block custom or third-party application binaries
4. **Replace `YOUR_COMPANY_NAME`** in `/etc/issue.net` and `/etc/motd` before deploying
5. **Reboot** after the script completes to activate all changes
