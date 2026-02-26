# Linux-Hardening

Operating System Security Hardening for Linux Distributions.

---

## RHEL 8 Hardening Script

A comprehensive, automated hardening script for **Red Hat Enterprise Linux 8** and compatible derivatives (CentOS Stream 8, AlmaLinux 8, Rocky Linux 8).

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
- Disables daemon umask set to `027`

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

---

### Audit Artefact Location

All backups and findings are written to:
```
/tmp/<hostname>_audit/
```

Key files created:

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

### Disclaimer

This script makes **system-wide changes** including service removal, SSH restart, and kernel parameter modification. Always:

1. Test in a non-production environment first
2. Ensure you have out-of-band console access before running
3. Review and adjust settings (e.g. `vfat` disable may break EFI-only systems) to match your environment
4. Replace `YOUR_COMPANY_NAME` in the banner templates before deploying
