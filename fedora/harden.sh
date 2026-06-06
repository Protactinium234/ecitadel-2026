#!/usr/bin/env bash
# Fedora 43 hardening entry point. Run as root.
#   sudo BACKUP_SERVER=10.0.0.5 ./harden.sh
#
# Addresses Fedora-specific Lynis suggestions from ../fedora/lynis.txt:
#   AUTH-9230/9286/9328 in login.defs, KRNL-5820 cores, FINT-4350 AIDE,
#   HRDN-7230 malware scanners, plus all distro-agnostic items in
#   ../harden-common.sh.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export DISTRO="fedora"
export PKG_BIN="dnf"
export PKG_UPDATE="dnf -y makecache"
export PKG_UPGRADE="dnf -y --skip-unavailable upgrade --refresh"
# --skip-unavailable: dnf5 transactions are atomic — without this, a single
# missing package (e.g. an old name no longer in the repos) aborts the whole
# install and none of the listed packages land.
export PKG_INSTALL="dnf -y --skip-unavailable install"

# Hooks invoked from main() in harden-common.sh

distro_pre_harden() {
    section "Fedora-specific package install"
    pkg_install \
        firewalld fail2ban \
        libpwquality \
        dnf-automatic \
        aide \
        rkhunter chkrootkit clamav clamav-update \
        audit psacct sysstat \
        rsync curl ca-certificates plocate \
        policycoreutils policycoreutils-python-utils setroubleshoot-server \
        dnf-plugins-core
}

distro_post_harden() {
    section "Fedora-specific lynis fixes"

    # AUTH-9262/pwquality — Fedora ships /etc/security/pwquality.conf via libpwquality
    if [[ -f /etc/security/pwquality.conf ]]; then
        preserve /etc/security/pwquality.conf
        local pwq_conf=/etc/security/pwquality.conf
        [[ -d /etc/security/pwquality.conf.d ]] && pwq_conf=/etc/security/pwquality.conf.d/99-harden.conf
        cat >>"$pwq_conf" <<'EOF'

# harden-common additions
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
difok = 5
enforce_for_root
EOF
        ok "pwquality tightened ($pwq_conf)"
    fi

    # SELinux must be enforcing
    if command -v setenforce >/dev/null 2>&1; then
        setenforce 1 2>/dev/null || true
        preserve /etc/selinux/config
        sed -i 's|^SELINUX=.*|SELINUX=enforcing|' /etc/selinux/config 2>/dev/null || true
        ok "SELinux set to enforcing"
    fi

    # firewalld: default zone drop-everything except SSH
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --set-default-zone=drop >>"$HARDEN_LOG" 2>&1 || true
        firewall-cmd --permanent --zone=drop --add-service=ssh >>"$HARDEN_LOG" 2>&1 || true
        if [[ "$SSH_HARDEN_PORT" != "22" ]]; then
            firewall-cmd --permanent --zone=drop --add-port="${SSH_HARDEN_PORT}/tcp" >>"$HARDEN_LOG" 2>&1 || true
        fi
        firewall-cmd --reload >>"$HARDEN_LOG" 2>&1 || true
        ok "firewalld default zone=drop, ssh allowed"
    fi

    # Fail2ban with SSH jail
    if command -v fail2ban-client >/dev/null 2>&1; then
        mkdir -p /etc/fail2ban/jail.d
        cat >/etc/fail2ban/jail.d/harden-ssh.local <<EOF
[sshd]
enabled = true
port    = ${SSH_HARDEN_PORT}
backend = systemd
maxretry = 3
bantime = 1h
findtime = 10m
EOF
        systemctl enable --now fail2ban >>"$HARDEN_LOG" 2>&1 || true
        ok "fail2ban sshd jail active"
    fi

    # Disable noisy/unsafe services flagged UNSAFE by systemd-analyze that we
    # *know* aren't needed for a server CTF box. (Most UNSAFE services in the
    # Lynis output are required system bits — skipped, see deferred list.)
    for svc in cups cups-browsed avahi-daemon abrt-journal-core abrt-oops abrt-xorg abrtd \
               mdmonitor smartd iscsid iscsiuio bluetooth ModemManager \
               libvirtd libvirtd.socket virtnetworkd virtstoraged virtqemud \
               wpa_supplicant; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}"; then
            systemctl disable --now "$svc" 2>/dev/null && log "  disabled $svc" || true
        fi
    done
    ok "noisy services disabled (re-enable on day-of if scored)"

    # ClamAV on Fedora — the freshclam.conf usually ships with an Example line
    # that must be removed before freshclam will run.
    if [[ -f /etc/freshclam.conf ]]; then
        sed -i 's|^Example|#Example|' /etc/freshclam.conf
    fi
}

# Source the shared library AFTER hooks are defined
# shellcheck source=../harden-common.sh
source "${SCRIPT_DIR}/../harden-common.sh"

main "$@"
