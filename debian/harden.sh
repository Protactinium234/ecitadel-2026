#!/usr/bin/env bash
# Debian 13 hardening entry point. Run as root.
#   sudo BACKUP_SERVER=10.0.0.5 ./harden.sh
#
# Addresses Debian-specific Lynis suggestions from ../debian/lynis.txt:
#   PKGS-7370 debsums, PKGS-7394 apt-show-versions, AUTH-9262 libpam-pwquality,
#   plus all distro-agnostic items in ../harden-common.sh.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Export DEBIAN_FRONTEND as an actual env var — putting it inside the PKG_*
# strings doesn't work, because after $VAR expansion bash treats the first
# token as argv[0], not as an env-prefix assignment.
export DEBIAN_FRONTEND=noninteractive

export DISTRO="debian"
export PKG_BIN="apt-get"
export PKG_UPDATE="apt-get update"
export PKG_UPGRADE="apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade"
export PKG_INSTALL="apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

# Hooks invoked from main() in harden-common.sh

distro_pre_harden() {
    section "Debian-specific package install"
    pkg_install \
        ufw fail2ban \
        debsums apt-show-versions \
        libpam-pwquality libpam-tmpdir \
        unattended-upgrades \
        aide aide-common \
        rkhunter chkrootkit clamav clamav-freshclam \
        auditd audispd-plugins acct sysstat \
        rsync curl ca-certificates plocate \
        apparmor apparmor-utils apparmor-profiles \
        lynis
}

distro_post_harden() {
    section "Debian-specific lynis fixes"

    # AUTH-9262 — pam_pwquality
    if [[ -f /etc/security/pwquality.conf ]]; then
        preserve /etc/security/pwquality.conf
        cat >>/etc/security/pwquality.conf <<'EOF'

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
        ok "pwquality tightened"
    fi
    # Wire pwquality into PAM if not already
    if [[ -f /etc/pam.d/common-password ]] && ! grep -q pam_pwquality /etc/pam.d/common-password; then
        preserve /etc/pam.d/common-password
        sed -i 's|^\(password\s\+requisite\s\+pam_unix\.so.*\)|password requisite pam_pwquality.so retry=3\n\1|' /etc/pam.d/common-password \
            || true
        ok "pam_pwquality wired into common-password"
    fi

    # PKGS-7370 — debsums periodic verification. Two layers:
    #   1) /etc/default/debsums CRON_CHECK so the debsums-shipped cron entry
    #      actually runs (Lynis specifically checks this var)
    #   2) our own daily wrapper that logs to syslog for Splunk pickup
    if command -v debsums >/dev/null 2>&1; then
        if [[ -f /etc/default/debsums ]]; then
            preserve /etc/default/debsums
            if grep -q '^CRON_CHECK=' /etc/default/debsums; then
                sed -i 's|^CRON_CHECK=.*|CRON_CHECK=daily|' /etc/default/debsums
            else
                echo 'CRON_CHECK=daily' >>/etc/default/debsums
            fi
        fi
        cat >/etc/cron.daily/zzz-harden-debsums <<'EOF'
#!/bin/sh
debsums -cs 2>&1 | logger -t debsums-check
EOF
        chmod 750 /etc/cron.daily/zzz-harden-debsums
        ok "debsums CRON_CHECK=daily + daily check installed"
    fi

    # ACCT-9626 — sysstat ships disabled on Debian (/etc/default/sysstat).
    # Lynis checks for ENABLED="true" specifically, and the systemd timers
    # only collect data once enabled here.
    if [[ -f /etc/default/sysstat ]]; then
        preserve /etc/default/sysstat
        sed -i 's|^ENABLED=.*|ENABLED="true"|' /etc/default/sysstat
        grep -q '^ENABLED=' /etc/default/sysstat || echo 'ENABLED="true"' >>/etc/default/sysstat
        systemctl enable --now sysstat sysstat-collect.timer sysstat-summary.timer 2>/dev/null || true
        ok "sysstat enabled (ENABLED=true + timers)"
    fi

    # UFW default-deny + allow SSH on our externally-reachable port.
    # When the honeypot is enabled, that's port 22 (honeypot) and real sshd
    # is on 127.0.0.1:$SSH_HARDEN_PORT (no firewall rule needed). When the
    # honeypot is off, $SSH_HARDEN_PORT is whatever sshd actually listens on.
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >>"$HARDEN_LOG" 2>&1 || true
        ufw default deny incoming >>"$HARDEN_LOG" 2>&1
        ufw default allow outgoing >>"$HARDEN_LOG" 2>&1
        local ssh_external=22
        [[ ${HONEYPOT_ENABLE:-1} == 1 ]] || ssh_external=${SSH_HARDEN_PORT}
        ufw allow "${ssh_external}/tcp" comment 'ssh/honeypot' >>"$HARDEN_LOG" 2>&1 || true
        ufw --force enable >>"$HARDEN_LOG" 2>&1 || true
        ok "ufw enabled (default deny in, allow ${ssh_external}/tcp)"
    fi

    # Fail2ban — watch the externally-exposed SSH port (honeypot's :22, or
    # real sshd's port if honeypot is off). The honeypot logs auth failures
    # to /var/log/ssh-honeypot/access.log; we also add a jail for those.
    if command -v fail2ban-client >/dev/null 2>&1; then
        local ssh_external=22
        [[ ${HONEYPOT_ENABLE:-1} == 1 ]] || ssh_external=${SSH_HARDEN_PORT}
        cat >/etc/fail2ban/jail.d/harden-ssh.local <<EOF
[sshd]
enabled = true
port    = ${ssh_external}
maxretry = 3
bantime  = 1h
findtime = 10m
EOF
        if [[ ${HONEYPOT_ENABLE:-1} == 1 ]]; then
            install -d -m 755 /etc/fail2ban/filter.d
            cat >/etc/fail2ban/filter.d/ssh-honeypot.conf <<'EOF'
[Definition]
# Matches lines like:
#   2026-06-06T18:00:00+0000 event='auth_attempt' ip='1.2.3.4' user='root' password='123456' method='password' result='rejected'
failregex = ^.* event='auth_attempt' ip='<HOST>' .* result='rejected'$
ignoreregex =
EOF
            cat >/etc/fail2ban/jail.d/harden-ssh-honeypot.local <<EOF
[ssh-honeypot]
enabled  = true
filter   = ssh-honeypot
logpath  = /var/log/ssh-honeypot/access.log
port     = 22
maxretry = 5
bantime  = 6h
findtime = 10m
EOF
        fi
        systemctl enable --now fail2ban >>"$HARDEN_LOG" 2>&1 || true
        systemctl restart fail2ban >>"$HARDEN_LOG" 2>&1 || true
        ok "fail2ban active (sshd:${ssh_external}${HONEYPOT_ENABLE:+ + ssh-honeypot:22})"
    fi

    # AppArmor — enforce all profiles
    if command -v aa-enforce >/dev/null 2>&1; then
        aa-enforce /etc/apparmor.d/* >>"$HARDEN_LOG" 2>&1 || true
        ok "AppArmor profiles set to enforce"
    fi

    # Disable CUPS unless explicitly needed (PRNT-2307)
    if systemctl list-unit-files | grep -q '^cups\.service'; then
        systemctl disable --now cups cups-browsed 2>/dev/null || true
        ok "cups disabled (re-enable on day-of if scored)"
    fi
}

# Source the shared library AFTER hooks are defined
# shellcheck source=../harden-common.sh
source "${SCRIPT_DIR}/../harden-common.sh"

main "$@"
