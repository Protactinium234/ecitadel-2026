#!/usr/bin/env bash
# harden-common.sh — distro-agnostic CTF blue-team hardening library.
# Sourced by debian/harden.sh and fedora/harden.sh. Don't run directly.
#
# Caller MUST export before sourcing:
#   DISTRO          debian | fedora
#   PKG_BIN         apt-get | dnf
#   PKG_UPDATE      cmd to refresh package metadata
#   PKG_UPGRADE     cmd to upgrade all packages
#   PKG_INSTALL     cmd prefix to install a package list
#
# Then call:  main "$@"

# Deliberately not using `set -e`: every function in this library logs its own
# failures via warn/err and is expected to keep going. errexit would cause a
# single non-zero return (e.g. an apt mirror hiccup, a missing pkg, a service
# that's not running) to silently abort the whole hardening run.
set -uo pipefail

# ============================================================================
# CONFIG  (override via env, e.g.  BACKUP_SERVER=10.0.0.5 ./harden.sh)
# ============================================================================
: "${BACKUP_SERVER:=REPLACE_ME.ctf.local}"     # rsync/ssh target host
: "${BACKUP_USER:=ctfops}"                      # user on backup server
: "${BACKUP_SSH_KEY:=/root/.ssh/ctf_backup}"    # private key for rsync
: "${BACKUP_REMOTE_ROOT:=/srv/ctf-backups}"     # remote dir, host subdir auto-appended
: "${AIDE_BASELINE_URL_BASE:=rsync://${BACKUP_USER}@${BACKUP_SERVER}/ctf-aide}" # rsync module on server with per-host AIDE DBs
: "${SSH_HARDEN_PORT:=22}"                      # keep 22 per user choice; override to move
: "${HARDEN_LOG:=/var/log/harden-$(date +%Y%m%d-%H%M%S).log}"
: "${SKIP_REBOOT_PROMPT:=0}"

# Backup toggles — flip to 0 to skip a class. Day-of: enable what's running.
: "${BACKUP_WEB:=1}"       # nginx/apache/httpd configs + docroots
: "${BACKUP_SQL:=1}"       # mysql/mariadb/postgres dumps
: "${BACKUP_DNS:=1}"       # bind/named/unbound
: "${BACKUP_SSH:=1}"       # /etc/ssh + every user's ~/.ssh
: "${BACKUP_MAIL:=0}"      # postfix/dovecot
: "${BACKUP_FTP:=0}"       # vsftpd/proftpd
: "${BACKUP_DOCKER:=0}"    # /var/lib/docker volumes + compose files
: "${BACKUP_SYSTEM:=1}"    # /etc, /root, crontabs, /home (shallow)
: "${BACKUP_CUSTOM_PATHS:=}" # space-separated extra paths

# Splunk Universal Forwarder — fetched from $BACKUP_SERVER by default
: "${SPLUNK_FWD:=1}"                       # 0 to skip entirely
: "${SPLUNK_HOME:=/opt/splunkforwarder}"
: "${SPLUNK_INDEXER:=${BACKUP_SERVER}:9997}"
: "${SPLUNK_DEPLOYMENT_SERVER:=}"          # e.g. splunk-ds.ctf.local:8089; if set, supersedes outputs.conf
: "${SPLUNK_INDEX:=main}"
: "${SPLUNK_ADMIN_PASS:=ChangeMeAtRuntime!1}"
: "${SPLUNK_FWD_DEB_URL:=http://${BACKUP_SERVER}/splunk/splunkforwarder.deb}"
: "${SPLUNK_FWD_RPM_URL:=http://${BACKUP_SERVER}/splunk/splunkforwarder.rpm}"

# ============================================================================
# LOGGING / UI
# ============================================================================
C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[0;33m'
C_BLU=$'\033[0;34m'; C_BLD=$'\033[1m';    C_RST=$'\033[0m'

log()    { printf '%s[%s]%s %s\n' "$C_BLU" "$(date +%H:%M:%S)" "$C_RST" "$*" | tee -a "$HARDEN_LOG"; }
ok()     { printf '%s[ OK ]%s %s\n' "$C_GRN" "$C_RST" "$*" | tee -a "$HARDEN_LOG"; }
warn()   { printf '%s[WARN]%s %s\n' "$C_YEL" "$C_RST" "$*" | tee -a "$HARDEN_LOG"; }
err()    { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RST" "$*" | tee -a "$HARDEN_LOG" >&2; }
section(){ printf '\n%s== %s ==%s\n' "$C_BLD" "$*" "$C_RST" | tee -a "$HARDEN_LOG"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Must run as root. Try: sudo $0"
        exit 1
    fi
}

# Backup a file before mutating. Idempotent: keeps the first pristine copy.
preserve() {
    local f=$1
    [[ -e $f && ! -e ${f}.harden.orig ]] && cp -a -- "$f" "${f}.harden.orig"
}

pkg_install() {
    # Try the whole batch first — fast path. If anything goes wrong (apt is
    # atomic; dnf5 sometimes returns non-zero on partial success even with
    # --skip-unavailable), retry per-package so we still get everything that
    # IS available and can name exactly which packages aren't.
    # shellcheck disable=SC2086
    if $PKG_INSTALL "$@" >>"$HARDEN_LOG" 2>&1; then
        return 0
    fi
    log "batch install failed — retrying per-package"
    local installed=() missing=() p
    for p in "$@"; do
        # shellcheck disable=SC2086
        if $PKG_INSTALL "$p" >>"$HARDEN_LOG" 2>&1; then
            installed+=("$p")
        else
            missing+=("$p")
        fi
    done
    (( ${#installed[@]} > 0 )) && ok "installed: ${installed[*]}"
    (( ${#missing[@]} > 0 )) && warn "unavailable on this distro/version: ${missing[*]}"
    return 0
}

# ============================================================================
# 1. SYSTEM UPDATE
# ============================================================================
do_update() {
    section "Update & upgrade"
    # shellcheck disable=SC2086
    if $PKG_UPDATE >>"$HARDEN_LOG" 2>&1; then
        ok "metadata refreshed"
    else
        warn "metadata refresh failed — continuing"
    fi
    # shellcheck disable=SC2086
    if $PKG_UPGRADE >>"$HARDEN_LOG" 2>&1; then
        ok "packages upgraded"
    else
        warn "package upgrade failed — see $HARDEN_LOG; continuing"
    fi
}

# ============================================================================
# 2. BACKUP CRITICAL SERVICES
# ============================================================================
_rsync_push() {
    # _rsync_push <local-path> <remote-subdir>
    local src=$1 sub=$2
    [[ -e $src ]] || { warn "skip (missing): $src"; return; }
    local host; host=$(hostname -s)
    local dest="${BACKUP_USER}@${BACKUP_SERVER}:${BACKUP_REMOTE_ROOT}/${host}/${sub}/"
    log "rsync $src -> $dest"
    if rsync -aAXz --delete --numeric-ids \
        -e "ssh -i ${BACKUP_SSH_KEY} -o StrictHostKeyChecking=accept-new -o BatchMode=yes" \
        "$src" "$dest" >>"$HARDEN_LOG" 2>&1; then
        ok "backed up $src"
    else
        warn "rsync failed for $src (check key/host/path)"
    fi
}

_dump_sql() {
    local stage; stage=$(mktemp -d /tmp/sqldump.XXXXXX)
    chmod 700 "$stage"

    local sql_running=0
    for svc in mariadb mysql mysqld; do
        systemctl is-active --quiet "$svc" 2>/dev/null && sql_running=1 && break
    done
    if (( sql_running )) && command -v mysqldump >/dev/null 2>&1; then
        log "mysqldump --all-databases"
        if mysqldump --all-databases --single-transaction --routines --triggers \
                2>>"$HARDEN_LOG" | gzip > "$stage/mysql-all.sql.gz"; then
            ok "mysql dumped"
        else
            warn "mysql dump failed (creds? socket?)"
        fi
    fi

    if command -v pg_dumpall >/dev/null 2>&1 && systemctl is-active --quiet postgresql 2>/dev/null; then
        log "pg_dumpall"
        if sudo -u postgres pg_dumpall 2>>"$HARDEN_LOG" | gzip > "$stage/pgsql-all.sql.gz"; then
            ok "postgres dumped"
        else
            warn "postgres dump failed"
        fi
    fi

    [[ -n $(ls -A "$stage" 2>/dev/null) ]] && _rsync_push "$stage/" "sql"
    rm -rf "$stage"
}

do_backup() {
    section "Backup critical services to ${BACKUP_SERVER}"
    if ! command -v rsync >/dev/null 2>&1; then
        pkg_install rsync
    fi
    if [[ ! -f $BACKUP_SSH_KEY ]]; then
        warn "SSH key not found at $BACKUP_SSH_KEY — backups will fail until you drop it in"
    fi

    if [[ $BACKUP_SYSTEM == 1 ]]; then
        _rsync_push /etc/ system/etc
        _rsync_push /root/ system/root
        _rsync_push /var/spool/cron/ system/cron-spool
        [[ -d /var/spool/anacron ]] && _rsync_push /var/spool/anacron/ system/anacron
        # home: configs only, not user data dumps (size)
        for h in /home/*/; do
            [[ -d $h ]] && _rsync_push "$h" "system/home/$(basename "$h")"
        done
    fi

    if [[ $BACKUP_WEB == 1 ]]; then
        for p in /etc/nginx /etc/apache2 /etc/httpd /var/www /srv/www /srv/http; do
            [[ -e $p ]] && _rsync_push "$p/" "web/${p//\//_}"
        done
    fi

    [[ $BACKUP_SQL == 1 ]] && _dump_sql

    if [[ $BACKUP_DNS == 1 ]]; then
        for p in /etc/bind /var/named /etc/named.conf /etc/unbound; do
            [[ -e $p ]] && _rsync_push "$p" "dns/${p//\//_}"
        done
    fi

    if [[ $BACKUP_SSH == 1 ]]; then
        _rsync_push /etc/ssh/ ssh/etc-ssh
        for h in /home/*/.ssh /root/.ssh; do
            [[ -d $h ]] && _rsync_push "$h/" "ssh/$(echo "$h" | tr / _)"
        done
    fi

    if [[ $BACKUP_MAIL == 1 ]]; then
        for p in /etc/postfix /etc/dovecot /var/mail /var/spool/mail; do
            [[ -e $p ]] && _rsync_push "$p/" "mail/${p//\//_}"
        done
    fi

    if [[ $BACKUP_FTP == 1 ]]; then
        for p in /etc/vsftpd /etc/vsftpd.conf /etc/proftpd; do
            [[ -e $p ]] && _rsync_push "$p" "ftp/${p//\//_}"
        done
    fi

    if [[ $BACKUP_DOCKER == 1 ]]; then
        [[ -d /var/lib/docker/volumes ]] && _rsync_push /var/lib/docker/volumes/ docker/volumes
        for p in /etc/docker /opt/docker /srv/docker; do
            [[ -e $p ]] && _rsync_push "$p/" "docker/${p//\//_}"
        done
    fi

    for extra in $BACKUP_CUSTOM_PATHS; do
        _rsync_push "$extra" "custom/${extra//\//_}"
    done
}

# ============================================================================
# 3. AIDE BASELINE PULL + CHECK
# ============================================================================
do_aide() {
    section "AIDE — pull baseline & check"
    command -v aide >/dev/null 2>&1 || pkg_install aide

    local db_dir host
    host=$(hostname -s)
    if [[ $DISTRO == debian ]]; then
        db_dir=/var/lib/aide
    else
        db_dir=/var/lib/aide
    fi
    mkdir -p "$db_dir"

    log "rsync AIDE baseline from ${AIDE_BASELINE_URL_BASE}/${host}/"
    if rsync -az \
        -e "ssh -i ${BACKUP_SSH_KEY} -o StrictHostKeyChecking=accept-new -o BatchMode=yes" \
        "${BACKUP_USER}@${BACKUP_SERVER}:${BACKUP_REMOTE_ROOT}/aide-baselines/${host}/" "$db_dir/" \
        >>"$HARDEN_LOG" 2>&1; then
        ok "baseline pulled"
    else
        warn "no baseline available — generating one now (NOT a clean reference!)"
    fi

    # Standard expected name across distros
    if [[ ! -f $db_dir/aide.db.gz && ! -f $db_dir/aide.db ]]; then
        log "aide --init (this will take a while)"
        aide --init >>"$HARDEN_LOG" 2>&1 || warn "aide --init failed"
        [[ -f $db_dir/aide.db.new.gz ]] && mv "$db_dir/aide.db.new.gz" "$db_dir/aide.db.gz"
        [[ -f $db_dir/aide.db.new   ]] && mv "$db_dir/aide.db.new"   "$db_dir/aide.db"
    fi

    log "aide --check (results -> $HARDEN_LOG)"
    aide --check | tee -a "$HARDEN_LOG" || warn "aide --check reported changes — review now"
}

# ============================================================================
# 3b. SPLUNK UNIVERSAL FORWARDER
# ============================================================================
do_splunk_forwarder() {
    section "Splunk Universal Forwarder"
    if [[ $SPLUNK_FWD != 1 ]]; then
        log "SPLUNK_FWD=0 — skipping"
        return
    fi
    if [[ $SPLUNK_ADMIN_PASS == "ChangeMeAtRuntime!1" ]]; then
        warn "SPLUNK_ADMIN_PASS is the default — export a real one before re-running"
    fi

    # Install package if not already
    if [[ ! -x ${SPLUNK_HOME}/bin/splunk ]]; then
        local pkg_url pkg=/tmp/splunkforwarder.pkg
        if [[ $DISTRO == debian ]]; then pkg_url=$SPLUNK_FWD_DEB_URL; else pkg_url=$SPLUNK_FWD_RPM_URL; fi
        log "fetching UF package from $pkg_url"
        if curl -fsSLk -o "$pkg" "$pkg_url"; then
            if [[ $DISTRO == debian ]]; then
                if ! dpkg -i "$pkg" >>"$HARDEN_LOG" 2>&1; then
                    apt-get -f -y install >>"$HARDEN_LOG" 2>&1 || true
                fi
            else
                rpm -Uvh "$pkg" >>"$HARDEN_LOG" 2>&1 || dnf -y install "$pkg" >>"$HARDEN_LOG" 2>&1 || true
            fi
            rm -f "$pkg"
            ok "splunkforwarder package installed"
        else
            warn "could not download UF from $pkg_url — skipping Splunk setup"
            return
        fi
    else
        log "splunkforwarder already installed at ${SPLUNK_HOME}"
    fi

    if [[ ! -x ${SPLUNK_HOME}/bin/splunk ]]; then
        err "${SPLUNK_HOME}/bin/splunk missing after install — aborting splunk step"
        return
    fi

    mkdir -p "${SPLUNK_HOME}/etc/system/local"

    # Seed admin password (only respected if splunkd has not yet started)
    if [[ ! -f ${SPLUNK_HOME}/etc/passwd ]]; then
        cat >"${SPLUNK_HOME}/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = admin
PASSWORD = ${SPLUNK_ADMIN_PASS}
EOF
        chmod 600 "${SPLUNK_HOME}/etc/system/local/user-seed.conf"
    fi

    # If a deployment server is configured, hand off all config to it.
    # Otherwise write a static outputs.conf + inputs.conf for direct-to-indexer.
    if [[ -n $SPLUNK_DEPLOYMENT_SERVER ]]; then
        cat >"${SPLUNK_HOME}/etc/system/local/deploymentclient.conf" <<EOF
[deployment-client]

[target-broker:deploymentServer]
targetUri = ${SPLUNK_DEPLOYMENT_SERVER}
EOF
        log "configured for deployment server ${SPLUNK_DEPLOYMENT_SERVER}"
    else
        cat >"${SPLUNK_HOME}/etc/system/local/outputs.conf" <<EOF
[tcpout]
defaultGroup = primary_indexers

[tcpout:primary_indexers]
server = ${SPLUNK_INDEXER}
EOF

        cat >"${SPLUNK_HOME}/etc/system/local/inputs.conf" <<EOF
[default]
host = $(hostname)
index = ${SPLUNK_INDEX}

# --- security log sources ---
[monitor:///var/log/audit/audit.log]
disabled = false
sourcetype = linux_audit

[monitor:///var/log/auth.log]
disabled = false
sourcetype = linux_secure

[monitor:///var/log/secure]
disabled = false
sourcetype = linux_secure

[monitor:///var/log/syslog]
disabled = false
sourcetype = syslog

[monitor:///var/log/messages]
disabled = false
sourcetype = syslog

[monitor:///var/log/kern.log]
disabled = false
sourcetype = linux_kernel

[monitor:///var/log/dmesg]
disabled = false
sourcetype = linux_kernel

[monitor:///var/log/fail2ban.log]
disabled = false
sourcetype = fail2ban

[monitor:///var/log/ufw.log]
disabled = false
sourcetype = ufw

[monitor:///var/log/firewalld]
disabled = false
sourcetype = firewalld

[monitor:///var/log/cron]
disabled = false
sourcetype = cron

[monitor:///var/log/cron.log]
disabled = false
sourcetype = cron

[monitor:///var/log/wtmp]
disabled = false
sourcetype = linux_wtmp

[monitor:///var/log/btmp]
disabled = false
sourcetype = linux_btmp

# --- AV / IDS ---
[monitor:///var/log/clamav/*.log]
disabled = false
sourcetype = clamav

[monitor:///var/log/rkhunter*]
disabled = false
sourcetype = rkhunter

[monitor:///var/log/aide/*.log]
disabled = false
sourcetype = aide

# --- hardening pipeline itself ---
[monitor:///var/log/harden-*.log]
disabled = false
sourcetype = harden_script

# --- web / db / dns commonly scored in CTF ---
[monitor:///var/log/nginx/*.log]
disabled = false
sourcetype = nginx

[monitor:///var/log/apache2/*.log]
disabled = false
sourcetype = apache

[monitor:///var/log/httpd/*.log]
disabled = false
sourcetype = apache

[monitor:///var/log/mysql/*.log]
disabled = false
sourcetype = mysqld

[monitor:///var/log/postgresql/*.log]
disabled = false
sourcetype = postgresql

[monitor:///var/log/named/*.log]
disabled = false
sourcetype = bind

[monitor:///var/log/bind/*.log]
disabled = false
sourcetype = bind

[monitor:///var/log/maillog]
disabled = false
sourcetype = mail

[monitor:///var/log/mail.log]
disabled = false
sourcetype = mail

# --- systemd journal (catches everything sent to journald) ---
[journald://harden_journal]
disabled = false
EOF
        log "configured direct forward to indexer ${SPLUNK_INDEXER}"
    fi

    # The UF package usually creates a 'splunkfwd' user; fall back to splunk/root.
    local splunk_user
    if id splunkfwd >/dev/null 2>&1; then splunk_user=splunkfwd
    elif id splunk     >/dev/null 2>&1; then splunk_user=splunk
    else splunk_user=root
    fi
    chown -R "${splunk_user}:${splunk_user}" "${SPLUNK_HOME}" 2>/dev/null || true

    # First start accepts EULA; subsequent runs just restart.
    if "${SPLUNK_HOME}/bin/splunk" status >/dev/null 2>&1; then
        "${SPLUNK_HOME}/bin/splunk" restart >>"$HARDEN_LOG" 2>&1 || true
    else
        "${SPLUNK_HOME}/bin/splunk" start --accept-license --answer-yes --no-prompt >>"$HARDEN_LOG" 2>&1 || true
    fi

    # boot-start (systemd unit)
    "${SPLUNK_HOME}/bin/splunk" enable boot-start -systemd-managed 1 -user "$splunk_user" \
        --accept-license --answer-yes --no-prompt >>"$HARDEN_LOG" 2>&1 || true

    if "${SPLUNK_HOME}/bin/splunk" status 2>/dev/null | grep -q running; then
        if [[ -n $SPLUNK_DEPLOYMENT_SERVER ]]; then
            ok "UF running, deployment-managed by ${SPLUNK_DEPLOYMENT_SERVER}"
        else
            ok "UF running, forwarding to ${SPLUNK_INDEXER} (index=${SPLUNK_INDEX})"
        fi
    else
        warn "UF did not report running — check ${HARDEN_LOG} and ${SPLUNK_HOME}/var/log/splunk/"
    fi
}

# ============================================================================
# 4. MALWARE SCANNERS
# ============================================================================
do_malware_scan() {
    section "rkhunter / chkrootkit / clamscan"
    pkg_install rkhunter chkrootkit clamav

    if command -v rkhunter >/dev/null 2>&1; then
        log "rkhunter --update && --propupd && --check"
        rkhunter --update --nocolors            >>"$HARDEN_LOG" 2>&1 || true
        rkhunter --propupd --nocolors           >>"$HARDEN_LOG" 2>&1 || true
        rkhunter --check --sk --rwo --nocolors  | tee -a "$HARDEN_LOG" || true
    fi

    if command -v chkrootkit >/dev/null 2>&1; then
        log "chkrootkit"
        chkrootkit -q 2>&1 | tee -a "$HARDEN_LOG" || true
    fi

    if command -v freshclam >/dev/null 2>&1; then
        log "freshclam"
        # Some distros run freshclam as a service that holds the DB lock.
        systemctl stop clamav-freshclam 2>/dev/null || true
        systemctl stop clamav-freshclamd 2>/dev/null || true
        freshclam >>"$HARDEN_LOG" 2>&1 || warn "freshclam failed (DB may be stale)"
        systemctl start clamav-freshclam 2>/dev/null || true
    fi
    if command -v clamscan >/dev/null 2>&1; then
        log "clamscan -ri / (this is slow; bound to /etc /home /root /var/www /tmp /opt)"
        clamscan -ri --exclude-dir='^/sys|^/proc|^/dev' \
            /etc /home /root /tmp /opt /var/www 2>/dev/null \
            | tee -a "$HARDEN_LOG" || true
    fi
}

# ============================================================================
# 5. USER AUDIT  (interactive)
# ============================================================================
_show_user() {
    local u=$1
    local pw_status; pw_status=$(passwd -S "$u" 2>/dev/null || echo "n/a")
    local groups;    groups=$(id -nG "$u" 2>/dev/null || echo "?")
    local last;      last=$(lastlog -u "$u" 2>/dev/null | tail -1 || echo "?")
    local sudo_has="no"
    sudo -lU "$u" 2>/dev/null | grep -q '(ALL' && sudo_has="yes"

    cat <<EOF

--------------------------------------------------------------------------
USER : $u
UID  : $(id -u "$u" 2>/dev/null) / GID $(id -g "$u" 2>/dev/null)
HOME : $(getent passwd "$u" | cut -d: -f6)
SHELL: $(getent passwd "$u" | cut -d: -f7)
PASSWD: $pw_status
GROUPS: $groups
SUDO : $sudo_has
LASTLOG: $last
--------------------------------------------------------------------------
EOF
}

_audit_one_user() {
    local u=$1
    _show_user "$u"
    while true; do
        printf "  [s]kip  [p]asswd-change  [l]ock  [u]nlock  [g]roups  [h]ome-perms  [x]disable-shell  [D]ELETE  [n]ext: "
        read -r choice </dev/tty
        case "$choice" in
            s|S|n|N|"") return ;;
            p) passwd "$u" </dev/tty ;;
            l) passwd -l "$u"; ok "locked $u" ;;
            u) passwd -u "$u"; ok "unlocked $u" ;;
            g) printf "  current groups: %s\n  new supplementary group list (comma sep, empty=skip): " "$(id -nG "$u")"
               read -r gl </dev/tty
               [[ -n $gl ]] && usermod -G "$gl" "$u" && ok "groups updated" ;;
            h) local home; home=$(getent passwd "$u" | cut -d: -f6)
               [[ -d $home ]] && chmod 750 "$home" && chown "$u:$u" "$home" && ok "$home -> 750 $u:$u" ;;
            x) usermod -s /usr/sbin/nologin "$u" 2>/dev/null \
                || usermod -s /sbin/nologin "$u" && ok "shell disabled for $u" ;;
            D) printf "  Type the username again to confirm deletion: "
               read -r confirm </dev/tty
               if [[ $confirm == "$u" ]]; then
                   if userdel -r "$u"; then ok "deleted $u"; else err "userdel failed"; fi
                   return
               fi
               warn "no match — cancelled" ;;
            *) printf "  unrecognised\n" ;;
        esac
    done
}

do_user_audit() {
    section "User audit (interactive)"
    # System accounts skipped: UID < 1000 except root.
    local users=()
    while IFS=: read -r name _ uid _ _ _ shell; do
        if [[ $name == root ]]; then users+=("$name"); continue; fi
        if (( uid >= 1000 )) && [[ $shell != */nologin && $shell != */false ]]; then
            users+=("$name")
        fi
    done < /etc/passwd

    log "Real login accounts: ${users[*]:-<none>}"
    for u in "${users[@]}"; do
        _audit_one_user "$u"
    done

    # Add-new-users loop
    while true; do
        printf "\nAdd a new user? [y/N]: "
        read -r yn </dev/tty
        [[ $yn =~ ^[Yy]$ ]] || break
        printf "  username: "; read -r nu </dev/tty
        [[ -z $nu ]] && continue
        if id "$nu" >/dev/null 2>&1; then warn "exists"; continue; fi
        useradd -m -s /bin/bash "$nu" && passwd "$nu" </dev/tty
        printf "  add to sudo/wheel? [y/N]: "; read -r sg </dev/tty
        if [[ $sg =~ ^[Yy]$ ]]; then
            if [[ $DISTRO == debian ]]; then usermod -aG sudo "$nu"; else usermod -aG wheel "$nu"; fi
            ok "$nu added to admin group"
        fi
    done
}

# ============================================================================
# 6. LYNIS-DRIVEN HARDENING
#    Addresses the suggestions from /home/kali/ecitadel/{debian,fedora}/lynis.txt.
#    Items intentionally NOT addressed are listed at the bottom of this file
#    in fn `print_deferred_items` and printed to the user at the end.
# ============================================================================

harden_login_defs() {
    # AUTH-9230 hashing rounds, AUTH-9286 min/max age, AUTH-9328 umask
    section "Hardening /etc/login.defs (AUTH-9230, AUTH-9286, AUTH-9328)"
    local f=/etc/login.defs
    preserve "$f"
    _set_kv() {
        local k=$1 v=$2
        if grep -Eq "^\s*${k}\b" "$f"; then
            sed -i -E "s|^\s*${k}\b.*|${k} ${v}|" "$f"
        else
            printf '%s %s\n' "$k" "$v" >>"$f"
        fi
    }
    _set_kv SHA_CRYPT_MIN_ROUNDS 65536
    _set_kv SHA_CRYPT_MAX_ROUNDS 200000
    _set_kv PASS_MIN_DAYS 1
    _set_kv PASS_MAX_DAYS 90
    _set_kv PASS_WARN_AGE 7
    _set_kv UMASK 027
    _set_kv LOGIN_RETRIES 3
    _set_kv LOG_OK_LOGINS yes
    ok "login.defs updated"

    # AUTH-9282 — set expiry on existing accounts that have none
    while IFS=: read -r u _; do
        [[ -z $u || $u == root ]] && continue
        local uid; uid=$(id -u "$u" 2>/dev/null || echo 0)
        (( uid >= 1000 )) || continue
        chage -M 90 -m 1 -W 7 "$u" 2>/dev/null || true
    done </etc/passwd
    ok "password ageing applied to UID>=1000 accounts (AUTH-9282)"
}

harden_umask_shell() {
    # AUTH-9328 — umask in shell rc files (Lynis flagged 022)
    section "Hardening shell umask"
    for f in /etc/bashrc /etc/bash.bashrc /etc/profile /etc/csh.cshrc; do
        [[ -f $f ]] || continue
        preserve "$f"
        if grep -Eq '^\s*umask\s+0?22' "$f"; then
            sed -i -E 's|^\s*umask\s+0?22|umask 027|' "$f"
        elif ! grep -Eq '^\s*umask\b' "$f"; then
            printf '\numask 027\n' >>"$f"
        fi
    done
    ok "umask 027 in shell rc files"
}

harden_ssh() {
    # SSH-7408 — all flagged items, keeping port 22 per CTF requirement
    section "Hardening sshd_config (SSH-7408)"
    local f=/etc/ssh/sshd_config
    preserve "$f"
    _ssh_set() {
        local k=$1 v=$2
        if grep -Eq "^\s*#?\s*${k}\b" "$f"; then
            sed -i -E "s|^\s*#?\s*${k}\b.*|${k} ${v}|" "$f"
        else
            printf '%s %s\n' "$k" "$v" >>"$f"
        fi
    }
    _ssh_set Port                  "$SSH_HARDEN_PORT"
    _ssh_set AllowTcpForwarding    no
    _ssh_set ClientAliveCountMax   2
    _ssh_set ClientAliveInterval   300
    _ssh_set LogLevel              VERBOSE
    _ssh_set MaxAuthTries          3
    _ssh_set MaxSessions           2
    _ssh_set TCPKeepAlive          no
    _ssh_set X11Forwarding         no
    _ssh_set AllowAgentForwarding  no
    _ssh_set PermitRootLogin       prohibit-password
    _ssh_set PermitEmptyPasswords  no
    _ssh_set Protocol              2
    _ssh_set IgnoreRhosts          yes
    _ssh_set HostbasedAuthentication no
    _ssh_set LoginGraceTime        30

    if sshd -t 2>>"$HARDEN_LOG"; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
        ok "sshd reloaded"
    else
        err "sshd -t failed — restored original"
        cp -a "${f}.harden.orig" "$f"
    fi
}

harden_banners() {
    # BANN-7126 / BANN-7130
    section "Legal banners (BANN-7126, BANN-7130)"
    local banner
    read -r -d '' banner <<'EOF' || true
*****************************************************************
*  Authorized use only. All activity may be monitored and logged.
*  Unauthorized access is prohibited and may be prosecuted under
*  applicable law. Disconnect immediately if you are not an
*  authorised user.
*****************************************************************
EOF
    printf '%s\n' "$banner" >/etc/issue
    printf '%s\n' "$banner" >/etc/issue.net
    printf '%s\n' "$banner" >/etc/motd
    # Make sshd display issue.net
    if grep -Eq '^\s*#?\s*Banner\b' /etc/ssh/sshd_config 2>/dev/null; then
        sed -i -E 's|^\s*#?\s*Banner\b.*|Banner /etc/issue.net|' /etc/ssh/sshd_config
    else
        echo 'Banner /etc/issue.net' >>/etc/ssh/sshd_config
    fi
    ok "banners installed"
}

harden_sysctl() {
    # KRNL-6000, FS protections, network spoof/redirect/source-route protection
    section "Kernel/network sysctl hardening (KRNL-6000)"
    local f=/etc/sysctl.d/99-harden.conf
    cat >"$f" <<'EOF'
# === harden-common: kernel exposure ===
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.core_uses_pid = 1
kernel.perf_event_paranoid = 3
net.core.bpf_jit_harden = 2
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# === network: anti-spoof / redirect / source-route ===
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
EOF
    if sysctl --system >>"$HARDEN_LOG" 2>&1; then
        ok "sysctl applied"
    else
        warn "some sysctl values rejected — see log"
    fi
}

harden_disable_rare_protocols() {
    # NETW-3200 dccp/sctp/rds/tipc, USB-1000, STRG-1846
    section "Disable rare net protocols + USB/firewire storage (NETW-3200, USB-1000, STRG-1846)"
    cat >/etc/modprobe.d/harden-rare-protocols.conf <<'EOF'
install dccp /bin/true
install sctp /bin/true
install rds  /bin/true
install tipc /bin/true
EOF
    cat >/etc/modprobe.d/harden-usb-storage.conf <<'EOF'
install usb-storage /bin/true
EOF
    cat >/etc/modprobe.d/harden-firewire.conf <<'EOF'
install firewire-core /bin/true
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true
EOF
    # Also unload now if loaded (best-effort)
    for m in dccp sctp rds tipc usb_storage firewire_core firewire_ohci firewire_sbp2; do
        modprobe -r "$m" 2>/dev/null || true
    done
    ok "module blacklists written"
}

harden_core_dumps() {
    # KRNL-5820
    section "Disable core dumps (KRNL-5820)"
    preserve /etc/security/limits.conf
    grep -Eq '^\* hard core 0' /etc/security/limits.conf \
        || printf '* hard core 0\n* soft core 0\n' >>/etc/security/limits.conf
    mkdir -p /etc/systemd/coredump.conf.d
    cat >/etc/systemd/coredump.conf.d/disable.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    ok "core dumps disabled"
}

harden_compilers() {
    # HRDN-7222 — chmod 750 root:root common compilers
    section "Restrict compilers to root (HRDN-7222)"
    for c in gcc cc g++ c++ clang make as ld; do
        local p; p=$(command -v "$c" 2>/dev/null || true)
        [[ -n $p && -e $p ]] || continue
        chown root:root "$p" 2>/dev/null && chmod 750 "$p" && log "  $p -> 750 root:root"
    done
    ok "compilers locked down"
}

harden_proc_hidepid() {
    # Lynis hidepid suggestion (mount option for /proc)
    section "Set hidepid=2 on /proc"
    preserve /etc/fstab
    if ! grep -Eq '^\S+\s+/proc\s' /etc/fstab; then
        printf 'proc /proc proc nosuid,nodev,noexec,hidepid=2 0 0\n' >>/etc/fstab
    else
        sed -i -E 's|^(\S+\s+/proc\s+proc\s+)([^ \t]+)|\1nosuid,nodev,noexec,hidepid=2|' /etc/fstab
    fi
    if mount -o remount,hidepid=2 /proc 2>/dev/null; then
        ok "/proc remounted with hidepid=2"
    else
        warn "remount /proc deferred to reboot"
    fi
}

harden_file_perms() {
    # FILE-7524
    section "Restrict sensitive file permissions (FILE-7524)"
    for f in /etc/crontab /etc/cron.deny /etc/cron.allow \
             /etc/at.deny /etc/at.allow \
             /etc/ssh/sshd_config /etc/ssh/ssh_config \
             /boot/grub2/grub.cfg /boot/grub/grub.cfg /etc/securetty; do
        [[ -e $f ]] || continue
        chown root:root "$f" 2>/dev/null && chmod 600 "$f" && log "  $f -> 600 root:root"
    done
    # Cron directories
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [[ -d $d ]] && chown root:root "$d" && chmod 700 "$d"
    done
    ok "permissions restricted"
}

harden_audit() {
    # ACCT-9622 process accounting, ACCT-9626 sysstat, ACCT-9628 auditd
    section "Process accounting + sysstat + auditd (ACCT-9622/9626/9628)"
    if [[ $DISTRO == debian ]]; then
        pkg_install acct sysstat auditd audispd-plugins
    else
        pkg_install psacct sysstat audit
    fi
    systemctl enable --now auditd       2>/dev/null || true
    systemctl enable --now sysstat      2>/dev/null || true
    systemctl enable --now acct         2>/dev/null \
        || systemctl enable --now psacct 2>/dev/null || true

    # Minimal audit ruleset — file mods + privilege escalations + identity changes
    local rules=/etc/audit/rules.d/99-harden.rules
    cat >"$rules" <<'EOF'
-w /etc/passwd       -p wa -k identity
-w /etc/shadow       -p wa -k identity
-w /etc/group        -p wa -k identity
-w /etc/gshadow      -p wa -k identity
-w /etc/sudoers      -p wa -k scope
-w /etc/sudoers.d/   -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /var/log/faillog  -p wa -k logins
-w /var/log/lastlog  -p wa -k logins
-w /var/run/utmp     -p wa -k session
-w /var/log/wtmp     -p wa -k session
-w /var/log/btmp     -p wa -k session
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmd
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmd
EOF
    augenrules --load >>"$HARDEN_LOG" 2>&1 || warn "augenrules --load failed"
    ok "audit ruleset loaded"
}

harden_failed_logins() {
    # Lynis "Logging failed login attempts DISABLED" (Fedora)
    section "Enable failed-login logging"
    if [[ -f /etc/login.defs ]]; then
        grep -q '^FAILLOG_ENAB'   /etc/login.defs && sed -i 's|^FAILLOG_ENAB.*|FAILLOG_ENAB yes|'   /etc/login.defs || echo 'FAILLOG_ENAB yes'   >>/etc/login.defs
        grep -q '^SYSLOG_SU_ENAB' /etc/login.defs && sed -i 's|^SYSLOG_SU_ENAB.*|SYSLOG_SU_ENAB yes|' /etc/login.defs || echo 'SYSLOG_SU_ENAB yes' >>/etc/login.defs
        grep -q '^SYSLOG_SG_ENAB' /etc/login.defs && sed -i 's|^SYSLOG_SG_ENAB.*|SYSLOG_SG_ENAB yes|' /etc/login.defs || echo 'SYSLOG_SG_ENAB yes' >>/etc/login.defs
    fi
    ok "faillog/syslog su/sg enabled"
}

harden_locate_db() {
    # FILE-6410
    section "Build locate database (FILE-6410)"
    command -v updatedb >/dev/null 2>&1 || pkg_install mlocate plocate 2>/dev/null
    if updatedb 2>>"$HARDEN_LOG"; then
        ok "updatedb done"
    else
        warn "updatedb unavailable"
    fi
}

harden_hosts_fqdn() {
    # NAME-4404
    section "Ensure /etc/hosts has FQDN entry (NAME-4404)"
    local short fqdn
    short=$(hostname -s)
    fqdn=$(hostname -f 2>/dev/null || echo "${short}.localdomain")
    preserve /etc/hosts
    if ! grep -Eq "[[:space:]]${fqdn}([[:space:]]|$)" /etc/hosts; then
        printf '127.0.1.1 %s %s\n' "$fqdn" "$short" >>/etc/hosts
        ok "/etc/hosts updated with $fqdn"
    else
        ok "/etc/hosts already has FQDN"
    fi
}

# ============================================================================
# 7. ITEMS DELIBERATELY NOT AUTOMATED
# ============================================================================
print_deferred_items() {
    section "Lynis suggestions deliberately NOT applied"
    cat <<EOF | tee -a "$HARDEN_LOG"
The following Lynis findings were intentionally skipped — they cannot be
safely resolved by a script in a CTF context. Handle manually if you need
the score bump:

  * FILE-6310  — Place /var and /home on separate partitions.
                 Skipped: partitioning is set at install time. Would require
                 a reinstall or live LVM/migration — too risky during a CTF.

  * KRNL-5830  — Reboot required (Fedora flagged this on first scan).
                 Skipped: rebooting mid-CTF is your call, not the script's.
                 The script prints a reminder at the very end if a reboot
                 is needed (presence of /var/run/reboot-required or kernel
                 version mismatch).

  * BOOT-5264  — Per-service systemd hardening (\`systemd-analyze security\`).
                 Skipped: would require generating drop-ins for ~80 services
                 with no way to know which ones a CTF flag will need. Tighten
                 individually if a service you don't need is UNSAFE.

  * NETW-2705  — "Couldn't find 2 responsive nameservers" (Debian).
  * NAME-4028  — Check DNS configuration for the dns domain name.
                 Skipped: depends on the CTF network. Set /etc/resolv.conf
                 manually once you know the scoring DNS layout.

  * LOGG-2154  — External logging host.
                 Addressed: do_splunk_forwarder installs the Splunk UF and
                 forwards security/syslog/audit/journal/web/db/dns logs to
                 \${SPLUNK_INDEXER} (or a deployment server if set). Set
                 SPLUNK_FWD=0 to opt out.

  * LOGG-2190  — Deleted files still in use.
                 Skipped: requires manual investigation of \`lsof | grep deleted\`.

  * PKGS-7420  — Automatic upgrades.
                 Skipped on purpose: unattended-upgrades / dnf-automatic mid-CTF
                 can pull a package that breaks a scored service. Run the
                 do_update step manually.

  * BOOT-5122  — Set a password on GRUB.
                 Skipped: physical console access is usually not in scope and
                 a forgotten GRUB password locks you out of recovery. Set
                 manually with \`grub-mkpasswd-pbkdf2\` if you want it.

  * BOOT-5180  — Determine runlevel and services at startup.
                 Skipped: this is a Lynis informational; nothing to change.

  * HTTP-6640 / HTTP-6643 — Install mod_evasive / modsecurity.
                 Skipped from baseline: only relevant if Apache is the scored
                 service. Enable BACKUP_WEB=1 and install these on day-of if
                 your box runs Apache.

  * PRNT-2307  — CUPS configuration tighter.
                 Skipped: if you don't print, just \`systemctl disable --now cups\`.

  * PKGS-7370  — debsums.        (Debian) — added separately to do_update step.
  * PKGS-7394  — apt-show-versions. (Debian) — added separately to do_update step.

  * AUTH-9262  — pam_passwdqc / pam_cracklib.
                 Applied as best-effort in the distro wrappers (pwquality on
                 Fedora, libpam-pwquality on Debian) — see distro-specific
                 script.

  * TOOL-5002  — Automation tools (Ansible/Salt/...).
                 Skipped: out of scope for a CTF baseline.
EOF
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    require_root
    umask 077
    touch "$HARDEN_LOG" && chmod 600 "$HARDEN_LOG"
    log "Harden run starting on $(hostname) ($DISTRO). Log -> $HARDEN_LOG"

    do_update
    distro_pre_harden    # hook implemented by debian/fedora wrappers
    do_backup
    do_aide
    do_splunk_forwarder

    harden_login_defs
    harden_umask_shell
    harden_ssh
    harden_banners
    harden_sysctl
    harden_disable_rare_protocols
    harden_core_dumps
    harden_compilers
    harden_proc_hidepid
    harden_file_perms
    harden_audit
    harden_failed_logins
    harden_locate_db
    harden_hosts_fqdn

    distro_post_harden   # hook implemented by debian/fedora wrappers

    do_malware_scan
    do_user_audit

    print_deferred_items

    section "DONE"
    ok "Log saved to $HARDEN_LOG"
    local newest_kmod
    newest_kmod=$(find /lib/modules -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -V | tail -1)
    if [[ -f /var/run/reboot-required ]] || [[ $(uname -r) != "$newest_kmod" ]]; then
        warn "A reboot is recommended (kernel update or pending reboot flag)."
        if [[ $SKIP_REBOOT_PROMPT == 0 ]]; then
            printf "Reboot now? [y/N]: "; read -r yn </dev/tty
            [[ $yn =~ ^[Yy]$ ]] && systemctl reboot
        fi
    fi
}
