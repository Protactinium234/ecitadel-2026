#!/usr/bin/env python3
# ssh-honeypot.py — selective SSH honeypot for CTF blue-team use.
#
# Listens on :22 in front of the real sshd (which gets moved to
# 127.0.0.1:$REAL_SSH_PORT by the harden script). For each connection:
#
#   * weak password (matches a line in /etc/ssh-honeypot/weak-passwords.txt)
#     → accept, present a fake shell, log every command the attacker types,
#       NEVER execute anything for real.
#
#   * any other password → try it against the real backend; if backend accepts,
#       bidirectionally proxy the session so legit users see nothing unusual.
#
#   * pubkey auth → verified against the user's ACTUAL ~/.ssh/authorized_keys
#       on disk. If it's a valid key, we open the backend session using our
#       dedicated proxy key (which is installed in every real user's
#       authorized_keys with from="127.0.0.1" restriction). The client sees
#       a fully working pubkey session — fingerprint, auth, shell/sftp all
#       indistinguishable from connecting straight to real sshd.
#
#   * sftp/scp subsystems → proxied through in proxy mode; faked-fail in
#       honey mode (attackers using "password" rarely do SFTP first).
#
# Host keys: we load /etc/ssh/ssh_host_*_key (the real sshd's keys) so the
# host-key fingerprint a client sees is identical to what they'd see talking
# to real sshd directly. No host-key-changed warnings.
#
# Config (env vars, all optional):
#   HONEYPOT_PORT       listen port                       (default 22)
#   REAL_SSH_HOST       backend host                      (default 127.0.0.1)
#   REAL_SSH_PORT       backend port                      (default 2222)
#   WEAK_PASS_FILE      one password per line, # comments (default /etc/ssh-honeypot/weak-passwords.txt)
#   HOST_KEY_DIR        where to look for ssh_host_*_key  (default /etc/ssh)
#   FALLBACK_KEY_PATH   RSA key if real host keys absent  (default /etc/ssh-honeypot/host_rsa_key)
#   PROXY_KEY_PATH      ed25519 key for backend pubkey-as-user (default /etc/ssh-honeypot/proxy_id_ed25519)
#   LOG_DIR             session + access log root         (default /var/log/ssh-honeypot)
#   FAKE_HOSTNAME       what the fake shell pretends to be (default real hostname)
#
# Logs:
#   $LOG_DIR/access.log               — one line per event (auth_attempt,
#                                       connect, cmd, exec, disconnect)
#   $LOG_DIR/sessions/<id>.log        — full per-session trace

import logging
import os
import pwd
import select
import socket
import sys
import threading
import time
from pathlib import Path

import paramiko

HONEYPOT_PORT     = int(os.environ.get("HONEYPOT_PORT", "22"))
REAL_SSH_HOST     = os.environ.get("REAL_SSH_HOST", "127.0.0.1")
REAL_SSH_PORT     = int(os.environ.get("REAL_SSH_PORT", "2222"))
WEAK_PASS_FILE    = os.environ.get("WEAK_PASS_FILE", "/etc/ssh-honeypot/weak-passwords.txt")
HOST_KEY_DIR      = os.environ.get("HOST_KEY_DIR", "/etc/ssh")
FALLBACK_KEY_PATH = os.environ.get("FALLBACK_KEY_PATH", "/etc/ssh-honeypot/host_rsa_key")
PROXY_KEY_PATH    = os.environ.get("PROXY_KEY_PATH", "/etc/ssh-honeypot/proxy_id_ed25519")
LOG_DIR           = Path(os.environ.get("LOG_DIR", "/var/log/ssh-honeypot"))
FAKE_HOSTNAME     = os.environ.get("FAKE_HOSTNAME", socket.gethostname())

LOG_DIR.mkdir(parents=True, exist_ok=True)
(LOG_DIR / "sessions").mkdir(exist_ok=True)
ACCESS_LOG = LOG_DIR / "access.log"

_master_lock = threading.Lock()

def master_log(**kw):
    # Splunk-friendly key=value line, with timestamp first.
    pairs = " ".join(f"{k}={v!r}" for k, v in kw.items())
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {pairs}\n"
    with _master_lock:
        with open(ACCESS_LOG, "a") as f:
            f.write(line)

def session_log(sid, msg):
    with open(LOG_DIR / "sessions" / f"{sid}.log", "a") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

def load_weak_passwords():
    p = Path(WEAK_PASS_FILE)
    if not p.exists():
        logging.error("weak-password file missing: %s", p)
        return set()
    out = set()
    for line in p.read_text().splitlines():
        s = line.rstrip("\r")
        if not s or s.lstrip().startswith("#"):
            continue
        out.add(s)
    return out

WEAK_PASSWORDS = load_weak_passwords()

def load_host_keys():
    """Load /etc/ssh/ssh_host_*_key so the honeypot's fingerprint matches the
    real sshd byte-for-byte. Falls back to a self-generated RSA key only if
    no real host keys are readable (e.g. in tests)."""
    candidates = [
        (paramiko.Ed25519Key, f"{HOST_KEY_DIR}/ssh_host_ed25519_key"),
        (paramiko.ECDSAKey,   f"{HOST_KEY_DIR}/ssh_host_ecdsa_key"),
        (paramiko.RSAKey,     f"{HOST_KEY_DIR}/ssh_host_rsa_key"),
    ]
    keys = []
    for cls, path in candidates:
        if not os.path.exists(path):
            continue
        try:
            keys.append(cls(filename=path))
            logging.info("loaded host key %s (%s)", path, cls.__name__)
        except Exception as e:
            logging.warning("couldn't load %s: %s", path, e)
    if not keys:
        fb = Path(FALLBACK_KEY_PATH)
        if not fb.exists():
            fb.parent.mkdir(parents=True, exist_ok=True)
            logging.warning("no real host keys found — generating fallback at %s", fb)
            k = paramiko.RSAKey.generate(3072)
            k.write_private_key_file(str(fb))
            os.chmod(str(fb), 0o600)
        keys.append(paramiko.RSAKey(filename=str(fb)))
    return keys

HOST_KEYS = load_host_keys()


def load_proxy_key():
    """The honeypot's own key for connecting to backend AS the user — once
    we've verified the client's pubkey against their real authorized_keys."""
    if os.path.exists(PROXY_KEY_PATH):
        try:
            return paramiko.Ed25519Key(filename=PROXY_KEY_PATH)
        except Exception:
            try:
                return paramiko.RSAKey(filename=PROXY_KEY_PATH)
            except Exception as e:
                logging.error("proxy key at %s unreadable: %s", PROXY_KEY_PATH, e)
    logging.warning("no proxy key at %s — pubkey-mode proxying will fail", PROXY_KEY_PATH)
    return None

PROXY_KEY = load_proxy_key()
PROXY_PUBKEY_B64 = PROXY_KEY.get_base64() if PROXY_KEY else None


def try_backend_auth_password(username, password):
    """Open a real SSH connection to the backend with these creds.
    On success return the live Transport so we can reuse it as the
    proxy session — we don't want to authenticate twice."""
    try:
        sock = socket.create_connection((REAL_SSH_HOST, REAL_SSH_PORT), timeout=10)
        t = paramiko.Transport(sock)
        t.start_client(timeout=10)
        t.auth_password(username, password)
        if t.is_authenticated():
            return t
        t.close()
    except Exception as e:
        logging.debug("backend password auth failed for %s: %s", username, e)
    return None


def try_backend_auth_pubkey(username):
    """Open a backend session AS `username` using the honeypot's own proxy
    key. Backend trusts this key because the harden script installed its
    pubkey into every real user's authorized_keys with from=127.0.0.1."""
    if PROXY_KEY is None:
        return None
    try:
        sock = socket.create_connection((REAL_SSH_HOST, REAL_SSH_PORT), timeout=10)
        t = paramiko.Transport(sock)
        t.start_client(timeout=10)
        t.auth_publickey(username, PROXY_KEY)
        if t.is_authenticated():
            return t
        t.close()
    except Exception as e:
        logging.debug("backend pubkey auth failed for %s: %s", username, e)
    return None


# authorized_keys token names — anything starting with one of these is a key
# type rather than a comma-separated options field.
_KEY_TYPES = (
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
)

def _key_in_authorized_keys(presented_key, ak_path):
    """True if `presented_key` (a paramiko PKey) matches any entry in
    the OpenSSH authorized_keys file at `ak_path`. Honors options prefix
    (e.g. from="..."), ignores comments and blank lines, skips our own
    proxy key so attackers can't trivially auth as anyone by replaying it."""
    if not os.path.exists(ak_path):
        return False
    presented_b64 = presented_key.get_base64()
    presented_type = presented_key.get_name()
    try:
        with open(ak_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                toks = line.split()
                # Find the key-type token; everything before it is options.
                for i, tok in enumerate(toks):
                    if tok in _KEY_TYPES:
                        if i + 1 >= len(toks):
                            break
                        keytype, keydata = tok, toks[i + 1]
                        # Don't let an attacker who somehow learns our proxy
                        # pubkey use it as a client-side credential.
                        if PROXY_PUBKEY_B64 and keydata == PROXY_PUBKEY_B64:
                            break
                        if keytype == presented_type and keydata == presented_b64:
                            return True
                        break
    except Exception as e:
        logging.error("reading %s: %s", ak_path, e)
    return False


def _key_fingerprint(key):
    """Short SHA256 fingerprint for logging — matches `ssh-keygen -lf` output."""
    import hashlib
    import base64
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, peer, session_id):
        self.peer = peer
        self.session_id = session_id
        self.mode = None              # "honey" or "proxy"
        self.username = None
        self.password = None
        self.proxy_transport = None
        self.pty_term = "xterm"
        self.pty_size = (80, 24)
        self.pty_requested = False
        self.request_event = threading.Event()
        self.exec_command = None
        self.subsystem = None         # "sftp" if SFTP requested

    def get_allowed_auths(self, username):
        # Offer both — clients negotiate; we accept whichever first succeeds.
        return "password,publickey"

    def check_auth_publickey(self, username, key):
        self.username = username
        # First check the user's REAL authorized_keys — that's the ground truth.
        try:
            home = pwd.getpwnam(username).pw_dir
        except KeyError:
            master_log(event="auth_attempt", ip=self.peer[0], user=username,
                       method="publickey", result="rejected_no_user",
                       key_fp=_key_fingerprint(key))
            return paramiko.AUTH_FAILED
        ak_path = os.path.join(home, ".ssh", "authorized_keys")
        if not _key_in_authorized_keys(key, ak_path):
            master_log(event="auth_attempt", ip=self.peer[0], user=username,
                       method="publickey", result="rejected",
                       key_fp=_key_fingerprint(key))
            return paramiko.AUTH_FAILED

        # Verified. Now open the backend session AS this user using our proxy
        # key. Backend trusts it because harden_ssh_honeypot installed our
        # pubkey in this user's authorized_keys with from="127.0.0.1".
        t = try_backend_auth_pubkey(username)
        if t is None:
            master_log(event="auth_attempt", ip=self.peer[0], user=username,
                       method="publickey", result="proxy_key_unaccepted",
                       key_fp=_key_fingerprint(key))
            return paramiko.AUTH_FAILED

        self.proxy_transport = t
        self.mode = "proxy"
        master_log(event="auth_attempt", ip=self.peer[0], user=username,
                   method="publickey", result="proxy_accepted",
                   key_fp=_key_fingerprint(key))
        session_log(self.session_id,
                    f"AUTH (proxy/pubkey) user={username} fp={_key_fingerprint(key)}")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        if password in WEAK_PASSWORDS:
            self.mode = "honey"
            master_log(event="auth_attempt", ip=self.peer[0], user=username,
                       password=password, method="password",
                       result="honey_accepted")
            session_log(self.session_id,
                        f"AUTH (honey) user={username} pass={password}")
            return paramiko.AUTH_SUCCESSFUL
        t = try_backend_auth_password(username, password)
        if t is not None:
            self.proxy_transport = t
            self.mode = "proxy"
            master_log(event="auth_attempt", ip=self.peer[0], user=username,
                       method="password", result="proxy_accepted")
            session_log(self.session_id,
                        f"AUTH (proxy/password) user={username}")
            return paramiko.AUTH_SUCCESSFUL
        master_log(event="auth_attempt", ip=self.peer[0], user=username,
                   password=password, method="password", result="rejected")
        session_log(self.session_id,
                    f"AUTH rejected user={username} pass={password}")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return (paramiko.OPEN_SUCCEEDED if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_pty_request(self, ch, term, w, h, pw, ph, modes):
        self.pty_term = term.decode() if isinstance(term, bytes) else term
        self.pty_size = (w, h)
        self.pty_requested = True
        return True

    def check_channel_shell_request(self, ch):
        self.request_event.set()
        return True

    def check_channel_exec_request(self, ch, command):
        self.exec_command = (command.decode(errors="replace")
                             if isinstance(command, bytes) else command)
        self.request_event.set()
        return True

    def check_channel_window_change_request(self, ch, w, h, pw, ph):
        self.pty_size = (w, h)
        return True

    def check_channel_subsystem_request(self, ch, name):
        name = name.decode() if isinstance(name, bytes) else name
        if name == "sftp":
            if self.mode == "honey":
                # Don't expose anything in honey mode — but log the attempt.
                master_log(event="subsystem_request", ip=self.peer[0],
                           user=self.username, name=name, result="rejected_honey")
                return False
            self.subsystem = name
            self.request_event.set()
            master_log(event="subsystem_request", ip=self.peer[0],
                       user=self.username, name=name, result="proxied")
            return True
        master_log(event="subsystem_request", ip=self.peer[0],
                   user=self.username, name=name, result="rejected_unknown")
        return False

    def check_port_forward_request(self, addr, port):
        # Forwarded TCP-IP (ssh -R) — proxy mode could relay, but cross-thread
        # paramiko forwarding is finicky. Refuse for now; clients fall back to
        # local forwarding (ssh -L), which goes through the channel layer and
        # works transparently via the proxy session.
        master_log(event="port_forward_request", ip=self.peer[0],
                   user=self.username, target=f"{addr}:{port}", result="rejected")
        return False


# ---------- HONEY MODE ----------

# Canned responses for the handful of probes attackers usually run first.
# Real shell-out is never invoked — we just return plausible-looking text.
FAKE_PASSWD = (
    b"root:x:0:0:root:/root:/bin/bash\r\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
    b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
    b"sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n"
)

def honey_canned(line):
    """Return a bytes reply for known probe commands, or b'' for everything
    else (silently no-op). All commands are still logged before this is
    called — this only controls what the attacker sees back."""
    cmd = line.strip()
    if cmd in ("", ":"):                          return b""
    if cmd == "whoami":                           return None  # filled in caller
    if cmd == "id":                               return b"uid=0(root) gid=0(root) groups=0(root)\r\n"
    if cmd == "pwd":                              return b"/root\r\n"
    if cmd in ("ls", "ls -la", "ls -l", "ll", "dir"):
        return b"\r\n"                            # empty dir
    if cmd in ("hostname",):                      return f"{FAKE_HOSTNAME}\r\n".encode()
    if cmd.startswith("uname"):                   return b"Linux\r\n"
    if cmd in ("cat /etc/passwd", "head /etc/passwd"):
        return FAKE_PASSWD
    if cmd == "cat /etc/shadow":                  return b"cat: /etc/shadow: Permission denied\r\n"
    if cmd in ("ps", "ps aux", "ps -ef"):
        return (b"  PID TTY          TIME CMD\r\n"
                b"    1 ?        00:00:00 systemd\r\n"
                b"  427 ?        00:00:00 sshd\r\n")
    if cmd.startswith("sudo "):                   return b"sudo: a password is required\r\n"
    if cmd.startswith("wget ") or cmd.startswith("curl "):
        return b"\r\n"                            # silently swallow
    return b""                                    # default: no reply, no execution


def fake_shell(channel, server):
    session_log(server.session_id, "fake shell started")
    try:
        channel.send(b"Last login: " +
                     time.strftime("%a %b %e %T %Y").encode() +
                     b"\r\n")
        prompt = f"[{server.username}@{FAKE_HOSTNAME} ~]# ".encode()
        buf = b""
        channel.send(prompt)
        while True:
            data = channel.recv(1024)
            if not data:
                break
            # Echo (terminals normally echo, the attacker's client will turn
            # this off if it has its own line editor; harmless either way).
            channel.send(data)
            buf += data
            if b"\r" not in data and b"\n" not in data:
                continue
            # Process complete line(s)
            lines = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
            buf = lines.pop().encode() if isinstance(lines[-1], str) else lines.pop()
            for raw in lines:
                line = raw.decode(errors="replace")
                channel.send(b"\n")
                master_log(event="cmd", session=server.session_id,
                           user=server.username, ip=server.peer[0], cmd=line)
                session_log(server.session_id, f"CMD: {line!r}")
                if line.strip() in ("exit", "logout", "quit"):
                    channel.send(b"logout\r\n")
                    return
                reply = honey_canned(line)
                if reply is None:                # placeholder for "whoami"
                    reply = (server.username + "\r\n").encode()
                if reply:
                    channel.send(reply)
                channel.send(prompt)
    except Exception as e:
        session_log(server.session_id, f"shell exception: {e}")
    finally:
        session_log(server.session_id, "fake shell ended")


def fake_exec(channel, server, command):
    """Non-interactive form: `ssh user@host -- some-command`. Log and exit 0."""
    master_log(event="exec", session=server.session_id, user=server.username,
               ip=server.peer[0], cmd=command)
    session_log(server.session_id, f"EXEC (faked): {command!r}")
    try:
        # Return canned reply if we recognise it, else nothing
        reply = honey_canned(command)
        if reply is None:
            reply = (server.username + "\r\n").encode()
        if reply:
            channel.send(reply)
        channel.send_exit_status(0)
    finally:
        try: channel.close()
        except Exception: pass


# ---------- PROXY MODE ----------

def _bridge(a, b):
    """Bidirectional copy until either side closes."""
    while True:
        try:
            r, _, _ = select.select([a, b], [], [], 30)
        except Exception:
            return
        if not r:
            # Detect dead sides
            if (a.closed if hasattr(a, "closed") else False) or \
               (b.closed if hasattr(b, "closed") else False):
                return
            continue
        for src, dst in ((a, b), (b, a)):
            if src in r:
                try:
                    data = src.recv(4096)
                except Exception:
                    return
                if not data:
                    return
                try:
                    dst.send(data)
                except Exception:
                    return


def proxy_shell(channel, server):
    session_log(server.session_id, "proxy shell started")
    try:
        back = server.proxy_transport.open_session(timeout=10)
        if server.pty_requested:
            back.get_pty(term=server.pty_term,
                         width=server.pty_size[0], height=server.pty_size[1])
        back.invoke_shell()
        _bridge(channel, back)
    except Exception as e:
        session_log(server.session_id, f"proxy shell exception: {e}")
    finally:
        try: server.proxy_transport.close()
        except Exception: pass
        session_log(server.session_id, "proxy shell ended")


def proxy_subsystem(channel, server, name):
    """Bridge a subsystem channel (sftp) to the backend."""
    session_log(server.session_id, f"proxy subsystem={name} started")
    try:
        back = server.proxy_transport.open_session(timeout=10)
        back.invoke_subsystem(name)
        _bridge(channel, back)
    except Exception as e:
        session_log(server.session_id, f"proxy subsystem exception: {e}")
    finally:
        try: server.proxy_transport.close()
        except Exception: pass
        session_log(server.session_id, f"proxy subsystem={name} ended")


def proxy_exec(channel, server, command):
    session_log(server.session_id, f"proxy exec: {command!r}")
    try:
        back = server.proxy_transport.open_session(timeout=10)
        back.exec_command(command)
        _bridge(channel, back)
        try:
            channel.send_exit_status(back.recv_exit_status())
        except Exception: pass
    except Exception as e:
        session_log(server.session_id, f"proxy exec exception: {e}")
    finally:
        try: server.proxy_transport.close()
        except Exception: pass


# ---------- CONNECTION DISPATCH ----------

def handle_connection(client_sock, peer):
    sid = f"{time.strftime('%Y%m%d-%H%M%S')}-{peer[0]}-{peer[1]}-{os.getpid()}"
    session_log(sid, f"new connection from {peer[0]}:{peer[1]}")
    master_log(event="connect", ip=peer[0], port=peer[1], session=sid)

    t = paramiko.Transport(client_sock)
    for k in HOST_KEYS:
        t.add_server_key(k)
    t.local_version = "SSH-2.0-OpenSSH_9.6p1"   # match real Fedora 43 sshd
    server = HoneypotServer(peer, sid)
    try:
        t.start_server(server=server)
    except (paramiko.SSHException, EOFError) as e:
        session_log(sid, f"start_server failed: {e}")
        master_log(event="disconnect", ip=peer[0], session=sid,
                   reason="ssh_handshake_failed")
        try: t.close()
        except Exception: pass
        return

    channel = t.accept(20)
    if channel is None or not server.request_event.wait(20):
        session_log(sid, "no shell/exec within 20s")
        try: t.close()
        except Exception: pass
        return

    try:
        if server.mode == "honey":
            if server.exec_command is not None:
                fake_exec(channel, server, server.exec_command)
            else:
                fake_shell(channel, server)
        else:
            if server.subsystem == "sftp":
                proxy_subsystem(channel, server, "sftp")
            elif server.exec_command is not None:
                proxy_exec(channel, server, server.exec_command)
            else:
                proxy_shell(channel, server)
    finally:
        master_log(event="disconnect", ip=peer[0], session=sid,
                   mode=server.mode, user=server.username or "")
        try: channel.close()
        except Exception: pass
        try: t.close()
        except Exception: pass


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    paramiko.util.log_to_file(str(LOG_DIR / "paramiko.log"), level="WARNING")
    if not WEAK_PASSWORDS:
        logging.warning("weak password list is empty — nothing will be honey-trapped!")
    logging.info("listening on 0.0.0.0:%d → backend %s:%d (%d weak passwords)",
                 HONEYPOT_PORT, REAL_SSH_HOST, REAL_SSH_PORT,
                 len(WEAK_PASSWORDS))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", HONEYPOT_PORT))
    s.listen(100)

    while True:
        try:
            client, peer = s.accept()
        except KeyboardInterrupt:
            logging.info("shutting down")
            return
        except Exception as e:
            logging.error("accept(): %s", e)
            continue
        threading.Thread(target=handle_connection,
                         args=(client, peer), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("fatal: %s", e)
        sys.exit(1)
