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
#   * pubkey auth → rejected at the honeypot. Paramiko can't MITM pubkey
#       without the user's private key. Admins who need pubkey should connect
#       to 127.0.0.1:$REAL_SSH_PORT directly (e.g. via local console or an
#       ssh-tunnel established with a password first).
#
# Config (env vars, all optional):
#   HONEYPOT_PORT       listen port                       (default 22)
#   REAL_SSH_HOST       backend host                      (default 127.0.0.1)
#   REAL_SSH_PORT       backend port                      (default 2222)
#   WEAK_PASS_FILE      one password per line, # comments (default /etc/ssh-honeypot/weak-passwords.txt)
#   HOST_KEY_PATH       RSA key for honeypot              (default /etc/ssh-honeypot/host_rsa_key, auto-generated)
#   LOG_DIR             session + access log root         (default /var/log/ssh-honeypot)
#   FAKE_HOSTNAME       what the fake shell pretends to be (default real hostname)
#
# Logs:
#   $LOG_DIR/access.log               — one line per event (auth_attempt,
#                                       connect, cmd, exec, disconnect)
#   $LOG_DIR/sessions/<id>.log        — full per-session trace

import logging
import os
import select
import socket
import sys
import threading
import time
from pathlib import Path

import paramiko

HONEYPOT_PORT  = int(os.environ.get("HONEYPOT_PORT", "22"))
REAL_SSH_HOST  = os.environ.get("REAL_SSH_HOST", "127.0.0.1")
REAL_SSH_PORT  = int(os.environ.get("REAL_SSH_PORT", "2222"))
WEAK_PASS_FILE = os.environ.get("WEAK_PASS_FILE", "/etc/ssh-honeypot/weak-passwords.txt")
HOST_KEY_PATH  = os.environ.get("HOST_KEY_PATH",  "/etc/ssh-honeypot/host_rsa_key")
LOG_DIR        = Path(os.environ.get("LOG_DIR",   "/var/log/ssh-honeypot"))
FAKE_HOSTNAME  = os.environ.get("FAKE_HOSTNAME",  socket.gethostname())

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

def get_or_create_host_key():
    key_path = Path(HOST_KEY_PATH)
    if not key_path.exists():
        key_path.parent.mkdir(parents=True, exist_ok=True)
        logging.info("generating new RSA host key at %s", key_path)
        k = paramiko.RSAKey.generate(3072)
        k.write_private_key_file(str(key_path))
        os.chmod(str(key_path), 0o600)
    return paramiko.RSAKey(filename=str(key_path))

HOST_KEY = get_or_create_host_key()


def try_backend_auth(username, password):
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
        logging.debug("backend auth failed for %s: %s", username, e)
    return None


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
        self.request_event = threading.Event()
        self.exec_command = None

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_publickey(self, username, key):
        master_log(event="auth_attempt", ip=self.peer[0], user=username,
                   method="publickey", result="rejected_no_mitm")
        return paramiko.AUTH_FAILED

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
        t = try_backend_auth(username, password)
        if t is not None:
            self.proxy_transport = t
            self.mode = "proxy"
            master_log(event="auth_attempt", ip=self.peer[0], user=username,
                       method="password", result="proxy_accepted")
            session_log(self.session_id,
                        f"AUTH (proxy) user={username} — backend accepted")
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

    # Reject anything we can't safely proxy
    def check_channel_subsystem_request(self, ch, name):
        master_log(event="subsystem_request", ip=self.peer[0],
                   user=self.username, name=name, result="rejected")
        return False

    def check_port_forward_request(self, addr, port):
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
    t.add_server_key(HOST_KEY)
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
            if server.exec_command is not None:
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
