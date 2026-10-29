"""
bot.py - Habibi IRC bot (whois collector + !search).

Environment variables (all optional except NICKSERV_PASSWORD):
    NICKSERV_PASSWORD   NickServ password for the bot nick
    IRC_SERVER          default irc.hybridirc.com
    IRC_PORT            default 6697 (SSL)
    IRC_VERIFY_SSL      set to 1 to verify the server certificate (default: off)
    BOT_NICK / BOT_REALNAME   default habibi
    DEFAULT_CHANNELS    default #chatindian,#chatwithworld,#global
    COMMAND_CHANNEL     only channel where commands work, default #chatwithworld
    SUPER_ADMINS        default Antonio,juggu,Starboy,sasha
    TZ_OFFSET_MIN / TZ_LABEL   time shown in results, default 345 / Nepal Time
"""
import collections
import logging
import os
import re
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone

log = logging.getLogger("habibi.bot")


def env(name, default=""):
    return os.environ.get(name, default)


SERVER = env("IRC_SERVER", "irc.hybridirc.com")
PORT = int(env("IRC_PORT", "6697"))
USE_SSL = env("IRC_SSL", "1") != "0"
VERIFY_SSL = env("IRC_VERIFY_SSL", "0") == "1"
NICK = env("BOT_NICK", "habibi")
REALNAME = env("BOT_REALNAME", "habibi")
NICKSERV_PASSWORD = env("NICKSERV_PASSWORD")
DEFAULT_CHANNELS = [
    c.strip()
    for c in env("DEFAULT_CHANNELS", "#chatindian,#chatwithworld,#global").split(",")
    if c.strip()
]
COMMAND_CHANNEL = env("COMMAND_CHANNEL", "#chatwithworld").lower()
ADMIN_DISPLAY = [a.strip() for a in env("SUPER_ADMINS", "Antonio,juggu,Starboy,sasha").split(",") if a.strip()]
ADMIN_SET = {a.lower() for a in ADMIN_DISPLAY}

WHOIS_DELAY = float(env("WHOIS_DELAY", "1.5"))   # seconds between whois requests
LINE_DELAY = float(env("LINE_DELAY", "0.7"))     # seconds between reply lines (700 ms)
MAX_RESULTS = 30
NAMES_SKIP_SECONDS = 600   # on join-list, skip whois for users seen in the last 10 min

TZ_OFFSET_MIN = int(env("TZ_OFFSET_MIN", "345"))
TZ_LABEL = env("TZ_LABEL", "Nepal Time")

FORMAT_RE = re.compile(r"\x03\d{1,2}(?:,\d{1,2})?|[\x02\x0f\x16\x1d\x1e\x1f\x11\x03]")
NICK_RE = re.compile(r"^[A-Za-z0-9_\-\[\]\\`^{|}]{1,32}$")
CHAN_RE = re.compile(r"^#[^\s,\x07]{1,60}$")
NICKSERV_OK_RE = re.compile(
    r"(you are now (identified|logged in)|password accepted|identified for|you are already identified|recognized)",
    re.I,
)


def clean(s):
    return FORMAT_RE.sub("", s or "").strip()


def fmt_time(epoch):
    """Format like the JS Date string shown in the sample."""
    tz = timezone(timedelta(minutes=TZ_OFFSET_MIN))
    dt = datetime.fromtimestamp(int(epoch), tz)
    sign = "+" if TZ_OFFSET_MIN >= 0 else "-"
    m = abs(TZ_OFFSET_MIN)
    return dt.strftime("%a %b %d %Y %H:%M:%S") + f" GMT{sign}{m // 60:02d}{m % 60:02d} ({TZ_LABEL})"


def fmt_uptime(seconds):
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{s // 86400}d {(s % 86400) // 3600}h"


def parse_line(line):
    """Return (prefix, command, params). Trailing param is the last element."""
    prefix = ""
    if line.startswith(":"):
        prefix, _, line = line[1:].partition(" ")
    head, sep, trailing = line.partition(" :")
    params = head.split()
    if sep:
        params.append(trailing)
    if not params:
        return prefix, "", []
    return prefix, params[0].upper(), params[1:]


def nick_of(prefix):
    return prefix.split("!", 1)[0]


def split_text(text, limit=400):
    """Split text into chunks that fit in one IRC line."""
    out = []
    while len(text.encode("utf-8", "replace")) > limit:
        cut = limit
        while len(text[:cut].encode("utf-8", "replace")) > limit:
            cut -= 10
        sp = text.rfind(" ", 0, cut)
        if sp < limit // 2:
            sp = cut
        out.append(text[:sp])
        text = text[sp:].lstrip()
    out.append(text)
    return out


class HabibiBot:
    def __init__(self, store):
        self.store = store
        self.started = time.time()
        self.sock = None
        self.send_lock = threading.Lock()

        self.qlock = threading.Lock()
        self.out_q = collections.deque()      # reply lines, 700 ms apart
        self.whois_q = collections.deque()    # nicks to whois, 1.5 s apart
        self.whois_queued = set()
        self.last_whois = {}

        self.nick_key = store.load_nick_keys()
        self.last_touch = {}
        self.pending = {}                     # whois replies being assembled
        self.nick = NICK
        self._reset_session()

        if not self.store.list_channels():
            for c in DEFAULT_CHANNELS:
                self.store.add_channel(c)

    def _reset_session(self):
        self.registered = False
        self.identified = not bool(NICKSERV_PASSWORD)
        self.join_at = 0
        self.joined_done = False
        self.joined = {}                      # lower -> name
        self.rejoin = {}
        self.nick_fix_at = None
        self.last_recv = time.time()
        self.ping_sent = 0
        self.awaiting_pong = False
        with self.qlock:
            self.out_q.clear()
            self.whois_q.clear()
            self.whois_queued.clear()
            self.last_whois.clear()
        self.pending.clear()
        self.nick = NICK

    # ---------------------------------------------------------------- sending
    def send_raw(self, line):
        line = line.replace("\r", " ").replace("\n", " ")
        with self.send_lock:
            if not self.sock:
                raise OSError("not connected")
            self.sock.sendall((line + "\r\n").encode("utf-8", "replace"))

    def say(self, target, text):
        with self.qlock:
            for chunk in split_text(text):
                self.out_q.append(f"PRIVMSG {target} :{chunk}")

    def request_whois(self, nick, force=False):
        low = nick.lower()
        if low == self.nick.lower():
            return
        with self.qlock:
            if low in self.whois_queued or len(self.whois_q) >= 50000:
                return
            now = time.time()
            if not force and now - self.last_whois.get(low, 0) < 20:
                return
            self.whois_queued.add(low)
            self.whois_q.append(nick)
            self.last_whois[low] = now

    def _sender(self, stop):
        """Single writer thread. Reply lines have priority and go out 700 ms apart;
        whois requests go out 1.5 s apart."""
        next_whois = 0.0
        while not stop.is_set():
            line, delay = None, 0.0
            with self.qlock:
                now = time.time()
                if self.out_q:
                    line, delay = self.out_q.popleft(), LINE_DELAY
                elif self.whois_q and now >= next_whois:
                    nick = self.whois_q.popleft()
                    self.whois_queued.discard(nick.lower())
                    line = f"WHOIS {nick}"
                    next_whois = now + WHOIS_DELAY
            if line is None:
                stop.wait(0.05)
                continue
            try:
                self.send_raw(line)
            except OSError:
                return
            if delay:
                stop.wait(delay)

    # ------------------------------------------------------------- connection
    def _connect(self):
        raw = socket.create_connection((SERVER, PORT), timeout=30)
        if USE_SSL:
            ctx = ssl.create_default_context()
            if not VERIFY_SSL:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=SERVER)
        else:
            sock = raw
        sock.settimeout(1.0)
        self.sock = sock

    def _session(self):
        self._reset_session()
        self._connect()
        log.info("Connected to %s:%s", SERVER, PORT)
        stop = threading.Event()
        threading.Thread(target=self._sender, args=(stop,), daemon=True, name="irc-sender").start()
        try:
            self.send_raw(f"NICK {self.nick}")
            self.send_raw(f"USER {NICK} 0 * :{REALNAME}")
            buf = b""
            while True:
                try:
                    data = self.sock.recv(4096)
                except (socket.timeout, TimeoutError):
                    data = None
                except ssl.SSLError as e:
                    if "timed out" in str(e):
                        data = None
                    else:
                        raise
                if data is None:
                    self._tick()
                    continue
                if not data:
                    raise ConnectionError("connection closed by server")
                self.last_recv = time.time()
                self.awaiting_pong = False
                buf += data
                if len(buf) > 65536:
                    raise ConnectionError("receive buffer overflow")
                while b"\n" in buf:
                    raw_line, buf = buf.split(b"\n", 1)
                    line = raw_line.rstrip(b"\r").decode("utf-8", "replace")
                    if line:
                        self._handle(line)
                self._tick()
        finally:
            stop.set()
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.registered = False

    def run_forever(self):
        backoff = 5
        while True:
            started = time.time()
            try:
                self._session()
            except Exception as e:
                log.warning("Disconnected: %s", e)
            if time.time() - started > 60:
                backoff = 5
            log.info("Reconnecting in %ss", backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 120)

    def _tick(self):
        now = time.time()
        # keep-alive: ping the server if it has been quiet, reconnect if it never answers
        if not self.awaiting_pong and now - self.last_recv > 120:
            self.send_raw("PING :habibi-keepalive")
            self.awaiting_pong = True
            self.ping_sent = now
        elif self.awaiting_pong and now - self.ping_sent > 90:
            raise ConnectionError("ping timeout")

        if self.registered and not self.joined_done and (self.identified or now >= self.join_at):
            self.joined_done = True
            for c in self.store.list_channels():
                self.send_raw(f"JOIN {c}")

        if self.nick_fix_at and now >= self.nick_fix_at:
            self.nick_fix_at = None
            self.send_raw(f"NICK {NICK}")
            self._identify()

        for chan, due in list(self.rejoin.items()):
            if now >= due:
                del self.rejoin[chan]
                if chan in [c.lower() for c in self.store.list_channels()]:
                    self.send_raw(f"JOIN {chan}")

    def _identify(self):
        if NICKSERV_PASSWORD:
            self.send_raw(f"PRIVMSG NickServ :IDENTIFY {NICKSERV_PASSWORD}")

    # ----------------------------------------------------------------- events
    def _handle(self, line):
        prefix, cmd, p = parse_line(line)
        if cmd == "PING":
            self.send_raw("PONG :" + (p[-1] if p else ""))
        elif cmd == "ERROR":
            raise ConnectionError(line)
        elif cmd == "001":
            self.nick = p[0]
            self.registered = True
            self.join_at = time.time() + 6
            self._identify()
            if self.nick.lower() != NICK.lower() and NICKSERV_PASSWORD:
                self.send_raw(f"PRIVMSG NickServ :GHOST {NICK} {NICKSERV_PASSWORD}")
                self.nick_fix_at = time.time() + 3
        elif cmd == "433" and not self.registered:
            self.nick += "_"
            self.send_raw(f"NICK {self.nick}")
        elif cmd == "NOTICE":
            if nick_of(prefix).lower() == "nickserv" and len(p) > 1 and NICKSERV_OK_RE.search(p[1]):
                self.identified = True
        elif cmd == "JOIN" and p:
            self._on_join(nick_of(prefix), p[0])
        elif cmd == "PART" and p:
            n = nick_of(prefix)
            if n.lower() == self.nick.lower():
                self.joined.pop(p[0].lower(), None)
            else:
                self._touch(n, force=True)
        elif cmd == "QUIT":
            self._touch(nick_of(prefix), force=True)
        elif cmd == "KICK" and len(p) >= 2:
            if p[1].lower() == self.nick.lower():
                self.joined.pop(p[0].lower(), None)
                self.rejoin[p[0].lower()] = time.time() + 10
            else:
                self._touch(p[1], force=True)
        elif cmd == "NICK" and p:
            old, new = nick_of(prefix), p[0]
            if old.lower() == self.nick.lower():
                self.nick = new
            else:
                self._touch(old, force=True)
                self.request_whois(new, force=True)
        elif cmd == "PRIVMSG" and len(p) >= 2:
            self._on_privmsg(nick_of(prefix), p[0], p[1])
        elif cmd == "353" and p:
            self._on_names(p[-1])
        # --- whois replies
        elif cmd == "311" and len(p) >= 5:
            nick, ident, host = p[1], p[2], p[3]
            self.pending[nick.lower()] = {
                "nick": nick, "ident": ident, "host": host,
                "channels": "", "account": "", "country": "", "connected": "",
            }
        elif cmd == "319" and len(p) >= 3:
            rec = self.pending.get(p[1].lower())
            if rec is not None:
                rec["channels"] = (rec["channels"] + " " + clean(p[-1])).strip()
        elif cmd == "330" and len(p) >= 3:
            rec = self.pending.get(p[1].lower())
            if rec is not None:
                rec["account"] = clean(p[2])
        elif cmd == "317" and len(p) >= 4:
            rec = self.pending.get(p[1].lower())
            if rec is not None and p[3].isdigit():
                rec["connected"] = fmt_time(int(p[3]))
        elif cmd == "318" and len(p) >= 2:
            rec = self.pending.pop(p[1].lower(), None)
            if rec:
                self._save_whois(rec)
        elif cmd in ("401", "402") and len(p) >= 2:
            self.pending.pop(p[1].lower(), None)
        elif cmd.isdigit() and len(p) >= 3 and p[1].lower() in self.pending:
            # any other whois-style numeric (344, 320, 378 ...): look for the country line
            rec = self.pending[p[1].lower()]
            text = clean(p[-1])
            m = re.search(r"connecting from\s+(.+)$", text, re.I)
            # some servers put "*@host ip" here instead of a country - never store that
            if m and "@" not in m.group(1) and not re.search(r"\d+\.\d+\.\d+\.\d+", m.group(1)):
                rec["country"] = m.group(1).strip()
            else:
                log.debug("unhandled whois numeric: %s", line)

    def _save_whois(self, r):
        key = f"{r['nick'].lower()}!{r['ident'].lower()}@{r['host'].lower()}"
        rec = {
            "key": key,
            "nick": r["nick"],
            "ident": r["ident"],
            "host": r["host"],
            "display": f"{r['nick']}!{r['ident']}@{r['host']}",
            "country": r["country"],
            "channels": r["channels"],
            "account": r["account"],
            "connected": r["connected"],
            "last_seen": int(time.time()),
        }
        self.store.upsert_user(rec)
        self.nick_key[r["nick"].lower()] = key
        log.debug("Stored %s", rec["display"])

    def _on_join(self, nick, chan):
        if nick.lower() == self.nick.lower():
            self.joined[chan.lower()] = chan
            log.info("Joined %s", chan)
            return
        self.request_whois(nick)

    def _on_names(self, names):
        now = time.time()
        for n in names.split():
            n = n.lstrip("@+%&~!?")
            if not n or n.lower() == self.nick.lower():
                continue
            key = self.nick_key.get(n.lower())
            if key:
                seen = self.store.last_seen(key)
                if seen and now - seen < NAMES_SKIP_SECONDS:
                    self._touch(n, force=True)
                    continue
            self.request_whois(n)

    def _touch(self, nick, force=False):
        low = nick.lower()
        key = self.nick_key.get(low)
        if not key:
            return
        now = time.time()
        if not force and now - self.last_touch.get(low, 0) < 60:
            return
        self.last_touch[low] = now
        self.store.touch(key, now)

    # --------------------------------------------------------------- commands
    def _on_privmsg(self, nick, target, text):
        self._touch(nick)
        text = text.strip()
        if not text.startswith("!"):
            return
        parts = text.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        low = nick.lower()
        is_admin = low in ADMIN_SET
        in_channel = target[:1] in "#&"

        if in_channel:
            if target.lower() != COMMAND_CHANNEL:
                return
            if not (is_admin or self.store.is_searcher(low)):
                return                      # silently ignored
            reply_to = target
        else:
            if not is_admin:
                return                      # PM commands: super admins only
            reply_to = nick

        if cmd == "!search":
            self._cmd_search(reply_to, arg)
        elif cmd == "!status":
            self.say(reply_to, self.status_text())
        elif not is_admin:
            return                          # searchers only get !search / !status
        elif cmd == "!xlr8grantperm":
            self._cmd_grant(reply_to, arg)
        elif cmd == "!xlr8revokeperm":
            self._cmd_revoke(reply_to, arg)
        elif cmd == "!tjoin":
            self._cmd_tjoin(reply_to, arg)
        elif cmd == "!tpart":
            self._cmd_tpart(reply_to, arg)

    def _cmd_search(self, reply_to, arg):
        if not arg:
            self.say(reply_to, "[HABIBI] Usage: !search *pattern*")
            return
        rows = self.store.search(arg, MAX_RESULTS)
        if not rows:
            self.say(reply_to, f"[HABIBI] No matches for {arg}")
            return
        for i, r in enumerate(rows, 1):
            line = f"#{i} Username={r['display']}| Country={r['country'] or 'N/A'} | channels= {r['channels']} | "
            if r["account"]:
                line += f"AccountName={r['account']} | "
            line += f"Time= {r['connected'] or 'N/A'}"
            self.say(reply_to, line)

    def _cmd_grant(self, reply_to, arg):
        user = arg.split()[0] if arg else ""
        if not NICK_RE.match(user):
            self.say(reply_to, "[HABIBI] Usage: !xlr8grantperm username")
        elif user.lower() in ADMIN_SET:
            self.say(reply_to, f"[HABIBI] {user} is already a super admin")
        elif self.store.is_searcher(user):
            self.say(reply_to, f"[HABIBI] {user} already has search permission")
        else:
            self.store.add_searcher(user)
            self.say(reply_to, f"[HABIBI] {user} can now use !search")

    def _cmd_revoke(self, reply_to, arg):
        user = arg.split()[0] if arg else ""
        if not NICK_RE.match(user):
            self.say(reply_to, "[HABIBI] Usage: !xlr8revokeperm username")
        elif self.store.remove_searcher(user):
            self.say(reply_to, f"[HABIBI] {user} can no longer use !search")
        else:
            self.say(reply_to, f"[HABIBI] {user} was not a searcher")

    def _cmd_tjoin(self, reply_to, arg):
        chan = arg.split()[0] if arg else ""
        if not CHAN_RE.match(chan):
            self.say(reply_to, "[HABIBI] Usage: !tjoin #channel")
            return
        self.store.add_channel(chan)
        self.send_raw(f"JOIN {chan}")
        self.say(reply_to, f"[HABIBI] Joining {chan}")

    def _cmd_tpart(self, reply_to, arg):
        chan = arg.split()[0] if arg else ""
        if not CHAN_RE.match(chan):
            self.say(reply_to, "[HABIBI] Usage: !tpart #channel")
            return
        self.store.remove_channel(chan)
        self.rejoin.pop(chan.lower(), None)
        self.say(reply_to, f"[HABIBI] Leaving {chan}")
        with self.qlock:                    # PART goes out after the reply line
            self.out_q.append(f"PART {chan}")

    # ----------------------------------------------------------------- status
    def status_text(self):
        chans = sorted(self.joined.values(), key=str.lower)
        searchers = ", ".join(self.store.list_searchers()) or "none"
        state = "▶️ [ACTIVE]" if self.registered else "⏸️ [CONNECTING]"
        return (
            f"[HABIBI STATUS] Server: {SERVER}:{PORT} | "
            f"Uptime: {fmt_uptime(time.time() - self.started)} | {state} | "
            f"Channels ({len(chans)}): {', '.join(chans)} | "
            f"7-Day Hot Cache: {self.store.count_users()} users | "
            f"Super Admins: {', '.join(ADMIN_DISPLAY)} | "
            f"Searchers: {searchers} | Backup: Turso {self.store.turso_status()}"
        )

    def health(self):
        return {
            "bot": NICK,
            "connected": self.registered,
            "uptime": fmt_uptime(time.time() - self.started),
            "channels": sorted(self.joined.values(), key=str.lower),
            "users": self.store.count_users(),
            "turso": self.store.turso_status(),
        }
