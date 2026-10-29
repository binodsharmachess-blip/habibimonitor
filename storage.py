"""
storage.py - local SQLite (primary) + Turso (remote backup), 7-day rolling window.

Environment variables:
    DB_PATH      path of the local sqlite file      (default: habibi.db)
    TURSO_URL    e.g. libsql://habibi-yourname.turso.io   (optional but recommended)
    TURSO_TOKEN  Turso database auth token                (optional but recommended)

Every write goes to SQLite first, then is queued and pushed to Turso by a
background thread, so a slow/unavailable Turso never blocks the bot.
If the local database is empty at startup (e.g. Render wiped the disk),
data is restored from Turso.
"""
import logging
import os
import queue
import sqlite3
import threading
import time

import requests

log = logging.getLogger("habibi.storage")

RETENTION_DAYS = 7
RETENTION_SECONDS = RETENTION_DAYS * 86400

USER_COLS = "key,nick,ident,host,display,country,channels,account,connected,last_seen"
USER_UPSERT = (
    f"INSERT OR REPLACE INTO users ({USER_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?)"
)

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        key       TEXT PRIMARY KEY,
        nick      TEXT,
        ident     TEXT,
        host      TEXT,
        display   TEXT,
        country   TEXT,
        channels  TEXT,
        account   TEXT,
        connected TEXT,
        last_seen INTEGER
    )""",
    "CREATE INDEX IF NOT EXISTS idx_users_seen ON users(last_seen)",
    "CREATE TABLE IF NOT EXISTS searchers (nick TEXT PRIMARY KEY)",
    "CREATE TABLE IF NOT EXISTS channels (name TEXT PRIMARY KEY)",
]


class TursoSQLError(Exception):
    """The statement itself was rejected (retrying will not help)."""


class Turso:
    """Minimal Turso/libSQL client over the HTTP pipeline API."""

    def __init__(self, url, token):
        url = url.strip().rstrip("/")
        if url.startswith("libsql://"):
            url = "https://" + url[len("libsql://"):]
        self.endpoint = url + "/v2/pipeline"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self.http = requests.Session()

    @staticmethod
    def _arg(v):
        if v is None:
            return {"type": "null"}
        if isinstance(v, bool):
            v = int(v)
        if isinstance(v, int):
            return {"type": "integer", "value": str(v)}
        if isinstance(v, float):
            return {"type": "float", "value": v}
        return {"type": "text", "value": str(v)}

    @staticmethod
    def _cell(c):
        t = c.get("type")
        if t == "null":
            return None
        v = c.get("value")
        if t == "integer":
            return int(v)
        if t == "float":
            return float(v)
        return v

    def execute_many(self, stmts):
        """stmts: list of (sql, args). Returns list of raw results."""
        reqs = [
            {
                "type": "execute",
                "stmt": {"sql": sql, "args": [self._arg(a) for a in args]},
            }
            for sql, args in stmts
        ]
        reqs.append({"type": "close"})
        r = self.http.post(
            self.endpoint, json={"requests": reqs}, headers=self.headers, timeout=60
        )
        r.raise_for_status()
        results = r.json().get("results", [])
        out = []
        for res in results[:-1]:
            if res.get("type") == "error":
                raise TursoSQLError(res.get("error", {}).get("message", "sql error"))
            out.append(res["response"]["result"])
        return out

    def query(self, sql, args=()):
        res = self.execute_many([(sql, args)])[0]
        return [[self._cell(c) for c in row] for row in res.get("rows", [])]


class Storage:
    def __init__(self, path=None):
        self.path = path or os.environ.get("DB_PATH", "habibi.db")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        for stmt in SCHEMA:
            self.db.execute(stmt)
        self.db.commit()

        url = os.environ.get("TURSO_URL", "").strip()
        token = os.environ.get("TURSO_TOKEN", "").strip()
        self.turso = Turso(url, token) if url and token else None
        self.remote_ready = False
        self.needs_resync = False
        self.q = queue.Queue(maxsize=100000)

        if self.turso:
            try:
                self._init_remote()
            except Exception as e:  # worker will retry later
                log.warning("Turso init failed at startup (will retry): %s", e)
            threading.Thread(
                target=self._turso_worker, daemon=True, name="turso-sync"
            ).start()
        else:
            log.warning("TURSO_URL / TURSO_TOKEN not set - running WITHOUT remote backup")

        self.purge()
        threading.Thread(
            target=self._maintenance, daemon=True, name="maintenance"
        ).start()

    # ------------------------------------------------------------------ remote
    def _init_remote(self):
        self.turso.execute_many([(s, ()) for s in SCHEMA])
        self._restore_if_empty()
        self.remote_ready = True
        log.info("Turso backup ready")

    def _restore_if_empty(self):
        with self.lock:
            n_users = self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            n_search = self.db.execute("SELECT COUNT(*) FROM searchers").fetchone()[0]
            n_chan = self.db.execute("SELECT COUNT(*) FROM channels").fetchone()[0]
        cutoff = int(time.time()) - RETENTION_SECONDS
        if n_users == 0:
            rows = self.turso.query(
                f"SELECT {USER_COLS} FROM users WHERE last_seen>=?", (cutoff,)
            )
            with self.lock:
                self.db.executemany(USER_UPSERT, rows)
                self.db.commit()
            log.info("Restored %d users from Turso", len(rows))
        if n_search == 0:
            rows = self.turso.query("SELECT nick FROM searchers")
            with self.lock:
                self.db.executemany(
                    "INSERT OR REPLACE INTO searchers (nick) VALUES (?)", rows
                )
                self.db.commit()
        if n_chan == 0:
            rows = self.turso.query("SELECT name FROM channels")
            with self.lock:
                self.db.executemany(
                    "INSERT OR REPLACE INTO channels (name) VALUES (?)", rows
                )
                self.db.commit()

    def _enqueue(self, sql, args):
        if not self.turso:
            return
        try:
            self.q.put_nowait((sql, tuple(args)))
        except queue.Full:
            self.needs_resync = True

    def _turso_worker(self):
        backoff = 5
        batch = []
        while True:
            try:
                if not self.remote_ready:
                    self._init_remote()
                if not batch:
                    batch.append(self.q.get())
                    time.sleep(1)  # let a few more writes accumulate
                while len(batch) < 100:
                    try:
                        batch.append(self.q.get_nowait())
                    except queue.Empty:
                        break
                self.turso.execute_many(batch)
                batch = []
                backoff = 5
            except TursoSQLError as e:
                log.error("Turso rejected a batch, dropping it: %s", e)
                batch = []
                time.sleep(backoff)
            except Exception as e:
                log.warning("Turso sync failed (retry in %ss): %s", backoff, e)
                time.sleep(backoff)
                backoff = min(backoff * 2, 300)

    def _resync(self):
        """Push everything local to Turso (used after the queue overflowed)."""
        with self.lock:
            users = self.db.execute(f"SELECT {USER_COLS} FROM users").fetchall()
            searchers = self.db.execute("SELECT nick FROM searchers").fetchall()
            chans = self.db.execute("SELECT name FROM channels").fetchall()
        for i in range(0, len(users), 200):
            self.turso.execute_many(
                [(USER_UPSERT, tuple(r)) for r in users[i:i + 200]]
            )
        stmts = [("INSERT OR REPLACE INTO searchers (nick) VALUES (?)", tuple(r)) for r in searchers]
        stmts += [("INSERT OR REPLACE INTO channels (name) VALUES (?)", tuple(r)) for r in chans]
        if stmts:
            self.turso.execute_many(stmts)
        log.info("Full resync to Turso done (%d users)", len(users))

    def _maintenance(self):
        while True:
            time.sleep(3600)
            try:
                self.purge()
                if self.turso and self.remote_ready and self.needs_resync:
                    self.needs_resync = False
                    try:
                        self._resync()
                    except Exception as e:
                        self.needs_resync = True
                        log.warning("Resync failed: %s", e)
            except Exception as e:
                log.warning("Maintenance error: %s", e)

    # ------------------------------------------------------------------- users
    def purge(self):
        cutoff = int(time.time()) - RETENTION_SECONDS
        with self.lock:
            cur = self.db.execute("DELETE FROM users WHERE last_seen < ?", (cutoff,))
            self.db.commit()
        self._enqueue("DELETE FROM users WHERE last_seen < ?", (cutoff,))
        if cur.rowcount:
            log.info("Purged %d users older than %d days", cur.rowcount, RETENTION_DAYS)

    def upsert_user(self, rec):
        args = (
            rec["key"], rec["nick"], rec["ident"], rec["host"], rec["display"],
            rec["country"], rec["channels"], rec["account"], rec["connected"],
            int(rec["last_seen"]),
        )
        with self.lock:
            self.db.execute(USER_UPSERT, args)
            self.db.commit()
        self._enqueue(USER_UPSERT, args)

    def touch(self, key, ts):
        with self.lock:
            self.db.execute("UPDATE users SET last_seen=? WHERE key=?", (int(ts), key))
            self.db.commit()
        self._enqueue("UPDATE users SET last_seen=? WHERE key=?", (int(ts), key))

    def last_seen(self, key):
        with self.lock:
            row = self.db.execute(
                "SELECT last_seen FROM users WHERE key=?", (key,)
            ).fetchone()
        return row[0] if row else None

    def load_nick_keys(self):
        """nick(lower) -> key of the most recently seen record for that nick."""
        with self.lock:
            rows = self.db.execute(
                "SELECT lower(nick), key FROM users ORDER BY last_seen ASC"
            ).fetchall()
        return {n: k for n, k in rows}

    def count_users(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    @staticmethod
    def _like(pattern):
        p = pattern.strip().lower()
        esc = p.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        if "*" in p or "?" in p:  # wildcard mode: pattern is anchored as typed
            return esc.replace("*", "%").replace("?", "_")
        return f"%{esc}%"  # plain text: substring match

    def search(self, pattern, limit=30):
        """Match nick, host (vhost) or account name; newest activity first."""
        like = self._like(pattern)
        sql = (
            f"SELECT {USER_COLS} FROM users "
            "WHERE nick LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' "
            "OR account LIKE ? ESCAPE '\\' "
            "ORDER BY last_seen DESC LIMIT ?"
        )
        with self.lock:
            rows = self.db.execute(sql, (like, like, like, limit)).fetchall()
        cols = USER_COLS.split(",")
        return [dict(zip(cols, r)) for r in rows]

    # --------------------------------------------------------------- searchers
    def is_searcher(self, nick):
        with self.lock:
            return (
                self.db.execute(
                    "SELECT 1 FROM searchers WHERE nick=?", (nick.lower(),)
                ).fetchone()
                is not None
            )

    def add_searcher(self, nick):
        nick = nick.lower()
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO searchers (nick) VALUES (?)", (nick,))
            self.db.commit()
        self._enqueue("INSERT OR REPLACE INTO searchers (nick) VALUES (?)", (nick,))

    def remove_searcher(self, nick):
        nick = nick.lower()
        with self.lock:
            cur = self.db.execute("DELETE FROM searchers WHERE nick=?", (nick,))
            self.db.commit()
        self._enqueue("DELETE FROM searchers WHERE nick=?", (nick,))
        return cur.rowcount > 0

    def list_searchers(self):
        with self.lock:
            rows = self.db.execute("SELECT nick FROM searchers ORDER BY nick").fetchall()
        return [r[0] for r in rows]

    # ---------------------------------------------------------------- channels
    def list_channels(self):
        with self.lock:
            rows = self.db.execute("SELECT name FROM channels ORDER BY name").fetchall()
        return [r[0] for r in rows]

    def add_channel(self, name):
        name = name.lower()
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO channels (name) VALUES (?)", (name,))
            self.db.commit()
        self._enqueue("INSERT OR REPLACE INTO channels (name) VALUES (?)", (name,))

    def remove_channel(self, name):
        name = name.lower()
        with self.lock:
            self.db.execute("DELETE FROM channels WHERE name=?", (name,))
            self.db.commit()
        self._enqueue("DELETE FROM channels WHERE name=?", (name,))

    def turso_status(self):
        if not self.turso:
            return "OFF"
        return "ON" if self.remote_ready else "RETRYING"
