"""
app.py - entry point.

Starts the IRC bot in a background thread and serves a tiny HTTP health page so
Render sees an open port and UptimeRobot has something to ping (keeps the
free web service awake).

Render settings:
    Build command:  pip install -r requirements.txt
    Start command:  python app.py
"""
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bot import HabibiBot
from storage import Storage

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

store = Storage()
bot = HabibiBot(store)


class Health(BaseHTTPRequestHandler):
    def _respond(self, head_only=False):
        body = json.dumps(bot.health(), ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond(head_only=True)

    def log_message(self, *args):  # keep the logs quiet
        pass


def main():
    threading.Thread(target=bot.run_forever, daemon=True, name="irc-bot").start()
    port = int(os.environ.get("PORT", "10000"))
    logging.getLogger("habibi").info("Health server on port %s", port)
    ThreadingHTTPServer(("0.0.0.0", port), Health).serve_forever()


if __name__ == "__main__":
    main()
