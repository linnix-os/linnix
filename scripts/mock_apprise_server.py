#!/usr/bin/env python3
"""
Simple POST-capable mock Apprise server used by TEST_APPRISE.md.

Logs incoming POST requests (headers + body) to stdout and appends them to
/tmp/http-posts.log so tests can assert on deliveries.

Usage:
  python3 scripts/mock_apprise_server.py

Listens on 0.0.0.0:8888 by default.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG_PATH = "/tmp/http-posts.log"


class Handler(BaseHTTPRequestHandler):
    def _log(self, text: str):
        # Print to stdout
        print(text)
        # Append to log file for test automation
        try:
            with open(LOG_PATH, "a") as f:
                f.write(text + "\n")
        except Exception as e:
            print(f"Failed to write log: {e}")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        self._log("----- REQUEST ")
        self._log(f"Path: {self.path}")
        self._log("Headers:")
        for k, v in self.headers.items():
            self._log(f"{k}: {v}")
        self._log("Body:")
        self._log(body)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        # Silence BaseHTTPRequestHandler default logging (we log explicitly)
        return


def main(host: str = "0.0.0.0", port: int = 8888):
    # Ensure the directory exists for the log file
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    except Exception:
        pass

    srv = HTTPServer((host, port), Handler)
    print(f"Starting mock apprise server on :{port} (logging to {LOG_PATH})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down mock server")
        srv.server_close()


if __name__ == "__main__":
    main()
