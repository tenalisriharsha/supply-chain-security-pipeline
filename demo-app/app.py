"""Minimal HTTP service used as the sample build artifact for the pipeline."""

from http.server import BaseHTTPRequestHandler, HTTPServer
from json import dumps
from os import environ


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            body = dumps({"status": "ok"}).encode("utf-8")
        else:
            body = dumps({"service": "demo-app", "message": "hello from the supply chain"}).encode(
                "utf-8"
            )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - matches base signature
        pass


def main():
    port = int(environ.get("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
