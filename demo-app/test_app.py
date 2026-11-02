import json
import threading
import urllib.request
from http.server import HTTPServer

from app import Handler


def _start_server():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_healthz_returns_ok():
    server = _start_server()
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz") as response:
            body = json.loads(response.read())
        assert body == {"status": "ok"}
    finally:
        server.shutdown()


def test_root_returns_service_message():
    server = _start_server()
    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as response:
            body = json.loads(response.read())
        assert body["service"] == "demo-app"
    finally:
        server.shutdown()
