"""Run the vulnerable lab app on localhost.

  python -m bbagent_lab.server            # binds 127.0.0.1:8000
  python -m bbagent_lab.server --port 8080

The server refuses to bind to anything other than a loopback address.
"""

from __future__ import annotations

import argparse
import threading
from wsgiref.simple_server import WSGIServer, make_server

from bbagent_lab.app import create_app

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def make_lab_server(host: str = "127.0.0.1", port: int = 8000) -> WSGIServer:
    """Create (but do not serve) a WSGI server bound to a loopback address."""
    if host not in _LOOPBACK:
        raise ValueError(f"refusing to bind lab to non-loopback host: {host!r}")
    return make_server(host, port, create_app())


class BackgroundLab:
    """Context manager that runs the lab in a background thread on an ephemeral port.

    Used by integration tests to exercise the agent over a real localhost socket.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._server = make_lab_server(host, port)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "BackgroundLab":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bbagent_lab.server", description="Local vulnerable lab")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    server = make_lab_server(args.host, args.port)
    host, port = server.server_address[:2]
    print(f"bbagent lab running at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping lab")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
