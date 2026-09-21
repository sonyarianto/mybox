#!/usr/bin/env python3
"""Tiny disposable metrics and alert receiver for alert-delivery acceptance."""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, HTTPServer


OUTPUT = os.environ.get("MYBOX_ALERT_OUTPUT", "/tmp/mybox-alert.json")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = (
            b"# HELP mybox_readiness_failures_total Synthetic acceptance metric.\n"
            b"# TYPE mybox_readiness_failures_total counter\n"
            b"mybox_readiness_failures_total 1\n"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/alerts":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        with open(OUTPUT, "ab") as output:
            output.write(payload)
            output.write(b"\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
