#!/usr/bin/env python3
"""
Simple HTTP Preview Server for CloudSentinel Web Dashboard.

Runs a local web server on port 3000 serving dashboard/index.html.
"""

import http.server
import socketserver
import sys
from pathlib import Path

PORT = 3000
DASHBOARD_DIR = Path(__file__).resolve().parent

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[CloudSentinel Web] {self.address_string()} - {format % args}\n")


def run():
    port = PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), DashboardHandler) as httpd:
        print("=" * 60)
        print("🛡️  CloudSentinel Zero-Trust Web Dashboard")
        print(f"🚀 Running locally at: http://localhost:{port}")
        print("Press Ctrl+C to terminate.")
        print("=" * 60)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server.")


if __name__ == "__main__":
    run()
