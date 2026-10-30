#!/usr/bin/env python3
"""Private TCP bridge from the Zabbix Docker network to ChatOps loopback."""

import ipaddress
import os
import select
import socket
import socketserver


BIND_HOST = os.environ.get("ZABBIX_PROXY_BIND", "IP_REDACTED")
BIND_PORT = int(os.environ.get("ZABBIX_PROXY_PORT", "5001"))
# Prefer the stable Docker bridge network. Keep the exact-source setting as a
# compatibility override for deployments that cannot configure a network CIDR.
ALLOWED_NETWORK = os.environ.get("ZABBIX_PROXY_ALLOWED_NETWORK", "").strip()
ALLOWED_SOURCE = os.environ.get("ZABBIX_PROXY_ALLOWED_SOURCE", "").strip()
TARGET_HOST = os.environ.get("CHATOPS_PROXY_TARGET_HOST", "IP_REDACTED")
TARGET_PORT = int(os.environ.get("CHATOPS_PROXY_TARGET_PORT", "5000"))


def source_is_allowed(source):
    """Allow only the configured Docker network, failing closed on bad input."""
    if ALLOWED_NETWORK:
        try:
            network = ipaddress.ip_network(ALLOWED_NETWORK, strict=False)
        except ValueError:
            return False
        if network.prefixlen == 0:
            return False
        try:
            return ipaddress.ip_address(source) in network
        except ValueError:
            return False
    if ALLOWED_SOURCE:
        return source == ALLOWED_SOURCE
    return False


class ThreadingProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProxyHandler(socketserver.BaseRequestHandler):
    def _reply(self, status, body):
        payload = body.encode("ascii")
        response = (
            f"HTTP/1.1 {status}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + payload
        try:
            self.request.sendall(response)
        except OSError:
            pass

    def handle(self):
        source = self.client_address[0]
        if not source_is_allowed(source):
            self._reply("403 Forbidden", "forbidden\n")
            print(f"[ZABBIX PROXY] rejected source={source}", flush=True)
            return

        try:
            upstream = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=5)
        except OSError:
            self._reply("502 Bad Gateway", "chatops unavailable\n")
            print(f"[ZABBIX PROXY] target unavailable source={source}", flush=True)
            return

        sockets = (self.request, upstream)
        try:
            while True:
                readable, _, _ = select.select(sockets, (), (), 15)
                if not readable:
                    break
                for readable_socket in readable:
                    chunk = readable_socket.recv(65536)
                    if not chunk:
                        return
                    destination = upstream if readable_socket is self.request else self.request
                    destination.sendall(chunk)
        except (OSError, ValueError):
            pass
        finally:
            upstream.close()


def main():
    with ThreadingProxyServer((BIND_HOST, BIND_PORT), ProxyHandler) as server:
        allowed_scope = ALLOWED_NETWORK or ALLOWED_SOURCE or "none"
        print(
            f"[ZABBIX PROXY] listening={BIND_HOST}:{BIND_PORT} "
            f"allowed_scope={allowed_scope} target={TARGET_HOST}:{TARGET_PORT}",
            flush=True,
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
