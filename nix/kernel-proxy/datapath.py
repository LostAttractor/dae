import os
import socket
import socketserver
import sys
import threading

ECHO_PORT = 18080
QUESTION = bytes.fromhex("076578616d706c6504746573740000010001")
QUERY_HEADER = bytes.fromhex("01000001000000000000")


def dns_reply(query, tag):
    # One A question, uncompressed QNAME; discard any EDNS additional records.
    end = 12
    while query[end]:
        end += query[end] + 1
    question = query[12:end + 5]
    return (
        query[:2] + bytes.fromhex("81800001000100000000") + question
        + bytes.fromhex("c00c000100010000003c0004c00002") + bytes([tag])
    )


class Stream(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        if self.server.server_address[1] == 53:
            size = int.from_bytes(self.rfile.read(2), "big")
            if size:
                reply = dns_reply(self.rfile.read(size), self.server.tag)
                self.wfile.write(len(reply).to_bytes(2, "big") + reply)
        else:
            self.wfile.write(bytes([self.server.tag]) + self.rfile.read(16))


class Datagram(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if self.server.server_address[1] == 53:
            data = dns_reply(data, self.server.tag)
        else:
            data = bytes([self.server.tag]) + data
        sock.sendto(data, self.client_address)


def family(address):
    return socket.AF_INET6 if ":" in address else socket.AF_INET


def serve(tag, addresses):
    servers = []
    for address in addresses:
        for port in (53, ECHO_PORT):
            for base, handler in (
                (socketserver.ThreadingTCPServer, Stream),
                (socketserver.UDPServer, Datagram),
            ):
                server_type = type("Server", (base,), {"address_family": family(address)})
                server = server_type((address, port), handler)
                server.tag = tag
                servers.append(server)
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[0].serve_forever()


def exchange(address, protocol, port, payload, size):
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family(address), kind) as sock:
        sock.settimeout(3)
        sock.connect((address, port))
        sock.sendall(payload)
        if protocol == "tcp":
            with sock.makefile("rb") as stream:
                return stream.read(size)
        return sock.recv(4096)


def probe(tag, address, protocol, port, blocked):
    payload = os.urandom(16)
    if port == 53:
        payload = payload[:2] + QUERY_HEADER + QUESTION
        expected = dns_reply(payload, tag)
    else:
        expected = bytes([tag]) + payload
    try:
        reply = exchange(address, protocol, port, payload, len(expected))
    except TimeoutError:
        if blocked:
            return
        raise
    assert not blocked, "target replied without dae"
    assert reply == expected, (reply.hex(), expected.hex())


if __name__ == "__main__":
    mode, tag, *args = sys.argv[1:]
    if mode == "serve":
        serve(int(tag), args)
    else:
        address, protocol, port = args
        probe(int(tag), address, protocol, int(port), mode == "blocked")
