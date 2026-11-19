#!/usr/bin/env python3
"""One-shot K02 VSOCK challenge/echo server; does not implement the GUI protocol."""
import argparse
import json
from pathlib import Path
import secrets
import socket
import sys


def receive(connection, count):
    result = bytearray()
    while len(result) < count:
        block = connection.recv(count - len(result))
        if not block:
            raise ValueError('unexpected EOF')
        result.extend(block)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=lambda n: int(n, 0), default=0x4b434f56)
    parser.add_argument('--expected-peer-cid', type=int, default=5)
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--ready-file', type=Path)
    args = parser.parse_args()
    if not 0 < args.timeout <= 300 or not 0 < args.port < 2**32 - 1:
        parser.error('timeout must be in (0, 300], port in (0, 2**32-1)')
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as server:
        server.settimeout(args.timeout)
        server.bind((socket.VMADDR_CID_ANY, args.port))
        server.listen(1)
        ready = {'event': 'ready', 'port': args.port, 'expected_peer_cid': args.expected_peer_cid}
        if args.ready_file:
            # Exclusive create prevents mistaking a stale successful run for this listener.
            with args.ready_file.open('x', encoding='utf-8') as output:
                json.dump(ready, output)
                output.write('\n')
        print(json.dumps(ready), flush=True)
        connection, peer = server.accept()
        with connection:
            connection.settimeout(args.timeout)
            if peer[0] != args.expected_peer_cid:
                raise ValueError(f'unexpected guest CID {peer[0]}')
            request = receive(connection, 40)
            if request[:8] != b'K02VSOCK':
                raise ValueError('unexpected probe protocol')
            guest_nonce = request[8:]
            host_nonce = secrets.token_bytes(32)
            connection.sendall(guest_nonce + host_nonce)
            returned = receive(connection, 32)
            if not secrets.compare_digest(host_nonce, returned):
                raise ValueError('host nonce mismatch')
            connection.sendall(b'\x01')
            print(json.dumps({'passed': True, 'scope': 'vsock-transport-only',
                              'observed_peer_cid': peer[0], 'port': args.port,
                              'guest_nonce': guest_nonce.hex(),
                              'host_nonce': host_nonce.hex()}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, AttributeError) as error:
        print(json.dumps({'passed': False, 'error': str(error)}), flush=True)
        raise SystemExit(1)
