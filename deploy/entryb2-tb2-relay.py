#!/usr/bin/env python3
import selectors
import socket

LISTEN = ("10.77.63.2", 19091)
TARGET = ("10.77.62.2", 19091)
BUFFER = 262144

def relay(a, b):
    sel = selectors.DefaultSelector()
    a.setblocking(False); b.setblocking(False)
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    try:
        while sel.get_map():
            for key, _ in sel.select(30):
                src, dst = key.fileobj, key.data
                try:
                    data = src.recv(BUFFER)
                except (ConnectionResetError, OSError):
                    data = b""
                if not data:
                    try: sel.unregister(src)
                    except KeyError: pass
                    try: dst.shutdown(socket.SHUT_WR)
                    except OSError: pass
                    continue
                try:
                    dst.sendall(data)
                except OSError:
                    try: sel.unregister(src)
                    except KeyError: pass
                    try: sel.unregister(dst)
                    except KeyError: pass
    finally:
        sel.close()
        for sock in (a,b):
            try: sock.close()
            except OSError: pass

def main():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(LISTEN)
    listener.listen(64)
    while True:
        client, _ = listener.accept()
        try:
            upstream = socket.create_connection(TARGET, timeout=5)
        except OSError:
            client.close()
            continue
        relay(client, upstream)

if __name__ == "__main__":
    main()