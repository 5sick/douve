#!/usr/bin/env python3
# 원시 WebSocket 텍스트 프레임을 보내고 닫는다 (형식이 깨진 메시지 시험용, 의존성 없음).
# 사용: ws_send.py <host:port> <path> <메시지>...
import base64, os, socket, struct, sys, time

host, port = sys.argv[1].rsplit(":", 1)
s = socket.create_connection((host, int(port)), timeout=3)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((f"GET {sys.argv[2]} HTTP/1.1\r\nHost: {sys.argv[1]}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
if b" 101 " not in s.recv(4096).split(b"\r\n")[0]:
    sys.exit("업그레이드 실패")
for text in sys.argv[3:]:
    p = text.encode()
    n = len(p)
    head = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else
                            bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else
                            bytes([0x80 | 127]) + struct.pack(">Q", n))
    mask = os.urandom(4)
    s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(p)))
    time.sleep(0.1)
s.close()
