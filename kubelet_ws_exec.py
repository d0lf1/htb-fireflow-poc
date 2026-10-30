#!/usr/bin/env python3
"""kubelet_ws_exec.py — exec in un container via kubelet con WebSocket puro.

Subprotocol v4.channel.k8s.io; query LEGACY dei canali (output=1&error=1:
i kubelet di alcune build confrontano i valori con "1" sui nomi vecchi e
rispondono 400 "you must specify at least 1 of stdin, stdout, stderr" con
stdout/stderr). Il SA chiamante deve avere nodes/proxy se si passa
dall'API server, oppure authn/authz kubelet se diretti.

Uso:
  KUBELET_DIRECT=<host:port> python3 kubelet_ws_exec.py 'cmd' [node] [ns] [pod] [ctr]
  (senza KUBELET_DIRECT passa dal proxy dell'API server: /api/v1/nodes/<node>/proxy/exec/...)
"""
import base64
import os
import socket
import ssl
import struct
import sys
import urllib.parse

T = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
cmd = sys.argv[1] if len(sys.argv) > 1 else 'id'
host = '10.43.0.1'
port = 443
node = sys.argv[2] if len(sys.argv) > 2 else 'fireflow'
ns = sys.argv[3] if len(sys.argv) > 3 else 'monitoring'
pod = sys.argv[4] if len(sys.argv) > 4 else 'prometheus-prometheus-node-exporter-nmntq'
ctr = sys.argv[5] if len(sys.argv) > 5 else 'node-exporter'
qs = '&'.join([
    'command=/bin/sh', 'command=-c', 'command=' + urllib.parse.quote(cmd),
    'output=1', 'error=1', 'input=0',
])
direct = os.environ.get('KUBELET_DIRECT', '')
if direct:
    host, p = direct.split(':')
    port = int(p)
    path = f'/exec/{ns}/{pod}/{ctr}?{qs}'
else:
    path = f'/api/v1/nodes/{node}/proxy/exec/{ns}/{pod}/{ctr}?{qs}'
key = base64.b64encode(os.urandom(16)).decode()
req = (f'GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {T}\r\n'
       f'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
       f'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: v4.channel.k8s.io\r\n\r\n').encode()
ctx = ssl._create_unverified_context()
s = socket.create_connection((host, port), timeout=25)
s = ctx.wrap_socket(s, server_hostname=host)
s.send(req)
buf = b''
while b'\r\n\r\n' not in buf:
    d = s.recv(4096)
    if not d:
        break
    buf += d
head, _, rest = buf.partition(b'\r\n\r\n')
status = head.split(b'\r\n')[0].decode()
if '101' not in status:
    cl = 0
    for line in head.split(b'\r\n'):
        if line.lower().startswith(b'content-length:'):
            cl = int(line.split(b':')[1].strip())
    while len(rest) < cl:
        d = s.recv(4096)
        if not d:
            break
        rest += d
    print('HANDSHAKE FAIL:', status)
    print('BODY:', rest[:cl].decode(errors='replace'))
    sys.exit(1)
out = b''
err = b''
data = rest


def read_exact(n):
    global data
    while len(data) < n:
        d = s.recv(4096)
        if not d:
            break
        data += d
    r = data[:n]
    data = data[n:]
    return r


while True:
    h = read_exact(2)
    if len(h) < 2:
        break
    op = h[0] & 0x0f
    ln = h[1] & 0x7f
    if ln == 126:
        ln = struct.unpack('>H', read_exact(2))[0]
    elif ln == 127:
        ln = struct.unpack('>Q', read_exact(8))[0]
    payload = read_exact(ln)
    if op == 8:
        break
    if op in (1, 2) and payload:
        ch = payload[0]
        body = payload[1:]
        if ch == 1:
            out += body
        elif ch == 2:
            err += body
        elif ch == 3:
            print('ERRCHAN:', body.decode(errors='replace')[:300])
print(out.decode(errors='replace'))
if err:
    print('STDERR:', err.decode(errors='replace'))
