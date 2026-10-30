# HTB · Fireflow — PoC

Proof-of-concept per la macchina **Fireflow** (Hack The Box, Medium, Linux/Kubernetes).
Writeup completo: https://blog.ldsec.it/htb-fireflow

**Catena:** flow_id leakato → RCE pre-auth Langflow 1.8 (`build_public_tmp`, exec del
class body, esfiltrazione via eventi SSE) → `www-data` → password reuse in
`/etc/langflow/.env` → SSH `nightfall` → MCP server custom con JWT `alg=none` →
tool registration = code execution sul pod → `nodes/proxy` → kubelet exec in
container privileged con hostPath `/` → root sul filesystem host.

| File | Ruolo |
|------|-------|
| `langflow_rce.sh` | RCE pre-auth su Langflow 1.8.x: comando nel class body del componente, output esfiltrato negli eventi SSE del job (nessun egress necessario) |
| `mcp_rce.sh` | RCE sul pod MCP: token JWT `alg=none` + tool registration dinamica con codice malevolo, risultato via `tools/call` |
| `jwt_none.py` | Genera un JWT con `alg: none` e claim a scelta (helper per `mcp_rce.sh`) |
| `kubelet_ws_exec.py` | Exec in un container via kubelet/API-server con client WebSocket puro (subprotocol `v4.channel.k8s.io`, query legacy `output=1&error=1`) |

## Uso

```bash
# 1. RCE pre-auth Langflow (serve un flow_id con playground pubblico)
./langflow_rce.sh 'id; hostname' [target_base] [flow_id]
#    per host non in DNS (lab): RESOLVE=flow.fireflow.htb:443:10.129.189.116 ./langflow_rce.sh …

# 2. RCE sul pod MCP (da host o tunnel verso il NodePort del servizio)
./mcp_rce.sh 'id; cat /etc/hostname' [mcp_base]

# 3. Exec via kubelet in un container privileged (dal pod compromesso)
KUBELET_DIRECT=10.42.1.1:10250 python3 kubelet_ws_exec.py 'id; cat /host/root/root/root.txt'
```

Requisiti: `bash`, `curl`, `python3` (solo standard library). Nessun framework,
nessun listener: i canali di ritorno sono gli stessi response/SSE dei servizi.

> Le credenziali e gli indirizzi negli esempi sono quelli del lab HTB, non reali.
> La macchina era **attiva** al momento della pubblicazione: il repo non contiene flag.
> ⚠️ Solo a scopo educativo e per testing autorizzato.
