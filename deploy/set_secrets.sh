#!/usr/bin/env bash
# Add or replace API keys in the server's .env, then restart Tell.
# Run it yourself in a terminal: bash deploy/set_secrets.sh
# Typing is hidden; values travel over SSH stdin (never in argv, shell history or logs). Leave a prompt blank to skip it.
set -euo pipefail

HOST="${TELL_HOST:-root@149.28.52.109}"
SSH_KEY="${TELL_SSH_KEY:-$HOME/.ssh/tell_vultr_ed25519}"
VARS=(GEMINI_API_KEY IBM_WATSONX_APIKEY IBM_WATSONX_PROJECT_ID SNOWFLAKE_ACCOUNT SNOWFLAKE_USER SNOWFLAKE_PAT)

updates=""
for v in "${VARS[@]}"; do
  read -r -s -p "$v (blank = keep current): " val; echo
  [ -n "$val" ] && updates+="$v=$val"$'\n'
done
[ -n "$updates" ] || { echo "Nothing to change."; exit 0; }

printf '%s' "$updates" | ssh -i "$SSH_KEY" -o BatchMode=yes "$HOST" 'python3 -c "
import os, sys
new = dict(l.split(\"=\", 1) for l in sys.stdin.read().splitlines() if \"=\" in l)
p = \"/opt/tell/.env\"
lines = open(p).read().splitlines() if os.path.exists(p) else []
out = [l for l in lines if l.split(\"=\", 1)[0] not in new] + [k + \"=\" + v for k, v in new.items()]
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, (\"\n\".join(out) + \"\n\").encode()); os.close(fd); os.chmod(p, 0o600)
print(\"Updated:\", \", \".join(new))
" && cd /opt/tell && docker compose -f deploy/docker-compose.yml up -d --force-recreate >/dev/null 2>&1
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8000/api/status >/dev/null 2>&1 && break; sleep 2; done
curl -s http://127.0.0.1:8000/api/status | python3 -c "import json,sys; s=json.load(sys.stdin); print(\"Gemini live:\", s[\"gemini\"], \"| IBM Granite live:\", s.get(\"granite\"), \"| Snowflake live:\", s[\"snowflake\"])"'
