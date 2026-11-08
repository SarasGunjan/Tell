# Deploying Tell

Live: https://149-28-52-109.sslip.io (Vultr, paid from MLH's $100 Vultr credit).

## Alternative: Hugging Face Spaces (free; blocked for our account by HF rate limits)
1. Make a free account at huggingface.co, then create a token with "Write" access (Settings -> Access Tokens).
2. Sign in on the deploying machine: `.venv/bin/hf auth login` (paste the token there, never in chat or git).
3. Deploy or update: `.venv/bin/python deploy/push_hf_space.py` (Space `<you>/tell`; pass `owner/name` to change it).
4. Optional live AI: Space Settings -> Variables and secrets -> New secret `GEMINI_API_KEY`.

The app is served at `https://<you>-tell.hf.space` after a 3-5 min build. AI endpoints are rate-limited
in the app (5 burst, 10/min per IP) because Spaces has no nginx. A free Space sleeps after about 48 h with
no visits and wakes on the next one. `data/vulnerabilities.csv` is not uploaded, so CVE descriptions stay off.

## Vultr (current)

Stack: host nginx (80/443, rate limits, TLS) -> Docker container `tell` on 127.0.0.1:8000 (FastAPI + built SPA).

## 1. Create the server
Vultr Cloud Compute, Ubuntu 24.04, at least 2 GB RAM (use 4 GB if you upload `vulnerabilities.csv`, the API loads it into memory).

## 2. Install
```bash
ssh root@<IP>
curl -fsSL https://raw.githubusercontent.com/SarasGunjan/Tell/feature/web-frontend/deploy/setup_vultr.sh | bash
```
This only works once the branch is pushed to GitHub. Alternative:
```bash
git clone -b feature/web-frontend https://github.com/SarasGunjan/ThreatRank.git /opt/tell
bash /opt/tell/deploy/setup_vultr.sh
```
Optional overrides: `DOMAIN=tell.example.com EMAIL=you@example.com BRANCH=main bash setup_vultr.sh`. The script is safe to re-run.

## 3. Keys
From your own machine: `bash deploy/set_secrets.sh`. It asks (hidden) for `GEMINI_API_KEY` (free at aistudio.google.com),
`SNOWFLAKE_ACCOUNT` (`orgname-accountname`), `SNOWFLAKE_USER` and `SNOWFLAKE_PAT` (a programmatic access token from
Snowsight: user menu -> Settings -> Authentication; passwords don't work with the Cortex REST API), writes them to
`/opt/tell/.env` over SSH, restarts the app and prints whether Gemini and Snowflake are live. Blank answers keep the
current value. Without keys the AI features run in offline mode. To edit by hand instead, change `/opt/tell/.env` and apply:
```bash
cd /opt/tell && docker compose -f deploy/docker-compose.yml up -d
```

## 4. Data
- CVE descriptions (optional): `scp data/vulnerabilities.csv root@<IP>:/opt/tell/data/`
- Teammates' results: copy CSVs into `/opt/tell/results/`. Live on the next request (hot reload), no rebuild. Validate:
  ```bash
  docker compose -f deploy/docker-compose.yml exec tell python -m src.api.validate --dir /app/results
  ```
- When results are final, set `TELL_DATA_LABEL=final` in `/opt/tell/.env` and re-run `up -d`.

## 5. HTTPS
With no `DOMAIN` set, the script uses `<a-b-c-d>.sslip.io`, a free wildcard DNS name that resolves to `a.b.c.d`, and gets a Let's Encrypt cert through certbot. If certbot fails the site stays on http; retry `certbot --nginx -d <domain>`. Ports 80 and 443 must be reachable.

Own domain (e.g. the free MLH GoDaddy Registry one): add DNS `A` records `@` and `www` -> server IP, wait a few minutes,
then run `bash deploy/add_domain.sh yourname.tech` from your machine. It checks DNS, adds the name to nginx, extends the
certificate and keeps the sslip.io address working.

## 6. Updating code
```bash
/opt/tell/deploy/update.sh
```

## Troubleshooting
- Logs: `docker compose -f deploy/docker-compose.yml logs -f tell`
- Health: `curl -s http://127.0.0.1:8000/api/status`; `docker ps` shows `healthy`.
- HTTP 429: nginx rate limit. AI endpoints (`chat`, `explain`, `brief`, `ask`) allow 10 requests/min per IP (burst 5); other `/api/` 10/s.
- Blank page / console CSP errors: if `web/index.html` inline script changes, recompute its sha256 and update the CSP in `deploy/nginx.conf`.
- Old Streamlit app: `docker compose -f deploy/docker-compose.yml --profile streamlit up -d streamlit` (127.0.0.1:8501 only).
