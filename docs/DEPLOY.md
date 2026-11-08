# Deploying Tell on Vultr

Stack: host nginx (80/443, rate limits, TLS) -> Docker container `tell` on 127.0.0.1:8000 (FastAPI + built SPA).

## 1. Create the server
Vultr Cloud Compute, Ubuntu 24.04, at least 2 GB RAM (use 4 GB if you upload `vulnerabilities.csv`, the API loads it into memory).

## 2. Install
```bash
ssh root@<IP>
curl -fsSL https://raw.githubusercontent.com/SarasGunjan/ThreatRank/feature/web-frontend/deploy/setup_vultr.sh | bash
```
This only works once the branch is pushed to GitHub. Alternative:
```bash
git clone -b feature/web-frontend https://github.com/SarasGunjan/ThreatRank.git /opt/tell
bash /opt/tell/deploy/setup_vultr.sh
```
Optional overrides: `DOMAIN=tell.example.com EMAIL=you@example.com BRANCH=main bash setup_vultr.sh`. The script is safe to re-run.

## 3. Keys
Edit `/opt/tell/.env` (`GEMINI_API_KEY`, `GEMINI_MODEL`, `SNOWFLAKE_*`). Without keys the AI features run in offline mode. Apply:
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
