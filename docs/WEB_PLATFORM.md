# Tell Web Platform — Plan & API Contract

**Tell** — *Every attack has a tell.* Member 3 deliverable (full-stack, APIs, deployment).
Chart.js web frontend + thin read-only FastAPI layer. Replaces nothing: the Streamlit app keeps working.

## Integration with Members 1 & 2 (drop-in, no code changes)

Teammates finish their parts and drop files into the results folder; the site picks them up on the next request (the API checks file mtimes and reloads). Run `python -m src.api.validate` to check a drop.

| File | Owner | Required columns | Optional (used if present) | If missing |
|---|---|---|---|---|
| `predictions.csv` (alias `predictions_2026.csv`) | Member 1 | `cve_id, rank, prediction_score` (alias `score`), `epss` | `exploitdb, metasploit, nuclei, poc_github, published, snapshot_month` | site shows "not computed yet" everywhere predictions are needed |
| `metrics.csv` (alias `model_comparison.csv`) | Member 1 | `model, hits_100, hits_250, hits_500` | `precision_*, recall_*, roc_auc, pr_auc` | Model Evaluation shows "not computed yet"; derived columns hidden, never invented |
| `top500.csv` | Member 1 | `cve_id` | — | derived from `predictions` rank ≤ 500 and labelled as derived |
| `granite_features.csv` / `families.csv` | Member 2 | `cve_id, family_id` (+ `remote_local, auth_required` in granite_features) | `family_name, attack_type` | CVEs show "family: not computed yet"; Families page shows waiting state |
| `family_summary.csv` | Member 2 | `family_id, family_name, family_size` | `hist_kev_rate, avg_epss_2026, high_risk, key_traits` | Families page shows waiting state; missing optional columns hide their chart |

- Folder: `TELL_RESULTS_DIR` (default `results/`). Point it at `mock_data/` to test the UI.
- Data label: `TELL_DATA_LABEL=demo|final` (default `demo`). While `demo`, every page shows a "Demo data — not final results" banner. Members 1 & 2 confirm their files are final → set `final`.
- `/api/status` reports per-file `{present, rows, columns, missing_required, modified}` so the UI (status pill → popover) and teammates can see integration state.
- Missing value → `null` in JSON → UI renders "not computed yet". Never a fabricated default.

## Ground rules

1. **Nothing the backend doesn't support.** Every number on screen comes from `results/*.csv`, `data/vulnerabilities.csv`, or an existing `src/ai` module. Aggregates (counts, histograms) are computed from those files only. No invented metrics, no claims copied from README/docs that `metrics.csv` doesn't back.
2. **Label provenance everywhere** (spec §9): *Observed historical outcome* vs *Model prediction* vs *AI-generated summary*. AI text always carries a source tag + grounding badge.
3. **Secrets stay server-side.** `GEMINI_API_KEY`, Snowflake creds are read only by Python. The browser never sees them. `/api/status` reports booleans only.
4. AI output is untrusted: render Markdown through `marked` + `DOMPurify`, never raw `innerHTML`.

## Layout

```
src/api/            FastAPI app (new)
  server.py         app, routes, static serving of web/dist
  store.py          loads + merges CSVs once at startup (pandas)
  chat.py           Gemini chat w/ function calling + offline intent fallback
web/                Vite + TypeScript + Chart.js (new)
```

Run: `uvicorn src.api.server:app --reload --port 8000` and `cd web && npm run dev` (Vite proxies `/api` → `:8000`).
Prod: `npm run build` → FastAPI serves `web/dist` at `/`.

## Config (env / `.env`, loaded with python-dotenv)

| Var | Use |
|---|---|
| `THREATRANK_DATA_DIR` | folder holding raw CSVs (default `./data`). Only `vulnerabilities.csv` is read (`cve_id, description, cvss3_score, attack_vector, cwe_ids`), filtered to the 72,670 scored IDs. Missing → descriptions `null`, app still works. |
| `GEMINI_API_KEY` | chatbot, pet, briefs. Missing → offline grounded fallback. |
| `GEMINI_MODEL` | default `gemini-2.5-flash` (1.5 is retired). |
| Snowflake vars | unchanged, used by existing `SnowflakeCortexAssistant`. |

## Data model (merged at startup)

`CVE` = `predictions.csv` ⨝ `families.csv` (family_id, family_name, remote_local, auth_required, attack_type) ⨝ `vulnerabilities.csv` (optional cols):

```ts
type CVE = {
  cve_id: string; rank: number; prediction_score: number; epss: number;
  exploitdb: 0|1; metasploit: 0|1; nuclei: 0|1; poc_github: 0|1;
  published: string; snapshot_month: string; in_top500: boolean;
  family_id: string|null; family_name: string|null;
  remote_local: string|null; auth_required: string|null; attack_type: string|null;
  description: string|null; cvss3_score: number|null; attack_vector: string|null; cwe_ids: string|null;
}
type Family = { family_id; family_name; family_size; hist_kev_rate; avg_epss_2026; high_risk: boolean; key_traits: string }
type Metric = { model; hits_100; precision_100; recall_100; hits_250; precision_250; recall_250; hits_500; precision_500; recall_500; roc_auc; pr_auc }
type Grounding = { target_cve; grounding_score; status_label; checks: {item,status,detail}[]; hallucinations: string[]; is_grounded: boolean }  // EvidenceGroundingEngine.verify_response
type Action =                                   // UI actions the chatbot/pet may trigger
  | { type: "navigate"; page: "overview"|"top500"|"families"|"models"|"analyst" }
  | { type: "open_cve"; cve_id: string }
  | { type: "filter_top500"; q?: string; family_id?: string; min_epss?: number; signals?: string[] }
  | { type: "highlight"; target: string }      // chart/element id, see "Highlight targets"
  | { type: "show_cves"; cve_ids: string[] }   // inline result cards in chat
```

## Endpoints (all JSON, all GET are read-only)

| Method & path | Returns |
|---|---|
| `GET /api/status` | `{ gemini: bool, snowflake: bool, descriptions: bool, model: string, counts: {cves, top500, families} }` |
| `GET /api/overview` | `{ total_cves, top500_count, family_count, positives_2025` (= round(hits_500 / recall_500) from metrics.csv; 61)`, best_hits_500: Metric, epss_hits_500: number, tell: Metric, signal_counts: {all:{exploitdb,metasploit,nuclei,poc_github,any,none}, top500:{…}} }` |
| `GET /api/metrics` | `Metric[]` (metrics.csv as-is) |
| `GET /api/distributions` | `{ score_hist:{edges:number[],all:number[],top500:number[]}, epss_hist:{…same}, published_by_month:{months:string[],all:number[],top500:number[]}, remote_local:{label,count}[], auth_required:{label,count}[] }` — computed once at startup |
| `GET /api/families` | `Family[]` |
| `GET /api/families/{id}` | `{ family: Family, top_cves: CVE[20], in_top500: number, signal_counts }` 404 if unknown |
| `GET /api/cves?q=&family_id=&min_epss=&signals=metasploit,nuclei&scope=top500\|all&sort=rank\|epss\|score&limit=50&offset=0` | `{ total, items: CVE[] }` (limit ≤ 200; q matches cve_id or description, case-insensitive) |
| `GET /api/cves/{cve_id}` | `CVE` 404 if unknown |
| `POST /api/brief` `{cve_id}` | `{ source, model, content(md), grounding: Grounding }` via `GeminiBriefGenerator` |
| `POST /api/ask` `{cve_id, question}` | `{ source, model, response(md), grounding }` via `SnowflakeCortexAssistant` |
| `POST /api/chat` `{messages:[{role:"user"\|"assistant",content}], page, selection?}` | `{ reply(md), actions: Action[], cves: CVE[], source: "gemini"\|"offline", grounding?: Grounding }` |
| `POST /api/explain` `{target, page}` | `{ title, text(md), source, actions: Action[] }` — pet narration for a highlight target, grounded in that target's data |

Errors: `{detail}` with 4xx; AI routes never 500 on provider failure — they fall back offline and say so in `source`.

### `/api/chat` behaviour
Gemini function calling (`tools.functionDeclarations`) over the read endpoints: `search_cves`, `get_cve`, `list_families`, `get_family`, `get_metrics`, `get_distributions`, plus UI tools `navigate`, `highlight`, `open_cve`, `filter_top500`. Loop ≤ 4 tool rounds. Tool results are real store data; UI tools are collected into `actions`. System prompt: answer only from tool results, cite CVE IDs, never say a 2026 CVE is in KEV, state uncertainty. Final reply passes through `EvidenceGroundingEngine`.
**Offline fallback** (no key / API error): regex intent router — CVE id → get_cve + open_cve; family name/id → get_family + navigate families + highlight; "top"/"highest"/"riskiest" → top N; "metasploit|nuclei|exploitdb|poc" → filter; "model|hits|precision|recall|accuracy" → metrics + navigate models; else help text listing what it can do. Same response shape.
Send the Gemini key as header `x-goog-api-key`, not in the URL.

### Highlight targets (shared ids between pet, chat, and DOM `data-explain` attrs)
`kpi-candidates, kpi-hits500, kpi-lift, chart-score-dist, chart-epss-dist, chart-signals, chart-published, chart-family-size, chart-family-kev, chart-family-bubble, chart-hits, chart-precision-recall, table-auc, table-top500, panel-cve, panel-brief, panel-grounding`

`/api/explain` builds its text from the target's real data (e.g. `chart-family-kev` → reads family_summary). Offline: deterministic template from the same numbers.

## Frontend pages (hash router, View Transitions)

| Page | Contents (Chart.js) |
|---|---|
| Overview | KPI tiles; score distribution (top500 vs all, log y); EPSS distribution; exploit-signal prevalence top500 vs all; published-by-month |
| Top 500 | filter bar (search, family, min EPSS, signal chips); virtual/paged table; CVE drawer (fields, signals, family, description, provenance labels, "Brief" + "Ask" buttons) |
| Families | family size bar; historical KEV rate bar; bubble (size × KEV rate × avg EPSS); family detail panel w/ top CVEs |
| Model Evaluation | grouped Hits@100/250/500; precision/recall@K lines; AUC table; honest note: heuristic leads Hits@500 (19) over Tell ensemble (14); all teammate-reported caveats from spec |
| AI Analyst | CVE picker → Gemini brief + Cortex Q&A + grounding report |

Global: **Chat dock** (bottom-right, persists across pages, executes `actions`), **AI pet** (roams; on hover/click of any `[data-explain]` element walks there and narrates via `/api/explain`; clicking pet opens chat; draggable; dismissible; remembers state in localStorage).

## Theme: space × IBM (Sheridan Datathon 2026 theme = space, track = IBM)

- **Type:** IBM Plex Sans (UI) + IBM Plex Mono (numbers, IDs) via Google Fonts (OFL).
- **Base (Carbon Gray 100, deepened toward space):** page `#0b0d14`, surface-1 `#13161f`, surface-2 `#1b1f2b`, lines `#2a2f3d` / `#3a4152`; text `#f4f4f4` / `#c6c6c6` / `#8d8d8d` (verify AA on each surface).
- **Accent:** IBM Blue 60 `#0f62fe` (fills/buttons), Blue 40 `#78a9ff` (links, focus ring, accents on dark). One accent per view.
- **Highlight:** Yellow 30 `#f1c21b` — Crafternauta's colour; used sparingly (pet bubble edge, "Top 500" emphasis).
- **Data viz (Carbon dark categorical, colour-blind tested):** `#8a3ffc` purple 60, `#33b1ff` cyan 40, `#007d79` teal 60, `#ff7eb6` magenta 40, `#fa4d56` red 50, `#6fdc8c` green 30, `#4589ff` blue 50, `#d2a106` yellow 40. Tell ensemble always blue 40/60; "All CVEs" neutral `#6f6f6f`+; high-risk = red 50/magenta.
- **Status:** support colours from Carbon (success green 40 `#42be65`, warning yellow 30, error red 50, info blue 50).
- **Light theme:** Carbon White/Gray 10 equivalents with Blue 60 accent and the light categorical palette (`#6929c4, #1192e8, #005d5d, #9f1853, #fa4d56, #198038, #002d9c, #b28600`).
- **Space layer:** fixed `<canvas>` starfield behind content, ~120 stars, 2 depth layers, opacity ≤ .35, slow drift + scroll parallax (≤ 0.15), twinkle on a few; paused when hidden; static under reduced motion; hidden in light theme. Optional faint nebula radial wash in hero only (≤ 6% opacity). No glows on UI chrome, no gradients on cards.
- **No IBM logo/wordmark** and nothing implying IBM endorsement; "Built for the IBM *Before the Breach* track" as plain text is fine.

## Interactivity (all backed by existing endpoints)

- Chart click-through: family bars → Families detail; signal bars → Top 500 filtered by that signal; EPSS histogram bin → Top 500 with `min_epss` = bin lower edge; Hits chart model → highlights that model across Model Evaluation charts; bubble → family detail.
- Cursor `pointer` + tooltip hint "Click to filter" on clickable charts; keyboard equivalent via the chart's data table rows / buttons.

## Motion

- Tokens: `--ease-out: cubic-bezier(0.23,1,0.32,1)`, `--ease-in-out: cubic-bezier(0.77,0,0.175,1)`, durations 150/240/400ms.
- Site: page swaps via View Transitions (fade + 8px rise), cards stagger in (40ms), drawers/sheets slide with ease-out, buttons press-scale 0.97.
- Charts (subtler): Chart.js `animation.duration` 700, `easing: 'easeOutQuart'`, per-index delay ≤ 25ms, hover transitions 150ms, no bounce.
- Pet: spring-like WAAPI walks, idle breathing loop, looks toward cursor.
- `prefers-reduced-motion`: disable chart animation, pet walking (teleport + fade), stagger.
