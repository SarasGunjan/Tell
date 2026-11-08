// Client for the contract in docs/WEB_PLATFORM.md. Types mirror the backend; no mock data.

export type CVE = {
  cve_id: string; rank: number; prediction_score: number | null; epss: number;
  exploitdb: 0 | 1; metasploit: 0 | 1; nuclei: 0 | 1; poc_github: 0 | 1;
  published: string; snapshot_month: string; in_top500: boolean;
  family_id: string | null; family_name: string | null;
  remote_local: string | null; auth_required: string | null; vulnerability_type: string | null;
  // detail only (not in list payloads): IBM Granite extraction (Member 2)
  attack_surface?: string | null; product_or_vendor?: string | null; extraction_method?: string | null;
  extraction_confidence?: string | null; evidence?: string | null; extraction_source?: string | null;
  description: string | null; cvss3_score: number | null; attack_vector: string | null; cwe_ids: string | null;
};
// null = column not supplied yet (shown as "not computed yet", never as 0)
export type Family = {
  family_id: string; family_name: string; family_size: number; historical_kev_count: number | null;
  sample_kev_rate: number | null; population_kev_rate: number | null; population_lift: number | null; sample_lift: number | null;
  ci_95_low: number | null; ci_95_high: number | null; representative_cves: string[]; top_characteristics: string | null;
  high_risk: boolean | null; in_top500: number | null; scored_count: number | null; caveat: string | null; rate_basis: string;
};
export type Breakdown = { label: string; count: number; share: number };
export type Metric = {
  model: string;
  hits_100: number; precision_100: number | null; recall_100: number | null;
  hits_250: number; precision_250: number | null; recall_250: number | null;
  hits_500: number; precision_500: number | null; recall_500: number | null;
  roc_auc: number | null; pr_auc: number | null; average_precision: number | null;
};
export type BudgetPoint = { model: string; budget: number; hits: number; derived: boolean };
export type GroundingCheck = { item: string; status: string; detail: string };
export type Grounding = {
  target_cve: string; grounding_score: number; status_label: string;
  checks: GroundingCheck[]; hallucinations: string[]; is_grounded: boolean;
};
export type PageId = 'galaxy' | 'signals' | 'top500' | 'families' | 'discoveries' | 'how-we-ranked' | 'ask' | 'story';
/** Old page ids (backend chat actions, old bookmarks) to the current ones. */
export const LEGACY_PAGE: Record<string, PageId> = { dashboard: 'galaxy', overview: 'signals', research: 'discoveries', models: 'how-we-ranked', analyst: 'ask' };
const BACKEND_PAGE: Partial<Record<PageId, string>> = { galaxy: 'dashboard', signals: 'overview', discoveries: 'research', 'how-we-ranked': 'models', ask: 'analyst', story: 'overview' };
/** The backend only knows the old ids; send those. */
const toBackend = (p: PageId): string => BACKEND_PAGE[p] ?? p;
export type Action =
  | { type: 'navigate'; page: string }
  | { type: 'open_cve'; cve_id: string }
  | { type: 'filter_top500'; q?: string; family_id?: string; min_epss?: number; signals?: string[] }
  | { type: 'highlight'; target: string }
  | { type: 'show_cves'; cve_ids: string[] };

export type SignalCounts = { exploitdb: number | null; metasploit: number | null; nuclei: number | null; poc_github: number | null; any: number | null; none: number | null };
export type StatusFile = {
  name: string; owner: 'Member 1' | 'Member 2'; present: boolean; rows: number | null; columns: string[];
  missing_required: string[]; modified: string | null; optional?: boolean;
};
export type GalaxyFamily = { family_id: string; family_name: string | null; high_risk: boolean | null };
/** Columnar payload for the Threat Galaxy: every array has length n and is ordered by model rank. */
export type Galaxy =
  | { available: false; waiting: string }
  | {
      available: true; n: number; ids: string[]; rank: number[]; score?: number[]; epss: number[];
      fam: number[]; sig: number[]; top500: number[]; families: GalaxyFamily[]; signals_available: string[];
      ranking_method: string; x?: (number | null)[]; y?: (number | null)[];
    };
export type Status = {
  gemini: boolean; snowflake: boolean; granite?: boolean; granite_model?: string; descriptions: boolean; model: string;
  counts: { cves: number | null; top500: number | null; families: number | null };
  ranking_method: string; has_score: boolean; data_label: 'demo' | 'final'; results_dir: string; top500_source: 'file' | 'derived' | null; files: StatusFile[];
};
export type Overview = {
  total_cves: number | null; top500_count: number | null; family_count: number | null;
  best_hits_500: Metric | null; epss_hits_500: number | null; ranking: Metric | null; lift_over_epss: number | null;
  ranking_method: string; has_score: boolean;
  signal_counts: { all: SignalCounts; top500: SignalCounts } | null;
};
type Hist = { edges: number[]; all: number[]; top500: number[] };
export type Distributions = {
  score_hist: Hist | null;
  rank_epss: { label: string; from: number; to: number; count: number; median_epss: number; mean_epss: number; share_with_signal: number | null }[] | null;
  epss_hist: Hist | null;
  published_by_month: { months: string[]; all: number[]; top500: number[] } | null;
  remote_local: { label: string; count: number }[];
  auth_required: { label: string; count: number }[];
};
export type FamilyDetail = {
  family: Family; top_cves: CVE[]; in_top500: number | null; signal_counts: SignalCounts | null;
  attack_surface: Breakdown[]; vulnerability_type: Breakdown[]; historical_examples: string[]; historical_examples_label: string;
  historical_family_name: string | null; representative_2026: string[]; representative_2026_label: string; caveat: string | null;
};
type RBlock<T> = { data: T; provenance: string; cohort_label: string; note?: string } | null;
export type Headline = {
  top3_family_ids: string[]; top3_family_names: (string | null)[]; ranked_by: string; kev_share: number; volume_share: number; lift: number;
  val_kev_top3: number; val_kev_total: number; val_n_top3: number; val_n_total: number; matches_reported: boolean | null;
};
export type TemporalRow = { family_id: string; family_name: string | null; train_2024_n: number; train_2024_kev: number; train_2024_rate: number; train_2024_lift: number; val_2025_n: number; val_2025_kev: number; val_2025_rate: number; val_2025_lift: number };
export type Research =
  | { available: false; waiting: string }
  | {
      available: true; cohort_label: string; sample_caption: string; caveats: string[];
      cohort: { label: string; n: number | null; kev_total: number | null; sample_base_rate: number | null; population_total_cves: number | null; population_base_rate: number | null; years: number[] | null; n_clusters: number | null; mean_cosine_cohesion: number | null; silhouette_cosine: number | null; embedding_model: string | null };
      families: RBlock<Family[]>;
      concentration: RBlock<{ method: string; kev_share: number; population_volume_share: number; population_ratio: number; peak_population_lift: number | null }>;
      baselines: RBlock<{ method: string; non_missing_coverage: number | null; population_top3_concentration_ratio: number | null; population_top3_volume_share: number | null; top3_groups_kev_share: number | null }[]>;
      temporal: RBlock<{ rows: TemporalRow[]; headline: Headline | null; train_year: number | null; val_year: number | null }>;
      cwe: RBlock<{ families: string[]; rows: { cwe_id: string; cwe_name: string | null; total: number; cells: Record<string, { count: number; share: number | null }> }[]; unassigned: number }>;
    };
export type CveList = { total: number; items: CVE[] };
export type AiSource = 'gemini' | 'offline' | string;
export type BriefResult = { source: AiSource; model: string; content: string; grounding: Grounding };
export type AskResult = { source: AiSource; model: string; response: string; grounding: Grounding };
export type ChatMessage = { role: 'user' | 'assistant'; content: string };
export type ChatResult = { reply: string; actions: Action[]; cves: CVE[]; source: AiSource; grounding?: Grounding };
export type ExplainResult = { title: string; text: string; source: AiSource; actions: Action[] };

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function req<T>(path: string, init?: RequestInit, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { ...init, signal, headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) } });
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e;
    throw new ApiError(0, 'Cannot reach the Tell API. Is the backend running on :8000?');
  }
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); if (j?.detail) detail = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } catch { /* keep statusText */ }
    throw new ApiError(res.status, detail || `Request failed (${res.status})`);
  }
  return res.json() as Promise<T>;
}
const post = <T>(path: string, body: unknown) => req<T>(path, { method: 'POST', body: JSON.stringify(body) });

// Tiny in-memory cache for read-only GETs that never change within a session.
const cache = new Map<string, Promise<unknown>>();
function cached<T>(path: string): Promise<T> {
  let p = cache.get(path) as Promise<T> | undefined;
  if (!p) {
    p = req<T>(path);
    cache.set(path, p);
    p.catch(() => cache.delete(path));
  }
  return p;
}

export type CveQuery = {
  q?: string; family_id?: string; min_epss?: number; signals?: string[];
  scope?: 'top500' | 'all'; sort?: 'rank' | 'epss'; limit?: number; offset?: number;
};
export function cveQueryString(q: CveQuery): string {
  const p = new URLSearchParams();
  if (q.q) p.set('q', q.q);
  if (q.family_id) p.set('family_id', q.family_id);
  if (q.min_epss) p.set('min_epss', String(q.min_epss));
  if (q.signals?.length) p.set('signals', q.signals.join(','));
  p.set('scope', q.scope ?? 'top500');
  if (q.sort) p.set('sort', q.sort);
  p.set('limit', String(q.limit ?? 50));
  p.set('offset', String(q.offset ?? 0));
  return p.toString();
}

export const api = {
  status: () => req<Status>('/api/status'),
  galaxy: () => cached<Galaxy>('/api/galaxy'),
  overview: () => cached<Overview>('/api/overview'),
  metrics: () => cached<Metric[]>('/api/metrics'),
  distributions: () => cached<Distributions>('/api/distributions'),
  families: () => cached<Family[]>('/api/families'),
  patchBudget: () => cached<BudgetPoint[]>('/api/patch-budget'),
  research: () => cached<Research>('/api/research'),
  family: (id: string) => cached<FamilyDetail>(`/api/families/${encodeURIComponent(id)}`),
  cves: (q: CveQuery, signal?: AbortSignal) => req<CveList>(`/api/cves?${cveQueryString(q)}`, undefined, signal),
  cve: (id: string) => cached<CVE>(`/api/cves/${encodeURIComponent(id)}`),
  brief: (cve_id: string) => post<BriefResult>('/api/brief', { cve_id }),
  ask: (cve_id: string, question: string) => post<AskResult>('/api/ask', { cve_id, question }),
  chat: (messages: ChatMessage[], page: PageId, selection?: string | null) =>
    post<ChatResult>('/api/chat', { messages, page: toBackend(page), ...(selection ? { selection } : {}) }),
  explain: (target: string, page: PageId) => post<ExplainResult>('/api/explain', { target, page: toBackend(page) }),
};
