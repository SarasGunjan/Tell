// Client for the contract in docs/WEB_PLATFORM.md. Types mirror the backend; no mock data.

export type CVE = {
  cve_id: string; rank: number; prediction_score: number; epss: number;
  exploitdb: 0 | 1; metasploit: 0 | 1; nuclei: 0 | 1; poc_github: 0 | 1;
  published: string; snapshot_month: string; in_top500: boolean;
  family_id: string | null; family_name: string | null;
  remote_local: string | null; auth_required: string | null; attack_type: string | null;
  description: string | null; cvss3_score: number | null; attack_vector: string | null; cwe_ids: string | null;
};
// null = column not supplied yet (shown as "not computed yet", never as 0)
export type Family = {
  family_id: string; family_name: string; family_size: number; hist_kev_rate: number | null;
  avg_epss_2026: number | null; high_risk: boolean | null; key_traits: string | null;
};
export type Metric = {
  model: string;
  hits_100: number; precision_100: number | null; recall_100: number | null;
  hits_250: number; precision_250: number | null; recall_250: number | null;
  hits_500: number; precision_500: number | null; recall_500: number | null;
  roc_auc: number | null; pr_auc: number | null;
};
export type GroundingCheck = { item: string; status: string; detail: string };
export type Grounding = {
  target_cve: string; grounding_score: number; status_label: string;
  checks: GroundingCheck[]; hallucinations: string[]; is_grounded: boolean;
};
export type PageId = 'overview' | 'top500' | 'families' | 'models' | 'analyst';
export type Action =
  | { type: 'navigate'; page: PageId }
  | { type: 'open_cve'; cve_id: string }
  | { type: 'filter_top500'; q?: string; family_id?: string; min_epss?: number; signals?: string[] }
  | { type: 'highlight'; target: string }
  | { type: 'show_cves'; cve_ids: string[] };

export type SignalCounts = { exploitdb: number | null; metasploit: number | null; nuclei: number | null; poc_github: number | null; any: number | null; none: number | null };
export type StatusFile = {
  name: string; owner: 'Member 1' | 'Member 2'; present: boolean; rows: number | null; columns: string[];
  missing_required: string[]; modified: string | null; optional?: boolean;
};
export type Status = {
  gemini: boolean; snowflake: boolean; descriptions: boolean; model: string;
  counts: { cves: number | null; top500: number | null; families: number | null };
  data_label: 'demo' | 'final'; results_dir: string; top500_source: 'file' | 'derived' | null; files: StatusFile[];
};
export type Overview = {
  total_cves: number | null; top500_count: number | null; family_count: number | null; positives_2025: number | null;
  best_hits_500: Metric | null; epss_hits_500: number | null; tell: Metric | null;
  signal_counts: { all: SignalCounts; top500: SignalCounts } | null;
};
type Hist = { edges: number[]; all: number[]; top500: number[] };
export type Distributions = {
  score_hist: Hist | null; epss_hist: Hist | null;
  published_by_month: { months: string[]; all: number[]; top500: number[] } | null;
  remote_local: { label: string; count: number }[];
  auth_required: { label: string; count: number }[];
};
export type FamilyDetail = { family: Family; top_cves: CVE[]; in_top500: number | null; signal_counts: SignalCounts | null };
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
  scope?: 'top500' | 'all'; sort?: 'rank' | 'epss' | 'score'; limit?: number; offset?: number;
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
  overview: () => cached<Overview>('/api/overview'),
  metrics: () => cached<Metric[]>('/api/metrics'),
  distributions: () => cached<Distributions>('/api/distributions'),
  families: () => cached<Family[]>('/api/families'),
  family: (id: string) => cached<FamilyDetail>(`/api/families/${encodeURIComponent(id)}`),
  cves: (q: CveQuery, signal?: AbortSignal) => req<CveList>(`/api/cves?${cveQueryString(q)}`, undefined, signal),
  cve: (id: string) => cached<CVE>(`/api/cves/${encodeURIComponent(id)}`),
  brief: (cve_id: string) => post<BriefResult>('/api/brief', { cve_id }),
  ask: (cve_id: string, question: string) => post<AskResult>('/api/ask', { cve_id, question }),
  chat: (messages: ChatMessage[], page: PageId, selection?: string | null) =>
    post<ChatResult>('/api/chat', { messages, page, ...(selection ? { selection } : {}) }),
  explain: (target: string, page: PageId) => post<ExplainResult>('/api/explain', { target, page }),
};
