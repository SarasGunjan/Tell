import type { PageId, Status } from './api';
import { SIGNALS, type SignalKey } from './util';

export type Top500Filters = {
  q: string; family_id: string; min_epss: number; signals: SignalKey[];
  sort: 'rank' | 'epss'; offset: number;
};
export const state = {
  page: 'galaxy' as PageId,
  selection: null as string | null, // CVE currently open in the drawer / analyst picker
  chatContext: null as string | null, // e.g. a family the user asked about; sent as chat selection
  top500: { q: '', family_id: '', min_epss: 0, signals: [], sort: 'rank', offset: 0 } as Top500Filters,
};
export const bus = new EventTarget();
export const emit = (name: string, detail?: unknown) => bus.dispatchEvent(new CustomEvent(name, { detail }));

export function applyFilter(f: { q?: string; family_id?: string; min_epss?: number; signals?: string[] }): void {
  const valid = new Set<string>(SIGNALS.map((s) => s.key));
  state.top500 = {
    ...state.top500,
    q: f.q ?? '',
    family_id: f.family_id ?? '',
    min_epss: f.min_epss ?? 0,
    signals: (f.signals ?? []).filter((s): s is SignalKey => valid.has(s)),
    offset: 0,
  };
  emit('filterschange');
}

/** Latest /api/status (set by the shell). null until the first response. */
export const app = { status: null as Status | null };
const fileOk = (names: string[]) => !!app.status && app.status.files.some((f) => names.includes(f.name) && f.present && !f.missing_required.length);
/** True once status is known and no per-CVE family file (families.csv / granite_features.csv) is usable. */
export const familyWaiting = (): boolean => !!app.status && !fileOk(['benchmark_2026/families.csv', 'benchmark_2026/granite_features.csv', 'families.csv', 'granite_features.csv']);

/** Open the chat dock and ask `text`, with `context` sent as the chat selection (e.g. a family). */
export function emitAsk(text: string, context: string): void { emit('chat:ask', { text, context }); }
