// One small store for the Dashboard. Every panel renders from it; filters persist in the URL hash query.
import { SIGNALS, type SignalKey } from '../../util';
import type { Layout } from './encodings';
import { computeMatch, summarize, type Filters, type GalaxyData, type Scope, type Summary } from './data';

export type DashState = Filters & { view: Layout; hoverId: string | null; highlightModel: string | null };
export type Derived = { match: Uint8Array; summary: Summary; version: number };
export type Listener = (s: DashState, changed: ReadonlySet<string>) => void;
const FILTER_KEYS = ['scope', 'familyIdx', 'signals', 'minEpss'] as const;

export function readHash(d: GalaxyData): Filters & { view: Layout } {
  const q = new URLSearchParams(location.hash.split('?')[1] ?? '');
  const fam = q.get('fam');
  const fi = fam ? d.families.findIndex((f) => f.family_id === fam) : -1;
  const valid = new Set<string>(SIGNALS.map((s) => s.key).filter((k) => d.signals_available.includes(k)));
  const e = Number(q.get('epss'));
  return {
    scope: q.get('scope') === 'top500' ? 'top500' : 'all',
    familyIdx: fi >= 0 ? fi : null,
    signals: new Set((q.get('sig') ?? '').split(',').filter((x): x is SignalKey => valid.has(x))),
    view: q.get('view') === 'rows' ? 'rows' : q.get('view') === 'map' && d.pos.embedding ? 'embedding' : 'spiral',
    minEpss: Number.isFinite(e) && e > 0 && e <= 1 ? e : 0,
  };
}

function writeHash(d: GalaxyData, f: Filters & { view: Layout }): void {
  const q = new URLSearchParams();
  if (f.scope !== 'all') q.set('scope', f.scope);
  if (f.familyIdx !== null) q.set('fam', d.families[f.familyIdx].family_id);
  if (f.signals.size) q.set('sig', [...f.signals].join(','));
  if (f.minEpss > 0) q.set('epss', String(Number(f.minEpss.toPrecision(3))));
  if (f.view !== 'spiral') q.set('view', f.view === 'rows' ? 'rows' : 'map');
  const qs = q.toString();
  const next = `#/dashboard${qs ? `?${qs}` : ''}`;
  if (location.hash !== next && /^#\/dashboard/.test(location.hash || '#/dashboard')) history.replaceState(null, '', next); // replaceState: no hashchange, no remount
}

export function createStore(d: GalaxyData) {
  let s: DashState = { ...readHash(d), hoverId: null, highlightModel: null };
  let derived: Derived = compute(s, 0);
  const subs = new Set<Listener>();
  function compute(st: Filters, v: number): Derived {
    const match = computeMatch(d, st);
    return { match, summary: summarize(d, match), version: v };
  }
  const same = (a: unknown, b: unknown): boolean =>
    a instanceof Set && b instanceof Set ? a.size === b.size && [...a].every((x) => b.has(x)) : a === b;
  return {
    get state(): DashState { return s; },
    get derived(): Derived { return derived; },
    set(patch: Partial<DashState>): void {
      const changed = new Set<string>();
      for (const k of Object.keys(patch) as (keyof DashState)[]) if (!same(patch[k], s[k])) changed.add(k);
      if (!changed.size) return;
      s = { ...s, ...patch };
      if (FILTER_KEYS.some((k) => changed.has(k))) {
        derived = compute(s, derived.version + 1);
        changed.add('filters');
      }
      if (changed.has('filters') || changed.has('view')) writeHash(d, s);
      subs.forEach((fn) => fn(s, changed));
    },
    reset(): void {
      this.set({ scope: 'all', familyIdx: null, signals: new Set(), minEpss: 0 });
    },
    subscribe(fn: Listener): () => void { subs.add(fn); return () => subs.delete(fn); },
    isDefault: (): boolean => s.scope === 'all' && s.familyIdx === null && !s.signals.size && s.minEpss === 0,
  };
}
export type Store = ReturnType<typeof createStore>;
export type { Scope };
