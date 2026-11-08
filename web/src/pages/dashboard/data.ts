// Typed-array view of /api/galaxy plus the pure functions every dashboard panel shares.
// Nothing here is invented: positions are a deterministic layout of API values (rank, family, id hash).
import type { Galaxy } from '../../api';
import type { SignalKey } from '../../util';
import { ENCODINGS } from './encodings';

export type GalaxyOk = Extract<Galaxy, { available: true }>;
export const SIG_BIT: Record<SignalKey, number> = { exploitdb: 1, metasploit: 2, nuclei: 4, poc_github: 8 };
export type Scope = 'top500' | 'all';
export type Filters = { scope: Scope; familyIdx: number | null; signals: Set<SignalKey>; minEpss: number };

/** Geometry constants: rank percentile -> radius, family -> arm. */
export const R_MIN = ENCODINGS.distance.rMin;
export const RADIUS_EXP = ENCODINGS.distance.exponent;
export const TWIST = ENCODINGS.arm.twist;
export const radiusOfIndex = (i: number, n: number): number => R_MIN + (1 - R_MIN) * Math.pow(n > 1 ? i / (n - 1) : 0, RADIUS_EXP);

export type Pos = { x: Float32Array; y: Float32Array };
export type GalaxyData = GalaxyOk & {
  hash: Uint32Array; rad: Float32Array; // rad = star radius in px at 1x
  pos: { spiral: Pos; rows: Pos; embedding: Pos | null };
  epssA: Float32Array; sigA: Uint8Array; famA: Int16Array; topA: Uint8Array;
  idx: Map<string, number>; nFam: number; hasFamilies: boolean;
};

function fnv(s: string): number {
  let x = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 0x01000193); }
  return x >>> 0;
}
const mix = (h: number, k: number): number => {
  let x = (h ^ Math.imul(k, 0x9e3779b1)) >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x85ebca6b); x = Math.imul(x ^ (x >>> 13), 0xc2b2ae35);
  return ((x ^ (x >>> 16)) >>> 0) / 4294967296;
};

const ROWS_X0 = -0.3, ROWS_X1 = 0.97;
/** Robust min-max (0.5 to 99.5 percentile) into the unit disc; stars without a coordinate keep their spiral spot. */
function normalizeEmbedding(gx: (number | null)[], gy: (number | null)[], fx: Float32Array, fy: Float32Array): Pos {
  const q = (a: (number | null)[], p: number) => { const v = a.filter((x): x is number => x !== null).sort((u, w) => u - w); return v[Math.min(v.length - 1, Math.floor(p * v.length))]; };
  const x0 = q(gx, 0.005), x1 = q(gx, 0.995), y0 = q(gy, 0.005), y1 = q(gy, 0.995);
  const sc = 1.8 / Math.max(1e-9, x1 - x0, y1 - y0), cx = (x0 + x1) / 2, cy = (y0 + y1) / 2;
  const X = new Float32Array(gx.length), Y = new Float32Array(gx.length);
  for (let i = 0; i < gx.length; i++) {
    const a = gx[i], b = gy[i];
    if (a === null || b === null) { X[i] = fx[i]; Y[i] = fy[i]; continue; }
    X[i] = Math.max(-1.08, Math.min(1.08, (a - cx) * sc)); Y[i] = Math.max(-1.08, Math.min(1.08, (b - cy) * sc));
  }
  return { x: X, y: Y };
}

export function prepare(g: GalaxyOk): GalaxyData {
  const n = g.n, F = g.families.length;
  const hash = new Uint32Array(n), ux = new Float32Array(n), uy = new Float32Array(n), rad = new Float32Array(n);
  const rx = new Float32Array(n), ry = new Float32Array(n);
  const epssA = Float32Array.from(g.epss), sigA = Uint8Array.from(g.sig);
  const famA = Int16Array.from(g.fam), topA = Uint8Array.from(g.top500);
  const idx = new Map<string, number>();
  for (let i = 0; i < n; i++) {
    const h = fnv(g.ids[i]);
    hash[i] = h; idx.set(g.ids[i], i);
    let r = radiusOfIndex(i, n), a: number;
    const f = famA[i];
    if (f >= 0 && F > 0) {
      a = (2 * Math.PI * f) / F + TWIST * r + (mix(h, 1) + mix(h, 2) - 1) * 0.2;
      r *= 1 + (mix(h, 3) - 0.5) * 0.07;
    } else { // unknown family: diffuse halo
      a = mix(h, 1) * 2 * Math.PI;
      r = 0.12 + 0.93 * Math.sqrt(mix(h, 2)) * (0.4 + 0.6 * Math.pow(i / Math.max(1, n - 1), 0.3));
    }
    ux[i] = r * Math.cos(a); uy[i] = r * Math.sin(a);
  }
  const rows = F + (famA.some((x) => x < 0) ? 1 : 0), lg = Math.log(Math.max(2, n));
  for (let i = 0; i < n; i++) {
    const slot = famA[i] >= 0 ? famA[i] : F, rowH = rows > 1 ? 1.56 / (rows - 1) : 1;
    rx[i] = ROWS_X0 + (ROWS_X1 - ROWS_X0) * (Math.log(Math.max(1, g.rank[i])) / lg);
    ry[i] = (rows > 1 ? -0.78 + slot * rowH : 0) + (mix(hash[i], 4) - 0.5) * rowH * 0.72;
  }
  let emb: Pos | null = null;
  const gx = (g as { x?: (number | null)[] }).x, gy = (g as { y?: (number | null)[] }).y;
  if (gx && gy) emb = normalizeEmbedding(gx, gy, ux, uy);
  const base = { ...g, hash, rad, epssA, sigA, famA, topA, idx, nFam: F, hasFamilies: F > 0 && famA.some((x) => x >= 0) };
  const d = { ...base, pos: { spiral: { x: ux, y: uy }, rows: { x: rx, y: ry }, embedding: emb } } as GalaxyData;
  for (let i = 0; i < n; i++) rad[i] = ENCODINGS.size.px(d, i);
  return d;
}

export function computeMatch(d: GalaxyData, f: Filters): Uint8Array {
  const m = new Uint8Array(d.n);
  let mask = 0;
  f.signals.forEach((s) => { mask |= SIG_BIT[s]; });
  for (let i = 0; i < d.n; i++) {
    if (f.scope === 'top500' && !d.topA[i]) continue;
    if (f.familyIdx !== null && d.famA[i] !== f.familyIdx) continue;
    if ((d.sigA[i] & mask) !== mask) continue;
    if (d.epssA[i] < f.minEpss) continue;
    m[i] = 1;
  }
  return m;
}

/** CVEs per family under every filter except the family itself (last slot = unknown family). */
export function familyCounts(d: GalaxyData, f: Filters): Int32Array {
  const c = new Int32Array(d.nFam + 1);
  let mask = 0;
  f.signals.forEach((s) => { mask |= SIG_BIT[s]; });
  for (let i = 0; i < d.n; i++) {
    if (f.scope === 'top500' && !d.topA[i]) continue;
    if ((d.sigA[i] & mask) !== mask || d.epssA[i] < f.minEpss) continue;
    c[d.famA[i] >= 0 ? d.famA[i] : d.nFam]++;
  }
  return c;
}

export const EPSS_BINS = 20;
export const EPSS_LOG_MIN = -5;
export const epssBin = (e: number): number => {
  if (e <= 0) return 0;
  const b = Math.floor(((Math.log10(e) - EPSS_LOG_MIN) / -EPSS_LOG_MIN) * EPSS_BINS);
  return b < 0 ? 0 : b >= EPSS_BINS ? EPSS_BINS - 1 : b;
};
export const epssBinLabel = (b: number): string => {
  const lo = EPSS_LOG_MIN + (b * -EPSS_LOG_MIN) / EPSS_BINS, hi = EPSS_LOG_MIN + ((b + 1) * -EPSS_LOG_MIN) / EPSS_BINS;
  const f = (e: number) => { const v = 10 ** e; return v >= 0.1 ? `${(v * 100).toFixed(0)}%` : v >= 0.01 ? `${(v * 100).toFixed(1)}%` : `${(v * 100).toFixed(v >= 0.001 ? 2 : 3)}%`; };
  return b === 0 ? `≤ ${f(hi)}` : `${f(lo)}–${f(hi)}`;
};

export type Summary = {
  count: number; top500: number; withSignal: number; medianEpss: number | null;
  sigCounts: Record<SignalKey, number>; hist: number[]; firstIdx: number[]; // firstIdx: top matches by rank (up to 50)
};
export const KEYS: SignalKey[] = ['exploitdb', 'metasploit', 'nuclei', 'poc_github'];

export function summarize(d: GalaxyData, match: Uint8Array): Summary {
  const s: Summary = { count: 0, top500: 0, withSignal: 0, medianEpss: null, sigCounts: { exploitdb: 0, metasploit: 0, nuclei: 0, poc_github: 0 }, hist: new Array(EPSS_BINS).fill(0), firstIdx: [] };
  const vals = new Float32Array(d.n);
  for (let i = 0; i < d.n; i++) {
    if (!match[i]) continue;
    vals[s.count++] = d.epssA[i];
    if (d.topA[i]) s.top500++;
    const sg = d.sigA[i];
    if (sg) s.withSignal++;
    for (const k of KEYS) if (sg & SIG_BIT[k]) s.sigCounts[k]++;
    s.hist[epssBin(d.epssA[i])]++;
    if (s.firstIdx.length < 50) s.firstIdx.push(i);
  }
  if (s.count) {
    const v = vals.subarray(0, s.count).sort();
    s.medianEpss = s.count % 2 ? v[(s.count - 1) / 2] : (v[s.count / 2 - 1] + v[s.count / 2]) / 2;
  }
  return s;
}

/** Deterministic scatter sample: every Top 500 CVE with EPSS > 0 plus `k` others chosen by id hash (log axis cannot show EPSS = 0). */
export function scatterSample(d: GalaxyData, k = 4000): { idx: Int32Array; zeroEpssTop: number } {
  const top: number[] = [], rest: number[] = [];
  let zeroEpssTop = 0;
  for (let i = 0; i < d.n; i++) {
    if (d.epssA[i] <= 0) { if (d.topA[i]) zeroEpssTop++; continue; }
    (d.topA[i] ? top : rest).push(i);
  }
  rest.sort((a, b) => d.hash[a] - d.hash[b] || a - b);
  const out = Int32Array.from([...rest.slice(0, k), ...top]); // top500 last = drawn on top
  return { idx: out, zeroEpssTop };
}
