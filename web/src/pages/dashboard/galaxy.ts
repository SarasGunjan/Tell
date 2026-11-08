// Threat Galaxy: canvas 2D. All 72k stars are painted into an offscreen bitmap once per
// (filters, size, zoom-settle); each frame only blits that bitmap rotated, then draws a few hundred
// twinkles and the hover/selection overlay.
import { h, fmtEpss, fmtInt, SIGNALS } from '../../util';
import { provenanceTag } from '../../charts';
import { familyWaiting, state as appState, bus } from '../../state';
import { openCve } from '../../components/drawer';
import { TWIST, radiusOfIndex, type GalaxyData } from './data';
import { ENCODINGS, LEGEND_SYMBOLS, type Layout } from './encodings';
import type { Store } from './state';

const ROWS0 = -0.3, ROWS1 = 0.97; // must match data.ts
const E = 1.15;            // bitmap half-extent in galaxy units
const MAX_PX = 2560;       // bitmap side cap
const ZMIN = 0.8, ZMAX = 8;
const PERIOD_MS = 240000;  // 1 revolution / 4 min
const GRID = 0.03;
const TWINKLES = 600;
const INTRO_KEY = 'tell.galaxy.intro';

type Sprites = { dot: HTMLCanvasElement[]; glow: HTMLCanvasElement[] };
function sprite(size: number, color: string, glow: boolean): HTMLCanvasElement {
  const c = document.createElement('canvas');
  c.width = c.height = size;
  const g = c.getContext('2d')!, m = size / 2;
  const gr = g.createRadialGradient(m, m, 0, m, m, m);
  if (glow) { // bright core + soft halo, baked once (never shadowBlur per star)
    gr.addColorStop(0, '#fff'); gr.addColorStop(0.1, color); gr.addColorStop(0.22, color);
    gr.addColorStop(0.4, color + '55'); gr.addColorStop(1, color + '00');
  } else { gr.addColorStop(0, color); gr.addColorStop(0.45, color + 'aa'); gr.addColorStop(1, color + '00'); }
  g.fillStyle = gr; g.fillRect(0, 0, size, size);
  return c;
}
function coreSprite(): HTMLCanvasElement {
  const c = document.createElement('canvas');
  c.width = c.height = 256;
  const g = c.getContext('2d')!;
  const gr = g.createRadialGradient(128, 128, 0, 128, 128, 128);
  gr.addColorStop(0, 'rgba(255,244,224,0.55)'); gr.addColorStop(0.18, 'rgba(255,226,180,0.22)'); gr.addColorStop(0.5, 'rgba(120,169,255,0.06)'); gr.addColorStop(1, 'rgba(120,169,255,0)');
  g.fillStyle = gr; g.fillRect(0, 0, 256, 256);
  return c;
}

export type GalaxyView = { el: HTMLElement; destroy(): void; resetView(): void; spots: { stage: HTMLElement; core: HTMLElement; legend: HTMLElement } };

/** CSS cubic-bezier(x1,y1,x2,y2) as a function of progress. */
function bezier(x1: number, y1: number, x2: number, y2: number): (t: number) => number {
  const cx = 3 * x1, bx = 3 * (x2 - x1) - cx, ax = 1 - cx - bx, cy = 3 * y1, by = 3 * (y2 - y1) - cy, ay = 1 - cy - by;
  return (x) => {
    let t = x;
    for (let i = 0; i < 8; i++) { const f = ((ax * t + bx) * t + cx) * t - x, df = (3 * ax * t + 2 * bx) * t + cx; if (Math.abs(f) < 1e-5 || !df) break; t -= f / df; }
    t = Math.min(1, Math.max(0, t));
    return ((ay * t + by) * t + cy) * t;
  };
}
const easeLayout = bezier(0.77, 0, 0.175, 1);

export function createGalaxy(d: GalaxyData, store: Store, colors: string[]): GalaxyView {
  const canvas = h('canvas', { class: 'galaxy-canvas', tabindex: '0', role: 'application', 'aria-roledescription': 'interactive galaxy chart' });
  const tip = h('div', { class: 'galaxy-tip', role: 'status', hidden: true });
  const stage = h('div', { class: 'galaxy-stage' }, canvas, tip);
  const ctx = canvas.getContext('2d')!;
  const rm = window.matchMedia('(prefers-reduced-motion: reduce)');

  const n = d.n;
  const colorOf = (f: number) => (f >= 0 ? colors[f % (colors.length - 1)] : colors[colors.length - 1]);
  const spr: Sprites = { dot: [], glow: [] };
  const nCol = Math.max(1, d.nFam) + 1;
  for (let f = 0; f < nCol; f++) {
    const col = f < d.nFam ? colors[f % (colors.length - 1)] : colors[colors.length - 1];
    spr.dot.push(sprite(32, col, false)); spr.glow.push(sprite(96, col, true));
  }
  const slot = (f: number) => (f >= 0 && f < d.nFam ? f : nCol - 1);
  const slotA = new Int16Array(n), glowA = new Uint8Array(n), twA = new Uint8Array(n);
  for (let i = 0; i < n; i++) { slotA[i] = slot(ENCODINGS.colour.slot(d, i)); glowA[i] = ENCODINGS.glow.on(d, i) ? 1 : 0; twA[i] = ENCODINGS.twinkle.on(d, i) ? 1 : 0; }
  const core = coreSprite();
  const tw = sprite(48, '#ffffff', true);

  // ---- current star positions (tweened between layouts) + spatial grid over them
  const posOf = (l: Layout) => (l === 'embedding' && d.pos.embedding ? d.pos.embedding : l === 'rows' ? d.pos.rows : d.pos.spiral);
  let lay: Layout = store.state.view;
  const px = Float32Array.from(posOf(lay).x), py = Float32Array.from(posOf(lay).y);
  const gw = Math.ceil((2 * E) / GRID);
  const cellStart = new Int32Array(gw * gw + 1), cellItems = new Int32Array(n);
  const cellOf = (i: number) => Math.min(gw - 1, Math.max(0, Math.floor((py[i] + E) / GRID))) * gw + Math.min(gw - 1, Math.max(0, Math.floor((px[i] + E) / GRID)));
  function buildGrid(): void {
    cellStart.fill(0);
    for (let i = 0; i < n; i++) cellStart[cellOf(i) + 1]++;
    for (let c = 0; c < gw * gw; c++) cellStart[c + 1] += cellStart[c];
    const fill = cellStart.slice(0, gw * gw);
    for (let i = 0; i < n; i++) cellItems[fill[cellOf(i)]++] = i;
  }
  buildGrid();
  type Tween = { t0: number; fx: Float32Array; fy: Float32Array; to: { x: Float32Array; y: Float32Array }; a0: number; a1: number };
  let tween: Tween | null = null, overlayT0 = 0;
  const spins = () => lay === 'spiral' && !tween;
  function switchLayout(next: Layout): void {
    if (next === lay) return;
    lay = next;
    const to = posOf(next);
    if (rm.matches) { px.set(to.x); py.set(to.y); angle = 0; buildGrid(); setHover(-1, false); bmpDirty = true; frameDirty = true; schedule(); paintLegend(); return; }
    tween = { t0: -1, fx: px.slice(), fy: py.slice(), to, a0: angle, a1: next === 'spiral' ? angle : angle > Math.PI ? Math.PI * 2 : 0 };
    setHover(-1, false);
    paintLegend();
    bmpDirty = true; schedule();
  }

  // ---- view state
  let w = 0, hgt = 0, dpr = 1, R = 100;
  let zoom = 1, panX = 0, panY = 0, angle = 0;
  let bmp: HTMLCanvasElement | null = null, bs = 1;
  let bmpDirty = true, frameDirty = true, rerenderAt = 0;
  let hoverIdx = -1, tipIdx = -1, kbPos = -1;
  let ptr: { x: number; y: number; type: string } | null = null;
  let twList: number[] = [];
  let visible = true, raf = 0, last = 0, frame = 0, destroyed = false;
  let introT0 = -1;
  const pointers = new Map<number, { x: number; y: number }>();
  let drag: { x: number; y: number; moved: boolean } | null = null, pinch0: { d: number; z: number } | null = null;

  const match = () => store.derived.match;
  const summary = () => store.derived.summary;

  function resize(): void {
    const r = stage.getBoundingClientRect();
    w = Math.max(1, r.width); hgt = Math.max(1, r.height);
    dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(hgt * dpr);
    R = (Math.min(w, hgt) / 2) * 0.92;
    bmpDirty = frameDirty = true;
  }

  // ---- offscreen render
  function renderBitmap(): void {
    const want = Math.min(R * dpr * Math.max(1, zoom), MAX_PX / (2 * E));
    bs = want;
    const side = Math.ceil(2 * E * bs);
    if (!bmp) bmp = document.createElement('canvas');
    if (bmp.width !== side) { bmp.width = bmp.height = side; }
    const g = bmp.getContext('2d')!;
    g.setTransform(1, 0, 0, 1, 0, 0);
    g.globalCompositeOperation = 'source-over';
    g.clearRect(0, 0, side, side);
    g.globalCompositeOperation = 'lighter';
    const lite = !!tween, m = match(), k = bs / R; // star radius (css px at 1x) -> bitmap px; grows with zoom like a real image
    const pass = (sel: (i: number) => boolean, alpha: (i: number) => number, glow: boolean, step = 1) => {
      let lastA = -1;
      for (let i = 0; i < n; i += step) {
        if (!sel(i)) continue;
        const a = alpha(i);
        if (a !== lastA) { g.globalAlpha = a; lastA = a; }
        const r = d.rad[i] * k * (glow ? 2.6 : 1.5), x = (px[i] + E) * bs, y = (py[i] + E) * bs;
        g.drawImage((glow ? spr.glow : spr.dot)[slotA[i]], x - r, y - r, r * 2, r * 2);
      }
    };
    // while tweening, a thinned subset keeps the frame cheap; the full field is repainted when it lands
    if (!lite) pass((i) => !m[i], () => 0.06, false);
    pass((i) => !!m[i] && !glowA[i], (i) => Math.min(1, (lite ? 2.2 : 1) * Math.round(0.2 * (0.12 + 0.88 * Math.min(1, (i / n) * 3)) * 50) / 50), false, lite ? 9 : 1);
    pass((i) => !!m[i] && !!glowA[i], () => 1, true);
    g.globalAlpha = 1;
    // twinkle candidates: matching stars with any public exploit signal, thinned to a fixed budget
    const sg: number[] = [];
    for (let i = 0; i < n; i++) if (m[i] && twA[i]) sg.push(i);
    const stride = Math.max(1, Math.ceil(sg.length / TWINKLES));
    twList = sg.filter((_, j) => j % stride === 0);
    bmpDirty = false; frameDirty = true;
  }

  // ---- coordinates
  const U = () => zoom * R; // css px per galaxy unit
  function toScreen(i: number): [number, number] {
    const c = Math.cos(angle), s = Math.sin(angle), u = U();
    return [w / 2 + panX + u * (px[i] * c - py[i] * s), hgt / 2 + panY + u * (px[i] * s + py[i] * c)];
  }
  function toWorld(sx: number, sy: number): [number, number] {
    const c = Math.cos(angle), s = Math.sin(angle), u = U(), dx = sx - w / 2 - panX, dy = sy - hgt / 2 - panY;
    return [(dx * c + dy * s) / u, (-dx * s + dy * c) / u];
  }
  function hit(sx: number, sy: number, pxr: number): number {
    if (tween) return -1;
    const [wx, wy] = toWorld(sx, sy), u = U(), rr = pxr / u, m = match();
    const cx0 = Math.floor((wx - rr + E) / GRID), cx1 = Math.floor((wx + rr + E) / GRID);
    const cy0 = Math.floor((wy - rr + E) / GRID), cy1 = Math.floor((wy + rr + E) / GRID);
    let best = -1, bd = rr * rr;
    for (let cy = Math.max(0, cy0); cy <= Math.min(gw - 1, cy1); cy++) {
      for (let cx = Math.max(0, cx0); cx <= Math.min(gw - 1, cx1); cx++) {
        const c = cy * gw + cx;
        for (let q = cellStart[c]; q < cellStart[c + 1]; q++) {
          const i = cellItems[q];
          if (!m[i]) continue;
          const dx = px[i] - wx, dy = py[i] - wy, dd = dx * dx + dy * dy;
          if (dd < bd || (dd === bd && best >= 0 && i < best)) { bd = dd; best = i; }
        }
      }
    }
    return best;
  }

  // ---- tooltip
  function showTip(i: number): void {
    if (i === tipIdx) return;
    tipIdx = i;
    if (i < 0) { tip.hidden = true; return; }
    const sigs = SIGNALS.filter((_s, k) => d.sigA[i] & (1 << k)).map((s) => s.label);
    const fam = d.famA[i] >= 0 ? d.families[d.famA[i]].family_name ?? d.families[d.famA[i]].family_id : null;
    tip.replaceChildren(
      h('div', { class: 'gt-top' }, h('b', { class: 'mono' }, d.ids[i]), d.topA[i] ? h('span', { class: 'chip' }, 'Top 500') : null),
      h('div', { class: 'gt-row num' }, `Rank #${fmtInt(d.rank[i])} (${d.ranking_method})`),
      h('div', { class: 'gt-row num' }, `EPSS ${fmtEpss(d.epssA[i])}`),
      h('div', { class: 'gt-row muted' }, `Ranking method: ${d.ranking_method}`),
      h('div', { class: 'gt-row' }, sigs.length ? sigs.join(', ') : 'No public exploit signal'),
      h('div', { class: 'gt-row' }, h('i', { class: 'swatch', style: `background:${colorOf(d.famA[i])}`, 'aria-hidden': 'true' }), fam ?? (familyWaiting() ? 'Family: not computed yet' : 'Unassigned family')),
      h('div', { class: 'gt-prov' }, provenanceTag('model'), provenanceTag('snapshot')));
    tip.hidden = false;
  }
  function placeTip(): void {
    if (tip.hidden || tipIdx < 0) return;
    const [x, y] = toScreen(tipIdx), tw0 = tip.offsetWidth, th = tip.offsetHeight;
    let left = x + 14, top = y + 14;
    if (left + tw0 > w - 6) left = x - tw0 - 14;
    if (top + th > hgt - 6) top = y - th - 14;
    tip.style.transform = `translate(${Math.max(6, left).toFixed(1)}px, ${Math.max(6, top).toFixed(1)}px)`;
  }
  function setHover(i: number, withTip: boolean): void {
    hoverIdx = i;
    showTip(withTip ? i : -1);
    store.set({ hoverId: i >= 0 ? d.ids[i] : null });
    canvas.style.cursor = i >= 0 ? 'pointer' : drag ? 'grabbing' : 'grab';
    frameDirty = true;
  }

  // ---- draw
  function ringPos(rank: number): number { return radiusOfIndex(rank - 1, n); }
  const fontSans = () => getComputedStyle(document.documentElement).getPropertyValue('--font-sans') || 'sans-serif';
  const famTotals = (() => { const c = new Array(d.nFam + 1).fill(0); for (let i = 0; i < n; i++) c[d.famA[i] >= 0 ? d.famA[i] : d.nFam]++; return c as number[]; })();
  function drawRings(): void {
    const u = U(), cx = w / 2 + panX, cy = hgt / 2 + panY;
    ctx.font = `500 11px ${fontSans()}`; ctx.textBaseline = 'middle';
    const rankX = (k: number) => cx + u * (ROWS0 + (ROWS1 - ROWS0) * (Math.log(k) / Math.log(Math.max(2, n))));
    if (lay === 'embedding') return;
    if (lay === 'rows') {
      const rows = d.nFam + (famTotals[d.nFam] ? 1 : 0), rowH = rows > 1 ? 1.56 / (rows - 1) : 1;
      ctx.setLineDash([2, 4]); ctx.lineWidth = 1; ctx.textAlign = 'center';
      ENCODINGS.rings.forEach((k, j) => { // vertical tick lines at the real cut-offs
        const x = rankX(k), y0 = cy + u * -0.9, y1 = cy + u * 0.9;
        ctx.strokeStyle = k === 500 ? 'rgba(120,169,255,0.42)' : 'rgba(160,178,220,0.2)';
        ctx.beginPath(); ctx.moveTo(x, y0); ctx.lineTo(x, y1); ctx.stroke();
        ctx.fillStyle = k === 500 ? 'rgba(166,200,255,0.95)' : 'rgba(198,205,222,0.8)';
        ctx.fillText(`Top ${k}`, x, y0 - 8 - (j % 3) * 0 - j * 12);
      });
      ctx.setLineDash([]);
      ctx.textAlign = 'center'; ctx.fillStyle = 'rgba(198,205,222,0.7)';
      ctx.fillText('rank, log scale (rank 1 at left)', (rankX(1) + rankX(n)) / 2, cy + u * 0.97);
      ctx.textAlign = 'left'; ctx.fillText('#1', rankX(1) - 4, cy + u * 0.9 + 4); ctx.textAlign = 'right'; ctx.fillText(`#${fmtInt(n)}`, rankX(n) + 4, cy + u * 0.9 + 4);
      ctx.textAlign = 'right';
      for (let s0 = 0; s0 < rows; s0++) {
        const y = cy + u * (rows > 1 ? -0.78 + s0 * rowH : 0), f = s0 < d.nFam ? d.families[s0] : null;
        const name = f ? f.family_name ?? f.family_id : 'Unassigned', cnt = ` · ${fmtInt(famTotals[s0])}`;
        const maxW = Math.max(60, rankX(1) - 8 - 10 - Math.max(0, cx - w / 2 - 0));
        let t = name; const avail = Math.max(60, (rankX(1) - 12) - 6);
        while (t.length > 3 && ctx.measureText(t + cnt).width > Math.min(avail, 230) + 0 * maxW) t = t.slice(0, -2);
        ctx.fillStyle = s0 < d.nFam ? colors[s0 % (colors.length - 1)] : colors[colors.length - 1];
        ctx.fillText((t === name ? t : t.trimEnd() + '…') + cnt, rankX(1) - 12, y);
      }
      ctx.textAlign = 'left';
      return;
    }
    ctx.lineWidth = 1; ctx.setLineDash([2, 4]);
    const ang = -Math.PI / 4.2, items: { x: number; y: number; t: string; strong: boolean }[] = [];
    for (const rk of ENCODINGS.rings) {
      if (rk > n) continue;
      const r = ringPos(rk) * u;
      ctx.strokeStyle = rk === 500 ? 'rgba(120,169,255,0.42)' : 'rgba(160,178,220,0.2)';
      ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.stroke();
      items.push({ x: cx + Math.cos(ang) * r, y: cy + Math.sin(ang) * r, t: `Top ${rk}`, strong: rk === 500 });
    }
    ctx.setLineDash([]);
    const lx = cx + Math.max(...items.map((it) => it.x - cx), 0) + 34;
    let labelY = Infinity;
    for (let k = items.length - 1; k >= 0; k--) { // labels fan out to the upper right so the tight inner rings stay readable
      const it = items[k], ly = Math.min(it.y - 4, labelY - 15);
      labelY = ly;
      ctx.strokeStyle = 'rgba(160,178,220,0.35)'; ctx.beginPath(); ctx.moveTo(it.x, it.y); ctx.lineTo(lx - 4, ly); ctx.stroke();
      ctx.fillStyle = it.strong ? 'rgba(166,200,255,0.95)' : 'rgba(198,205,222,0.8)';
      ctx.fillText(it.t, lx, ly);
    }
  }
  function ringAt(i: number, color: string, extra: number, lw: number): void {
    const [x, y] = toScreen(i), r = Math.max(5, d.rad[i] * Math.sqrt(zoom) * 1.4) + extra;
    ctx.strokeStyle = color; ctx.lineWidth = lw;
    ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.stroke();
  }
  function draw(t: number): void {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, hgt);
    const cx = w / 2 + panX, cy = hgt / 2 + panY, u = U();
    let settle = 1, fade = 1;
    if (introT0 >= 0) {
      const p = Math.min(1, (t - introT0) / 900);
      settle = 1 + 0.07 * Math.pow(1 - p, 3); fade = 1 - Math.pow(1 - p, 3);
      if (p >= 1) introT0 = -1;
    }
    ctx.globalAlpha = fade;
    // core glow
    ctx.globalCompositeOperation = 'lighter';
    const cr = u * 0.34 * settle;
    if (lay === 'spiral') ctx.drawImage(core, cx - cr, cy - cr, cr * 2, cr * 2);
    // star bitmap (rotated)
    if (bmp) {
      ctx.save();
      ctx.translate(cx, cy); ctx.rotate(angle); ctx.scale(u * settle, u * settle);
      ctx.drawImage(bmp, -E, -E, 2 * E, 2 * E);
      ctx.restore();
    }
    // twinkle overlay: a bounded subset, additive
    if (!rm.matches) {
      const sec = t / 1000, c = Math.cos(angle), s = Math.sin(angle);
      for (const i of twList) {
        const hh = d.hash[i], period = 2.4 + (hh % 1000) / 1000 * 3.6, ph = ((hh >>> 10) % 1000) / 1000 * 6.283;
        const a = 0.5 + 0.5 * Math.sin((sec / period) * 6.283 + ph);
        const x = cx + u * settle * (px[i] * c - py[i] * s), y = cy + u * settle * (px[i] * s + py[i] * c);
        if (x < -8 || y < -8 || x > w + 8 || y > hgt + 8) continue;
        const r = (1.6 + d.rad[i] * 1.1) * Math.sqrt(zoom);
        ctx.globalAlpha = fade * (0.08 + 0.5 * a * a);
        ctx.drawImage(tw, x - r, y - r, r * 2, r * 2);
      }
    }
    ctx.globalCompositeOperation = 'source-over';
    ctx.globalAlpha = fade;
    if (!tween) { ctx.globalAlpha = fade * Math.min(1, (t - overlayT0) / 250); drawRings(); ctx.globalAlpha = fade; }
    // selection (drawer open), external/internal hover
    const sel = appState.selection ? d.idx.get(appState.selection) : undefined;
    if (sel !== undefined) ringAt(sel, 'rgba(241,194,27,0.95)', 5, 1.5);
    const hid = store.state.hoverId, hi = hid ? d.idx.get(hid) : undefined;
    if (hi !== undefined) {
      const pulse = rm.matches ? 0 : 0.5 + 0.5 * Math.sin(t / 260);
      ringAt(hi, 'rgba(166,200,255,0.95)', 3 + pulse * 2.5, 1.5);
      if (!rm.matches) ringAt(hi, `rgba(120,169,255,${0.35 * (1 - pulse)})`, 8 + pulse * 7, 1);
    }
    ctx.globalAlpha = 1;
    placeTip();
    frameDirty = false;
  }

  // ---- loop
  function tick(t: number): void {
    raf = 0;
    if (destroyed || !visible || document.hidden) return;
    const dt = last ? Math.min(100, t - last) : 0;
    last = t; frame++;
    if (tween) {
      if (tween.t0 < 0) tween.t0 = t;
      const p = Math.min(1, (t - tween.t0) / 700), e = easeLayout(p), tw1 = tween;
      for (let i = 0; i < n; i++) { px[i] = tw1.fx[i] + (tw1.to.x[i] - tw1.fx[i]) * e; py[i] = tw1.fy[i] + (tw1.to.y[i] - tw1.fy[i]) * e; }
      angle = tw1.a0 + (tw1.a1 - tw1.a0) * e;
      bmpDirty = true; frameDirty = true;
      if (p >= 1) { tween = null; angle = angle % (Math.PI * 2); if (lay !== 'spiral') angle = 0; buildGrid(); overlayT0 = t; }
    }
    const animating = (!rm.matches && lay === 'spiral') || introT0 >= 0 || hi_pulse() || !!tween || t - overlayT0 < 300;
    if (!rm.matches && spins()) angle = (angle + (dt / PERIOD_MS) * Math.PI * 2) % (Math.PI * 2);
    if (bmpDirty || (rerenderAt && t > rerenderAt)) {
      if (tween) { rerenderAt = 0; renderBitmap(); } else {
      const want = Math.min(R * dpr * Math.max(1, zoom), MAX_PX / (2 * E));
      if (bmpDirty || Math.abs(Math.log(want / bs)) > 0.26) { rerenderAt = 0; renderBitmap(); } else rerenderAt = 0;
    } }
    if (ptr && !drag && !pinch0 && frame % 5 === 0 && !rm.matches) {
      const i = hit(ptr.x, ptr.y, ptr.type === 'touch' ? 16 : 8);
      if (i !== hoverIdx) setHover(i, true);
    }
    if (animating || frameDirty) draw(t);
    schedule();
  }
  const hi_pulse = () => { const id = store.state.hoverId; return !!id && !rm.matches; };
  function schedule(): void { if (!raf && !destroyed && visible && !document.hidden) raf = requestAnimationFrame(tick); }
  const wake = () => { last = 0; frameDirty = true; schedule(); };
  const io = new IntersectionObserver((e) => { visible = e[e.length - 1].isIntersecting; if (visible) wake(); });
  io.observe(stage);
  const onVis = () => { if (!document.hidden) wake(); };
  document.addEventListener('visibilitychange', onVis);
  const ro = new ResizeObserver(() => { resize(); wake(); });
  ro.observe(stage);
  const onRm = () => { if (rm.matches) angle = 0; wake(); };
  rm.addEventListener('change', onRm);

  // ---- zoom / pan
  function setZoom(z: number, ax: number, ay: number): void {
    const nz = Math.min(ZMAX, Math.max(ZMIN, z));
    const k = nz / zoom;
    panX = ax - w / 2 - (ax - w / 2 - panX) * k; panY = ay - hgt / 2 - (ay - hgt / 2 - panY) * k;
    zoom = nz;
    clampPan();
    canvas.style.touchAction = zoom > 1.05 ? 'none' : 'pan-y';
    rerenderAt = performance.now() + 160; frameDirty = true; schedule();
  }
  function clampPan(): void { const lim = R * zoom * 1.05; panX = Math.max(-lim, Math.min(lim, panX)); panY = Math.max(-lim, Math.min(lim, panY)); }
  function resetView(): void {
    const z0 = zoom, px0 = panX, py0 = panY, t0 = performance.now(), dur = rm.matches ? 0 : 280;
    const step = (t: number) => {
      const p = dur ? Math.min(1, (t - t0) / dur) : 1, e = 1 - Math.pow(1 - p, 3);
      zoom = z0 + (1 - z0) * e; panX = px0 * (1 - e); panY = py0 * (1 - e);
      canvas.style.touchAction = zoom > 1.05 ? 'none' : 'pan-y';
      rerenderAt = performance.now() + 160; frameDirty = true; schedule();
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  function nearestArm(wx: number, wy: number): number | null {
    const r = Math.hypot(wx, wy);
    if (!d.hasFamilies || d.nFam < 1 || r < 0.1 || r > 1.08) return null;
    const a = Math.atan2(wy, wx);
    let best = 0, bd = 9;
    for (let f = 0; f < d.nFam; f++) {
      let diff = Math.abs(((a - (2 * Math.PI * f) / d.nFam - TWIST * r) % (2 * Math.PI) + 3 * Math.PI) % (2 * Math.PI) - Math.PI);
      if (diff < bd) { bd = diff; best = f; }
    }
    return bd < Math.PI / d.nFam ? best : null;
  }

  canvas.addEventListener('wheel', (e) => {
    e.preventDefault();
    const r = canvas.getBoundingClientRect();
    setZoom(zoom * Math.exp(-e.deltaY * (e.deltaMode ? 0.05 : 0.0016)), e.clientX - r.left, e.clientY - r.top);
  }, { passive: false });
  canvas.addEventListener('pointerdown', (e) => {
    const r = canvas.getBoundingClientRect();
    pointers.set(e.pointerId, { x: e.clientX - r.left, y: e.clientY - r.top });
    canvas.setPointerCapture(e.pointerId);
    if (pointers.size === 2) { const [a, b] = [...pointers.values()]; pinch0 = { d: Math.hypot(a.x - b.x, a.y - b.y), z: zoom }; drag = null; }
    else drag = { x: e.clientX, y: e.clientY, moved: false };
  });
  canvas.addEventListener('pointermove', (e) => {
    const r = canvas.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    ptr = { x, y, type: e.pointerType };
    if (pointers.has(e.pointerId)) pointers.set(e.pointerId, { x, y });
    if (pinch0 && pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      setZoom(pinch0.z * (Math.hypot(a.x - b.x, a.y - b.y) / pinch0.d), (a.x + b.x) / 2, (a.y + b.y) / 2);
      return;
    }
    if (drag) {
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (!drag.moved && Math.hypot(dx, dy) > 4) { drag.moved = true; setHover(-1, false); canvas.style.cursor = 'grabbing'; }
      if (drag.moved) { panX += dx; panY += dy; drag.x = e.clientX; drag.y = e.clientY; clampPan(); frameDirty = true; schedule(); }
      return;
    }
    if (e.pointerType !== 'touch') { const i = hit(x, y, 8); if (i !== hoverIdx) setHover(i, true); else frameDirty = true; }
  });
  const endPtr = (e: PointerEvent, cancelled: boolean) => {
    const r = canvas.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    pointers.delete(e.pointerId);
    if (pinch0) { if (pointers.size < 2) pinch0 = null; drag = null; return; }
    const was = drag; drag = null;
    if (e.pointerType !== 'mouse') ptr = null;
    if (!was || was.moved || cancelled) { canvas.style.cursor = hoverIdx >= 0 ? 'pointer' : 'grab'; return; }
    const i = hit(x, y, e.pointerType === 'touch' ? 16 : 8);
    if (i >= 0) { setHover(i, true); openCve(d.ids[i]); return; }
    if (zoom <= 1.5) {
      const [wx, wy] = toWorld(x, y), f = nearestArm(wx, wy);
      if (f !== null) store.set({ familyIdx: store.state.familyIdx === f ? null : f });
    }
  };
  canvas.addEventListener('pointerup', (e) => endPtr(e, false));
  canvas.addEventListener('pointercancel', (e) => endPtr(e, true));
  canvas.addEventListener('pointerleave', (e) => { if (e.pointerType === 'mouse') { ptr = null; if (!drag) setHover(-1, false); } });
  canvas.addEventListener('dblclick', () => resetView());

  // ---- keyboard: arrows cycle the top matching CVEs, Enter opens
  canvas.addEventListener('keydown', (e) => {
    const list = summary().firstIdx;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown' || e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      if (!list.length) return;
      e.preventDefault();
      const fwd = e.key === 'ArrowRight' || e.key === 'ArrowDown';
      kbPos = (kbPos + (fwd ? 1 : -1) + list.length) % list.length;
      setHover(list[kbPos], true);
    } else if (e.key === 'Enter' && hoverIdx >= 0) { e.preventDefault(); openCve(d.ids[hoverIdx]); }
    else if (e.key === '+' || e.key === '=') setZoom(zoom * 1.25, w / 2, hgt / 2);
    else if (e.key === '-') setZoom(zoom / 1.25, w / 2, hgt / 2);
    else if (e.key === '0') resetView();
  });
  canvas.addEventListener('blur', () => { kbPos = -1; });

  // ---- legend (generated from encodings.ts) and coach-mark anchors
  const legendList = h('ul', { class: 'lg-list' });
  const legendSym = h('ul', { class: 'lg-sym' }, LEGEND_SYMBOLS.map((x) => h('li', {}, h('i', { class: `lg lg-${x.kind}`, 'aria-hidden': 'true' }), x.text)));
  const legend = h('details', { class: 'galaxy-legend' }, h('summary', {}, 'Legend'), legendList, legendSym);
  if (!window.matchMedia('(max-width: 700px)').matches) legend.setAttribute('open', '');
  function paintLegend(): void {
    const L = ENCODINGS.layouts[lay];
    legendList.replaceChildren(...L.legend.map((t, k) => h('li', { class: k === L.legend.length - 1 ? 'muted' : '' }, t.replace('{method}', d.ranking_method))));
  }
  paintLegend();
  const coreSpot = h('div', { class: 'coach-spot', 'aria-hidden': 'true' });
  stage.append(legend, coreSpot);

  // ---- on-canvas controls
  const btn = (label: string, text: string, fn: () => void) => h('button', { type: 'button', class: 'icon-btn galaxy-btn', 'aria-label': label, title: label, onClick: fn }, text);
  const controls = h('div', { class: 'galaxy-controls' },
    btn('Zoom in', '+', () => setZoom(zoom * 1.4, w / 2, hgt / 2)),
    btn('Zoom out', '−', () => setZoom(zoom / 1.4, w / 2, hgt / 2)),
    btn('Reset view', '⟲', () => resetView()));
  stage.append(controls);

  // ---- state subscriptions
  const label = () => {
    const s = summary();
    canvas.setAttribute('aria-label', `Threat Galaxy: ${fmtInt(n)} CVEs plotted by model rank; ${fmtInt(s.count)} match the current filters, ${fmtInt(s.top500)} of them in the Top 500. Use the arrow keys to step through the highest-ranked matching CVEs and Enter to open one. Escape clears the selection.`);
  };
  const unsub = store.subscribe((_s, changed) => {
    if (changed.has('view')) switchLayout(_s.view);
    if (changed.has('filters')) { bmpDirty = true; kbPos = -1; if (hoverIdx >= 0 && !match()[hoverIdx]) setHover(-1, false); label(); }
    frameDirty = true; schedule();
  });
  // hover coming from elsewhere (list, scatter, chat card): clear a stale local tooltip
  const unsubHover = store.subscribe((s, changed) => {
    if (changed.has('hoverId') && (s.hoverId === null ? hoverIdx >= 0 && !ptr : d.ids[hoverIdx] !== s.hoverId)) {
      if (!(ptr && hoverIdx >= 0)) { hoverIdx = -1; showTip(-1); }
    }
  });
  const onSel = () => { frameDirty = true; schedule(); };
  bus.addEventListener('selectionchange', onSel);
  const onKeyDoc = (e: KeyboardEvent) => {
    if (e.key !== 'Escape' || document.documentElement.classList.contains('has-drawer')) return;
    const t = e.target as HTMLElement | null;
    if (t && /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return;
    setHover(-1, false);
    if (store.state.familyIdx !== null) store.set({ familyIdx: null });
  };
  document.addEventListener('keydown', onKeyDoc);

  // ---- boot (called once the stage is in the DOM)
  requestAnimationFrame(() => {
    if (destroyed) return;
    resize(); label();
    canvas.style.touchAction = 'pan-y'; canvas.style.cursor = 'grab';
    let first = false;
    try { first = !sessionStorage.getItem(INTRO_KEY); sessionStorage.setItem(INTRO_KEY, '1'); } catch { /* ignore */ }
    if (first && !rm.matches) {
      introT0 = performance.now();
      stage.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 900, easing: 'cubic-bezier(0.23,1,0.32,1)' });
    }
    wake();
  });

  return {
    el: stage,
    resetView,
    spots: { stage, core: coreSpot, legend },
    destroy() {
      destroyed = true; cancelAnimationFrame(raf);
      io.disconnect(); ro.disconnect(); unsub(); unsubHover();
      document.removeEventListener('visibilitychange', onVis); document.removeEventListener('keydown', onKeyDoc);
      bus.removeEventListener('selectionchange', onSel); rm.removeEventListener('change', onRm);
    },
  };
}
