import { api, type ExplainResult } from '../api';
import { h, clear, mdToSafeHtml, reducedMotion, store } from '../util';
import { state, bus, emit } from '../state';
import { findTarget, highlightTarget } from './highlight';
import { runActions, describeAction } from '../actions';
import { provenanceTag } from '../charts';

let SIZE = 96; // box edge in px; sprite is scaled to fit (72 on narrow screens)
const MARGIN = 8;
const KEY = 'tr.pet';
const HOVER_KEY = 'tr.pet.hover';

/** Crafternauta sprite sheet: 8 cols x 11 rows of 192x208 frames. [row, frame count, fps] per state. */
const SHEET = '/pet/crafternauta.webp';
const FW = 192, FH = 208;
const FRAMES: Record<string, [number, number, number]> = {
  idle: [0, 7, 6], runR: [1, 8, 10], runL: [2, 8, 10], wave: [3, 4, 8], jump: [4, 5, 9],
  fail: [5, 8, 8], wait: [6, 6, 7], work: [7, 6, 10], review: [8, 6, 6], look: [9, 8, 8],
};

type Saved = { min: boolean; fx: number; fy: number };

/** Spring easing as a CSS linear() list (damping ratio ~0.82: tiny overshoot, then rest). */
function springEasing(zeta = 0.82, samples = 36): string {
  if (!CSS.supports('animation-timing-function', 'linear(0, 1)')) return 'cubic-bezier(0.22, 1, 0.36, 1)';
  const w = 7 / zeta; // settles inside ~1 unit of time
  const wd = w * Math.sqrt(1 - zeta * zeta);
  const pts: string[] = [];
  for (let i = 0; i <= samples; i++) {
    const t = i / samples;
    const x = i === samples ? 1 : 1 - Math.exp(-zeta * w * t) * (Math.cos(wd * t) + (zeta * w / wd) * Math.sin(wd * t));
    pts.push(x.toFixed(4));
  }
  return `linear(${pts.join(', ')})`;
}

export function mountPet(app: HTMLElement): void {
  const spring = springEasing();
  let saved: Saved = { min: false, fx: 0.02, fy: 1 };
  try { const s = store.get(KEY); if (s) saved = { ...saved, ...JSON.parse(s) }; } catch { /* default */ }
  const hadSaved = store.get(KEY) !== null;
  if (!hadSaved && window.innerWidth <= 640) saved.min = true; // start minimized on phones until the user opts in
  let hoverOn = store.get(HOVER_KEY) === 'on';

  // ---------- DOM ----------
  const body = h('button', { type: 'button', class: 'pet-body', 'aria-label': 'Crafternauta, your Tell guide. Open chat. Arrow keys move me.', title: 'Open chat (drag to move)' });
  const sprite = h('span', { class: 'pet-sprite', 'aria-hidden': 'true' });
  body.append(sprite);
  const inner = h('div', { class: 'pet-inner' }, body);
  const bubbleTitle = h('strong', { class: 'bubble-title' });
  const bubbleText = h('div', { class: 'bubble-text md', 'aria-hidden': 'true' });
  const bubbleMeta = h('div', { class: 'bubble-meta' });
  const bubbleActs = h('div', { class: 'bubble-acts' });
  const skipBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-sm', onClick: () => finishTyping() }, 'Skip');
  const bubbleClose = h('button', { type: 'button', class: 'icon-btn icon-btn-sm', 'aria-label': 'Dismiss explanation', onClick: () => hideBubble() }, '✕');
  const sr = h('div', { class: 'sr-only', role: 'status', 'aria-live': 'polite' });
  const bubble = h('div', { class: 'pet-bubble', hidden: true, 'data-pos': 'tr' },
    h('div', { class: 'bubble-head' }, bubbleTitle, bubbleClose), bubbleText, bubbleMeta, bubbleActs);
  const hoverBtn = h('button', { type: 'button', class: 'pet-chip', 'aria-pressed': String(hoverOn), title: 'Explain things when I hover for a moment',
    onClick: () => { hoverOn = !hoverOn; store.set(HOVER_KEY, hoverOn ? 'on' : 'off'); hoverBtn.setAttribute('aria-pressed', String(hoverOn)); } }, 'Hover');
  const minBtn = h('button', { type: 'button', class: 'pet-chip', 'aria-label': 'Minimize assistant', title: 'Minimize', onClick: () => setMin(true) }, '–');
  const tools = h('div', { class: 'pet-tools' }, hoverBtn, minBtn);
  const root = h('div', { class: 'pet', 'data-state': 'idle' }, inner, tools, bubble, sr);
  const dockTab = h('button', { type: 'button', class: 'pet-tab', 'aria-label': 'Show Crafternauta, your Tell guide', hidden: true, onClick: () => { setMin(false); } }, 'Crafternauta');
  app.append(root, dockTab);


  // ---------- sprite animation ----------
  let sc = 1, mood: 'idle' | 'wait' | 'review' = 'idle', runKey: string | null = null, dragging = false;
  let lookIdx: number | null = null, once: { key: string; res: () => void } | null = null;
  let raf = 0, t0 = 0, cur = 'idle';
  const show = (row: number, col: number) => { sprite.style.backgroundPosition = `${-col * FW * sc}px ${-row * FH * sc}px`; };
  const base = () => (dragging ? 'work' : runKey ?? mood);
  function applySize() {
    SIZE = window.innerWidth <= 480 ? 72 : 96;
    sc = SIZE / FH;
    root.style.setProperty('--pet', `${SIZE}px`);
    Object.assign(sprite.style, { width: `${FW * sc}px`, height: `${FH * sc}px`, backgroundSize: `${8 * FW * sc}px ${11 * FH * sc}px` });
  }
  function apply() {
    cancelAnimationFrame(raf); raf = 0;
    cur = once ? once.key : base();
    if (reducedMotion()) { show(cur === 'review' ? 8 : 0, 0); return; }
    if (!once && cur === 'idle' && lookIdx !== null) { show(9 + (lookIdx >> 3), lookIdx & 7); return; }
    t0 = performance.now(); show(FRAMES[cur][0], 0);
    raf = requestAnimationFrame(tick);
  }
  function tick(ts: number) {
    const [row, n, fps] = FRAMES[cur];
    let f = Math.max(0, Math.floor(((ts - t0) * fps) / 1000));
    if (f >= n) {
      if (once) { const o = once; once = null; apply(); o.res(); return; }
      f %= n;
    }
    show(row, f);
    raf = requestAnimationFrame(tick);
  }
  const refresh = () => { if (!once) apply(); };
  function cutOnce() { if (once) { const o = once; once = null; o.res(); } }
  function playOnce(key: string): Promise<void> {
    if (reducedMotion()) return Promise.resolve();
    cutOnce();
    return new Promise((res) => { once = { key, res }; apply(); });
  }
  const setRun = (k: string | null) => { if (k) cutOnce(); runKey = k; refresh(); };
  const setMood = (m: 'idle' | 'wait' | 'review') => { mood = m; refresh(); };
  applySize();
  const img = new Image();
  img.onload = () => { sprite.style.backgroundImage = `url(${SHEET})`; sprite.style.opacity = '1'; apply(); };
  img.src = SHEET;

  // ---------- geometry ----------
  let x = 0, y = 0;
  const navH = () => document.querySelector('.topbar')?.getBoundingClientRect().bottom ?? 56;
  const avoid = (): DOMRect[] => {
    const out: DOMRect[] = [];
    const l = document.querySelector('.chat-launcher'); if (l) out.push(l.getBoundingClientRect());
    const p = document.querySelector<HTMLElement>('.chat-panel'); if (p && !p.hidden) out.push(p.getBoundingClientRect());
    if (document.documentElement.classList.contains('has-drawer') && window.innerWidth > 640) {
      const w = Math.min(560, window.innerWidth);
      out.push(new DOMRect(window.innerWidth - w, 0, w, window.innerHeight));
    }
    return out;
  };
  const hit = (ax: number, ay: number, r: DOMRect) => ax < r.right + 6 && ax + SIZE > r.left - 6 && ay < r.bottom + 6 && ay + SIZE > r.top - 6;
  function clampPos(px: number, py: number): { x: number; y: number } {
    let nx = Math.min(Math.max(px, MARGIN), window.innerWidth - SIZE - MARGIN);
    let ny = Math.min(Math.max(py, navH() + MARGIN), window.innerHeight - SIZE - MARGIN);
    for (const r of avoid()) {
      if (hit(nx, ny, r)) {
        const left = r.left - SIZE - 8, up = r.top - SIZE - 8;
        if (left >= MARGIN && (Math.abs(nx - left) <= Math.abs(ny - up) || up < navH() + MARGIN)) nx = left; else if (up >= navH() + MARGIN) ny = up; else nx = Math.max(MARGIN, left);
      }
    }
    return { x: nx, y: ny };
  }
  const place = (px: number, py: number) => { x = px; y = py; root.style.transform = `translate(${px}px, ${py}px)`; };
  let home = { x: MARGIN, y: 0 };
  const persist = () => {
    home = { x, y };
    const mx = Math.max(1, window.innerWidth - SIZE - 2 * MARGIN), my = Math.max(1, window.innerHeight - SIZE - 2 * MARGIN);
    saved = { ...saved, fx: (x - MARGIN) / mx, fy: (y - MARGIN) / my };
    store.set(KEY, JSON.stringify(saved));
  };
  const restore = () => {
    const mx = window.innerWidth - SIZE - 2 * MARGIN, my = window.innerHeight - SIZE - 2 * MARGIN;
    const c = clampPos(MARGIN + saved.fx * mx, MARGIN + saved.fy * my);
    place(c.x, c.y);
    home = { x: c.x, y: c.y };
  };

  // ---------- movement ----------
  let walkAnim: Animation | null = null;
  function currentXY() { const r = root.getBoundingClientRect(); return { x: r.left, y: r.top }; }
  function moveTo(tx: number, ty: number): Promise<void> {
    const to = clampPos(tx, ty);
    const from = currentXY();
    walkAnim?.cancel();
    setRun(null);
    place(to.x, to.y);
    const dist = Math.hypot(to.x - from.x, to.y - from.y);
    if (dist < 2) return Promise.resolve();
    if (reducedMotion()) {
      walkAnim = root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: 'ease-out' });
      return walkAnim.finished.then(() => undefined, () => undefined);
    }
    const dur = Math.min(900, 380 + dist * 0.7);
    root.dataset.state = 'walk';
    setRun(to.x >= from.x ? 'runR' : 'runL');
    walkAnim = root.animate(
      [{ transform: `translate(${from.x}px, ${from.y}px)` }, { transform: `translate(${to.x}px, ${to.y}px)` }],
      { duration: dur, easing: spring });
    const lean = Math.sign(to.x - from.x) * 5;
    inner.animate([{ transform: 'translateY(0) rotate(0)' }, { transform: `translateY(-5px) rotate(${lean}deg)`, offset: 0.2 }, { transform: 'translateY(0) rotate(0)', offset: 0.4 }, { transform: `translateY(-3px) rotate(${lean * 0.6}deg)`, offset: 0.65 }, { transform: 'translateY(0) rotate(0)' }], { duration: Math.min(dur, 700), easing: 'ease-in-out' });
    const anim = walkAnim;
    return anim.finished.then(() => { if (walkAnim === anim) land(); }, () => undefined);
  }
  function land() {
    root.dataset.state = 'idle';
    setRun(null);
    if (reducedMotion()) return;
    inner.animate([{ transform: 'scale(1.1, 0.88)' }, { transform: 'scale(0.97, 1.04)', offset: 0.55 }, { transform: 'scale(1,1)' }], { duration: 300, easing: 'cubic-bezier(0.23,1,0.32,1)' });
  }

  /** Spot beside the target, off to a side; falls back to above/below, then a corner. */
  function spotFor(el: HTMLElement): { x: number; y: number } {
    const r = el.getBoundingClientRect();
    const vis = { l: Math.max(r.left, 0), r: Math.min(r.right, window.innerWidth), t: Math.max(r.top, navH()), b: Math.min(r.bottom, window.innerHeight) };
    const midY = (vis.t + vis.b) / 2 - SIZE / 2;
    const cands = [
      { x: vis.r + 10, y: Math.min(midY, vis.t + 24) },
      { x: vis.l - SIZE - 10, y: Math.min(midY, vis.t + 24) },
      { x: vis.l + 16, y: vis.t - SIZE - 2 },
      { x: vis.l + 16, y: vis.b + 4 },
      { x: vis.r - SIZE - 16, y: vis.b - SIZE - 12 },
    ];
    const free = (c: { x: number; y: number }) => {
      // Don't park on top of another explainable card or its Explain button.
      const pts: [number, number][] = [[c.x + SIZE / 2, c.y + SIZE / 2], [c.x + 6, c.y + 6], [c.x + SIZE - 6, c.y + SIZE - 6]];
      return pts.every(([px, py]) => { const hit2 = document.elementFromPoint(px, py)?.closest('[data-explain]'); return !hit2 || hit2 === el || el.contains(hit2); });
    };
    const ok = (c: { x: number; y: number }) => free(c) && c.x >= MARGIN && c.x + SIZE <= window.innerWidth - MARGIN && c.y >= navH() + MARGIN && c.y + SIZE <= window.innerHeight - MARGIN && !avoid().some((a) => hit(c.x, c.y, a));
    return cands.find(ok) ?? cands[cands.length - 1];
  }
  async function walkTo(el: HTMLElement) {
    if (saved.min) return;
    const r = el.getBoundingClientRect();
    if (r.bottom < navH() || r.top > window.innerHeight) el.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
    const s = spotFor(el);
    await moveTo(s.x, s.y);
    positionBubble();
  }

  // ---------- idle life ----------
  const life = () => {
    if (!reducedMotion() && !document.hidden && !saved.min && !once && base() === 'idle' && lookIdx === null) void playOnce(Math.random() < 0.7 ? 'wave' : 'look');
    window.setTimeout(life, 8000 + Math.random() * 7000);
  };
  window.setTimeout(life, 8000);
  // Cursor following: 16 look frames (rows 9-10), index i faces i*22.5deg clockwise from straight up.
  let lookT = 0;
  window.addEventListener('pointermove', (e) => {
    if (reducedMotion() || saved.min || once || base() !== 'idle') return;
    const r = body.getBoundingClientRect();
    const dx = e.clientX - (r.left + r.width / 2), dy = e.clientY - (r.top + r.height / 2);
    if (Math.hypot(dx, dy) < 150) return;
    const i = Math.round(((Math.atan2(dx, -dy) * 180) / Math.PI + 360) % 360 / 22.5) % 16;
    if (i !== lookIdx) { lookIdx = i; apply(); }
    window.clearTimeout(lookT);
    lookT = window.setTimeout(() => { lookIdx = null; refresh(); }, 2000);
  }, { passive: true });

  // ---------- drag / click / keyboard ----------
  let drag: { sx: number; sy: number; ox: number; oy: number; moved: boolean; id: number } | null = null;
  body.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;
    walkAnim?.cancel(); setRun(null);
    const p = currentXY(); place(p.x, p.y);
    drag = { sx: e.clientX, sy: e.clientY, ox: e.clientX - p.x, oy: e.clientY - p.y, moved: false, id: e.pointerId };
    body.setPointerCapture(e.pointerId);
    root.classList.add('pressed');
  });
  body.addEventListener('pointermove', (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    if (!drag.moved && Math.hypot(e.clientX - drag.sx, e.clientY - drag.sy) < 6) return;
    drag.moved = true; root.dataset.state = 'drag'; if (!dragging) { dragging = true; refresh(); }
    const c = clampPos(e.clientX - drag.ox, e.clientY - drag.oy);
    place(c.x, c.y); positionBubble();
  });
  const endDrag = (e: PointerEvent) => {
    if (!drag || e.pointerId !== drag.id) return;
    const moved = drag.moved; drag = null;
    root.classList.remove('pressed'); root.dataset.state = 'idle'; dragging = false; refresh();
    if (moved) { persist(); land(); suppressClick = true; window.setTimeout(() => (suppressClick = false), 0); }
  };
  let suppressClick = false;
  body.addEventListener('pointerup', endDrag);
  body.addEventListener('pointercancel', endDrag);
  body.addEventListener('click', () => { if (!suppressClick) { emit('chat:open'); void playOnce('jump'); } });
  body.addEventListener('keydown', (e) => {
    const step = e.shiftKey ? 64 : 24;
    const d: Record<string, [number, number]> = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
    const v = d[e.key]; if (!v) return;
    e.preventDefault();
    void moveTo(x + v[0], y + v[1]).then(() => { persist(); positionBubble(); });
  });

  // ---------- minimize ----------
  function setMin(m: boolean) {
    saved.min = m; store.set(KEY, JSON.stringify(saved));
    root.hidden = m; dockTab.hidden = !m;
    if (m) { hideBubble(); dockTab.focus({ preventScroll: true }); }
    else { restore(); body.focus({ preventScroll: true }); }
  }

  // ---------- bubble ----------
  let typing: { stop: () => void; finish: () => void } | null = null;
  function positionBubble() {
    const right = x + SIZE / 2 > window.innerWidth / 2;
    const below = y < window.innerHeight / 2;
    const side = right ? 'l' : 'r';
    bubble.dataset.pos = `${below ? 'b' : 't'}${side}`;
    if (bubble.hidden) return;
    bubble.style.setProperty('--shift', '0px');
    let r = bubble.getBoundingClientRect();
    if (!below && r.top < navH() + 4) { bubble.dataset.pos = `b${side}`; r = bubble.getBoundingClientRect(); }
    else if (below && r.bottom > window.innerHeight - 4) { bubble.dataset.pos = `t${side}`; r = bubble.getBoundingClientRect(); }
    const shift = r.left < 8 ? 8 - r.left : r.right > window.innerWidth - 8 ? window.innerWidth - 8 - r.right : 0;
    bubble.style.setProperty('--shift', `${shift}px`);
  }
  function hideBubble() { typing?.stop(); typing = null; req++; bubble.hidden = true; clear(sr); setMood('idle'); }
  function finishTyping() { typing?.finish(); }

  function typewrite(container: HTMLElement, html: string): { stop: () => void; finish: () => void; done: Promise<void> } {
    container.innerHTML = html; // html comes from mdToSafeHtml (marked + DOMPurify)
    const nodes: { n: Text; full: string }[] = [];
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) nodes.push({ n: n as Text, full: (n as Text).data });
    let idx = 0, pos = 0, raf = 0, resolve!: () => void;
    const done = new Promise<void>((r) => (resolve = r));
    const finish = () => { cancelAnimationFrame(raf); nodes.forEach((o) => (o.n.data = o.full)); resolve(); };
    if (reducedMotion()) { finish(); return { stop: finish, finish, done }; }
    nodes.forEach((o) => (o.n.data = ''));
    const step = () => {
      let budget = 3;
      while (budget > 0 && idx < nodes.length) {
        const o = nodes[idx]; const take = Math.min(budget, o.full.length - pos);
        pos += take; budget -= take; o.n.data = o.full.slice(0, pos);
        if (pos >= o.full.length) { idx++; pos = 0; }
      }
      if (idx >= nodes.length) { resolve(); return; }
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return { stop: () => { cancelAnimationFrame(raf); resolve(); }, finish, done };
  }

  let holdHome = false;
  let req = 0, lastTarget = '', lastAt = 0;
  function showResult(r: ExplainResult, source: 'hover' | 'button' | 'chat') {
    typing?.stop();
    bubbleTitle.textContent = r.title;
    clear(bubbleMeta); clear(bubbleActs);
    const live = r.source === 'gemini';
    bubbleMeta.append(live ? provenanceTag('ai') : h('span', { class: 'prov prov-observed' }, h('i', { 'aria-hidden': 'true' }), 'Template from data'), h('span', { class: `src ${live ? 'src-live' : 'src-off'}` }, h('i', { 'aria-hidden': 'true' }), live ? 'Gemini live' : 'Offline mode'));
    for (const a of r.actions ?? []) {
      const label = describeAction(a);
      if (label && a.type !== 'highlight') bubbleActs.appendChild(h('button', { type: 'button', class: 'chip chip-toggle', onClick: () => runActions([a]) }, label));
    }
    setMood('review');
    bubble.hidden = false; positionBubble();
    const tw = typewrite(bubbleText, mdToSafeHtml(r.text));
    typing = tw;
    if (source !== 'hover') sr.textContent = `${r.title}. ${r.text.replace(/[*_`#>]/g, '')}`; // hover explanations stay silent for screen readers
    skipBtn.hidden = false;
    if (!bubbleActs.contains(skipBtn)) bubbleActs.prepend(skipBtn);
    void tw.done.then(() => { skipBtn.hidden = true; positionBubble(); if (typing === tw) setMood('idle'); });
  }

  async function explain(target: string, source: 'hover' | 'button' | 'chat') {
    if (saved.min) { if (source === 'hover') return; setMin(false); }
    const my = ++req;
    lastTarget = target; lastAt = Date.now();
    setMood('wait');
    typing?.stop();
    holdHome = source === 'chat';
    const el = source === 'chat' ? await highlightTarget(target) : findTarget(target);
    holdHome = false;
    if (my !== req) return;
    bubbleTitle.textContent = 'Looking…'; clear(bubbleMeta); clear(bubbleActs); clear(bubbleText);
    bubbleText.append(h('span', { class: 'dots', 'aria-hidden': 'true' }, h('i'), h('i'), h('i')));
    bubble.hidden = false; root.setAttribute('aria-busy', 'true');
    if (el) { await walkTo(el); if (my === req) void playOnce('wave'); }
    if (my !== req) return;
    try {
      const r = await api.explain(target, state.page);
      if (my !== req) return;
      showResult(r, source);
    } catch (e) {
      if (my !== req) return;
      setMood('idle'); void playOnce('fail');
      bubbleTitle.textContent = 'Could not explain this';
      clear(bubbleText); bubbleText.textContent = (e as Error).message;
      bubbleActs.appendChild(h('button', { type: 'button', class: 'btn btn-sm', onClick: () => void explain(target, 'button') }, 'Retry'));
    } finally { root.removeAttribute('aria-busy'); }
  }

  bus.addEventListener('pet:explain', ((e: CustomEvent<{ target: string; source: 'button' | 'chat' | 'hover' }>) => void explain(e.detail.target, e.detail.source)) as EventListener);
  bus.addEventListener('chat:busy', ((e: CustomEvent<{ on: boolean; failed?: boolean }>) => {
    setMood(e.detail.on ? 'wait' : 'idle');
    if (e.detail.failed) void playOnce('fail');
  }) as EventListener);
  bus.addEventListener('selectionchange', () => window.setTimeout(() => { if (!saved.min) void moveTo(x, y).then(positionBubble); }, 30));
  bus.addEventListener('pagerendered', () => { if (saved.min || holdHome) return; hideBubble(); if (Math.hypot(home.x - x, home.y - y) >= 4) void moveTo(home.x, home.y); });
  bus.addEventListener('chat:toggle', () => window.setTimeout(() => { if (!saved.min) void moveTo(x, y).then(positionBubble); }, 280));

  // ---------- hover-to-explain (mouse only, off by default, 900ms dwell) ----------
  // Scrolling moves content under a still cursor and makes the browser fire pointerover, so a hover only
  // counts after a real pointermove inside the element, outside a 400ms window after any scroll.
  let hoverEl: HTMLElement | null = null, hoverT = 0, lastScroll = 0;
  const scrolling = () => performance.now() - lastScroll < 400;
  window.addEventListener('scroll', () => { lastScroll = performance.now(); window.clearTimeout(hoverT); }, { passive: true, capture: true });
  document.addEventListener('pointerover', (e) => {
    if (e.pointerType !== 'mouse') return;
    const el = (e.target as HTMLElement).closest<HTMLElement>('[data-explain]');
    if (el === hoverEl) return;
    window.clearTimeout(hoverT); hoverEl = el;
  }, { passive: true });
  document.addEventListener('pointermove', (e) => {
    const el = hoverEl;
    if (e.pointerType !== 'mouse' || !el || !hoverOn || saved.min || scrolling() || document.documentElement.classList.contains('has-drawer') || el.closest('.pet')) return;
    window.clearTimeout(hoverT);
    hoverT = window.setTimeout(() => {
      if (el !== hoverEl || scrolling()) return;
      const id = el.dataset.explain!;
      if (id === lastTarget && Date.now() - lastAt < 20000) return;
      void explain(id, 'hover');
    }, 900);
  }, { passive: true });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !bubble.hidden && !document.querySelector('.drawer') && !(document.querySelector('.chat-dock.open'))) hideBubble();
  });

  // ---------- init / resize ----------
  root.hidden = saved.min; dockTab.hidden = !saved.min;
  place(MARGIN, window.innerHeight);
  requestAnimationFrame(() => requestAnimationFrame(restore));
  let rz = 0;
  window.addEventListener('resize', () => { window.clearTimeout(rz); rz = window.setTimeout(() => { applySize(); if (saved.min) return; const c = clampPos(x, y); place(c.x, c.y); positionBubble(); }, 100); });
}
