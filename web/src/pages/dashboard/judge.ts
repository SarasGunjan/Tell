// Three short answers shown above the galaxy: why it matters, what we found, how it helps. Numbers are from the team's verified results.
import { h } from '../../util';
import { provenanceTag, type ProvKind } from '../../charts';

const CARDS: { q: string; a: string; num: string; prov: ProvKind; href: string; cta: string }[] = [
  { q: 'Why does it matter?', a: 'Severity scores and weakness labels (CVSS, CWE) don’t capture every relationship between vulnerabilities.',
    num: 'CWE-79 (cross-site scripting) is spread across 8 of 10 Granite families', prov: 'granite', href: '#/families', cta: 'See the families' },
  { q: 'What did we discover?', a: 'IBM Granite found families of vulnerabilities with very different histories of being exploited.',
    num: '3 families held 64.7% of historical KEV cases but about 31% of vulnerabilities', prov: 'observed', href: '#/discoveries', cta: 'See the discoveries' },
  { q: 'How could it help?', a: 'Analysts get extra context on which vulnerabilities deserve attention and what they have in common.',
    num: 'Every one of the 72,670 2026 CVEs has a family, even the 8.7% with no CVSS v3 score', prov: 'granite', href: '#/galaxy?view=split', cta: 'Open the split view' },
];

export function judgeStrip(): HTMLElement {
  return h('div', { class: 'judge-strip', role: 'region', 'aria-label': 'Three quick answers', tabindex: '0' },
    CARDS.map((c, i) => h('section', { class: 'judge-card', style: `--i:${i}` },
      h('h2', { class: 'judge-q' }, c.q),
      h('p', { class: 'judge-a' }, c.a),
      h('p', { class: 'judge-num' }, c.num),
      h('div', { class: 'judge-foot' }, provenanceTag(c.prov), h('a', { href: c.href }, `${c.cta} →`)))));
}
