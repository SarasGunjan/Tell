// Our Story: the team's written analysis as one readable page. Static copy; every number is from the team's own results.
import '../styles/story.css';
import { h, reducedMotion } from '../util';
import { provenanceTag, type ProvKind } from '../charts';
import { pageHead } from './shared';

const stat = (num: string, label: string, prov?: ProvKind): HTMLElement =>
  h('div', { class: 'story-stat' },
    h('span', { class: 'story-stat-num num' }, num),
    h('span', { class: 'story-stat-label' }, label),
    prov ? provenanceTag(prov) : null);
const statRow = (...s: HTMLElement[]) => h('div', { class: 'story-stats' }, s);
const link = (href: string, text: string) => h('a', { href }, text);

type Sect = { id: string; title: string; body: (Node | string | null)[] };

function sections(): Sect[] {
  return [
    { id: 'problem', title: 'What problem are we solving?', body: [
      h('p', {}, 'Thousands of new software vulnerabilities (CVEs) are published every year, and only a few are ever used in real attacks. IBM puts it at fewer than 1 in 250 being confirmed as exploited.'),
      h('p', {}, 'The usual severity score, CVSS, tells us how bad a vulnerability could be. It does not tell us whether anyone will attack it. A team with a long patch list needs the second answer.'),
      h('p', {}, 'IBM’s challenge: from the 72,670 benchmark CVEs, pick the 500 most likely to enter the CISA Known Exploited Vulnerabilities list (KEV).'),
      statRow(stat('72,670', 'benchmark CVEs from 2026'), stat('500', 'we may shortlist'), stat('< 1 in 250', 'ever confirmed exploited, per IBM')),
    ] },
    { id: 'analysis', title: 'How did we analyze the data?', body: [
      h('p', {}, 'We started from eight IBM datasets: vulnerability descriptions, CVSS scores, EPSS scores, weakness types (CWE), affected products, public exploit signals, and the historical record of KEV entries. Then we did two separate pieces of work.'),
      h('h3', {}, 'Part 1. Ranking'),
      h('p', {}, 'We compared five ways to rank: CVSS first, EPSS first, public exploit code then EPSS, Logistic Regression, and LightGBM. We trained on 2024 and tested on 2025, counting how many real KEV entries each method placed in its top 500 (Hits@500).'),
      statRow(stat('18', 'Public Code + EPSS', 'observed'), stat('16', 'Logistic Regression', 'observed'), stat('16', 'LightGBM', 'observed'), stat('8', 'EPSS alone', 'observed')),
      h('p', {}, 'The simplest rule held up best, so our submitted Top 500 uses public exploit code first, then EPSS. See ', link('#/how-we-ranked', 'How We Ranked'), ' for the full comparison.'),
      h('h3', {}, 'Part 2. IBM Granite'),
      h('p', {}, 'We used the IBM Granite model ', h('span', { class: 'mono' }, 'granite-embedding-small-english-r2'), ' to turn 2,500 historical CVE descriptions into embeddings, which are numbers that capture what a text is about. K-Means then grouped them into 10 semantic families. Finally, every one of the 72,670 CVEs from 2026 was assigned to a family.'),
      h('p', {}, 'Families describe and explain. We did not use them to rank.'),
      statRow(stat('10', 'Granite families', 'granite'), stat('72,670', '2026 CVEs, each with a family', 'granite')),
    ] },
    { id: 'discoveries', title: 'What did we discover?', body: [
      h('p', {}, 'We asked three research questions. The full charts are on ', link('#/discoveries', 'Discoveries'), '.'),
      h('h3', {}, 'RQ1. Can semantic analysis reveal relationships that CWE misses?'),
      h('p', {}, 'Yes. The cross-site scripting weakness, CWE-79, shows up in 8 of the 10 families. Vulnerabilities with different CWEs often land in the same family, and the same CWE splits across families by technical context.'),
      statRow(stat('8 of 10', 'families contain CWE-79', 'granite')),
      h('h3', {}, 'RQ2. Are some families more associated with historical exploitation?'),
      h('p', {}, 'Yes. Our 2,500-CVE sample holds 317 KEV cases. Three families (Privilege Escalation, Remote Code Execution, and RCE with Path Traversal or File Upload) held 64.67% of them while making up about 31.45% of the estimated historical population. The sample over-represents KEV cases, so we re-weighted it to estimate the population.'),
      h('p', {}, 'A separate check ran forward in time. The top families from 2024 held 64.24% of 2025 KEV cases in 33.28% of the evaluated volume, a 1.93× concentration.'),
      statRow(stat('64.67%', 'of historical KEV cases', 'observed'), stat('31.45%', 'of estimated population', 'observed'), stat('1.93×', 'concentration, 2024 to 2025', 'observed')),
      h('h3', {}, 'RQ3. Can Granite help when information is missing?'),
      h('p', {}, 'Yes. Of the 72,670 benchmark CVEs, 8.74% have no CVSS v3 score and 6.82% have no CWE. Every one has a description, so every CVE still gets a family.'),
      statRow(stat('8.74%', 'no CVSS v3 score', 'source'), stat('6.82%', 'no CWE', 'source'), stat('100%', 'have a description, so a family', 'granite')),
    ] },
    { id: 'answer', title: 'How Tell answers IBM’s challenge', body: [
      h('p', {}, 'Tell covers three things IBM asked for.'),
      h('ul', { class: 'story-list' },
        h('li', {}, h('b', {}, 'Prediction. '), 'A ranked list with a Top 500. See ', link('#/top500', 'Top 500'), ' and ', link('#/signals', 'Signals'), '.'),
        h('li', {}, h('b', {}, 'Understanding. '), 'Granite families that show what vulnerabilities have in common. See ', link('#/families', 'Families'), '.'),
        h('li', {}, h('b', {}, 'Visualization. '), 'This site, including the ', link('#/galaxy', 'Galaxy'), ' view and the ', link('#/ask', 'Ask Telly'), ' assistant, which explains any CVE in plain language.')),
    ] },
    { id: 'data', title: 'Data we used and fairness', body: [
      h('p', {}, 'The ranking used only columns that were known at snapshot time, from ', h('span', { class: 'mono' }, 'scoreboard_2026.csv'), ': ', h('span', { class: 'mono' }, 'epss, exploitdb, metasploit, nuclei, poc_github'), '.'),
      h('p', {}, 'It did not use ', h('span', { class: 'mono' }, 'nvd_status'), ', ', h('span', { class: 'mono' }, 'n_affected_cpes'), ', ', h('span', { class: 'mono' }, 'n_references'), ', blank-severity patterns, or reference links. IBM flags these as leaky, meaning they can reveal the answer after the fact.'),
      h('p', {}, 'Granite read description text from ', h('span', { class: 'mono' }, 'vulnerabilities.csv'), '. Those descriptions may include edits made after a vulnerability was disclosed. That is one reason families explain rather than rank.'),
    ] },
    { id: 'impact', title: 'Impact', body: [
      h('blockquote', { class: 'story-quote' }, 'Severity tells us how serious a vulnerability could be. Ranking estimates which ones deserve attention first. IBM Granite helps explain the patterns behind them.'),
      h('p', {}, 'Together they give an analyst a shorter list, and a reason for each item on it.'),
    ] },
    { id: 'limits', title: 'Limitations', body: [
      h('ul', { class: 'story-list' },
        h('li', {}, 'The KEV-enriched sample needs population weighting before its rates mean anything about all CVEs.'),
        h('li', {}, 'Descriptions can contain updates written after disclosure.'),
        h('li', {}, 'KEV is not a complete record of real-world exploitation.'),
        h('li', {}, 'Adding Granite features to the ranking model has not been shown to help yet.')),
      h('p', {}, 'These are research findings, not exploit probabilities.'),
    ] },
  ];
}

export function mountStory(root: HTMLElement): void {
  const secs = sections();
  const toc = h('nav', { class: 'story-toc', 'aria-label': 'On this page' },
    h('p', { class: 'story-toc-title' }, 'On this page'),
    h('ul', {}, secs.map((s) => h('li', {}, h('button', { type: 'button', class: 'link-btn', onClick: () => {
      const el = document.getElementById(`story-${s.id}`);
      if (!el) return;
      el.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
      el.focus({ preventScroll: true });
    } }, s.title)))));
  const article = h('article', { class: 'story' }, secs.map((s) =>
    h('section', { 'aria-labelledby': `story-${s.id}` }, h('h2', { id: `story-${s.id}`, tabindex: '-1' }, s.title), ...s.body)));
  root.append(
    pageHead('Our Story', 'The problem, how we analyzed the data, what we found, and where it falls short.'),
    h('div', { class: 'story-layout' }, toc, article));
}
