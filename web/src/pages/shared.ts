import { h } from '../util';

export function pageHead(title: string, lead: string, extra?: Node): HTMLElement {
  return h('header', { class: 'page-head' },
    h('div', {}, h('h1', { class: 'page-title' }, title), h('p', { class: 'page-lead' }, lead)),
    extra ?? null);
}
