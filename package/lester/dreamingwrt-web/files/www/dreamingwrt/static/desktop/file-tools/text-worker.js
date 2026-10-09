'use strict';
self.Prism = { manual: true, disableWorkerMessageHandler: true };
let syntaxLoaded = false, diffLoaded = false;
const splitLines = (text) => text.match(/[^\n]*\n|[^\n]+$/g) || [];
self.onmessage = ({ data }) => {
  const { id, type } = data;
  try {
    if (type === 'highlight') {
      if (!syntaxLoaded) { importScripts('vendor/prism.min.js?v=1.30.0'); syntaxLoaded = true; }
      const grammar = Prism.languages[data.language];
      self.postMessage({ id, html: grammar ? Prism.highlight(data.text, grammar, data.language) : null });
      return;
    }
    if (!diffLoaded) { importScripts('vendor/diff.min.js?v=9.0.0'); diffLoaded = true; }
    const changes = Diff.diffLines(data.before, data.after, { timeout: 1500, maxEditLength: 3000 });
    if (!changes) { self.postMessage({ id, limited: true }); return; }
    let left = 1, right = 1, added = 0, removed = 0;
    const rows = [];
    for (let index = 0; index < changes.length; index++) {
      const change = changes[index], lines = splitLines(change.value);
      if (!change.added && !change.removed) {
        if (lines.length > 12) {
          for (const text of lines.slice(0, 3)) rows.push({ left: left++, right: right++, a: text, b: text });
          rows.push({ skipped: lines.length - 6 });
          left += lines.length - 6; right += lines.length - 6;
          for (const text of lines.slice(-3)) rows.push({ left: left++, right: right++, a: text, b: text });
        } else for (const text of lines) rows.push({ left: left++, right: right++, a: text, b: text });
      } else {
        const a = change.removed ? lines : [];
        const b = change.added ? lines : changes[index + 1]?.added ? splitLines(changes[++index].value) : [];
        removed += a.length; added += b.length;
        for (let row = 0; row < Math.max(a.length, b.length); row++) rows.push({
          left: row < a.length ? left++ : null, right: row < b.length ? right++ : null,
          a: a[row], b: b[row], changed: true
        });
      }
    }
    self.postMessage({ id, rows, added, removed, equal: data.before === data.after });
  } catch (error) { self.postMessage({ id, error: error.message }); }
};
