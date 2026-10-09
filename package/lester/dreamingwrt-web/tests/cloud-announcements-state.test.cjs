const { test } = require('node:test');
const assert = require('node:assert/strict');
const { State, snapshot } = require('../files/www/dreamingwrt/static/js/cloud-announcements-state.js');
const row = (extra = {}) => ({ id: 'a', revision: 1, title: 'Title', content: '<plain text>',
  type: 'info', targets: ['router'], published: true, ...extra });
test('independent targets including none, draft and levels', () => {
  for (const targets of [[], ['android', 'ios', 'tv']]) {
    assert.equal(snapshot({ revision: 1, announcements: [row({ targets })] }).announcements.length, 0);
  }
  assert.equal(snapshot({ revision: 1, announcements: [row({ published: false })] }).announcements.length, 0);
  for (const type of ['info', 'warning', 'danger']) {
    assert.equal(snapshot({ revision: 1, announcements: [row({ type, targets: ['router', 'tv'] })] }).announcements[0].type, type);
  }
});
test('read persists, repeat dedupes, edits unread, removal and stale snapshot', () => {
  let state = new State();
  state.replace({ revision: 1, announcements: [row()] });
  state.read(state.items[0]);
  state = new State(JSON.parse(JSON.stringify(state.preferences)));
  state.replace({ revision: 1, announcements: [row()] });
  assert.equal(state.unread.length, 0);
  state.replace({ revision: 2, announcements: [row({ revision: 2 })] });
  assert.equal(state.unread.length, 1);
  state.replace({ revision: 3, announcements: [] });
  assert.equal(state.replace({ revision: 1, announcements: [row()] }), false);
  assert.equal(state.items.length, 0);
});
test('invalid data retains known state', () => {
  const state = new State();
  state.replace({ revision: 1, announcements: [row()] });
  for (const bad of [{ revision: 2 }, { revision: 2, announcements: [row({ type: 'other' })] },
    { revision: 2, announcements: [row(), row()] }, { revision: -1, announcements: [] }]) {
    assert.throws(() => state.replace(bad));
    assert.equal(state.items.length, 1);
  }
});
