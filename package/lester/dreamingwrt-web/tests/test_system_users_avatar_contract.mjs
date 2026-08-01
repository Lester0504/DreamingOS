import assert from 'node:assert/strict';
import fs from 'node:fs';

import {
  mergeSystemUserAvatar,
  normalizeSystemUserAvatarUrl,
  withSystemUserAvatarRevision
} from '../files/www/dreamingwrt/plugins/native/system-users.js';

const base = 'http://192.168.30.1:12517/app/#/system/users';

assert.equal(
  normalizeSystemUserAvatarUrl('/luci-static/dreamingwrt/avatar/Lester.webp', base),
  '/luci-static/dreamingwrt/avatar/Lester.webp'
);
assert.equal(
  normalizeSystemUserAvatarUrl('/www/luci-static/dreamingwrt/avatar/Lester.webp', base),
  '/luci-static/dreamingwrt/avatar/Lester.webp'
);
assert.equal(
  normalizeSystemUserAvatarUrl('/www/dreamingwrt/static/images/avatar.webp', base),
  '/static/images/avatar.webp'
);
assert.equal(normalizeSystemUserAvatarUrl('javascript:alert(1)', base), '');
assert.equal(normalizeSystemUserAvatarUrl('https://example.com/avatar.webp', base), '');
assert.equal(normalizeSystemUserAvatarUrl('/luci-static/../etc/passwd', base), '');

assert.equal(
  withSystemUserAvatarRevision('/luci-static/dreamingwrt/avatar/Lester.webp?size=small', 1234, base),
  '/luci-static/dreamingwrt/avatar/Lester.webp?size=small&v=1234'
);

const users = [
  { username: 'Lester', avatarUrl: '' },
  { username: 'Viewer', avatarUrl: '/static/images/viewer.webp' }
];
const merged = mergeSystemUserAvatar(users, {
  username: 'lester',
  avatar_url: '/luci-static/dreamingwrt/avatar/Lester.webp'
});
assert.equal(merged[0].avatarUrl, '/luci-static/dreamingwrt/avatar/Lester.webp');
assert.equal(merged[1], users[1]);

const js = fs.readFileSync(new URL('../files/www/dreamingwrt/plugins/native/system-users.js', import.meta.url), 'utf8');
const css = fs.readFileSync(new URL('../files/www/dreamingwrt/static/css/system-users.css', import.meta.url), 'utf8');

assert.match(js, /value\.avatar_url \|\| value\.avatarUrl \|\| value\.avatar/);
assert.match(js, /basic\.admin/);
assert.match(js, /dwrt:admin-avatar-changed/);
assert.match(js, /window\.removeEventListener\('dwrt:admin-avatar-changed'/);
assert.match(js, /data-system-user-avatar-image/);
assert.match(js, /classList\.remove\('has-image'\)/);
assert.match(js, /function patchTable\(\)[\s\S]*bindAvatarImages\(tbody\)/);
assert.match(js, /function patchLoadedUsers\(\)[\s\S]*bindAvatarImages\(root\.querySelector\('\.system-users-table-card'\)\)/);
assert.match(css, /\.system-user-avatar img[^}]*object-fit:\s*cover/s);
assert.match(css, /overflow:\s*hidden/);
assert.match(css, /\.system-user-profile \.system-user-avatar-fallback[^}]*font-size:\s*inherit/s);

console.log('ok: system users avatar source, cache revision, live update, fallback, and crop contract');
