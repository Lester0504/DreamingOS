import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const modulePath = path.join(root, 'files/www/dreamingwrt/plugins/native/storage-partitions.js');
const stylePath = path.join(root, 'files/www/dreamingwrt/static/css/storage-partitions.css');
const source = fs.readFileSync(modulePath, 'utf8');
const style = fs.readFileSync(stylePath, 'utf8');

const requireSource = (token, message) => assert.ok(source.includes(token), message || `missing module contract: ${token}`);
const requireStyle = (token, message) => assert.ok(style.includes(token), message || `missing style contract: ${token}`);

assert.match(source, /export function mount\(context = \{\}\)/, 'route must expose mount(context)');
assert.match(source, /export default \{ mount \}/, 'route must expose the default mount adapter');
for (const endpoint of [
  '/api/v1/storage/partitions',
  '/api/v1/storage/overview?range=1h',
  '/api/v1/system/mounts',
  '/api/v1/system/mounts/discovery'
]) requireSource(endpoint, `missing real read source ${endpoint}`);

requireSource("!response.ok || json?.ok === false || payload?.ok === false || normalizeCodeFailure(json) || normalizeCodeFailure(payload)", 'request helper must reject HTTP, ok=false and non-success business codes');
requireSource("json?.code", 'business response code must be inspected');
requireSource("Promise.allSettled", 'read-only fallback sources must not block one another');
requireSource("sourceDisks.length ? 'partition-api' : 'fallback'", 'official partition API and read-only fallback must remain distinguishable');
requireSource("当前由存储概览与挂载接口合并真实只读信息", 'fallback UI must disclose read-only provenance');

for (const contract of [
  'data-dwrt-component="tabs"',
  'dwrt-kit-page-tabs',
  'data-dwrt-component="table"',
  'dwrt-kit-table',
  'data-dwrt-component="sheet"',
  'data-dwrt-component="field"',
  'statusBadgeMarkup',
  'confirmationMarkup',
  'data-dwrt-component="button"',
  'data-dwrt-component="icon-button"',
  'data-dwrt-component="async-button"'
]) requireSource(contract, `UI Kit escape: ${contract}`);

for (const field of [
  'startSector', 'endSector', 'filesystem', 'mountPoints', 'usedBytes',
  'availableBytes', 'unallocatedBytes', 'partition_table', 'sector_size',
  'physical_sector_size', 'serial', 'transport'
]) requireSource(field, `partition information dimension missing: ${field}`);

for (const action of ['create', 'delete', 'format', 'mount', 'unmount', 'resize']) {
  requireSource(`${action}: false`, `capability must fail closed for ${action}`);
}
requireSource("transactionPreview: false", 'transaction preview must fail closed');
requireSource("transactionCommit: false", 'transaction commit must fail closed');
requireSource("if (!state.capabilities.transactionPreview || !state.capabilities.transactionCommit || !state.capabilities[action]) return false", 'all writes need preview, commit and per-action capabilities');
requireSource("`${PARTITION_ENDPOINT}/preview`", 'destructive operations need a preview request');
requireSource("`${PARTITION_ENDPOINT}/commit`", 'confirmed operations need an explicit commit request');
requireSource("preview_token", 'preview must yield a single-use transaction token');
requireSource("confirm_destructive: true", 'commit must carry explicit destructive confirmation');
requireSource("await load(true)", 'writes must perform authoritative readback');

assert.ok(!/localStorage\.setItem|sessionStorage\.setItem/.test(source), 'partition data must never persist in browser storage');
assert.ok(!/\bconfirm\s*\(/.test(source), 'browser confirm() is forbidden');
assert.ok(!/\b(?:parted|fdisk|sfdisk|mkfs|wipefs|umount)\b[^'"\n]*\(/.test(source), 'frontend must not invoke partitioning commands');
assert.ok(!/(?:exec|spawn|system)\s*\([^\n]*(?:mount|umount)/.test(source), 'frontend must not execute mount commands');
assert.ok(!/sample|mock|fixture|demo-disk/i.test(source), 'runtime module must not fabricate sample disks');
assert.ok(!/totalBytes\s*-|total_bytes\s*-/.test(source), 'unallocated capacity must not be guessed by subtraction');

for (const lifecycle of [
  "signal: context.signal",
  "context.signal?.addEventListener('abort', unmount, { once: true })",
  "context.signal?.removeEventListener('abort', unmount)",
  "root.removeEventListener('click', onClick)",
  "document.removeEventListener('keydown', onKeydown, true)",
  "ui.unmount?.(root)"
]) requireSource(lifecycle, `lifecycle cleanup missing: ${lifecycle}`);

assert.ok(!style.includes('!important'), 'new page CSS must not add !important');
assert.ok(!style.includes('backdrop-filter'), 'page CSS must not own glass blur');
assert.ok(!/#[0-9a-fA-F]{3,8}\b/.test(style), 'page CSS must not hardcode hex colors');
assert.ok(!/rgba?\(/.test(style), 'page CSS must use semantic tokens instead of raw color functions');
for (const radius of ['border-radius: 8px', 'border-radius: 6px', 'border-radius: 4px']) requireStyle(radius);
requireStyle('var(--color-surface-stable', 'stable surfaces must consume semantic material tokens');
requireStyle('@media (max-width: 767px)', 'mobile layout contract missing');
requireStyle('--dwrt-kit-sheet-width: 100vw', 'mobile sheet must become full screen');
requireStyle('overflow: auto', 'wide tables and long content need scoped scrolling');

for (const sourcePath of [modulePath, stylePath]) {
  const gzipPath = `${sourcePath}.gz`;
  assert.ok(fs.existsSync(gzipPath), `missing gzip: ${path.relative(root, gzipPath)}`);
  assert.deepEqual(zlib.gunzipSync(fs.readFileSync(gzipPath)), fs.readFileSync(sourcePath), `gzip differs from source: ${path.relative(root, gzipPath)}`);
}

console.log('storage partitions frontend contract: ok');
