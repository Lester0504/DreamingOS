import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/plugins/native/wifi-management.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/static/css/wifi-management.css'), 'utf8');

for (const expected of [
  "configView: 'broadcasts'",
  "['broadcasts', 'Wi-Fi 广播']",
  "['radios', 'Radio 与信道']",
  "['extensions', '扩展能力']",
  'dwrt-kit-tabs dwrt-kit-page-tabs wifi-config-tabs',
  'wifi-config-surface dwrt-kit-table-wrap dwrt-kit-glass-surface',
  'class="dwrt-kit-table"',
  'wifi-setting-row dwrt-kit-switch',
  'data-dwrt-component="state-panel"',
  '未检测到无线硬件',
  '因此不构造信道矩阵',
  'wifi-dependency-panel ${global.mesh ? \'is-active\' : \'\'}',
  "state.config.radios.length ? `${radioSummary()}${defaultSpeed()}${channelPlan()}` : radioSummary()",
  "if (state.configView === 'extensions') return `${globalSettings()}${extendedSettings()}`",
  'data-wifi-speed-create',
  'data-wifi-reset-channels',
  'data-wifi-apply-all',
  "switchRow('global.mesh'",
  'data-wifi-setting="global.country"',
  "switchRow('global.band_steering'",
  'data-wifi-create',
  'data-wifi-config-tab',
  'data-dwrt-sheet-variant="copilot"'
]) {
  if (!source.includes(expected)) throw new Error(`missing Wi-Fi config layout contract: ${expected}`);
}

for (const expected of [
  'border-radius: var(--app-radius-card);',
  'border-radius: var(--app-radius-control);',
  'border-radius: var(--app-radius-compact);',
  '.wifi-config-tabs',
  '.wifi-config-surface',
  '.wifi-panel-section + .wifi-panel-section',
  '.wifi-dependency-panel.is-active',
  '@media (max-width: 720px)'
]) {
  if (!css.includes(expected)) throw new Error(`missing Wi-Fi CSS contract: ${expected}`);
}

for (const forbidden of [
  '<section class="wifi-section policy-stable-glass"',
  '<section class="wifi-config-table policy-stable-glass"',
  '<section class="wifi-section wifi-unifi-global policy-stable-glass"',
  '.wifi-config-table,\n.wifi-section,\n.airview-sidebar',
  '.wifi-setting-row > i,'
]) {
  if (source.includes(forbidden) || css.includes(forbidden)) throw new Error(`stale Wi-Fi card/control escape remains: ${forbidden}`);
}

const configRadiusBlock = css.slice(0, css.indexOf('.wireless-status-route-host .airview-shell'));
for (const hardcoded of ['border-radius: 24px', 'border-radius: 20px', 'border-radius: 18px', 'border-radius: 16px', 'border-radius: 14px']) {
  if (configRadiusBlock.includes(hardcoded)) throw new Error(`hard-coded config surface radius remains: ${hardcoded}`);
}

console.log('ok: Wi-Fi config uses one Kit surface, token radii, dependency hierarchy and preserves all settings entry points');
