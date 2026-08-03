import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/plugins/native/wifi-management.js'), 'utf8');
const shell = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/static/js/menu-shell.js'), 'utf8');
const routeCss = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/static/css/wifi-management.css'), 'utf8');

// 版本键每次改动都会 bump。这里断言模块声明了 VERSION 并且 main.json 的两个版本键与它
// 一致，而不是把某一次的字面量钉死在测试里。
const menu = JSON.parse(fs.readFileSync(path.join(root, 'files/www/dreamingwrt/static/menu/main.json'), 'utf8'));
const moduleVersion = source.match(/const VERSION = '([^']+)'/);
if (!moduleVersion) throw new Error('wifi-management.js missing const VERSION');
const wifiRoutes = [];
(function walk(items) {
  items.forEach((item) => {
    if (item.module === 'native/wifi-management.js') wifiRoutes.push(item);
    if (item.children) walk(item.children);
  });
})(menu.items);
if (!wifiRoutes.length) throw new Error('no wifi-management routes in main.json');
wifiRoutes.forEach((item) => {
  if (item.module_version !== moduleVersion[1] || item.style_version !== moduleVersion[1]) {
    throw new Error(`stale cache key on ${item.id}: ${item.module_version} / ${item.style_version} vs ${moduleVersion[1]}`);
  }
});

for (const expected of [
  'const LABEL_MAX_CHARS = 22',
  'function clipLabel(value, max = LABEL_MAX_CHARS)',
  'class="airview-check-label"',
  'class="dwrt-kit-sheet airview-radio-sheet policy-stable-glass is-open" data-dwrt-component="sheet"',
  'const offsets = captureScrollOffsets(results)',
  'restoreScrollOffsets(results, offsets)',
  "boundary.querySelectorAll('.wifi-table-scroll, [data-airview-scroll]')",
  "ap_id: apId || firstText(",
  "radio_id: firstText(ssid.radio_id",
  "const broadcasts = new Map()",
  "broadcast.radioIds.has(radio.id)",
  "['client', '客户端'], ['event', '事件'], ['ap', 'AP'], ['result', '结果'], ['signal', '信号'], ['band', '频段'], ['broadcast', 'WiFi 广播'], ['time', '日期/时间']",
  "['nearest', '最近的 AP']",
  '<th>名称</th><th>频段</th><th>信道</th><th>信道宽度</th><th>Tx 功率</th><th>客户端</th><th>平均信号</th><th>过去 24 小时</th><th>平均干扰</th>',
  "radio.clients === null ? '--' : radio.clients",
  "image_url: firstText(radio.image_url",
  "window.DWRT_DEVICE_IMAGES",
  "data-airview-radio-row=",
  "data-airview-radio-select=",
  "data-airview-radio-select-all",
  "data-dwrt-sheet-variant=\"copilot\"",
  "data-dwrt-sheet-motion=\"settled\"",
  "无线电设置",
  "信道宽度",
  "发射功率",
  "最小 RSSI",
  "关键指标",
  "活动客户端分布",
  "radio_update_endpoint",
  "当前展示真实运行值，修改与保存保持禁用",
  "后端尚未提供漫游、断开、重连和 AP 切换事件历史",
  "environment.channel_survey",
  "environment.neighbor_scan",
  "environment.spectral_fft",
  "/api/v1/wifi/environment/survey-history",
  "cacheVersion: false",
  "mode: 'neighbor'",
  "idempotency_key:",
  "/api/v1/wifi/scan/jobs/",
  "scanJobs: new Map()",
  "payload.item && typeof payload.item === 'object'",
  "source.error_code",
  "iw_neighbor_scan_failed_or_unsupported",
  "data-airview-ap-details=",
  "ui.mountAll(root)",
  "data-airview-ap-tab=",
  "['overview', '概览', 'overview']",
  "['insights', '洞察', 'insights']",
  "['settings', '设置', 'settings']",
  "TX 重试",
  "空中统计",
  "活动客户端 RSSI 分布",
  "Mesh Connect",
  "更新固件",
  "尚未执行邻居扫描",
  "Radio 已上报，但驱动未返回完整 Survey 数值",
  "暂无可绘制的信道利用率历史"
]) {
  if (!source.includes(expected)) throw new Error(`missing AirView contract: ${expected}`);
}

for (const forbidden of [
  '<th>Airtime</th>',
  '<th>Tx Retry / Dropped</th>',
  'const rows = state.status.interference.length ? state.status.interference : state.status.ssids',
  'filters.aps.has(radio.ap)',
  'ssid.bands.includes(radio.band)',
  '<input type="checkbox" disabled aria-label="选择全部射频">',
  'fetch(\'/api/v1/wifi/radios\'',
  "mode: 'airtime'",
  "后端尚未提供环境扫描与频谱样本"
]) {
  if (source.includes(forbidden)) throw new Error(`stale imitation remains: ${forbidden}`);
}

if (/shellVersioned = new Set\([^\n]*wifi-management/.test(shell)) {
  throw new Error('Wi-Fi route resources must use their menu-owned version instead of the shell version');
}

// Both AirView drawers must keep the fixed right-edge geometry even when the
// ui-kit legacy-glass allowlist misses a class combination, and the width
// override must not sit on a bare page class that loses to the kit base rule.
for (const expected of [
  '.wireless-status-route-host .dwrt-kit-sheet.airview-radio-sheet,\n.wireless-status-route-host .dwrt-kit-sheet.airview-ap-sheet {',
  '.dwrt-kit-sheet.airview-radio-sheet {',
  '.wireless-status-route-host .dwrt-kit-sheet-overlay {'
]) {
  if (!routeCss.includes(expected)) throw new Error(`missing AirView sheet geometry rule: ${expected}`);
}

// A bare text node cannot take min-width: 0, so the label needs its own element
// or a long AP name pushes the device icon onto a second line.
if (!/\.airview-check > span > \.airview-check-label \{[^}]*text-overflow: ellipsis/.test(routeCss)) {
  throw new Error('filter labels must carry ellipsis on their own element');
}

if (/(^|\n)\.airview-radio-sheet\s*\{/.test(routeCss)) {
  throw new Error('airview-radio-sheet width override must be prefixed with .dwrt-kit-sheet to outweigh the kit base rule');
}

console.log('ok: wireless status follows the UniFi AirView resource and column contract without fabricated telemetry');
