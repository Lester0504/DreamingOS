import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/plugins/native/wifi-management.js'), 'utf8');
const shell = fs.readFileSync(path.join(root, 'files/www/dreamingwrt/static/js/menu-shell.js'), 'utf8');

for (const expected of [
  "const VERSION = '20260725-wifi-environment-02'",
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

console.log('ok: wireless status follows the UniFi AirView resource and column contract without fabricated telemetry');
