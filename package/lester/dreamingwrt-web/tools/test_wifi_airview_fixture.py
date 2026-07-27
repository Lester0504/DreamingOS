#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Override with PLAYWRIGHT_RUNTIME to point at a local Node + Playwright install.
RUNTIME = Path(os.environ.get("PLAYWRIGHT_RUNTIME", Path.home() / ".cache/dreamingwrt-playwright"))
NODE = Path(shutil.which("node") or RUNTIME / "node/bin/node")
NODE_MODULES = RUNTIME / "node/node_modules"

if not NODE.is_file():
    raise SystemExit(f"Node.js not found: {NODE}")
if not (NODE_MODULES / "playwright").exists():
    raise SystemExit(f"Playwright not found: {NODE_MODULES / 'playwright'}")

server = subprocess.Popen(
    ["python3", "-m", "http.server", "18769", "--bind", "127.0.0.1"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
)
try:
    time.sleep(.4)
    if server.poll() is not None:
        raise RuntimeError(f"fixture server failed: {(server.stderr.read() if server.stderr else '').strip()}")

    script = r"""
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, channel: 'chrome' });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.goto('http://127.0.0.1:18769/tests/fixtures/wifi-airview.html', { waitUntil: 'networkidle' });
  await page.waitForSelector('.airview-radio-table tbody tr', { timeout: 10000 });
  const initial = await page.evaluate(() => ({
    apLabels: Array.from(document.querySelectorAll('[data-airview-filter="aps"]')).map(input => input.closest('label').innerText.trim()),
    broadcasts: Array.from(document.querySelector('[data-airview-broadcast]').options).map(option => option.text),
    headers: Array.from(document.querySelectorAll('.airview-radio-table th')).map(node => node.innerText.trim()).filter(Boolean),
    rows: Array.from(document.querySelectorAll('.airview-radio-table tbody tr')).map(row => Array.from(row.cells).map(cell => cell.innerText.trim())),
    imageSources: Array.from(document.querySelectorAll('.airview-device-image img')).map(image => image.getAttribute('src')),
    filterImages: Array.from(document.querySelectorAll('.airview-filter-device-image img')).map(image => image.getAttribute('src')),
    nameWrap: Array.from(document.querySelectorAll('.airview-ap-cell strong')).map(node => {
      const style = getComputedStyle(node);
      return { height: node.getBoundingClientRect().height, lineHeight: parseFloat(style.lineHeight) || parseFloat(style.fontSize) * 1.2 };
    }),
    pageOverflow: document.documentElement.scrollWidth > innerWidth + 1
  }));

  await page.locator('[data-airview-radio-select]').first().check();
  const sheet = await page.evaluate(() => {
    const node = document.querySelector('.airview-radio-sheet');
    return {
      open: Boolean(node), title: node?.getAttribute('aria-label'), variant: node?.dataset.dwrtSheetVariant,
      bands: Array.from(node?.querySelectorAll('.airview-radio-sheet-band > header strong') || []).map(item => item.textContent.trim()),
      labels: node?.innerText || '', saveDisabled: Boolean(node?.querySelector('[data-airview-radio-save]')?.disabled),
      imageSources: Array.from(node?.querySelectorAll('img') || []).map(image => image.getAttribute('src'))
    };
  });
  await page.locator('[data-airview-radio-sheet-close]').last().click();
  const closed = await page.locator('.airview-radio-sheet').count();
  await page.locator('[data-airview-radio-select-all]').check();
  const allSheet = await page.evaluate(() => ({
    radios: document.querySelectorAll('.airview-selected-aps > button').length,
    bands: Array.from(document.querySelectorAll('.airview-radio-sheet-band > header strong')).map(item => item.textContent.trim())
  }));
  await page.locator('[data-airview-radio-sheet-close]').last().click();

  await page.locator('[data-airview-broadcast]').selectOption({ label: 'Xiaomi_DE23' });
  const filteredRows = await page.locator('.airview-radio-table tbody tr').count();
  await page.locator('[data-airview-view="connectivity"]').click();
  const connectivity = await page.locator('[data-airview-results]').innerText();
  await page.locator('[data-airview-columns="connectivity"]').click();
  const connectivityColumns = await page.locator('.airview-column-editor label').allTextContents();
  await page.locator('[data-airview-columns-done]').click();
  await page.locator('[data-airview-view="environment"]').click();
  const environment = await page.locator('[data-airview-results]').innerText();
  const environmentControls = await page.evaluate(() => {
    const picker = document.querySelector('.airview-ap-picker');
    const select = picker.querySelector('select');
    const insights = picker.querySelector('[data-airview-ap-details]');
    const thumbs = Array.from(document.querySelectorAll('.airview-signal-range input')).map(input => {
      const style = getComputedStyle(input, '::-webkit-slider-thumb');
      return { label: input.getAttribute('aria-label'), width: parseFloat(style.width) || 0, height: parseFloat(style.height) || 0 };
    });
    return {
      selected: select.options[select.selectedIndex].text,
      insightsLabel: insights.getAttribute('aria-label'),
      pickerOverflow: picker.scrollWidth > picker.clientWidth + 1,
      thumbs
    };
  });
  await page.locator('[data-airview-ap-details]').click();
  const apOverview = await page.evaluate(() => {
    const sheet = document.querySelector('.airview-ap-sheet');
    const rect = sheet.getBoundingClientRect();
    return {
      variant: sheet.dataset.dwrtSheetVariant,
      tabs: Array.from(sheet.querySelectorAll('[data-airview-ap-tab]')).map(tab => ({ label: tab.getAttribute('aria-label'), selected: tab.getAttribute('aria-selected') })),
      text: sheet.innerText,
      right: Math.abs(innerWidth - rect.right),
      wallpaper: Boolean(sheet.querySelector(':scope > .dwrt-kit-sheet-wallpaper')),
      material: Boolean(sheet.querySelector(':scope > .dwrt-kit-sheet-material')),
      tabsBottom: sheet.querySelector('.airview-ap-sheet-tabs').getBoundingClientRect().bottom,
      bodyTop: sheet.querySelector('.airview-ap-sheet-body').getBoundingClientRect().top
    };
  });
  await page.locator('[data-airview-ap-tab="insights"]').click();
  const apInsights = await page.locator('.airview-ap-sheet-body').innerText();
  await page.locator('[data-airview-ap-tab="settings"]').click();
  const apSettings = await page.locator('.airview-ap-sheet-body').innerText();
  const disabledSettings = await page.locator('.airview-ap-settings-card input:disabled, .airview-ap-settings-card select:disabled, .airview-ap-settings-card button:disabled').count();
  await page.locator('[data-airview-ap-sheet-close]').last().click();
  await page.locator('[data-airview-scan]').click();
  await page.waitForFunction(() => document.querySelector('[data-airview-scan]') && !document.querySelector('[data-airview-scan]').disabled, null, { timeout: 10000 });
  const scanJobs = await page.locator('[data-airview-scan-jobs]').innerText();
  await page.locator('[data-airview-columns="environment"]').click();
  const columnLabels = await page.locator('.airview-column-editor label').allTextContents();
  await page.locator('[data-airview-filter="columns.environment"][value="vendor"]').uncheck();
  await page.locator('[data-airview-columns-done]').click();
  const environmentHeaders = await page.locator('.airview-spectrum-table th').allTextContents();

  const viewports = [];
  for (const viewport of [{width:1440,height:1000},{width:1024,height:768},{width:390,height:844}]) {
    await page.setViewportSize(viewport);
    await page.locator('[data-airview-view="radios"]').click();
    await page.locator('[data-airview-radio-select]').first().check();
    viewports.push(await page.evaluate(viewport => {
      const route = document.getElementById('routePreview');
      const sheet = document.querySelector('.airview-radio-sheet');
      const rect = sheet.getBoundingClientRect();
      return {
        ...viewport,
        pageOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        routeOverflow: route.scrollWidth > route.clientWidth + 1,
        routeWidth: route.clientWidth,
        sidebarWidth: document.querySelector('.airview-sidebar').clientWidth,
        resultsWidth: document.querySelector('.airview-results').clientWidth,
        sheetInside: rect.left >= -1 && rect.right <= innerWidth + 1,
        sheetRight: Math.abs(innerWidth - rect.right),
        sheetScrollable: sheet.querySelector('.dwrt-kit-sheet-body').scrollHeight > sheet.querySelector('.dwrt-kit-sheet-body').clientHeight
      };
    }, viewport));
    await page.locator('[data-airview-radio-sheet-close]').last().click();
  }
  await browser.close();
  process.stdout.write(JSON.stringify({ initial, sheet, closed, allSheet, filteredRows, connectivity, connectivityColumns, environment, environmentControls, apOverview, apInsights, apSettings, disabledSettings, scanJobs, columnLabels, environmentHeaders, viewports }));
})().catch(error => { console.error(error); process.exit(1); });
"""
    env = os.environ.copy()
    env["NODE_PATH"] = str(NODE_MODULES)
    result = subprocess.run([str(NODE), "-e", script], cwd=ROOT, env=env, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    data = json.loads(result.stdout)

    assert data["initial"]["apLabels"] == ["Xiaomi Router BE10000 (Wi-Fi 7)"], data
    assert data["initial"]["broadcasts"] == ["所有 WiFi 广播 (2)", "Xiaomi_DE23", "Xiaomi_52A3-IoT"], data
    assert data["initial"]["headers"] == ["名称", "频段", "信道", "信道宽度", "TX 功率", "客户端", "平均信号", "过去 24 小时", "平均干扰"], data
    assert [row[2] for row in data["initial"]["rows"]] == ["2.4 GHz", "5 GHz", "6 GHz"], data
    assert [row[5] for row in data["initial"]["rows"]] == ["28 dBm", "27 dBm", "24 dBm"], data
    assert all(row[6:] == ["--", "--", "--", "--"] for row in data["initial"]["rows"]), data
    assert len(data["initial"]["imageSources"]) == 3 and all("gateway-wide.svg" in item for item in data["initial"]["imageSources"]), data
    assert len(data["initial"]["filterImages"]) == 1, data
    assert all(item["height"] <= item["lineHeight"] * 1.25 for item in data["initial"]["nameWrap"]), data
    assert data["sheet"]["open"] and data["sheet"]["title"] == "无线电设置" and data["sheet"]["variant"] == "copilot", data
    assert data["sheet"]["bands"] == ["2.4 GHz"] and data["sheet"]["saveDisabled"], data
    assert all(text in data["sheet"]["labels"] for text in ["信道宽度", "信道", "发射功率", "最小 RSSI", "关键指标", "活动客户端分布"]), data
    assert data["closed"] == 0, data
    assert data["allSheet"] == {"radios": 3, "bands": ["2.4 GHz", "5 GHz", "6 GHz"]}, data
    assert data["filteredRows"] == 3, data
    assert "连接性历史不可用" in data["connectivity"], data
    assert data["connectivityColumns"] == ["全部", "客户端", "事件", "AP", "结果", "信号", "频段", "WiFi 广播", "日期/时间"], data
    assert all(text in data["environment"] for text in [
        "邻居扫描", "实时 Survey", "Survey 历史", "频谱 FFT",
        "暂无可绘制的信道利用率历史",
    ]), data
    assert data["environmentControls"]["selected"] == "Xiaomi Router BE10000 (Wi-Fi 7)", data
    assert data["environmentControls"]["insightsLabel"] == "打开 Xiaomi Router BE10000 (Wi-Fi 7) 详情", data
    assert not data["environmentControls"]["pickerOverflow"], data
    assert [item["label"] for item in data["environmentControls"]["thumbs"]] == ["最低信号", "最高信号"], data
    assert data["apOverview"]["variant"] == "copilot" and data["apOverview"]["right"] <= 1, data
    assert data["apOverview"]["wallpaper"] and data["apOverview"]["material"], data
    assert data["apOverview"]["tabsBottom"] <= data["apOverview"]["bodyTop"], data
    assert data["apOverview"]["tabs"] == [
        {"label": "概览", "selected": "true"}, {"label": "洞察", "selected": "false"}, {"label": "设置", "selected": "false"}
    ], data
    assert all(text in data["apOverview"]["text"] for text in ["Xiaomi Router BE10000", "TX 重试", "IP 地址", "MAC 地址", "空中统计", "AP 组"]), data
    assert all(text in data["apInsights"] for text in ["2.4 GHz", "5 GHz", "6 GHz", "历史", "活动客户端 RSSI 分布", "统计"]), data
    assert all(text in data["apSettings"] for text in ["设备标签", "信道宽度", "发射功率", "最小 RSSI", "Mesh Connect", "IP 配置", "更新固件", "移除"]), data
    assert data["disabledSettings"] >= 12, data
    assert all(text in data["scanJobs"] for text in ["2.4 GHz", "5 GHz", "6 GHz", "驱动不支持邻居扫描或扫描失败", "失败"]), data
    assert data["scanJobs"].index("2.4 GHz") < data["scanJobs"].index("5 GHz") < data["scanJobs"].index("6 GHz"), data
    assert data["columnLabels"] == ["全部", "AP", "WiFi 名称", "信号", "信道", "信道宽度", "标准", "MAC 地址", "安全", "供应商", "最近的 AP"], data
    assert "供应商" not in data["environmentHeaders"], data
    assert all(not item["pageOverflow"] and not item["routeOverflow"] and item["sheetInside"] and item["sheetRight"] <= 1 for item in data["viewports"]), data
    mobile = next(item for item in data["viewports"] if item["width"] == 390)
    assert mobile["sidebarWidth"] >= mobile["routeWidth"] - 2, data
    assert mobile["resultsWidth"] >= mobile["routeWidth"] - 2, data
    assert mobile["sheetScrollable"], data
    print("ok: AirView fixture passes device images, single-line names, radio sheet, capability gates and three viewports")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
