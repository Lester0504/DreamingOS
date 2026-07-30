#!/usr/bin/env python3
"""Contracts for the shared glass and Dashboard mount hot paths."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "files" / "www" / "dreamingwrt" / "static" / "js"
NATIVE = ROOT / "files" / "www" / "dreamingwrt" / "plugins" / "native"
KIT = ROOT / "files" / "www" / "dreamingwrt" / "static" / "ui-kit" / "dwrt-ui-kit.js"
GLASS = ROOT / "files" / "www" / "dreamingwrt" / "static" / "ui-kit" / "dwrt-sampled-liquid-glass.js"
WORKER = JS / "page-glass-map-worker.js"

shell = (JS / "menu-shell.js").read_text(encoding="utf-8")
dashboard = (JS / "dashboard.js").read_text(encoding="utf-8")
kit = KIT.read_text(encoding="utf-8")
glass = GLASS.read_text(encoding="utf-8")
worker = WORKER.read_text(encoding="utf-8")
global_config = (NATIVE / "global-config.js").read_text(encoding="utf-8")

map_start = shell.index("  function pageGlassDisplacementMap(geometry) {")
map_end = shell.index("\n  function cancelPageGlassIdleWork()", map_start)
map_source = shell[map_start:map_end]

assert "toDataURL" not in map_source, "shared page glass must not synchronously encode PNG data URLs"
assert "requestPageGlassMapBlob(mapWidth, mapHeight, scaledRects, signature)" in map_source
assert "pageGlassMapBlobFallback(mapWidth, mapHeight, scaledRects)" in map_source
assert "URL.createObjectURL(blob)" in map_source
assert "PAGE_GLASS_MAP_CACHE.set(signature, entry)" in map_source

worker_request_start = shell.index("  function requestPageGlassMapBlob(")
worker_request_end = shell.index("\n\n  function pageGlassMapBlobFallback(", worker_request_start)
worker_request_source = shell[worker_request_start:worker_request_end]
assert "worker.postMessage({ id, mapWidth, mapHeight, scaledRects, signature })" in worker_request_source
assert "PAGE_GLASS_MAP_WORKER_TIMEOUT_MS" in worker_request_source
assert "disablePageGlassMapWorker(worker)" in worker_request_source
assert "appShell.dataset.pageGlassMapExecution = 'worker'" in shell

fallback_start = shell.index("  function pageGlassMapBlobFallback(")
fallback_end = shell.index("\n\n  function pageGlassDisplacementMap(", fallback_start)
fallback_source = shell[fallback_start:fallback_end]
assert "canvas.toBlob(resolve, 'image/png')" in fallback_source
assert "appShell.dataset.pageGlassMapExecution = 'main-thread-fallback'" in fallback_source
assert "toDataURL" not in fallback_source
assert "new Worker(PAGE_GLASS_MAP_WORKER_URL)" in shell
assert "window.addEventListener('pagehide', stopPageGlassMapWorker)" in shell

assert "new OffscreenCanvas(mapWidth, mapHeight)" in worker
assert "canvas.convertToBlob({ type: 'image/png' })" in worker
assert "self.postMessage({ id, signature, blob })" in worker
assert "pageGlassFragment(localX / rect.width, localY / rect.height)" in worker
assert "toDataURL" not in worker
assert "message.task === 'uniform'" in worker
assert "renderUniformDisplacementMap(" in worker
assert "new FileReaderSync().readAsDataURL(blob)" in worker

assert "toDataURL" not in glass
assert "new Worker(MAP_WORKER_URL)" in glass
assert "task: 'uniform'" in glass
assert "renderMapFallback(w, h, mode, preserveCenter)" in glass
assert "canvas.toBlob(blob =>" in glass
assert "const dataUrl = result.dataUrl || await blobDataUrl(result.blob)" in glass
assert "URL.createObjectURL(result.blob)" not in glass
assert "const requestToken = ++this.mapRequestToken" in glass
assert "requestToken !== this.mapRequestToken" in glass
assert "this.pendingMapKey === key" in glass
assert "window.addEventListener('pagehide', stopMapWorker)" in glass
assert "this.filterPadding = Math.ceil(" in glass
assert "const activeDisplacement = this.lightRenderer" in glass
assert "Math.max(Math.abs(redScale), Math.abs(greenScale), Math.abs(blueScale))" in glass
assert "activeDisplacement * 0.5" in glass
assert "this.filter.setAttribute('x', String(-filterPadding))" in glass
assert "this.filter.setAttribute('width', String(width + filterPadding * 2))" in glass
assert "const SAFARI_LIGHT_PROFILE" in glass
assert "vendor === 'Apple Computer, Inc.'" in glass
assert "this.trackMotion = !this.lightRenderer" in glass
assert "this.trackScroll = !this.lightRenderer" in glass
assert "this.root.dataset.glassRenderer = this.lightRenderer ? 'safari-light-sampling'" in glass
light_filter_start = glass.index("if (this.lightRenderer) {", glass.index("buildSvg()"))
light_filter_end = glass.index("} else {", light_filter_start)
light_filter = glass[light_filter_start:light_filter_end]
assert light_filter.count("svgNode('feDisplacementMap'") == 0
assert "this.redDisplacement" in light_filter
assert "this.greenDisplacement" not in light_filter
assert "this.blueDisplacement" not in light_filter

trim_start = shell.index("  function trimPageGlassMapCache() {")
trim_source = shell[trim_start:map_start]
assert "URL.revokeObjectURL(entry.url)" in trim_source
assert "PAGE_GLASS_MAP_CACHE.size <= 8" in trim_source
assert "activeLabels.has(signature)" in trim_source

reconcile_start = shell.index("  function reconcilePageGlassRenderers(")
reconcile_end = shell.index("\n  function scheduleGlassCardsRender(", reconcile_start)
reconcile_source = shell[reconcile_start:reconcile_end]
assert "schedulePageGlassDisplacementMap(scope, geometry, signature)" in reconcile_source
assert "pageGlassDisplacementMap(geometry).then" not in reconcile_source

schedule_start = shell.index("  function schedulePageGlassDisplacementMap(scope, geometry, signature) {")
schedule_end = shell.index("\n\n  function cancelPageGlassIdleWork()", schedule_start)
schedule_source = shell[schedule_start:schedule_end]
assert "window.setTimeout" in schedule_source
assert "const mapRequestToken = ++scope.mapRequestToken" in schedule_source
assert "scope.mapRequestToken !== mapRequestToken" in schedule_source
assert "scope.signature !== signature" in schedule_source
assert "state.liquidGlass.pageRouteToken !== routeToken" in schedule_source
assert "!scope.sampler.isConnected" in schedule_source
assert "scope.displacementMapLabel = displacementMap.label" in schedule_source

rank_update_start = dashboard.index("  function updateRankValues(items, kind) {")
rank_update_end = dashboard.index("\n\n  function rankListScrollState()", rank_update_start)
rank_update_source = dashboard[rank_update_start:rank_update_end]
assert "mountAll(" not in rank_update_source, "value-only rank refreshes must not remount Kit controls"

rank_render_start = dashboard.index("  function renderRankSections(model) {")
rank_render_end = dashboard.index("\n\n  function compactUrl(", rank_render_start)
rank_render_source = dashboard[rank_render_start:rank_render_end]
assert "let structureChanged = false" in rank_render_source
assert "structureChanged = true" in rank_render_source
assert "if (structureChanged) window.DWRT_UI_KIT?.mountAll(dashboardRankGrid);" in rank_render_source
assert rank_render_source.count("mountAll(") == 1

mount_start = kit.index("  function mountAll(context = document) {")
mount_end = kit.index("\n\n  function mount(context = document)", mount_start)
mount_source = kit[mount_start:mount_end]
assert "const components = collectComponentRoots(context)" in mount_source
assert "matchingRoots(context" not in mount_source
assert "componentRoots(context" not in mount_source
assert "matchingRoots(context, '[data-dwrt-component], .dwrt-kit-tabs, .dwrt-kit-sheet, .dwrt-kit-modal-layer')" in kit

assert 'data-dwrt-component="data-table" data-global-table' in global_config
assert 'data-dwrt-component="select" data-gateway-assignment=' in global_config
assert 'data-dwrt-component="select" data-global-setting=' in global_config
assert 'data-dwrt-component="select" data-port-draft="speed"' in global_config
assert 'data-dwrt-component="select" data-port-draft="duplex"' in global_config
assert 'data-dwrt-component="select" data-bulk-field="speed"' in global_config
assert 'data-dwrt-component="select" data-bulk-field="duplex"' in global_config
assert "gateway.replaceWith(freshGateway);\n        ui.mountAll?.(freshGateway);" in global_config

print("global UI Kit and performance contracts passed")
