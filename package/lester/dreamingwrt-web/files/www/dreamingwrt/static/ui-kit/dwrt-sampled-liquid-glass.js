/*
 * Explicit image-sampling liquid glass for Safari and Chromium.
 *
 * The displacement-map algorithm is adapted from liquid-glass-react 1.1.1.
 * Copyright 2025 Max Rovensky. Licensed under the MIT License.
 */
(function () {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const XLINK_NS = 'http://www.w3.org/1999/xlink';
  const DEFAULTS = Object.freeze({
    mode: 'shader',
    displacementScale: 80,
    baseBlur: 3.2,
    blurAmount: 0,
    saturation: 140,
    aberrationIntensity: 2,
    neutralDensity: 0.06,
    neutralColor: '10 16 25',
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.22)',
    highlight: 0.28,
    cornerRadius: 32,
    overLight: false,
    highlightAngle: 135,
    preserveCenter: false,
    mapResolution: 1,
    trackMotion: true,
    trackScroll: true,
    scrollSettleDelay: 180,
    scrollIdleTimeout: 900
  });
  const WARM_MAP_STORAGE_PREFIX = 'dreamingwrt.sampledGlass.map.v2:';
  const MAP_WORKER_URL = '/static/js/page-glass-map-worker.js?v=20260722-ui-kit-perf-04';
  const MAP_WORKER_TIMEOUT_MS = 5000;
  const MAP_CANCELLED = Symbol('sampled-glass-map-cancelled');
  const mapCache = new Map();
  const mapWorkerRequests = new Map();
  const pendingScrollSettles = new Set();
  let mapWorker = null;
  let mapWorkerDisabled = false;
  let mapWorkerRequestId = 0;
  let instanceCount = 0;
  let scrollSettleHandle = 0;
  let scrollSettleHandleType = '';
  let scrollSettleNextFrame = 0;

  function cancelScrollSettlePump() {
    if (scrollSettleHandle) {
      if (scrollSettleHandleType === 'idle' && typeof window.cancelIdleCallback === 'function') {
        window.cancelIdleCallback(scrollSettleHandle);
      } else {
        window.clearTimeout(scrollSettleHandle);
      }
    }
    scrollSettleHandle = 0;
    scrollSettleHandleType = '';
    if (scrollSettleNextFrame) {
      window.cancelAnimationFrame(scrollSettleNextFrame);
      scrollSettleNextFrame = 0;
    }
  }

  function runScrollSettlePump(deadline) {
    scrollSettleHandle = 0;
    scrollSettleHandleType = '';
    const iterator = pendingScrollSettles.values();
    const next = iterator.next();
    if (!next.done) {
      const renderer = next.value;
      pendingScrollSettles.delete(renderer);
      renderer.settleAfterScroll();
    }
    if (pendingScrollSettles.size && !scrollSettleNextFrame) {
      scrollSettleNextFrame = window.requestAnimationFrame(() => {
        scrollSettleNextFrame = 0;
        scheduleScrollSettlePump();
      });
    }
  }

  function scheduleScrollSettlePump() {
    if (scrollSettleHandle || scrollSettleNextFrame || !pendingScrollSettles.size) return;
    if (typeof window.requestIdleCallback === 'function') {
      scrollSettleHandleType = 'idle';
      scrollSettleHandle = window.requestIdleCallback(runScrollSettlePump, { timeout: DEFAULTS.scrollIdleTimeout });
      return;
    }
    scrollSettleHandleType = 'timeout';
    scrollSettleHandle = window.setTimeout(() => runScrollSettlePump(null), 48);
  }

  function queueScrollSettle(renderer) {
    pendingScrollSettles.add(renderer);
    scheduleScrollSettlePump();
  }

  function cancelScrollSettle(renderer) {
    pendingScrollSettles.delete(renderer);
    if (!pendingScrollSettles.size) cancelScrollSettlePump();
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, Number(value) || 0));
  }

  function roundMetric(value) {
    return Math.round(value * 1000) / 1000;
  }

  function svgNode(name, attributes) {
    const node = document.createElementNS(SVG_NS, name);
    Object.entries(attributes || {}).forEach(([key, value]) => node.setAttribute(key, String(value)));
    return node;
  }

  function setImageHref(node, src) {
    const value = src || '';
    node.setAttribute('href', value);
    node.setAttributeNS(XLINK_NS, 'xlink:href', value);
  }

  function resolveObjectPosition(token, freeSpace) {
    const value = String(token || '50%').toLowerCase();
    if (value === 'left' || value === 'top') return 0;
    if (value === 'center') return freeSpace * 0.5;
    if (value === 'right' || value === 'bottom') return freeSpace;
    if (value.endsWith('%')) return freeSpace * (Number.parseFloat(value) / 100);
    if (value.endsWith('px')) return Number.parseFloat(value);
    return freeSpace * 0.5;
  }

  function parseObjectPosition(value) {
    const tokens = String(value || '50% 50%').trim().split(/\s+/).filter(Boolean);
    const vertical = new Set(['top', 'bottom']);
    const horizontal = new Set(['left', 'right']);
    if (tokens.length === 1) {
      if (vertical.has(tokens[0])) return ['50%', tokens[0]];
      if (horizontal.has(tokens[0])) return [tokens[0], '50%'];
      return [tokens[0] || '50%', '50%'];
    }
    if (vertical.has(tokens[0]) && horizontal.has(tokens[1])) return [tokens[1], tokens[0]];
    return [tokens[0] || '50%', tokens[1] || '50%'];
  }

  function getImageContentBox(media, mediaRect, glassRect, glassScaleX, glassScaleY) {
    const style = window.getComputedStyle(media);
    const borderLeft = Number.parseFloat(style.borderLeftWidth) || 0;
    const borderRight = Number.parseFloat(style.borderRightWidth) || 0;
    const borderTop = Number.parseFloat(style.borderTopWidth) || 0;
    const borderBottom = Number.parseFloat(style.borderBottomWidth) || 0;
    const paddingLeft = Number.parseFloat(style.paddingLeft) || 0;
    const paddingRight = Number.parseFloat(style.paddingRight) || 0;
    const paddingTop = Number.parseFloat(style.paddingTop) || 0;
    const paddingBottom = Number.parseFloat(style.paddingBottom) || 0;
    const mediaScaleX = media.offsetWidth ? mediaRect.width / media.offsetWidth : 1;
    const mediaScaleY = media.offsetHeight ? mediaRect.height / media.offsetHeight : 1;
    const contentWidth = Math.max(1, media.offsetWidth - borderLeft - borderRight - paddingLeft - paddingRight);
    const contentHeight = Math.max(1, media.offsetHeight - borderTop - borderBottom - paddingTop - paddingBottom);

    let renderedWidth = contentWidth;
    let renderedHeight = contentHeight;
    if (media.naturalWidth > 0 && media.naturalHeight > 0 && style.objectFit !== 'fill') {
      const containScale = Math.min(contentWidth / media.naturalWidth, contentHeight / media.naturalHeight);
      const coverScale = Math.max(contentWidth / media.naturalWidth, contentHeight / media.naturalHeight);
      let imageScale = 1;
      if (style.objectFit === 'cover') imageScale = coverScale;
      if (style.objectFit === 'contain') imageScale = containScale;
      if (style.objectFit === 'scale-down') imageScale = Math.min(1, containScale);
      renderedWidth = media.naturalWidth * imageScale;
      renderedHeight = media.naturalHeight * imageScale;
    }

    const [positionX, positionY] = parseObjectPosition(style.objectPosition);
    const offsetX = resolveObjectPosition(positionX, contentWidth - renderedWidth);
    const offsetY = resolveObjectPosition(positionY, contentHeight - renderedHeight);
    const viewportX = mediaRect.left + (borderLeft + paddingLeft + offsetX) * mediaScaleX;
    const viewportY = mediaRect.top + (borderTop + paddingTop + offsetY) * mediaScaleY;
    return {
      sourceX: (viewportX - glassRect.left) / glassScaleX,
      sourceY: (viewportY - glassRect.top) / glassScaleY,
      sourceWidth: (renderedWidth * mediaScaleX) / glassScaleX,
      sourceHeight: (renderedHeight * mediaScaleY) / glassScaleY
    };
  }

  function smoothStep(a, b, value) {
    const t = clamp((value - a) / (b - a), 0, 1);
    return t * t * (3 - 2 * t);
  }

  function roundedRectSdf(x, y, width, height, radius) {
    const qx = Math.abs(x) - width + radius;
    const qy = Math.abs(y) - height + radius;
    return Math.min(Math.max(qx, qy), 0) + Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) - radius;
  }

  function fragmentForMode(mode, x, y) {
    const ix = x - 0.5;
    const iy = y - 0.5;
    const distance = roundedRectSdf(ix, iy, 0.3, 0.2, 0.6);
    if (mode === 'polar') {
      const radius = Math.hypot(ix, iy);
      const angle = Math.atan2(iy, ix) + (1 - Math.min(1, radius * 2)) * 0.35;
      const scale = 0.68 + smoothStep(0.15, 0.72, radius) * 0.32;
      return { x: Math.cos(angle) * radius * scale + 0.5, y: Math.sin(angle) * radius * scale + 0.5 };
    }
    if (mode === 'prominent') {
      const displacement = smoothStep(0.9, -0.08, distance - 0.11);
      const scale = smoothStep(0, 1, displacement) ** 1.45;
      return { x: ix * scale + 0.5, y: iy * scale + 0.5 };
    }
    if (mode === 'standard') {
      const displacement = smoothStep(0.72, 0.02, distance - 0.12);
      const scale = 0.72 + smoothStep(0, 1, displacement) * 0.28;
      return { x: ix * scale + 0.5, y: iy * scale + 0.5 };
    }
    const displacement = smoothStep(0.8, 0, distance - 0.15);
    const scale = smoothStep(0, 1, displacement);
    return { x: ix * scale + 0.5, y: iy * scale + 0.5 };
  }

  function displacementMapKey(width, height, mode, preserveCenter) {
    return `${width}x${height}:${mode}:${preserveCenter ? 'edge' : 'full'}`;
  }

  function readWarmedMap(key) {
    try {
      return window.sessionStorage.getItem(`${WARM_MAP_STORAGE_PREFIX}${key}`) || '';
    } catch (_) {
      return '';
    }
  }

  function persistWarmedMap(key, value) {
    if (!value) return;
    try {
      window.sessionStorage.setItem(`${WARM_MAP_STORAGE_PREFIX}${key}`, value);
    } catch (_) {}
  }

  function finishMapWorkerRequests(result) {
    for (const request of mapWorkerRequests.values()) {
      window.clearTimeout(request.timer);
      request.resolve(result);
    }
    mapWorkerRequests.clear();
  }

  function disableMapWorker(worker) {
    if (worker && mapWorker !== worker) return;
    mapWorker?.terminate();
    mapWorker = null;
    mapWorkerDisabled = true;
    finishMapWorkerRequests(null);
  }

  function stopMapWorker() {
    mapWorker?.terminate();
    mapWorker = null;
    finishMapWorkerRequests(MAP_CANCELLED);
  }

  function ensureMapWorker() {
    if (mapWorker) return mapWorker;
    if (mapWorkerDisabled || typeof window.Worker !== 'function') return null;
    try {
      const worker = new Worker(MAP_WORKER_URL);
      worker.addEventListener('message', event => {
        if (mapWorker !== worker) return;
        const message = event.data || {};
        const id = Number(message.id);
        const request = mapWorkerRequests.get(id);
        if (!request || request.signature !== String(message.signature || '')) return;
        mapWorkerRequests.delete(id);
        window.clearTimeout(request.timer);
        if (message.error || (!message.dataUrl && !(message.blob instanceof Blob))) {
          request.resolve(null);
          disableMapWorker(worker);
          return;
        }
        request.resolve({ blob: message.blob, dataUrl: String(message.dataUrl || ''), execution: 'worker' });
      });
      worker.addEventListener('error', event => {
        event.preventDefault?.();
        disableMapWorker(worker);
      });
      worker.addEventListener('messageerror', () => disableMapWorker(worker));
      mapWorker = worker;
      return worker;
    } catch (_) {
      mapWorkerDisabled = true;
      return null;
    }
  }

  function requestMapFromWorker(width, height, mode, preserveCenter, signature) {
    const worker = ensureMapWorker();
    if (!worker) return Promise.resolve(null);
    const id = ++mapWorkerRequestId;
    return new Promise(resolve => {
      const timer = window.setTimeout(() => {
        if (!mapWorkerRequests.has(id)) return;
        mapWorkerRequests.delete(id);
        resolve(null);
        disableMapWorker(worker);
      }, MAP_WORKER_TIMEOUT_MS);
      mapWorkerRequests.set(id, { resolve, signature, timer });
      try {
        worker.postMessage({
          task: 'uniform',
          id,
          mapWidth: width,
          mapHeight: height,
          mode,
          preserveCenter,
          signature
        });
      } catch (_) {
        mapWorkerRequests.delete(id);
        window.clearTimeout(timer);
        resolve(null);
        disableMapWorker(worker);
      }
    });
  }

  function blobDataUrl(blob) {
    if (!blob) return Promise.resolve('');
    return new Promise(resolve => {
      const reader = new FileReader();
      reader.addEventListener('load', () => resolve(String(reader.result || '')), { once: true });
      reader.addEventListener('error', () => resolve(''), { once: true });
      reader.readAsDataURL(blob);
    });
  }

  function renderMapFallback(width, height, mode, preserveCenter) {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    if (!context) return Promise.resolve(null);
    canvas.width = width;
    canvas.height = height;
    const vectors = new Float32Array(width * height * 2);
    let maxScale = 1;
    let vectorIndex = 0;
    for (let y = 0; y < height; y += 1) {
      for (let x = 0; x < width; x += 1) {
        const position = fragmentForMode(mode, x / width, y / height);
        const dx = position.x * width - x;
        const dy = position.y * height - y;
        vectors[vectorIndex] = dx;
        vectors[vectorIndex + 1] = dy;
        vectorIndex += 2;
        maxScale = Math.max(maxScale, Math.abs(dx), Math.abs(dy));
      }
    }
    const imageData = context.createImageData(width, height);
    vectorIndex = 0;
    for (let y = 0; y < height; y += 1) {
      for (let x = 0; x < width; x += 1) {
        const edgeDistance = Math.min(x, y, width - x - 1, height - y - 1);
        const seamFactor = Math.min(1, edgeDistance / 2);
        const shortEdge = Math.max(1, Math.min(width, height));
        const normalizedEdge = edgeDistance / shortEdge;
        const centerFactor = preserveCenter ? 1 - smoothStep(0.035, 0.24, normalizedEdge) : 1;
        const dx = vectors[vectorIndex] * seamFactor * centerFactor;
        const dy = vectors[vectorIndex + 1] * seamFactor * centerFactor;
        vectorIndex += 2;
        const pixelIndex = (y * width + x) * 4;
        imageData.data[pixelIndex] = clamp((dx / maxScale + 0.5) * 255, 0, 255);
        imageData.data[pixelIndex + 1] = clamp((dy / maxScale + 0.5) * 255, 0, 255);
        imageData.data[pixelIndex + 2] = imageData.data[pixelIndex + 1];
        imageData.data[pixelIndex + 3] = 255;
      }
    }
    context.putImageData(imageData, 0, 0);
    return new Promise(resolve => canvas.toBlob(blob => {
      if (!blob) return resolve(null);
      blobDataUrl(blob).then(dataUrl => resolve({ blob, dataUrl, execution: 'main-thread-fallback' }));
    }, 'image/png'));
  }

  function generateDisplacementMap(width, height, mode, preserveCenter, config) {
    const w = Math.max(1, Math.round(width));
    const h = Math.max(1, Math.round(height));
    const key = displacementMapKey(w, h, mode, preserveCenter);
    if (mapCache.has(key)) {
      const cached = mapCache.get(key);
      if (config?.persist) cached.promise.then(result => persistWarmedMap(key, result?.dataUrl));
      return cached.promise;
    }
    const warmed = readWarmedMap(key);
    if (warmed) {
      const result = { url: warmed, dataUrl: warmed, execution: 'warm-cache' };
      mapCache.set(key, { promise: Promise.resolve(result) });
      return Promise.resolve(result);
    }
    const entry = { promise: null };
    entry.promise = requestMapFromWorker(w, h, mode, preserveCenter, key)
      .then(result => result === MAP_CANCELLED ? result : (result || renderMapFallback(w, h, mode, preserveCenter)))
      .then(async result => {
        if (!result || result === MAP_CANCELLED) {
          mapCache.delete(key);
          return { url: '', dataUrl: '', execution: 'unavailable' };
        }
        const dataUrl = result.dataUrl || await blobDataUrl(result.blob);
        const map = { url: dataUrl, dataUrl, execution: result.execution };
        if (config?.persist) persistWarmedMap(key, dataUrl);
        return map;
      });
    mapCache.set(key, entry);
    if (mapCache.size > 10) mapCache.delete(mapCache.keys().next().value);
    return entry.promise;
  }

  class SampledLiquidGlass {
    constructor(config) {
      if (!config || !config.root) throw new Error('Sampled liquid glass requires a root element.');
      this.root = config.root;
      this.options = { ...DEFAULTS, ...(config.options || {}) };
      this.current = { media: config.backgroundElement || null, src: config.backgroundSrc || '' };
      this.incoming = { media: null, src: '' };
      this.observedMedia = new Set();
      this.width = 0;
      this.height = 0;
      this.measureFrame = 0;
      this.motionFrame = 0;
      this.motionDeadline = 0;
      this.transitionTimer = 0;
      this.mapTimer = 0;
      this.mapRequestToken = 0;
      this.pendingMapKey = '';
      this.scrollTimer = 0;
      this.scrollRevealTimer = 0;
      this.scrollSuspended = false;
      this.scrollEventCount = 0;
      this.scrollSettleCount = 0;
      this.scrollPositions = new WeakMap();
      this.glassScaleX = 1;
      this.glassScaleY = 1;
      this.filterPadding = 0;
      this.mapReady = false;
      this.externalMapUrl = '';
      this.externalMapLabel = '';
      this.ready = false;
      this.destroyed = false;
      this.layerRepairQueued = false;
      this.trackMotion = this.options.trackMotion !== false;
      this.trackScroll = this.options.trackScroll !== false;
      this.id = `dwrt-sampled-glass-${Date.now().toString(36)}-${++instanceCount}`;
      this.scheduleMeasure = this.scheduleMeasure.bind(this);
      this.syncDuringMotion = this.syncDuringMotion.bind(this);
      this.handleScroll = this.handleScroll.bind(this);
      this.settleAfterScroll = this.settleAfterScroll.bind(this);
      this.buildSvg();
      this.bind();
      this.update(this.options);
      this.setBackground(this.current.media, this.current.src);
      if (this.trackMotion) this.syncDuringMotion(1100);
      else this.scheduleMeasure();
    }

    buildSvg() {
      const svg = svgNode('svg', {
        class: 'dwrt-sampled-glass-media',
        preserveAspectRatio: 'none',
        'aria-hidden': 'true'
      });
      const defs = svgNode('defs');
      const filter = svgNode('filter', {
        id: this.id,
        x: 0,
        y: 0,
        width: 1,
        height: 1,
        filterUnits: 'userSpaceOnUse',
        primitiveUnits: 'userSpaceOnUse',
        colorInterpolationFilters: 'sRGB'
      });
      this.blurNode = svgNode('feGaussianBlur', { in: 'SourceGraphic', stdDeviation: 4, edgeMode: 'duplicate', result: 'BLURRED' });
      this.saturationNode = svgNode('feColorMatrix', { in: 'BLURRED', type: 'saturate', values: 1.4, result: 'FROSTED' });
      this.mapNode = svgNode('feImage', { x: 0, y: 0, width: 1, height: 1, preserveAspectRatio: 'none', result: 'DISPLACEMENT_MAP' });
      this.redDisplacement = svgNode('feDisplacementMap', { in: 'FROSTED', in2: 'DISPLACEMENT_MAP', scale: 80, xChannelSelector: 'R', yChannelSelector: 'B', result: 'RED_DISPLACED' });
      this.redChannel = svgNode('feColorMatrix', { in: 'RED_DISPLACED', type: 'matrix', values: '1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0', result: 'RED_CHANNEL' });
      this.greenDisplacement = svgNode('feDisplacementMap', { in: 'FROSTED', in2: 'DISPLACEMENT_MAP', scale: 72, xChannelSelector: 'R', yChannelSelector: 'B', result: 'GREEN_DISPLACED' });
      this.greenChannel = svgNode('feColorMatrix', { in: 'GREEN_DISPLACED', type: 'matrix', values: '0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0', result: 'GREEN_CHANNEL' });
      this.blueDisplacement = svgNode('feDisplacementMap', { in: 'FROSTED', in2: 'DISPLACEMENT_MAP', scale: 64, xChannelSelector: 'R', yChannelSelector: 'B', result: 'BLUE_DISPLACED' });
      this.blueChannel = svgNode('feColorMatrix', { in: 'BLUE_DISPLACED', type: 'matrix', values: '0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0', result: 'BLUE_CHANNEL' });
      this.greenBlueBlend = svgNode('feBlend', { in: 'GREEN_CHANNEL', in2: 'BLUE_CHANNEL', mode: 'screen', result: 'GB_COMBINED' });
      this.rgbBlend = svgNode('feBlend', { in: 'RED_CHANNEL', in2: 'GB_COMBINED', mode: 'screen', result: 'RGB_COMBINED' });
      this.finalBlur = svgNode('feGaussianBlur', { in: 'RGB_COMBINED', stdDeviation: 0.3 });
      [
        this.blurNode, this.saturationNode, this.mapNode,
        this.redDisplacement, this.redChannel,
        this.greenDisplacement, this.greenChannel,
        this.blueDisplacement, this.blueChannel,
        this.greenBlueBlend, this.rgbBlend, this.finalBlur
      ].forEach(node => filter.appendChild(node));
      defs.appendChild(filter);
      this.currentNode = svgNode('image', { class: 'dwrt-sampled-glass-source is-current', preserveAspectRatio: 'none', filter: `url(#${this.id})` });
      this.incomingNode = svgNode('image', { class: 'dwrt-sampled-glass-source is-incoming', preserveAspectRatio: 'none', filter: `url(#${this.id})`, opacity: 0 });
      svg.append(defs, this.currentNode, this.incomingNode);
      this.svg = svg;
      this.filter = filter;
      this.scrollFallback = document.createElement('span');
      this.scrollFallback.className = 'dwrt-sampled-glass-scroll-fallback';
      this.scrollFallback.setAttribute('aria-hidden', 'true');
      this.absorption = document.createElement('span');
      this.absorption.className = 'dwrt-sampled-glass-absorption';
      this.absorption.setAttribute('aria-hidden', 'true');
      this.rimScreen = document.createElement('span');
      this.rimScreen.className = 'dwrt-sampled-glass-rim is-screen';
      this.rimScreen.setAttribute('aria-hidden', 'true');
      this.rimOverlay = document.createElement('span');
      this.rimOverlay.className = 'dwrt-sampled-glass-rim is-overlay';
      this.rimOverlay.setAttribute('aria-hidden', 'true');
      this.root.prepend(this.rimOverlay);
      this.root.prepend(this.rimScreen);
      this.root.prepend(this.absorption);
      this.root.prepend(svg);
      this.root.prepend(this.scrollFallback);
      this.root.classList.add('dwrt-sampled-glass');
      this.root.dataset.glassRenderer = 'svg-explicit-sampling';
      this.root.dataset.glassScrollStrategy = 'material-fallback-idle-queue';
      this.root.dataset.glassScrollState = 'idle';
      this.syncContentLayers();
    }

    bind() {
      this.resizeObserver = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(this.scheduleMeasure);
      this.resizeObserver?.observe(this.root);
      if (this.trackScroll) document.addEventListener('scroll', this.handleScroll, { capture: true, passive: true });
      window.addEventListener('resize', this.scheduleMeasure, { passive: true });
      window.addEventListener('orientationchange', this.scheduleMeasure, { passive: true });
      window.visualViewport?.addEventListener('resize', this.scheduleMeasure, { passive: true });
      if (this.trackScroll) window.visualViewport?.addEventListener('scroll', this.handleScroll, { passive: true });
      if (this.trackMotion) {
        this.root.addEventListener('transitionrun', this.syncDuringMotion);
        this.root.addEventListener('transitionend', this.scheduleMeasure);
        this.root.addEventListener('transitioncancel', this.scheduleMeasure);
        this.root.addEventListener('animationstart', this.syncDuringMotion);
        this.root.addEventListener('animationend', this.scheduleMeasure);
      }
      if (typeof MutationObserver !== 'undefined') {
        this.layerObserver = new MutationObserver(() => {
          if (this.destroyed || this.layerRepairQueued) return;
          this.layerRepairQueued = true;
          queueMicrotask(() => {
            this.layerRepairQueued = false;
            if (this.destroyed || !this.root.isConnected) return;
            this.ensureLayers();
            this.syncContentLayers();
            this.scheduleMeasure();
          });
        });
        this.layerObserver.observe(this.root, { childList: true });
      }
    }

    observeMedia(media) {
      if (!media || this.observedMedia.has(media)) return;
      this.observedMedia.add(media);
      this.resizeObserver?.observe(media);
      media.addEventListener('load', this.scheduleMeasure);
      if (this.trackMotion) {
        media.addEventListener('transitionrun', this.syncDuringMotion);
        media.addEventListener('transitionend', this.scheduleMeasure);
        media.addEventListener('transitioncancel', this.scheduleMeasure);
      }
    }

    update(options) {
      const previousMode = this.options.mode;
      const previousPreserveCenter = Boolean(this.options.preserveCenter);
      const previousMapResolution = clamp(this.options.mapResolution, 0.125, 1);
      this.options = { ...this.options, ...(options || {}) };
      const displacement = clamp(this.options.displacementScale, 0, 180);
      const aberration = clamp(this.options.aberrationIntensity, 0, 8);
      const directionSign = this.options.mode === 'shader' ? 1 : -1;
      const redScale = displacement * directionSign;
      const greenScale = displacement * (directionSign - aberration * 0.05);
      const blueScale = displacement * (directionSign - aberration * 0.1);
      const baseBlur = clamp(this.options.baseBlur, 0, 24);
      const blur = (this.options.overLight ? Math.max(baseBlur, 8) : baseBlur) + clamp(this.options.blurAmount, 0, 1) * 32;
      const neutralDensity = clamp(this.options.neutralDensity + (this.options.overLight ? 0.08 : 0), 0, 0.35);
      const neutralColor = /^\s*\d{1,3}\s+\d{1,3}\s+\d{1,3}\s*$/.test(String(this.options.neutralColor || ''))
        ? String(this.options.neutralColor).trim()
        : DEFAULTS.neutralColor;
      // SVG displacement can pull pixels from half the configured scale beyond
      // the card bounds. Keep that source area inside the filter region so
      // Chromium never substitutes transparent pixels at rounded edges.
      this.filterPadding = Math.ceil(
        Math.max(Math.abs(redScale), Math.abs(greenScale), Math.abs(blueScale)) * 0.5 +
        blur * 2 +
        2
      );
      this.blurNode.setAttribute('stdDeviation', String(roundMetric(blur)));
      this.saturationNode.setAttribute('values', String(clamp(this.options.saturation, 70, 220) / 100));
      this.redDisplacement.setAttribute('scale', String(roundMetric(redScale)));
      this.greenDisplacement.setAttribute('scale', String(roundMetric(greenScale)));
      this.blueDisplacement.setAttribute('scale', String(roundMetric(blueScale)));
      this.finalBlur.setAttribute('stdDeviation', String(Math.max(0.1, 0.5 - aberration * 0.1)));
      this.root.style.setProperty('--sampled-glass-radius', `${clamp(this.options.cornerRadius, 0, 80)}px`);
      this.root.style.setProperty('--sampled-glass-neutral-density', String(roundMetric(neutralDensity)));
      this.root.style.setProperty('--sampled-glass-neutral-color', neutralColor);
      this.root.style.setProperty('--sampled-glass-border-width', `${clamp(this.options.borderWidth, 0, 4)}px`);
      this.root.style.setProperty('--sampled-glass-border-color', String(this.options.borderColor || DEFAULTS.borderColor));
      this.root.style.setProperty('--sampled-glass-highlight', String(clamp(this.options.highlight, 0, 1)));
      this.root.style.setProperty('--sampled-glass-base-blur', `${roundMetric(baseBlur)}px`);
      this.root.style.setProperty('--sampled-glass-saturation', `${roundMetric(clamp(this.options.saturation, 70, 220))}%`);
      const highlightAngle = Number(this.options.highlightAngle);
      this.root.style.setProperty('--sampled-glass-highlight-angle', `${Number.isFinite(highlightAngle) ? highlightAngle : 135}deg`);
      this.root.classList.toggle('is-over-light', Boolean(this.options.overLight));
      this.root.dataset.glassScales = `${roundMetric(redScale)}/${roundMetric(greenScale)}/${roundMetric(blueScale)}`;
      this.root.dataset.glassFilterPadding = String(this.filterPadding);
      this.root.dataset.glassBaseBlur = String(roundMetric(baseBlur));
      this.root.dataset.glassNeutralDensity = String(roundMetric(neutralDensity));
      if (this.width && this.height &&
          (previousMode !== this.options.mode ||
           previousPreserveCenter !== Boolean(this.options.preserveCenter) ||
           previousMapResolution !== clamp(this.options.mapResolution, 0.125, 1))) {
        this.scheduleMapUpdate(0);
      }
      this.scheduleMeasure();
    }

    setBackground(media, src) {
      window.clearTimeout(this.transitionTimer);
      this.current = { media: media || null, src: src || media?.currentSrc || media?.getAttribute('src') || '' };
      this.incoming = { media: null, src: '' };
      this.observeMedia(this.current.media);
      setImageHref(this.currentNode, this.current.src);
      setImageHref(this.incomingNode, '');
      this.currentNode.style.transition = 'none';
      this.incomingNode.style.transition = 'none';
      this.currentNode.style.opacity = '1';
      this.incomingNode.style.opacity = '0';
      this.root.dataset.backgroundSrc = this.current.src;
      this.scheduleMeasure();
    }

    transitionBackground(media, src, duration) {
      if (!media || !src || src === this.current.src) return;
      window.clearTimeout(this.transitionTimer);
      const milliseconds = Math.max(0, Number(duration) || 0);
      this.incoming = { media, src };
      this.observeMedia(media);
      setImageHref(this.incomingNode, src);
      this.measure();
      this.currentNode.style.transition = 'none';
      this.incomingNode.style.transition = 'none';
      this.currentNode.style.opacity = '1';
      this.incomingNode.style.opacity = '0';
      void this.incomingNode.getBoundingClientRect();
      const easing = 'cubic-bezier(0.22, 1, 0.36, 1)';
      this.incomingNode.style.transition = `opacity ${milliseconds}ms ${easing}`;
      this.incomingNode.style.opacity = '1';
      this.transitionTimer = window.setTimeout(() => {
        this.current = { ...this.incoming };
        this.incoming = { media: null, src: '' };
        setImageHref(this.currentNode, this.current.src);
        this.currentNode.style.transition = 'none';
        this.currentNode.style.opacity = '1';
        this.incomingNode.style.transition = 'none';
        this.incomingNode.style.opacity = '0';
        setImageHref(this.incomingNode, '');
        this.root.dataset.backgroundSrc = this.current.src;
        this.scheduleMeasure();
      }, milliseconds + 34);
      if (this.trackMotion) this.syncDuringMotion(milliseconds + 120);
      else this.scheduleMeasure();
    }

    sourceBox(media) {
      if (!media) return null;
      const glassRect = this.root.getBoundingClientRect();
      const mediaRect = media.getBoundingClientRect();
      const width = Math.max(1, this.root.offsetWidth);
      const height = Math.max(1, this.root.offsetHeight);
      const glassScaleX = glassRect.width / width || 1;
      const glassScaleY = glassRect.height / height || 1;
      this.glassScaleX = glassScaleX;
      this.glassScaleY = glassScaleY;
      if (media instanceof HTMLImageElement) return getImageContentBox(media, mediaRect, glassRect, glassScaleX, glassScaleY);
      return {
        sourceX: (mediaRect.left - glassRect.left) / glassScaleX,
        sourceY: (mediaRect.top - glassRect.top) / glassScaleY,
        sourceWidth: mediaRect.width / glassScaleX,
        sourceHeight: mediaRect.height / glassScaleY
      };
    }

    applySourceGeometry(node, source) {
      if (!node || !source) return;
      node.setAttribute('x', String(roundMetric(source.sourceX)));
      node.setAttribute('y', String(roundMetric(source.sourceY)));
      node.setAttribute('width', String(roundMetric(source.sourceWidth)));
      node.setAttribute('height', String(roundMetric(source.sourceHeight)));
    }

    ensureLayers() {
      if (this.svg.parentElement === this.root &&
          this.scrollFallback.parentElement === this.root &&
          this.absorption.parentElement === this.root &&
          this.rimScreen.parentElement === this.root &&
          this.rimOverlay.parentElement === this.root) return false;
      this.root.prepend(this.rimOverlay);
      this.root.prepend(this.rimScreen);
      this.root.prepend(this.absorption);
      this.root.prepend(this.svg);
      this.root.prepend(this.scrollFallback);
      this.syncContentLayers();
      return true;
    }

    syncContentLayers() {
      Array.from(this.root.children).forEach(node => {
        if (node === this.svg || node === this.scrollFallback || node === this.absorption || node === this.rimScreen || node === this.rimOverlay) return;
        node.classList.add('dwrt-sampled-glass-content-layer');
        node.classList.toggle('is-static', window.getComputedStyle(node).position === 'static');
      });
    }

    async updateMap() {
      if (this.externalMapUrl) {
        this.mapRequestToken += 1;
        this.pendingMapKey = '';
        setImageHref(this.mapNode, this.externalMapUrl);
        this.mapNode.setAttribute('width', String(this.width));
        this.mapNode.setAttribute('height', String(this.height));
        this.root.dataset.glassMapSize = `${this.width}x${this.height}`;
        this.root.dataset.glassMapResolution = 'shared';
        this.root.dataset.glassMapLabel = this.externalMapLabel || 'external';
        this.mapReady = true;
        return;
      }
      const resolution = clamp(this.options.mapResolution, 0.125, 1);
      const mapWidth = Math.max(1, Math.round(this.width * resolution));
      const mapHeight = Math.max(1, Math.round(this.height * resolution));
      const key = displacementMapKey(mapWidth, mapHeight, this.options.mode, Boolean(this.options.preserveCenter));
      if (this.pendingMapKey === key) return;
      const requestToken = ++this.mapRequestToken;
      this.pendingMapKey = key;
      const map = await generateDisplacementMap(mapWidth, mapHeight, this.options.mode, Boolean(this.options.preserveCenter));
      if (this.destroyed || requestToken !== this.mapRequestToken || this.externalMapUrl || this.pendingMapKey !== key) return;
      this.pendingMapKey = '';
      setImageHref(this.mapNode, map.url);
      this.mapNode.setAttribute('width', String(this.width));
      this.mapNode.setAttribute('height', String(this.height));
      this.root.dataset.glassMapSize = `${mapWidth}x${mapHeight}`;
      this.root.dataset.glassMapResolution = String(resolution);
      this.root.dataset.glassMapExecution = map.execution;
      this.mapReady = Boolean(map.url);
    }

    setDisplacementMap(mapUrl, label) {
      this.externalMapUrl = String(mapUrl || '');
      this.externalMapLabel = String(label || 'external');
      this.mapRequestToken += 1;
      this.pendingMapKey = '';
      this.mapReady = false;
      window.clearTimeout(this.mapTimer);
      this.mapTimer = 0;
      this.updateMap();
    }

    clearDisplacementMap() {
      if (!this.externalMapUrl) return;
      this.externalMapUrl = '';
      this.externalMapLabel = '';
      this.mapRequestToken += 1;
      this.pendingMapKey = '';
      this.mapReady = false;
      this.scheduleMapUpdate(0);
    }

    scheduleMapUpdate(delay = 96) {
      this.mapNode.setAttribute('width', String(this.width));
      this.mapNode.setAttribute('height', String(this.height));
      if (!this.mapReady) {
        this.updateMap();
        return;
      }
      window.clearTimeout(this.mapTimer);
      this.mapTimer = window.setTimeout(() => {
        this.mapTimer = 0;
        if (!this.destroyed) this.updateMap();
      }, delay);
    }

    measure() {
      if (this.destroyed || !this.root.isConnected) return;
      this.ensureLayers();
      const width = Math.max(1, Math.round(this.root.offsetWidth));
      const height = Math.max(1, Math.round(this.root.offsetHeight));
      const sizeChanged = width !== this.width || height !== this.height;
      this.width = width;
      this.height = height;
      this.svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
      const filterPadding = Math.max(0, Number(this.filterPadding) || 0);
      this.filter.setAttribute('x', String(-filterPadding));
      this.filter.setAttribute('y', String(-filterPadding));
      this.filter.setAttribute('width', String(width + filterPadding * 2));
      this.filter.setAttribute('height', String(height + filterPadding * 2));
      if (sizeChanged) this.scheduleMapUpdate();
      this.applySourceGeometry(this.currentNode, this.sourceBox(this.current.media));
      if (this.incoming.media) this.applySourceGeometry(this.incomingNode, this.sourceBox(this.incoming.media));
      this.currentNode.removeAttribute('transform');
      this.incomingNode.removeAttribute('transform');
      this.primeScrollPositions();
      const ready = Boolean(this.current.src && this.current.media && this.current.media.complete && this.current.media.naturalWidth);
      this.root.classList.toggle('sampled-glass-ready', ready);
      this.root.dataset.glassReady = ready ? 'true' : 'false';
      if (ready && !this.ready) this.root.dispatchEvent(new CustomEvent('dwrt:sampled-glass-ready', { bubbles: false }));
      this.ready = ready;
    }

    scheduleMeasure() {
      if (this.destroyed || this.measureFrame || this.scrollSuspended) return;
      this.measureFrame = requestAnimationFrame(() => {
        this.measureFrame = 0;
        this.measure();
      });
    }

    scrollAffectsRoot(event) {
      const target = event?.target;
      if (!target ||
          target === document ||
          target === window ||
          target === document.documentElement ||
          target === document.body ||
          target === document.scrollingElement ||
          target === window.visualViewport) return true;
      if (!(target instanceof Element)) return true;
      return target !== this.root && target.contains(this.root);
    }

    scrollPosition(target) {
      if (target === window.visualViewport) {
        return {
          x: Number(window.visualViewport?.pageLeft ?? window.scrollX) || 0,
          y: Number(window.visualViewport?.pageTop ?? window.scrollY) || 0
        };
      }
      if (!target ||
          target === document ||
          target === window ||
          target === document.documentElement ||
          target === document.body ||
          target === document.scrollingElement) {
        return { x: window.scrollX || 0, y: window.scrollY || 0 };
      }
      return {
        x: Number(target.scrollLeft) || 0,
        y: Number(target.scrollTop) || 0
      };
    }

    primeScrollPositions() {
      const viewportPosition = { x: window.scrollX || 0, y: window.scrollY || 0 };
      [document, window, document.documentElement, document.body, document.scrollingElement]
        .filter(Boolean)
        .forEach(target => this.scrollPositions.set(target, viewportPosition));
      if (window.visualViewport) {
        this.scrollPositions.set(window.visualViewport, this.scrollPosition(window.visualViewport));
      }
      let ancestor = this.root.parentElement;
      while (ancestor) {
        this.scrollPositions.set(ancestor, this.scrollPosition(ancestor));
        ancestor = ancestor.parentElement;
      }
    }

    handleScroll(event) {
      if (!this.scrollAffectsRoot(event)) return;
      cancelScrollSettle(this);
      window.clearTimeout(this.scrollRevealTimer);
      this.scrollRevealTimer = 0;
      this.root.classList.remove('is-scroll-revealing');
      if (this.measureFrame) {
        cancelAnimationFrame(this.measureFrame);
        this.measureFrame = 0;
      }
      const target = event?.target || document;
      const position = this.scrollPosition(target);
      const previous = this.scrollPositions.get(target);
      this.scrollPositions.set(target, position);
      if (!previous) this.primeScrollPositions();
      this.scrollSuspended = true;
      this.scrollEventCount += 1;
      this.root.dataset.glassScrollEvents = String(this.scrollEventCount);
      this.root.dataset.glassScrollState = 'tracking';
      this.root.classList.add('is-scroll-tracking');
      window.clearTimeout(this.scrollTimer);
      const settleDelay = clamp(this.options.scrollSettleDelay, 120, 420);
      this.scrollTimer = window.setTimeout(() => {
        this.scrollTimer = 0;
        if (this.destroyed || !this.root.isConnected) return;
        queueScrollSettle(this);
      }, settleDelay);
    }

    settleAfterScroll() {
      if (this.destroyed || !this.root.isConnected || !this.scrollSuspended) return;
      this.measure();
      this.scrollSuspended = false;
      this.scrollSettleCount += 1;
      this.root.dataset.glassScrollSettles = String(this.scrollSettleCount);
      this.root.dataset.glassScrollState = 'revealing';
      this.root.classList.add('is-scroll-revealing');
      this.root.classList.remove('is-scroll-tracking');
      this.scrollRevealTimer = window.setTimeout(() => {
        this.scrollRevealTimer = 0;
        if (!this.destroyed) {
          this.root.classList.remove('is-scroll-revealing');
          this.root.dataset.glassScrollState = 'idle';
        }
      }, 150);
    }

    syncDuringMotion(duration) {
      const requestedDuration = typeof duration === 'number' ? duration : 420;
      this.motionDeadline = Math.max(this.motionDeadline, performance.now() + requestedDuration);
      if (this.motionFrame) return;
      const tick = () => {
        if (!this.scrollSuspended) this.measure();
        if (performance.now() < this.motionDeadline) {
          this.motionFrame = requestAnimationFrame(tick);
        } else {
          this.motionFrame = 0;
        }
      };
      this.motionFrame = requestAnimationFrame(tick);
    }

    destroy() {
      this.destroyed = true;
      this.mapRequestToken += 1;
      this.pendingMapKey = '';
      window.clearTimeout(this.transitionTimer);
      window.clearTimeout(this.mapTimer);
      window.clearTimeout(this.scrollTimer);
      window.clearTimeout(this.scrollRevealTimer);
      cancelScrollSettle(this);
      this.resizeObserver?.disconnect();
      this.layerObserver?.disconnect();
      if (this.trackScroll) document.removeEventListener('scroll', this.handleScroll, true);
      window.removeEventListener('resize', this.scheduleMeasure);
      window.removeEventListener('orientationchange', this.scheduleMeasure);
      window.visualViewport?.removeEventListener('resize', this.scheduleMeasure);
      if (this.trackScroll) window.visualViewport?.removeEventListener('scroll', this.handleScroll);
      if (this.trackMotion) {
        this.root.removeEventListener('transitionrun', this.syncDuringMotion);
        this.root.removeEventListener('transitionend', this.scheduleMeasure);
        this.root.removeEventListener('transitioncancel', this.scheduleMeasure);
        this.root.removeEventListener('animationstart', this.syncDuringMotion);
        this.root.removeEventListener('animationend', this.scheduleMeasure);
      }
      this.observedMedia.forEach(media => {
        media.removeEventListener('load', this.scheduleMeasure);
        if (this.trackMotion) {
          media.removeEventListener('transitionrun', this.syncDuringMotion);
          media.removeEventListener('transitionend', this.scheduleMeasure);
          media.removeEventListener('transitioncancel', this.scheduleMeasure);
        }
      });
      if (this.measureFrame) cancelAnimationFrame(this.measureFrame);
      if (this.motionFrame) cancelAnimationFrame(this.motionFrame);
      this.svg.remove();
      this.scrollFallback.remove();
      this.absorption.remove();
      this.rimScreen.remove();
      this.rimOverlay.remove();
      this.root.querySelectorAll(':scope > .dwrt-sampled-glass-content-layer').forEach(node => {
        node.classList.remove('dwrt-sampled-glass-content-layer', 'is-static');
      });
      this.root.classList.remove('dwrt-sampled-glass', 'sampled-glass-ready', 'is-scroll-tracking', 'is-scroll-revealing');
      [
        'glassRenderer', 'glassScales', 'glassFilterPadding', 'glassBaseBlur', 'glassNeutralDensity',
        'glassMapSize', 'glassMapResolution', 'glassReady', 'backgroundSrc',
        'glassMapLabel', 'glassMapExecution', 'glassScrollStrategy', 'glassScrollState', 'glassScrollEvents', 'glassScrollSettles'
      ].forEach(key => delete this.root.dataset[key]);
      [
        '--sampled-glass-radius', '--sampled-glass-neutral-density',
        '--sampled-glass-neutral-color', '--sampled-glass-border-width',
        '--sampled-glass-border-color', '--sampled-glass-highlight',
        '--sampled-glass-highlight-angle', '--sampled-glass-base-blur',
        '--sampled-glass-saturation'
      ].forEach(name => this.root.style.removeProperty(name));
    }
  }

  async function prewarm(config) {
    const options = { ...DEFAULTS, ...(config || {}) };
    const resolution = clamp(options.mapResolution, 0.125, 1);
    const width = Math.max(1, Math.round((Number(options.width) || 1) * resolution));
    const height = Math.max(1, Math.round((Number(options.height) || 1) * resolution));
    const map = await generateDisplacementMap(width, height, options.mode, Boolean(options.preserveCenter), { persist: true });
    return {
      key: displacementMapKey(width, height, options.mode, Boolean(options.preserveCenter)),
      width,
      height,
      ready: Boolean(map.url)
    };
  }

  window.DWRTSampledLiquidGlass = {
    defaults: DEFAULTS,
    create(config) {
      return new SampledLiquidGlass(config);
    },
    generateDisplacementMap,
    prewarm
  };
  window.addEventListener('pagehide', stopMapWorker);
})();
