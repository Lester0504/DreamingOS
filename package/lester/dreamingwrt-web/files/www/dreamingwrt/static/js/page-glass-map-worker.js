(() => {
  'use strict';

  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

  function pageGlassFragment(x, y) {
    const ix = x - 0.5;
    const iy = y - 0.5;
    const radius = 0.6;
    const qx = Math.abs(ix) - 0.3 + radius;
    const qy = Math.abs(iy) - 0.2 + radius;
    const distance = Math.min(Math.max(qx, qy), 0) + Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) - radius;
    const smooth = (a, b, value) => {
      const t = clamp((value - a) / (b - a), 0, 1);
      return t * t * (3 - 2 * t);
    };
    const displacement = smooth(0.8, 0, distance - 0.15);
    const scale = smooth(0, 1, displacement);
    return { x: ix * scale + 0.5, y: iy * scale + 0.5 };
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

  function renderUniformDisplacementMap(mapWidth, mapHeight, mode, preserveCenter) {
    const canvas = new OffscreenCanvas(mapWidth, mapHeight);
    const context = canvas.getContext('2d');
    if (!context) throw new Error('2d_context_unavailable');
    const vectors = new Float32Array(mapWidth * mapHeight * 2);
    let maxScale = 1;
    let vectorIndex = 0;
    for (let y = 0; y < mapHeight; y += 1) {
      for (let x = 0; x < mapWidth; x += 1) {
        const position = fragmentForMode(mode, x / mapWidth, y / mapHeight);
        const dx = position.x * mapWidth - x;
        const dy = position.y * mapHeight - y;
        vectors[vectorIndex] = dx;
        vectors[vectorIndex + 1] = dy;
        vectorIndex += 2;
        maxScale = Math.max(maxScale, Math.abs(dx), Math.abs(dy));
      }
    }
    const image = context.createImageData(mapWidth, mapHeight);
    vectorIndex = 0;
    for (let y = 0; y < mapHeight; y += 1) {
      for (let x = 0; x < mapWidth; x += 1) {
        const edgeDistance = Math.min(x, y, mapWidth - x - 1, mapHeight - y - 1);
        const seamFactor = Math.min(1, edgeDistance / 2);
        const shortEdge = Math.max(1, Math.min(mapWidth, mapHeight));
        const normalizedEdge = edgeDistance / shortEdge;
        const centerFactor = preserveCenter ? 1 - smoothStep(0.035, 0.24, normalizedEdge) : 1;
        const dx = vectors[vectorIndex] * seamFactor * centerFactor;
        const dy = vectors[vectorIndex + 1] * seamFactor * centerFactor;
        vectorIndex += 2;
        const target = (y * mapWidth + x) * 4;
        image.data[target] = clamp((dx / maxScale + 0.5) * 255, 0, 255);
        image.data[target + 1] = clamp((dy / maxScale + 0.5) * 255, 0, 255);
        image.data[target + 2] = image.data[target + 1];
        image.data[target + 3] = 255;
      }
    }
    context.putImageData(image, 0, 0);
    return canvas.convertToBlob({ type: 'image/png' });
  }

  function renderDisplacementMap(mapWidth, mapHeight, scaledRects) {
    const canvas = new OffscreenCanvas(mapWidth, mapHeight);
    const context = canvas.getContext('2d');
    if (!context) throw new Error('2d_context_unavailable');
    const vectors = new Float32Array(mapWidth * mapHeight * 2);
    let maxScale = 1;
    scaledRects.forEach((rect) => {
      const startX = Math.max(0, Math.floor(rect.x));
      const startY = Math.max(0, Math.floor(rect.y));
      const endX = Math.min(mapWidth, Math.ceil(rect.x + rect.width));
      const endY = Math.min(mapHeight, Math.ceil(rect.y + rect.height));
      for (let y = startY; y < endY; y += 1) {
        for (let x = startX; x < endX; x += 1) {
          const localX = x - rect.x;
          const localY = y - rect.y;
          const position = pageGlassFragment(localX / rect.width, localY / rect.height);
          const edgeDistance = Math.min(localX, localY, rect.width - localX - 1, rect.height - localY - 1);
          const seamFactor = Math.min(1, Math.max(0, edgeDistance) / 2);
          const normalizedEdge = Math.max(0, edgeDistance) / Math.max(1, Math.min(rect.width, rect.height));
          const centerT = clamp((normalizedEdge - 0.035) / (0.24 - 0.035), 0, 1);
          const centerFactor = 1 - centerT * centerT * (3 - 2 * centerT);
          const dx = (position.x * rect.width - localX) * seamFactor * centerFactor;
          const dy = (position.y * rect.height - localY) * seamFactor * centerFactor;
          const index = (y * mapWidth + x) * 2;
          vectors[index] = dx;
          vectors[index + 1] = dy;
          maxScale = Math.max(maxScale, Math.abs(dx), Math.abs(dy));
        }
      }
    });
    const image = context.createImageData(mapWidth, mapHeight);
    for (let pixel = 0; pixel < mapWidth * mapHeight; pixel += 1) {
      const vector = pixel * 2;
      const target = pixel * 4;
      image.data[target] = clamp((vectors[vector] / maxScale + 0.5) * 255, 0, 255);
      image.data[target + 1] = clamp((vectors[vector + 1] / maxScale + 0.5) * 255, 0, 255);
      image.data[target + 2] = image.data[target + 1];
      image.data[target + 3] = 255;
    }
    context.putImageData(image, 0, 0);
    return canvas.convertToBlob({ type: 'image/png' });
  }

  self.addEventListener('message', async (event) => {
    const message = event.data || {};
    const id = Number(message.id);
    const signature = String(message.signature || '');
    const mapWidth = Math.max(1, Math.round(Number(message.mapWidth) || 1));
    const mapHeight = Math.max(1, Math.round(Number(message.mapHeight) || 1));
    const scaledRects = Array.isArray(message.scaledRects) ? message.scaledRects : [];
    try {
      if (message.task === 'uniform') {
        const blob = await renderUniformDisplacementMap(
          mapWidth,
          mapHeight,
          String(message.mode || 'shader'),
          Boolean(message.preserveCenter)
        );
        const dataUrl = typeof FileReaderSync === 'function' ? new FileReaderSync().readAsDataURL(blob) : '';
        self.postMessage({ id, signature, blob: dataUrl ? null : blob, dataUrl });
        return;
      }
      const blob = await renderDisplacementMap(mapWidth, mapHeight, scaledRects);
      self.postMessage({ id, signature, blob });
    } catch (error) {
      self.postMessage({ id, signature, error: error?.message || 'map_render_failed' });
    }
  });
})();
