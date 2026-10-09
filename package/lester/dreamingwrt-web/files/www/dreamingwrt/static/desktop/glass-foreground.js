/* Shared foreground adaptation for transparent desktop surfaces:
 *  - iframe mode (resource-manager, network-tools, app store, …): runs inside a desktop
 *    window's same-origin iframe and adapts that page's text plus the host titlebar.
 *  - shell mode (desktop.html): adapts the window rails the shell renders itself
 *    (.dwrt-rail — 系统设置 and every multi-page app). They sit on window glass in the
 *    parent document, where no iframe script can reach them; without this they kept a
 *    fixed theme ink and vanished over bright wallpaper (用户 2026-09-27：要学资源管理器的策略).
 *  - standalone console: reads its visible .app-wallpaper instead of a desktop host.
 * One small offscreen map, sampled on layout/content changes, never an optical layer.
 * Frosted and desktop liquid surfaces use the shared gradient/transparent backdrop.
 * The standalone liquid console keeps its existing optical renderer and foreground. No material token or wallpaper setting is written here — only
 * neutral text/monochrome-icon `color`, while frosted or desktop liquid glass is active. Brand, status and data colours are preserved. Text-like inputs take part
 * too (their placeholder can inherit the adapted color, see dwrt-rail.css).
 * A chosen ink is HELD (hysteresis) until its source changes or it drops below the AA
 * floor, so live-updating dashboards no longer flicker. See glass-readability-spec §4/§6.
 */
(function () {
  'use strict';
  var host, frame, wallpaper, header, shell = false;
  try {
    frame = window.frameElement;
    if (frame) {
      host = frame.closest('.desktop-window');
      wallpaper = host && parent.document.querySelector('.desktop-wallpaper img');
      header = host && host.querySelector('.desktop-window-head');
    } else {
      // Top-level desktop shell: `parent` is this window, so the shared paths below hold.
      wallpaper = document.querySelector('.dwrt-desktop .desktop-wallpaper img');
      shell = !!wallpaper;
      if (!shell) {
        wallpaper = document.querySelector('img.app-wallpaper');
        host = wallpaper && document.querySelector('.dwrt-app');
      }
    }
  } catch (_) { return; }
  if (!wallpaper || (!shell && !host)) return;

  var canvas = document.createElement('canvas');
  var ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) return;
  var colorCanvas = document.createElement('canvas');
  colorCanvas.width = colorCanvas.height = 1;
  var colorCtx = colorCanvas.getContext('2d', { willReadFrequently: true });
  var colors = new Map(), applied = new Map(), settled = new Map();
  var timer = 0, active = false, lastCtx = '', hostVisible = true;
  var root = document.documentElement;
  var FLOOR = 4.8;
  var TEXT_INPUT = /^(text|search|email|url|tel|number|password)$/;
  function clearInk() {
    applied.forEach(function (original, el) {
      if (original) el.style.color = original;
      else el.style.removeProperty('color');
    });
    applied.clear();
    settled.clear();
  }
  function rgba(value) {
    if (!colors.has(value)) {
      colorCtx.clearRect(0, 0, 1, 1);
      colorCtx.fillStyle = value;
      colorCtx.fillRect(0, 0, 1, 1);
      colors.set(value, Array.from(colorCtx.getImageData(0, 0, 1, 1).data));
    }
    return colors.get(value);
  }
  function luma(rgb) {
    return rgb.slice(0, 3).reduce(function (sum, v, i) {
      v /= 255;
      return sum + [0.2126, 0.7152, 0.0722][i] *
        (v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4));
    }, 0);
  }
  function contrast(fg, samples) {
    return Math.min.apply(null, samples.map(function (bg) {
      var a = fg[3] / 255;
      var ink = luma(bg.map(function (v, i) { return fg[i] * a + v * (1 - a); }));
      var surface = luma(bg);
      return (Math.max(ink, surface) + 0.05) / (Math.min(ink, surface) + 0.05);
    }));
  }
  // Computed shared surfaces contain stacked linear/radial gradients. Paint the
  // same layers bottom-up; ignoring a leading radial layer also lost the neutral
  // absorption below it and chose dark ink over visibly dark liquid glass.
  function parts(value) {
    var depth = 0, start = 0, result = [];
    for (var i = 0; i < value.length; i++) {
      if (value[i] === '(') depth++;
      if (value[i] === ')') depth--;
      if (value[i] === ',' && !depth) { result.push(value.slice(start, i).trim()); start = i + 1; }
    }
    result.push(value.slice(start).trim());
    return result;
  }
  function paintGradients(image, rect) {
    parts(image).reverse().forEach(function (layer) {
      var match = /^(linear|radial)-gradient\((.*)\)$/.exec(layer);
      if (!match) return;
      var list = parts(match[2]), setup = list[0], gradient;
      var radial = match[1] === 'radial';
      if (/deg$|^to |^ellipse|^circle|^at /.test(setup)) list.shift(); else setup = '';
      ctx.save();
      if (radial) {
        var center = /at\s+(-?[\d.]+)%\s+(-?[\d.]+)%/.exec(setup);
        var x = rect.width * (center ? Number(center[1]) / 100 : 0.5);
        var y = rect.height * (center ? Number(center[2]) / 100 : 0.5);
        var rx = Math.max(x, rect.width - x) * Math.SQRT2;
        var ry = Math.max(y, rect.height - y) * Math.SQRT2;
        ctx.translate(rect.x + x, rect.y + y); ctx.scale(rx, ry);
        gradient = ctx.createRadialGradient(0, 0, 0, 0, 0, 1);
      } else {
        var rad = (setup ? parseFloat(setup) : 180) * Math.PI / 180;
        if (!Number.isFinite(rad)) { ctx.restore(); return; }
        var dx = Math.sin(rad), dy = -Math.cos(rad);
        var length = Math.abs(rect.width * dx) + Math.abs(rect.height * dy);
        var cx = rect.x + rect.width / 2, cy = rect.y + rect.height / 2;
        gradient = ctx.createLinearGradient(cx - dx * length / 2, cy - dy * length / 2,
          cx + dx * length / 2, cy + dy * length / 2);
      }
      var stops = list.map(function (stop) {
        var m = /^(rgba?\([^)]+\)|color\([^)]+\)|transparent)(?:\s+([\d.]+)%)?$/.exec(stop);
        return m ? { color: m[1], at: m[2] === undefined ? null : Number(m[2]) / 100 } : null;
      });
      if (stops.length < 2 || stops.some(function (s) { return !s; })) { ctx.restore(); return; }
      if (stops[0].at === null) stops[0].at = 0;
      if (stops[stops.length - 1].at === null) stops[stops.length - 1].at = 1;
      for (var i = 0; i < stops.length - 1; i++) {
        if (stops[i + 1].at !== null) continue;
        var end = i + 1;
        while (stops[end].at === null) end++;
        for (var j = i + 1; j < end; j++) stops[j].at = stops[i].at + (stops[end].at - stops[i].at) * (j - i) / (end - i);
      }
      // CSS interpolates transparent stops with premultiplied alpha; Canvas
      // gradients do not. A white sheen fading to transparent black otherwise
      // becomes grey in this map and incorrectly selects white tab text.
      for (var si = 0; si < stops.length - 1; si++) {
        var a = rgba(stops[si].color), b = rgba(stops[si + 1].color);
        for (var step = 0; step <= 8; step++) {
          var t = step / 8, alpha = a[3] * (1 - t) + b[3] * t;
          var rgb = a.slice(0, 3).map(function (v, channel) {
            return alpha ? (v * a[3] * (1 - t) + b[channel] * b[3] * t) / alpha
              : (a[3] ? v : b[channel]);
          });
          var at = stops[si].at + (stops[si + 1].at - stops[si].at) * t;
          gradient.addColorStop(Math.max(0, Math.min(1, at)),
            'rgba(' + rgb.join(',') + ',' + alpha / 255 + ')');
        }
      }
      ctx.fillStyle = gradient;
      if (radial) ctx.fillRect(-x / rx, -y / ry, rect.width / rx, rect.height / ry);
      else ctx.fillRect(rect.x, rect.y, rect.width, rect.height);
      ctx.restore();
    });
  }
  function readable(original, samples) {
    if (contrast(original, samples) >= 4.8) return original;
    var dark = [8, 13, 21, 255], light = [251, 253, 255, 255];
    var target = contrast(dark, samples) >= contrast(light, samples) ? dark : light;
    for (var step = 0; step <= 10; step++) {
      var t = step / 10;
      var candidate = target.slice(0, 3).concat(Math.max(220, original[3]) +
        (255 - Math.max(220, original[3])) * t);
      if (contrast(candidate, samples) >= 4.8) return candidate;
    }
    var black = [0, 0, 0, 255], white = [255, 255, 255, 255];
    return contrast(black, samples) >= contrast(white, samples) ? black : white;
  }
  function intersection(a, b) {
    var x = Math.max(a.x, b.x), y = Math.max(a.y, b.y);
    return { x: x, y: y, width: Math.max(0, Math.min(a.x + a.width, b.x + b.width) - x),
      height: Math.max(0, Math.min(a.y + a.height, b.y + b.height) - y) };
  }
  // Shell mode: every visible window whose rail the shell renders (not an iframe's).
  function shellHosts() {
    return Array.from(document.querySelectorAll('.desktop-window')).filter(function (win) {
      return win.querySelector('.dwrt-rail') && win.getClientRects().length;
    });
  }
  function sample() {
    timer = 0;
    if (!active || document.hidden || !hostVisible || !(root.dataset.themeFamily === 'frosted-glass' ||
          (root.dataset.themeFamily === 'liquid-glass' && (frame || shell))) ||
        !wallpaper.complete || !wallpaper.naturalWidth || (!shell && !host.getClientRects().length)) {
      clearInk();
      return;
    }
    // A theme flip (family/light-dark) changes every element's source ink and the
    // whole backdrop, so drop the held-ink cache and recompute from scratch.
    var cur = root.dataset.themeFamily + '|' + root.dataset.themeResolved;
    if (cur !== lastCtx) { clearInk(); lastCtx = cur; }
    // Read authored colors, not our previous pass's inline overrides.
    applied.forEach(function (original, el) {
      if (original) el.style.color = original;
      else el.style.removeProperty('color');
    });
    var w = parent.innerWidth, h = parent.innerHeight, scale = Math.min(1, 320 / w);
    canvas.width = Math.ceil(w * scale); canvas.height = Math.ceil(h * scale);
    var wr = wallpaper.getBoundingClientRect();
    var seen = new Set();
    var passes = shell ? shellHosts().map(function (win) {
      return { host: win, collect: function (record) {
        var hr = win.getBoundingClientRect();
        var base = { x: 0, y: 0, clip: { x: hr.x, y: hr.y, width: hr.width, height: hr.height } };
        var rail = win.querySelector('.dwrt-rail');
        [rail].concat(Array.from(rail.querySelectorAll('*'))).forEach(function (el) {
          if (!/^(script|path|circle|line|rect|ellipse|polyline|polygon)$/i.test(el.tagName)) record(el, base);
        });
      } };
    }) : [{ host: host, collect: function (record) {
      var fr = frame ? frame.getBoundingClientRect() : { x: 0, y: 0, width: w, height: h };
      var base = { x: fr.x, y: fr.y, clip: { x: fr.x, y: fr.y, width: fr.width, height: fr.height } };
      if (header) [header].concat(Array.from(header.querySelectorAll('*'))).forEach(function (el) { record(el, null); });
      [document.body].concat(Array.from(document.body.querySelectorAll('*'))).forEach(function (el) {
        if (!/^(script|path|circle|line|rect|ellipse)$/i.test(el.tagName)) record(el, base);
      });
    } }];
    passes.forEach(function (pass) {
      var records = [], styles = new Map(), clips = new Map();
      // base === null: a chrome element in the top document (no offset, no clipping).
      // Otherwise: offset by base.x/y and clipped by base.clip plus scrolling ancestors.
      function record(el, base) {
        var style = el.ownerDocument.defaultView.getComputedStyle(el);
        var r = el.getBoundingClientRect();
        var dx = base ? base.x : 0, dy = base ? base.y : 0;
        var rect = { x: r.x + dx, y: r.y + dy, width: r.width, height: r.height };
        var clip = { x: 0, y: 0, width: w, height: h };
        if (base) {
          clip = clips.get(el.parentElement) || base.clip;
          var ps = styles.get(el.parentElement);
          if (ps && /auto|scroll|hidden|clip/.test(ps.overflow + ps.overflowX + ps.overflowY)) {
            var pr = el.parentElement.getBoundingClientRect();
            clip = intersection(clip, { x: pr.x + dx, y: pr.y + dy, width: pr.width, height: pr.height });
          }
          clips.set(el, clip); styles.set(el, style);
        }
        var visible = intersection(rect, clip);
        if (!visible.width || !visible.height || style.visibility === 'hidden') return;
        var texts = [];
        Array.from(el.childNodes).forEach(function (node) {
          if (node.nodeType !== 3 || !node.textContent.trim()) return;
          var range = el.ownerDocument.createRange(); range.selectNodeContents(node);
          Array.from(range.getClientRects()).forEach(function (tr) {
            var textRect = intersection(clip, { x: tr.x + dx, y: tr.y + dy, width: tr.width, height: tr.height });
            if (textRect.width && textRect.height) texts.push(textRect);
          });
        });
        if (el.tagName.toLowerCase() === 'svg' ||
            el.matches('.window-controls button')) texts.push(visible);
        // Typed text / placeholder live in the input's padding box, middle band.
        if ((el.tagName === 'INPUT' && TEXT_INPUT.test(el.type)) ||
            el.tagName === 'SELECT' || el.tagName === 'TEXTAREA') {
          var pl = parseFloat(style.paddingLeft) || 0, pe = parseFloat(style.paddingRight) || 0;
          var field = intersection(clip, { x: rect.x + pl, y: rect.y + rect.height * 0.25,
            width: Math.max(0, rect.width - pl - pe), height: rect.height * 0.5 });
          if (field.width && field.height) texts.push(field);
        }
        // The top-level body was painted below the wallpaper, not above it.
        var backgroundAlreadyPainted = !frame && el === document.body;
        var materialStyle = el.classList.contains('desktop-window') ?
          el.ownerDocument.defaultView.getComputedStyle(el, '::before') : style;
        records.push({ el: el, rect: rect, clip: clip,
          bg: backgroundAlreadyPainted ? 'transparent' : materialStyle.backgroundColor,
          image: backgroundAlreadyPainted ? 'none' : materialStyle.backgroundImage,
          texts: texts, ink: texts.length ? rgba(style.color) : null });
        // Kit's moving selection pill has a separate upper sheen. It visibly
        // lightens active tab labels, so it belongs in their sampled surface too.
        if (el.classList.contains('dwrt-kit-tab-pill')) {
          var sheen = el.ownerDocument.defaultView.getComputedStyle(el, '::before');
          var sw = parseFloat(sheen.width), sh = parseFloat(sheen.height);
          if (sheen.content !== 'none' && sheen.display !== 'none' && sw > 0 && sh > 0) {
            records.push({ el: el, clip: clip,
              rect: { x: rect.x + (parseFloat(sheen.left) || 0), y: rect.y + (parseFloat(sheen.top) || 0), width: sw, height: sh },
              bg: sheen.backgroundColor, image: sheen.backgroundImage,
              opacity: Number(sheen.opacity), texts: [], ink: null });
          }
        }
      }
      record(pass.host, null);
      pass.collect(record);

      ctx.setTransform(scale, 0, 0, scale, 0, 0);
      ctx.fillStyle = parent.getComputedStyle(parent.document.body).backgroundColor;
      ctx.fillRect(0, 0, w, h);
      var cover = Math.max(wr.width / wallpaper.naturalWidth, wr.height / wallpaper.naturalHeight);
      ctx.save();
      var plane = pass.host.querySelector('.desktop-window-wallpaper');
      var opticalFilter = plane ? parent.getComputedStyle(plane).filter : parent.getComputedStyle(pass.host).backdropFilter;
      ctx.filter = opticalFilter.replace(/blur\(([\d.]+)px\)/g,
        function (_, px) { return 'blur(' + Number(px) * scale + 'px)'; });
      ctx.globalAlpha = Number(parent.getComputedStyle(wallpaper).opacity) * Number(parent.getComputedStyle(wallpaper.parentElement).opacity);
      ctx.drawImage(wallpaper, wr.x + (wr.width - wallpaper.naturalWidth * cover) / 2,
        wr.y + (wr.height - wallpaper.naturalHeight * cover) / 2,
        wallpaper.naturalWidth * cover, wallpaper.naturalHeight * cover);
      ctx.restore();
      records.forEach(function (r) {
        ctx.save(); ctx.beginPath(); ctx.rect(r.clip.x, r.clip.y, r.clip.width, r.clip.height); ctx.clip();
        if (r.opacity !== undefined) ctx.globalAlpha = r.opacity;
        ctx.fillStyle = r.bg; ctx.fillRect(r.rect.x, r.rect.y, r.rect.width, r.rect.height);
        paintGradients(r.image, r.rect);
        ctx.restore();
      });
      var pixels;
      try { pixels = ctx.getImageData(0, 0, canvas.width, canvas.height).data; }
      catch (_) { return; } // Cross-origin media retains the theme's foreground.
      records.forEach(function (r) {
        if (!r.ink) return;
        // Authored chromatic text/currentColor SVG carries accent, status or data
        // meaning. Neutral adaptation must never turn it into black/white. The
        // explicit marker also protects intentionally low-chroma semantic artwork.
        if (r.el.closest('[data-glass-color="preserve"]') ||
            Math.max.apply(null, r.ink.slice(0, 3)) - Math.min.apply(null, r.ink.slice(0, 3)) >= 40) return;
        var samples = [];
        r.texts.forEach(function (rect) {
          for (var y = 0.2; y < 1; y += 0.3) for (var x = 0.1; x < 1; x += 0.2) {
            var px = Math.min(canvas.width - 1, Math.max(0, Math.floor((rect.x + rect.width * x) * scale)));
            var py = Math.min(canvas.height - 1, Math.max(0, Math.floor((rect.y + rect.height * y) * scale)));
            var i = (py * canvas.width + px) * 4;
            samples.push([pixels[i], pixels[i + 1], pixels[i + 2]]);
          }
        });
        // Hysteresis: reuse the previously-applied ink while its SOURCE color is
        // unchanged and it still clears the AA floor against the current backdrop.
        // Only recompute when the source changed (e.g. muted→status color) or the
        // held ink actually failed — this stops the per-tick flicker on live
        // dashboards, where an animating backdrop would otherwise flip the choice.
        var prev = settled.get(r.el);
        var same = prev && prev.src[0] === r.ink[0] && prev.src[1] === r.ink[1] &&
          prev.src[2] === r.ink[2] && prev.src[3] === r.ink[3];
        var ink = (same && contrast(prev.out, samples) >= FLOOR) ? prev.out : readable(r.ink, samples);
        settled.set(r.el, { src: r.ink, out: ink });
        seen.add(r.el);
        if (!applied.has(r.el)) applied.set(r.el, r.el.style.color);
        var css = 'rgba(' + ink.slice(0, 3).join(',') + ',' + ink[3] / 255 + ')';
        if (r.el.style.color !== css) r.el.style.color = css;
      });
    });
    // Reconcile: revert any element that dropped out of this pass back to its
    // token color, and forget its held ink.
    applied.forEach(function (original, el) {
      if (seen.has(el)) return;
      if (original) el.style.color = original;
      else el.style.removeProperty('color');
      applied.delete(el);
      settled.delete(el);
    });
  }
  function schedule() {
    if (active && !timer) timer = window.setTimeout(sample, 120);
  }
  // Shell mode watches the window layer: open/close, focus, rail search/selection, and
  // window moves. A `style` change only counts on a window itself — the per-text color
  // this script writes is also a style mutation and must not re-trigger a pass.
  var content = new MutationObserver(shell ? function (list) {
    for (var i = 0; i < list.length; i++) {
      var m = list[i];
      if (m.attributeName !== 'style' || m.target.classList.contains('desktop-window')) { schedule(); return; }
    }
  } : schedule);
  var themeObs = new MutationObserver(schedule);
  var resize = new ResizeObserver(schedule);
  function start() {
    if (active || !hostVisible) return;
    active = true;
    if (shell) {
      content.observe(document.querySelector('.desktop-windows') || document.body,
        { subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'hidden', 'style'] });
    } else {
      content.observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'hidden', 'disabled'] });
      themeObs.observe(host, { attributes: true, attributeFilter: ['style', 'class', 'hidden'] });
      resize.observe(frame || host);
    }
    themeObs.observe(root, { attributes: true, attributeFilter: ['data-theme-family', 'data-theme-resolved'] });
    themeObs.observe(wallpaper, { attributes: true, attributeFilter: ['src', 'style'] });
    resize.observe(wallpaper);
    document.addEventListener('scroll', schedule, true);
    document.addEventListener('pointerover', schedule);
    document.addEventListener('pointerout', schedule);
    wallpaper.addEventListener('load', schedule);
    schedule();
  }
  function stop() {
    active = false; clearTimeout(timer); timer = 0;
    content.disconnect(); themeObs.disconnect(); resize.disconnect(); clearInk();
    document.removeEventListener('scroll', schedule, true);
    document.removeEventListener('pointerover', schedule);
    document.removeEventListener('pointerout', schedule);
    wallpaper.removeEventListener('load', schedule);
  }
  // A hidden iframe does not receive document.visibilitychange. The desktop host
  // sends this lifecycle event on minimize/restore; release observers and ink there.
  window.addEventListener('message', function (event) {
    if (!frame || event.source !== parent || event.origin !== location.origin ||
        !event.data || event.data.type !== 'dwrt-app-visibility') return;
    hostVisible = Boolean(event.data.visible);
    if (hostVisible) start(); else stop();
  });
  window.addEventListener('pagehide', stop);
  window.addEventListener('pageshow', start);
  document.addEventListener('visibilitychange', function () { if (document.hidden) stop(); else start(); });
  start();
})();
