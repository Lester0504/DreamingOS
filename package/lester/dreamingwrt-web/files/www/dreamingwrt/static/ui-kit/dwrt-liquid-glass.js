(() => {
  'use strict';

  function clamp(value, min, max) {
    const num = Number(value);
    if (!Number.isFinite(num)) return min;
    return Math.max(min, Math.min(max, num));
  }

  function roundRectPath(ctx, x, y, width, height, radius) {
    const r = Math.max(0, Math.min(radius, width / 2, height / 2));
    if (ctx.roundRect) {
      ctx.roundRect(x, y, width, height, r);
      return;
    }
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + width, y, x + width, y + height, r);
    ctx.arcTo(x + width, y + height, x, y + height, r);
    ctx.arcTo(x, y + height, x, y, r);
    ctx.arcTo(x, y, x + width, y, r);
  }

  function coverDrawArgs(image, viewportW, viewportH) {
    const imageW = image && (image.naturalWidth || image.width) || 1;
    const imageH = image && (image.naturalHeight || image.height) || 1;
    const scale = Math.max(viewportW / imageW, viewportH / imageH);
    const drawW = imageW * scale;
    const drawH = imageH * scale;
    return {
      width: drawW,
      height: drawH,
      x: (viewportW - drawW) / 2,
      y: (viewportH - drawH) / 2
    };
  }

  function drawCoverBackground(ctx, image, rect, offsetX = 0, offsetY = 0, scaleBoost = 1) {
    const viewportW = window.innerWidth || document.documentElement.clientWidth || 1;
    const viewportH = window.innerHeight || document.documentElement.clientHeight || 1;
    const imageW = image.naturalWidth || image.width || 1;
    const imageH = image.naturalHeight || image.height || 1;
    const scale = Math.max(viewportW / imageW, viewportH / imageH) * scaleBoost;
    const drawW = imageW * scale;
    const drawH = imageH * scale;
    const drawX = (viewportW - drawW) / 2 - rect.left + offsetX;
    const drawY = (viewportH - drawH) / 2 - rect.top + offsetY;
    ctx.drawImage(image, drawX, drawY, drawW, drawH);
  }

  function createViewportSnapshot(image) {
    const viewportW = window.innerWidth || document.documentElement.clientWidth || 1;
    const viewportH = window.innerHeight || document.documentElement.clientHeight || 1;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const canvas = createViewportSnapshot.canvas || document.createElement('canvas');
    createViewportSnapshot.canvas = canvas;
    const pxW = Math.max(1, Math.round(viewportW * dpr));
    const pxH = Math.max(1, Math.round(viewportH * dpr));
    if (canvas.width !== pxW || canvas.height !== pxH) {
      canvas.width = pxW;
      canvas.height = pxH;
    }
    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return image;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, viewportW, viewportH);
    ctx.filter = 'none';
    const imageW = image.naturalWidth || image.width || 1;
    const imageH = image.naturalHeight || image.height || 1;
    const scale = Math.max(viewportW / imageW, viewportH / imageH);
    const drawW = imageW * scale;
    const drawH = imageH * scale;
    const drawX = (viewportW - drawW) / 2;
    const drawY = (viewportH - drawH) / 2;
    ctx.drawImage(image, drawX, drawY, drawW, drawH);
    const scrim = ctx.createLinearGradient(0, 0, viewportW, viewportH);
    scrim.addColorStop(0, 'rgba(5, 5, 16, 0.18)');
    scrim.addColorStop(0.34, 'rgba(10, 22, 40, 0.13)');
    scrim.addColorStop(0.68, 'rgba(30, 27, 75, 0.13)');
    scrim.addColorStop(1, 'rgba(5, 5, 16, 0.20)');
    ctx.fillStyle = scrim;
    ctx.fillRect(0, 0, viewportW, viewportH);
    const glow = ctx.createRadialGradient(viewportW * 0.5, viewportH * 0.18, 0, viewportW * 0.5, viewportH * 0.18, Math.max(viewportW, viewportH) * 0.34);
    glow.addColorStop(0, 'rgba(255,255,255,0.055)');
    glow.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = glow;
    ctx.fillRect(0, 0, viewportW, viewportH);
    return canvas;
  }

  function drawGlassBand(ctx, image, rect, vars, x, y, width, height, offsetX, offsetY, alpha) {
    ctx.save();
    ctx.beginPath();
    ctx.rect(x, y, width, height);
    ctx.clip();
    ctx.globalAlpha = alpha;
    ctx.filter = `blur(${Math.max(1, clamp(vars.blurRadius, 0.5, 18) * 0.45)}px) saturate(170%) brightness(1.16)`;
    drawCoverBackground(ctx, image, rect, offsetX, offsetY, 1.006);
    ctx.restore();
  }

  function createCanvasLiquidRenderer(canvas, ctx) {
    return {
      mode: ctx ? '2d' : 'none',
      render(image, rect, vars) {
        const sourceW = image ? (image.naturalWidth || image.width || 0) : 0;
        const sourceH = image ? (image.naturalHeight || image.height || 0) : 0;
        if (!canvas || !ctx || !image || !sourceW || !sourceH) return false;
        const width = Math.round(rect.width);
        const height = Math.round(rect.height);
        if (width <= 1 || height <= 1) return false;

        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        const pxW = Math.max(1, Math.round(width * dpr));
        const pxH = Math.max(1, Math.round(height * dpr));
        if (canvas.width !== pxW || canvas.height !== pxH) {
          canvas.width = pxW;
          canvas.height = pxH;
        }
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, width, height);

        const radius = clamp(vars.cornerRadius, 0, Math.min(width, height) / 2);
        const edge = clamp(vars.refractionHeight, 6, 28);
        const shift = clamp(vars.refractionOffset * 0.07, 5, 18);
        const opacity = clamp(vars.opacity, 0, 1);
        const highlight = clamp(vars.highlight, 0, 1.2);
        const dispersion = clamp(vars.dispersion, 0, 2);
        const warp = vars.warp ? 1 : 0;
        const cornerBoost = clamp(vars.cornerBoost, 0, 2);
        const rippleEffect = clamp(vars.rippleEffect, 0, 2);
        const baseIntensity = clamp(vars.baseIntensity, 0, 1);
        const edgeIntensity = clamp(vars.edgeIntensity, 0, 2);
        const rimIntensity = clamp(vars.rimIntensity, 0, 2);
        const edgeDistance = clamp(vars.edgeDistance, 0.001, 1);
        const rimDistance = clamp(vars.rimDistance, 0.001, 1);
        const baseDistance = clamp(vars.baseDistance, 0.001, 1);

        const cover = coverDrawArgs(image, window.innerWidth || document.documentElement.clientWidth || 1, window.innerHeight || document.documentElement.clientHeight || 1);
        const drawCover = (offsetX = 0, offsetY = 0, scaleBoost = 1) => {
          const dw = cover.width * scaleBoost;
          const dh = cover.height * scaleBoost;
          const dx = cover.x - rect.left - (dw - cover.width) / 2 + offsetX;
          const dy = cover.y - rect.top - (dh - cover.height) / 2 + offsetY;
          ctx.drawImage(image, dx, dy, dw, dh);
        };

        ctx.save();
        ctx.beginPath();
        roundRectPath(ctx, 0, 0, width, height, radius);
        ctx.clip();
        ctx.filter = `blur(${Math.max(0.25, clamp(vars.blurRadius, 0.5, 18) * 0.12)}px) saturate(150%) brightness(1.045)`;
        drawCover(0, 0, 1.002);
        ctx.filter = 'none';
        ctx.globalCompositeOperation = 'screen';
        ctx.fillStyle = `rgba(255,255,255,${0.003 + opacity * 0.012})`;
        ctx.fillRect(0, 0, width, height);
        ctx.globalCompositeOperation = 'source-over';
        const depthGradient = ctx.createLinearGradient(0, 0, 0, height);
        depthGradient.addColorStop(0, `rgba(255,255,255,${0.012 * highlight})`);
        depthGradient.addColorStop(0.58, 'rgba(255,255,255,0)');
        depthGradient.addColorStop(1, `rgba(4,8,18,${0.030 * opacity})`);
        ctx.fillStyle = depthGradient;
        ctx.fillRect(0, 0, width, height);
        ctx.restore();

        ctx.save();
        ctx.beginPath();
        roundRectPath(ctx, 0, 0, width, height, radius);
        ctx.clip();
        drawGlassBand(ctx, image, rect, vars, 0, 0, width, edge, 0, shift, 0.30 + highlight * 0.18);
        drawGlassBand(ctx, image, rect, vars, 0, height - edge, width, edge, 0, -shift, 0.20 + highlight * 0.10);
        drawGlassBand(ctx, image, rect, vars, 0, 0, edge, height, shift, 0, 0.18 + highlight * 0.09);
        drawGlassBand(ctx, image, rect, vars, width - edge, 0, edge, height, -shift, 0, 0.16 + highlight * 0.08);
        ctx.restore();

        ctx.save();
        ctx.beginPath();
        roundRectPath(ctx, 0.5, 0.5, width - 1, height - 1, Math.max(0, radius - 0.5));
        ctx.clip();
        let gradient = ctx.createLinearGradient(0, 0, width, height);
        gradient.addColorStop(0, `rgba(255,255,255,${0.15 * highlight})`);
        gradient.addColorStop(0.42, 'rgba(255,255,255,0.014)');
        gradient.addColorStop(1, `rgba(255,255,255,${0.08 * highlight})`);
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 0, width, height);
        gradient = ctx.createLinearGradient(0, 0, 0, Math.max(edge * 3, 48));
        gradient.addColorStop(0, `rgba(255,255,255,${0.26 * highlight})`);
        gradient.addColorStop(1, 'rgba(255,255,255,0)');
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 0, width, Math.max(edge * 3, 48));
        ctx.strokeStyle = vars.borderColor || '#ffffff25';
        ctx.lineWidth = Math.max(1, clamp(vars.borderWidth, 1, 2));
        ctx.beginPath();
        roundRectPath(ctx, 0.5, 0.5, width - 1, height - 1, Math.max(0, radius - 0.5));
        ctx.stroke();
        ctx.restore();

        if (dispersion > 0.001 || warp > 0.001 || edgeIntensity > 0.001 || rimIntensity > 0.001 || baseIntensity > 0.001 || cornerBoost > 0.001 || rippleEffect > 0.001) {
          ctx.save();
          ctx.beginPath();
          roundRectPath(ctx, 0, 0, width, height, radius);
          ctx.clip();
          ctx.globalCompositeOperation = 'screen';
          ctx.globalAlpha = 0.08 + highlight * 0.05;
          ctx.filter = `blur(${Math.max(0.5, clamp(vars.blurRadius, 0.5, 18) * 0.20)}px) saturate(190%) brightness(1.18)`;
          drawCover(dispersion * 0.2, rippleEffect * 0.2, 1.009);
          ctx.restore();
        }

        return true;
      }
    };
  }

  function compileShader(gl, type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      console.warn('Liquid glass shader failed:', gl.getShaderInfoLog(shader));
      gl.deleteShader(shader);
      return null;
    }
    return shader;
  }

  function createProgram(gl, vertexSource, fragmentSource) {
    const vertex = compileShader(gl, gl.VERTEX_SHADER, vertexSource);
    const fragment = compileShader(gl, gl.FRAGMENT_SHADER, fragmentSource);
    if (!vertex || !fragment) return null;
    const program = gl.createProgram();
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      console.warn('Liquid glass program failed:', gl.getProgramInfoLog(program));
      gl.deleteProgram(program);
      return null;
    }
    return program;
  }

  function createWebGlLiquidRenderer(canvas, gl) {
    canvas.__dwrtGlassGl = gl;
    const vertexSource = `
      attribute vec2 a_position;
      attribute vec2 a_texcoord;
      varying vec2 v_texcoord;
      void main() {
        gl_Position = vec4(a_position, 0.0, 1.0);
        v_texcoord = a_texcoord;
      }
    `;
    const fragmentSource = `
      precision mediump float;
      uniform sampler2D u_image;
      uniform vec2 u_cssSize;
      uniform vec2 u_cardOrigin;
      uniform vec2 u_viewportSize;
      uniform vec2 u_textureSize;
      uniform float u_cornerRadius;
      uniform float u_blurRadius;
      uniform float u_refractionOffset;
      uniform float u_refractionHeight;
      uniform float u_opacity;
      uniform float u_highlight;
      uniform float u_dispersion;
      uniform float u_edgeIntensity;
      uniform float u_rimIntensity;
      uniform float u_baseIntensity;
      uniform float u_edgeDistance;
      uniform float u_rimDistance;
      uniform float u_baseDistance;
      uniform float u_cornerBoost;
      uniform float u_rippleEffect;
      uniform float u_tintOpacity;
      uniform float u_warp;
      varying vec2 v_texcoord;

      float roundedRectDistance(vec2 pixel, vec2 size, float radius) {
        vec2 halfSize = size * 0.5;
        vec2 p = pixel - halfSize;
        vec2 q = abs(p) - halfSize + radius;
        return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - radius;
      }

      vec2 shapeNormal(vec2 pixel, vec2 size, float radius) {
        vec2 halfSize = size * 0.5;
        vec2 p = pixel - halfSize;
        vec2 q = abs(p) - halfSize + radius;
        vec2 corner = max(q, 0.0) * sign(p);
        if (length(corner) > 0.001) return normalize(corner);
        vec2 edgeNormal = abs(q.x) > abs(q.y) ? vec2(sign(p.x), 0.0) : vec2(0.0, sign(p.y));
        vec2 centerNormal = normalize(p / max(halfSize, vec2(1.0)));
        return length(edgeNormal) > 0.0 ? normalize(mix(edgeNormal, centerNormal, 0.30)) : centerNormal;
      }

      vec4 sampleUv(vec2 uv) {
        uv = clamp(uv, vec2(0.001), vec2(0.999));
        return texture2D(u_image, uv);
      }

      vec2 coverUv(vec2 pagePixel) {
        return clamp(pagePixel / max(u_textureSize, vec2(1.0)), vec2(0.001), vec2(0.999));
      }

      vec4 sampleCover(vec2 pagePixel) {
        return sampleUv(coverUv(pagePixel));
      }

      vec4 blurredCoverUv(vec2 uv) {
        vec4 color = vec4(0.0);
        float sigma = max(u_blurRadius, 0.5) / 2.0;
        vec2 blurStep = vec2(sigma) / max(u_textureSize, vec2(1.0));
        float totalWeight = 0.0;

        for (float i = -6.0; i <= 6.0; i += 1.0) {
          for (float j = -6.0; j <= 6.0; j += 1.0) {
            float dist = length(vec2(i, j));
            if (dist > 6.0) continue;
            float weight = exp(-(dist * dist) / (2.0 * sigma * sigma));
            color += sampleUv(uv + vec2(i, j) * blurStep) * weight;
            totalWeight += weight;
          }
        }

        return color / max(totalWeight, 0.001);
      }

      void main() {
        vec2 pixel = v_texcoord * u_cssSize;
        float distance = roundedRectDistance(pixel, u_cssSize, u_cornerRadius);
        float mask = 1.0 - smoothstep(-1.2, 1.2, distance);
        if (mask <= 0.001) discard;

        float inside = max(-distance, 0.0);
        vec2 normal = shapeNormal(pixel, u_cssSize, u_cornerRadius);
        vec2 tangent = vec2(-normal.y, normal.x);
        float edge = exp(-inside * max(u_edgeDistance, 0.001)) * u_edgeIntensity;
        float rim = exp(-inside * max(u_rimDistance, 0.001)) * u_rimIntensity;
        float base = (1.0 - exp(-inside * max(u_baseDistance, 0.001))) * u_baseIntensity * u_warp;
        vec2 cornerUv = min(v_texcoord, 1.0 - v_texcoord);
        float cornerDistance = max(cornerUv.x, cornerUv.y) * min(u_cssSize.x, u_cssSize.y);
        float corner = exp(-cornerDistance * 0.30) * u_cornerBoost;
        float distFromEdge = inside / max(min(u_cssSize.x, u_cssSize.y), 1.0);
        float ripple = sin(distFromEdge * 25.0) * u_rippleEffect * rim;
        vec2 refract = normal * (edge + rim + base + corner) + tangent * ripple;
        vec2 textureCoord = coverUv(u_cardOrigin + pixel) + refract;

        vec4 color = blurredCoverUv(textureCoord);
        if (u_dispersion > 0.001) {
          vec2 spread = normal * clamp(u_dispersion, 0.0, 2.0) / max(u_textureSize, vec2(1.0));
          color.r = sampleUv(textureCoord + spread).r;
          color.b = sampleUv(textureCoord - spread).b;
        }

        vec3 coolTint = mix(vec3(1.0, 1.0, 1.0), vec3(0.70, 0.70, 0.70), v_texcoord.y);
        vec3 sampledTint = mix(sampleCover(vec2(u_viewportSize.x * 0.5, u_cardOrigin.y + u_cssSize.y * 0.10)).rgb, sampleCover(vec2(u_viewportSize.x * 0.5, u_cardOrigin.y + u_cssSize.y * 0.92)).rgb, v_texcoord.y);
        color.rgb = mix(color.rgb, coolTint, clamp(u_tintOpacity, 0.0, 0.36));
        color.rgb = mix(color.rgb, sampledTint, clamp(u_tintOpacity * 0.30, 0.0, 0.11));

        float topGlow = 1.0 - smoothstep(0.0, max(18.0, u_refractionHeight * 3.4), pixel.y);
        float bottomGlow = smoothstep(u_cssSize.y - max(22.0, u_refractionHeight * 3.2), u_cssSize.y, pixel.y);
        float edgeGlow = (edge + rim + corner) * 0.42 + topGlow * 0.06 + bottomGlow * 0.025;
        color.rgb += vec3(edgeGlow * u_highlight);
        color.rgb = mix(color.rgb, vec3(0.96, 0.98, 1.0), clamp(topGlow * u_highlight * 0.055, 0.0, 0.06));
        gl_FragColor = vec4(color.rgb, mask);
      }
    `;
    const program = createProgram(gl, vertexSource, fragmentSource);
    if (!program) return createCanvasLiquidRenderer(canvas, canvas.getContext('2d', { alpha: true }));

    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]), gl.STATIC_DRAW);

    const texcoordBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, texcoordBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0]), gl.STATIC_DRAW);

    const locations = {
      position: gl.getAttribLocation(program, 'a_position'),
      texcoord: gl.getAttribLocation(program, 'a_texcoord'),
      image: gl.getUniformLocation(program, 'u_image'),
      cssSize: gl.getUniformLocation(program, 'u_cssSize'),
      cardOrigin: gl.getUniformLocation(program, 'u_cardOrigin'),
      viewportSize: gl.getUniformLocation(program, 'u_viewportSize'),
      textureSize: gl.getUniformLocation(program, 'u_textureSize'),
      cornerRadius: gl.getUniformLocation(program, 'u_cornerRadius'),
      blurRadius: gl.getUniformLocation(program, 'u_blurRadius'),
      refractionOffset: gl.getUniformLocation(program, 'u_refractionOffset'),
      refractionHeight: gl.getUniformLocation(program, 'u_refractionHeight'),
      opacity: gl.getUniformLocation(program, 'u_opacity'),
      highlight: gl.getUniformLocation(program, 'u_highlight'),
      dispersion: gl.getUniformLocation(program, 'u_dispersion'),
      edgeIntensity: gl.getUniformLocation(program, 'u_edgeIntensity'),
      rimIntensity: gl.getUniformLocation(program, 'u_rimIntensity'),
      baseIntensity: gl.getUniformLocation(program, 'u_baseIntensity'),
      edgeDistance: gl.getUniformLocation(program, 'u_edgeDistance'),
      rimDistance: gl.getUniformLocation(program, 'u_rimDistance'),
      baseDistance: gl.getUniformLocation(program, 'u_baseDistance'),
      cornerBoost: gl.getUniformLocation(program, 'u_cornerBoost'),
      rippleEffect: gl.getUniformLocation(program, 'u_rippleEffect'),
      tintOpacity: gl.getUniformLocation(program, 'u_tintOpacity'),
      warp: gl.getUniformLocation(program, 'u_warp')
    };

    let texture = null;
    let textureSource = null;

    function uploadImage(image) {
      if (textureSource === image && texture && image.tagName !== 'CANVAS') return;
      textureSource = image;
      texture = texture || gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, texture);
      gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, false);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, image);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    }

    function render(image, rect, vars) {
      const sourceW = image ? (image.naturalWidth || image.width || 0) : 0;
      const sourceH = image ? (image.naturalHeight || image.height || 0) : 0;
      if (!image || !sourceW || !sourceH) return false;
      const width = Math.round(rect.width);
      const height = Math.round(rect.height);
      if (width <= 1 || height <= 1) return false;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const pxW = Math.max(1, Math.round(width * dpr));
      const pxH = Math.max(1, Math.round(height * dpr));
      if (canvas.width !== pxW || canvas.height !== pxH) {
        canvas.width = pxW;
        canvas.height = pxH;
      }

      const viewportW = window.innerWidth || document.documentElement.clientWidth || 1;
      const viewportH = window.innerHeight || document.documentElement.clientHeight || 1;
      const textureW = sourceW || viewportW;
      const textureH = sourceH || viewportH;
      const opacity = clamp(vars.opacity, 0, 1);
      const highlight = clamp(vars.highlight, 0, 1.2);
      const dispersion = clamp(vars.dispersion, 0, 2);
      const edgeIntensity = clamp(vars.edgeIntensity, 0, 2);
      const rimIntensity = clamp(vars.rimIntensity, 0, 2);
      const baseIntensity = clamp(vars.baseIntensity, 0, 1);
      const edgeDistance = clamp(vars.edgeDistance, 0.001, 1);
      const rimDistance = clamp(vars.rimDistance, 0.001, 1);
      const baseDistance = clamp(vars.baseDistance, 0.001, 1);
      const cornerBoost = clamp(vars.cornerBoost, 0, 2);
      const rippleEffect = clamp(vars.rippleEffect, 0, 2);
      const tintOpacity = clamp(vars.tintOpacity, 0, 1);
      const warp = vars.warp ? 1 : 0;

      gl.viewport(0, 0, pxW, pxH);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.useProgram(program);
      uploadImage(image);

      gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
      gl.enableVertexAttribArray(locations.position);
      gl.vertexAttribPointer(locations.position, 2, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, texcoordBuffer);
      gl.enableVertexAttribArray(locations.texcoord);
      gl.vertexAttribPointer(locations.texcoord, 2, gl.FLOAT, false, 0, 0);

      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, texture);
      gl.uniform1i(locations.image, 0);
      gl.uniform2f(locations.cssSize, width, height);
      gl.uniform2f(locations.cardOrigin, rect.left, rect.top);
      gl.uniform2f(locations.viewportSize, viewportW, viewportH);
      gl.uniform2f(locations.textureSize, textureW, textureH);
      gl.uniform1f(locations.cornerRadius, clamp(vars.cornerRadius, 0, Math.min(width, height) / 2));
      gl.uniform1f(locations.blurRadius, clamp(vars.blurRadius, 0.5, 18));
      gl.uniform1f(locations.refractionOffset, clamp(vars.refractionOffset, 0, 260));
      gl.uniform1f(locations.refractionHeight, clamp(vars.refractionHeight, 4, 38));
      gl.uniform1f(locations.opacity, opacity);
      gl.uniform1f(locations.highlight, highlight);
      gl.uniform1f(locations.dispersion, dispersion);
      gl.uniform1f(locations.edgeIntensity, edgeIntensity);
      gl.uniform1f(locations.rimIntensity, rimIntensity);
      gl.uniform1f(locations.baseIntensity, baseIntensity);
      gl.uniform1f(locations.edgeDistance, edgeDistance);
      gl.uniform1f(locations.rimDistance, rimDistance);
      gl.uniform1f(locations.baseDistance, baseDistance);
      gl.uniform1f(locations.cornerBoost, cornerBoost);
      gl.uniform1f(locations.rippleEffect, rippleEffect);
      gl.uniform1f(locations.tintOpacity, tintOpacity);
      gl.uniform1f(locations.warp, warp);
      gl.drawArrays(gl.TRIANGLES, 0, 6);
      return true;
    }

    return {
      mode: 'webgl',
      render,
      destroy: () => {
        const ext = gl && gl.getExtension && gl.getExtension('WEBGL_lose_context');
        if (ext && ext.loseContext) {
          try { ext.loseContext(); } catch (_) {}
        }
        canvas.__dwrtGlassGl = null;
      }
    };
  }

  function createLiquidGlassRenderer(canvas) {
    if (!canvas) return { mode: 'none', render: () => false };
    try {
      const gl = canvas.getContext('webgl', {
        alpha: true,
        premultipliedAlpha: false,
        antialias: false,
        preserveDrawingBuffer: true
      }) || canvas.getContext('experimental-webgl', {
        alpha: true,
        premultipliedAlpha: false,
        antialias: false,
        preserveDrawingBuffer: true
      });
      if (gl) return createWebGlLiquidRenderer(canvas, gl);
    } catch (_) {}
    const ctx = canvas.getContext('2d', { alpha: true });
    return createCanvasLiquidRenderer(canvas, ctx);
  }

  window.DWRTLiquidGlass = window.DWRTLiquidGlass || {};
  window.DWRTLiquidGlass.createRenderer = createLiquidGlassRenderer;
  window.DWRTLiquidGlass.createLiquidGlassRenderer = createLiquidGlassRenderer;
  window.DWRTLiquidGlass.createCanvasLiquidRenderer = createCanvasLiquidRenderer;
  window.DWRTLiquidGlass.createWebGlLiquidRenderer = createWebGlLiquidRenderer;
})();
