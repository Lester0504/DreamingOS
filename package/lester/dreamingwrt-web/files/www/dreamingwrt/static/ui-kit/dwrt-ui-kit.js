(() => {
  'use strict';

  const tabState = new WeakMap();
  const tabMemory = new Map();
  const sheetState = new WeakMap();
  const modalState = new WeakMap();
  const expandSearchState = new WeakMap();
  const expandSearchIntent = new Map();
  const tooltipState = new WeakMap();
  const componentState = new WeakMap();
  const virtualTableState = new WeakMap();
  const dataGridState = new WeakMap();
  let activeDatePicker = null;
  let activeTooltip = null;
  let lastTrigger = null;
  let sheetWallpaperObserver = null;

  const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

  function lucideIcon(name, options = {}) {
    const library = window.lucide;
    if (!library?.createElement || !library.icons || !name) return '';
    const rawName = String(name).trim();
    const componentName = rawName
      .split(/[^a-zA-Z0-9]+/)
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join('');
    const definition = library.icons[rawName]
      || library.icons[componentName]
      || library[rawName]
      || library[componentName];
    if (!definition) return '';
    const size = Math.max(1, Number(options.size) || 24);
    const ariaLabel = String(options.ariaLabel || '').trim();
    const attributes = {
      width: size,
      height: size,
      class: String(options.className || 'dwrt-lucide-icon'),
      'stroke-width': Math.max(0.5, Number(options.strokeWidth) || 2),
      focusable: 'false',
      ...(ariaLabel ? { role: 'img', 'aria-label': ariaLabel } : { 'aria-hidden': 'true' })
    };
    return library.createElement(definition, attributes).outerHTML;
  }

  function mountLucide(context = document, attributes = {}) {
    if (!window.lucide?.icons || !context?.querySelectorAll) return false;
    const roots = context instanceof Element && context.matches('[data-lucide]:not([data-dwrt-lucide-mounted])')
      ? [context]
      : [];
    const placeholders = roots.concat(Array.from(context.querySelectorAll('[data-lucide]:not([data-dwrt-lucide-mounted])')));
    placeholders.forEach((placeholder) => {
      const name = placeholder.getAttribute('data-lucide');
      const markup = lucideIcon(name, {
        size: Number(attributes.width || placeholder.getAttribute('width')) || 24,
        strokeWidth: Number(attributes['stroke-width'] || placeholder.getAttribute('stroke-width')) || 2,
        className: [placeholder.getAttribute('class'), attributes.class].filter(Boolean).join(' ') || 'dwrt-lucide-icon',
        ariaLabel: placeholder.getAttribute('aria-label') || attributes['aria-label'] || ''
      });
      if (!markup) return;
      const template = document.createElement('template');
      template.innerHTML = markup;
      const svg = template.content.firstElementChild;
      if (!svg) return;
      svg.setAttribute('data-lucide', name);
      svg.setAttribute('data-dwrt-lucide-mounted', 'true');
      placeholder.getAttributeNames().forEach((attribute) => {
        if (attribute !== 'data-lucide' && attribute !== 'class') svg.setAttribute(attribute, placeholder.getAttribute(attribute));
      });
      placeholder.replaceWith(svg);
    });
    return placeholders.length > 0;
  }

  function triggerSelector(element) {
    if (!(element instanceof Element)) return '';
    if (element.id) return `#${CSS.escape(element.id)}`;
    const data = Array.from(element.attributes).find((attribute) => attribute.name.startsWith('data-') && !attribute.name.startsWith('data-dwrt-'));
    if (data) return `[${CSS.escape(data.name)}${data.value ? `="${CSS.escape(data.value)}"` : ''}]`;
    const label = element.getAttribute('aria-label');
    return label ? `[aria-label="${CSS.escape(label)}"]` : '';
  }

  function rememberTrigger(element) {
    if (!(element instanceof HTMLElement)) return;
    lastTrigger = { element, selector: triggerSelector(element), at: performance.now() };
  }

  function springStep(value, velocity, target, dt, response = 0.34, damping = 1) {
    const omega = (Math.PI * 2) / response;
    const acceleration = omega * omega * (target - value) - 2 * damping * omega * velocity;
    const nextVelocity = velocity + acceleration * dt;
    return [value + nextVelocity * dt, nextVelocity];
  }

  function settled(value, velocity, target, epsilon = 0.12) {
    return Math.abs(target - value) < epsilon && Math.abs(velocity) < epsilon * 8;
  }

  function ensureTabPill(root) {
    let pill = root.querySelector(':scope > .dwrt-kit-tab-pill');
    if (!pill) {
      pill = document.createElement('span');
      pill.className = 'dwrt-kit-tab-pill';
      pill.setAttribute('aria-hidden', 'true');
      root.prepend(pill);
    }
    return pill;
  }

  function activeTab(root) {
    return root.querySelector('.dwrt-kit-tab.is-active, .dwrt-kit-tab[aria-selected="true"]') || root.querySelector('.dwrt-kit-tab');
  }

  function tabGroupKey(root) {
    const label = root.dataset.dwrtTabsKey || root.getAttribute('aria-label') || '';
    return label ? `${window.location.hash}|${label}` : '';
  }

  function updateTabs(root, smooth = true) {
    if (!root) return;
    const pill = ensureTabPill(root);
    const active = activeTab(root);
    if (!active || !root.offsetWidth || !active.offsetWidth) {
      pill.classList.remove('is-visible');
      return;
    }
    const next = {
      x: active.offsetLeft,
      y: active.offsetTop,
      w: active.offsetWidth,
      h: active.offsetHeight
    };
    let state = tabState.get(root);
    if (!state) {
      const key = tabGroupKey(root);
      state = key ? tabMemory.get(key) : null;
      if (state?.frame) cancelAnimationFrame(state.frame);
      if (state) {
        state.frame = 0;
        state.last = 0;
      } else {
        state = {
          x: next.x, y: next.y, w: next.w, h: next.h,
          vx: 0, vy: 0, vw: 0, vh: 0,
          target: next, frame: 0, last: 0
        };
      }
      tabState.set(root, state);
      if (key) tabMemory.set(key, state);
    }
    state.target = next;
    pill.classList.add('is-visible');
    const paint = () => {
      pill.style.transform = `translate3d(${state.x}px, ${state.y}px, 0)`;
      pill.style.width = `${state.w}px`;
      pill.style.height = `${state.h}px`;
    };
    if (!smooth || reducedMotion()) {
      Object.assign(state, { x: next.x, y: next.y, w: next.w, h: next.h, vx: 0, vy: 0, vw: 0, vh: 0 });
      if (state.frame) cancelAnimationFrame(state.frame);
      state.frame = 0;
      paint();
      return;
    }
    if (state.frame) return;
    state.last = performance.now();
    const tick = (now) => {
      const dt = Math.min(0.032, Math.max(0.001, (now - state.last) / 1000));
      state.last = now;
      [state.x, state.vx] = springStep(state.x, state.vx, state.target.x, dt);
      [state.y, state.vy] = springStep(state.y, state.vy, state.target.y, dt);
      [state.w, state.vw] = springStep(state.w, state.vw, state.target.w, dt);
      [state.h, state.vh] = springStep(state.h, state.vh, state.target.h, dt);
      paint();
      const done = settled(state.x, state.vx, state.target.x)
        && settled(state.y, state.vy, state.target.y)
        && settled(state.w, state.vw, state.target.w)
        && settled(state.h, state.vh, state.target.h);
      if (done || !pill.isConnected) {
        Object.assign(state, { x: state.target.x, y: state.target.y, w: state.target.w, h: state.target.h, vx: 0, vy: 0, vw: 0, vh: 0, frame: 0 });
        if (pill.isConnected) paint();
        return;
      }
      state.frame = requestAnimationFrame(tick);
    };
    state.frame = requestAnimationFrame(tick);
  }

  function setActiveTab(root, value, notify = true) {
    const tabs = Array.from(root.querySelectorAll('.dwrt-kit-tab'));
    const target = tabs.find((tab) => tab.dataset.value === value || tab.dataset.tab === value || tab.getAttribute('aria-controls') === value) || tabs[0];
    if (!target) return '';
    tabs.forEach((tab) => {
      const active = tab === target;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.tabIndex = active ? 0 : -1;
    });
    updateTabs(root, true);
    if (notify) {
      root.dispatchEvent(new CustomEvent('dwrt-tab-change', {
        bubbles: true,
        detail: { value: target.dataset.value || target.dataset.tab || target.textContent.trim(), tab: target }
      }));
    }
    return target.dataset.value || target.dataset.tab || '';
  }

  function mountTabs(root) {
    if (!root || root.dataset.dwrtTabsMounted === 'true') return;
    root.dataset.dwrtTabsMounted = 'true';
    root.setAttribute('role', root.getAttribute('role') || 'tablist');
    ensureTabPill(root);
    Array.from(root.querySelectorAll('.dwrt-kit-tab')).forEach((tab) => {
      tab.setAttribute('role', tab.getAttribute('role') || 'tab');
      tab.type = tab.type || 'button';
      tab.addEventListener('click', () => setActiveTab(root, tab.dataset.value || tab.dataset.tab || tab.textContent.trim()));
    });
    root.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      const tabs = Array.from(root.querySelectorAll('.dwrt-kit-tab:not(:disabled)'));
      if (!tabs.length) return;
      const current = Math.max(0, tabs.indexOf(document.activeElement));
      const index = event.key === 'Home' ? 0
        : event.key === 'End' ? tabs.length - 1
          : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      event.preventDefault();
      tabs[index].focus();
      setActiveTab(root, tabs[index].dataset.value || tabs[index].dataset.tab || tabs[index].textContent.trim());
    });
    updateTabs(root, true);
  }

  function sheetOverlay(sheet) {
    const previous = sheet.previousElementSibling;
    if (previous?.classList.contains('dwrt-kit-sheet-overlay')) return previous;
    return null;
  }

  /*
   * 抽屉传送门。
   *
   * `.dwrt-kit-sheet` 靠 `position: fixed` 贴住视口右侧，但只要祖先链上任意一个元素带了
   * transform / filter / contain / will-change / perspective，它就会成为新的包含块，抽屉
   * 被重新锚定，表现为「掉到页面下方、整宽、被裁切」。页面壳层为了玻璃采样和滚动性能大量
   * 使用这些属性，逐个摘掉属性是打地鼠。
   *
   * 这里改为在挂载时把抽屉连同它的遮罩一起搬到 body 直属的 portal 层（AI 抽屉一直挂在
   * body 级的 .ai-global-layer 里，所以从来不犯这个病）。搬迁保持「遮罩紧邻抽屉之前」的
   * 兄弟关系，因为 sheetOverlay() 依赖它；并记住原位锚点，卸载时归位，避免页面模块重绘
   * 时找不到自己的节点。
   */
  const SHEET_PORTAL_ID = 'dwrtKitSheetPortal';

  function sheetPortal() {
    if (!document.body) return null;
    let portal = document.getElementById(SHEET_PORTAL_ID);
    if (!portal) {
      portal = document.createElement('div');
      portal.id = SHEET_PORTAL_ID;
      portal.className = 'dwrt-kit-sheet-portal';
      document.body.appendChild(portal);
    } else if (portal.parentElement !== document.body) {
      document.body.appendChild(portal);
    }
    return portal;
  }

  /*
   * 传送门的副作用：抽屉一旦离开路由宿主，页面 CSS 里所有以宿主为前缀的规则
   * （`.xxx-route-host .dwrt-kit-sheet …`）和挂在页面壳层上的自定义属性
   * （`.wifi-management-shell { --wifi-line: … }`）在抽屉内部同时失效。变量失效会让
   * `border: 1px solid var(--wifi-line)` 这类整条声明作废，表现为边框消失、下拉框回落
   * 成浏览器原生白底。
   *
   * 因此搬迁时把原祖先链上承载样式作用域的类名镜像到 portal 上：portal 自身不参与布局
   * （width/height 为 0、position: static），只作为样式作用域的替身。
   */
  const PORTAL_SCOPE_PATTERN = /(?:-route-host|-shell|-workspace|-layout|-scope)$/;

  function scopeClassesFor(node) {
    const classes = [];
    let cursor = node?.parentElement;
    let depth = 0;
    while (cursor && cursor !== document.body && depth < 12) {
      cursor.classList.forEach((name) => {
        if (PORTAL_SCOPE_PATTERN.test(name) && !classes.includes(name)) classes.push(name);
      });
      cursor = cursor.parentElement;
      depth += 1;
    }
    return classes;
  }

  function applyPortalScope(portal, classes) {
    const previous = portal.dataset.dwrtPortalScope ? portal.dataset.dwrtPortalScope.split(' ').filter(Boolean) : [];
    previous.forEach((name) => { if (!classes.includes(name)) portal.classList.remove(name); });
    classes.forEach((name) => portal.classList.add(name));
    if (classes.length) portal.dataset.dwrtPortalScope = classes.join(' ');
    else delete portal.dataset.dwrtPortalScope;
  }

  /*
   * 页面模块通常靠重绘整段 innerHTML 来关抽屉，被搬走的节点直接消失，unmountSheet() 不会
   * 被调用。留在 portal 上的作用域类名于是会跨路由残留，下一页的抽屉可能吃到上一页的
   * 变量。这里在 portal 变空时把作用域收回。
   */
  function pruneSheetPortal() {
    const portal = document.getElementById(SHEET_PORTAL_ID);
    if (!portal) return;
    if (!portal.dataset.dwrtPortalScope) return;
    if (portal.querySelector('.dwrt-kit-sheet, [data-dwrt-component="sheet"], [data-dwrt-component="filter-sheet"]')) return;
    portal.querySelectorAll('.dwrt-kit-sheet-overlay').forEach((node) => node.remove());
    applyPortalScope(portal, []);
  }

  function disposeSheet(sheet) {
    const state = sheetState.get(sheet);
    if (state?.frame) cancelAnimationFrame(state.frame);
    state?.observer?.disconnect();
    if (state?.onDocumentKeydown) document.removeEventListener('keydown', state.onDocumentKeydown, true);
    state?.releaseDelegation?.();
    sheetState.delete(sheet);
    sheetOverlay(sheet)?.remove();
    sheet.remove();
  }

  /*
   * 事件委托的接续。
   *
   * 页面模块普遍把交互绑成一条委托：`root.addEventListener('click', onClick)`，再在处理器里
   * 用 `target.matches('[data-...]')` 分派。抽屉被搬到 body 级 portal 之后就不再是 root 的
   * 后代，冒泡永远到不了那条委托，抽屉里的按钮、下拉、输入框会集体失灵 —— 「点关闭没反应」
   * 就是这个原因。
   *
   * 这里让 portal 里的抽屉把事件按原宿主重放：克隆一个同类型事件派发到宿主上，并把
   * `target` 指回真实的抽屉内节点，页面既有的委托无需改动即可继续工作。
   */
  const DELEGATED_EVENTS = ['click', 'input', 'change', 'submit', 'keydown'];

  function bindSheetDelegation(sheet, state) {
    /*
     * 转发目标不能只取抽屉的直接父节点。页面模块通常把委托绑在更外层的路由根（`context.root`
     * 即 `#routePreview`）上，而抽屉的父节点往往是页面壳层 `.xxx-shell`。因为重放事件刻意
     * 不冒泡（避免 document 级处理器把同一次交互跑两遍），派发到壳层就到不了那条委托。
     * 这里沿原祖先链一直派发到路由根，逐级触发，等价于事件正常冒泡到 root 的效果。
     */
    const chain = [];
    let cursor = state.portalHome?.parent;
    while (cursor && cursor !== document.body) {
      chain.push(cursor);
      if (cursor.id === 'routePreview' || cursor.classList.contains('route-preview')) break;
      cursor = cursor.parentElement;
    }
    if (!chain.length || state.releaseDelegation) return;
    const listeners = [];
    state.relayToHost = (event) => {
      if (chain[0]?.contains(sheet)) return;
      let prevented = false;
      chain.forEach((node) => {
        if (!node.isConnected) return;
        const replay = new event.constructor(event.type, { ...eventInit(event), bubbles: false, composed: false });
        replay.dwrtSheetRelayed = true;
        Object.defineProperty(replay, 'target', { value: event.target, configurable: true });
        node.dispatchEvent(replay);
        prevented = prevented || replay.defaultPrevented;
      });
      if (prevented) event.preventDefault();
    };
    DELEGATED_EVENTS.forEach((type) => {
      const relay = (event) => {
        if (event.dwrtSheetRelayed) return;
        state.relayToHost(event);
      };
      sheet.addEventListener(type, relay);
      listeners.push([type, relay]);
    });
    state.releaseDelegation = () => {
      listeners.forEach(([type, relay]) => sheet.removeEventListener(type, relay));
      delete state.releaseDelegation;
      delete state.relayToHost;
    };
  }

  function eventInit(event) {
    const init = { cancelable: event.cancelable };
    ['detail', 'button', 'buttons', 'clientX', 'clientY', 'ctrlKey', 'shiftKey', 'altKey', 'metaKey', 'key', 'code', 'data', 'inputType']
      .forEach((name) => { if (name in event && event[name] !== undefined) init[name] = event[name]; });
    return init;
  }

  /*
   * 页面模块关抽屉的做法是重绘整段 innerHTML，重绘后的标记里不再包含抽屉。但抽屉此刻已经
   * 被搬进 portal，既不在路由子树里被重绘冲掉，也不会被 `unmount(root)` 扫到，于是它带着
   * is-open 永久留在 portal 中；下一次开抽屉又插一份，选择器可能命中残留的那个，表现为
   * 「点了没反应」。
   *
   * 判定方式是记住每个被搬迁抽屉的原始宿主（`state.portalHome.parent`）。宿主的内容一旦被
   * 重绘，节点就不再是宿主的后代 —— 用这一点识别孤儿并回收。
   */
  function reclaimStaleSheets(context) {
    const portal = document.getElementById(SHEET_PORTAL_ID);
    if (!portal || !portal.firstElementChild) return;
    const host = context?.nodeType === 1 ? context : null;
    Array.from(portal.children).forEach((node) => {
      if (!node.matches?.('.dwrt-kit-sheet, [data-dwrt-component="sheet"], [data-dwrt-component="filter-sheet"]')) return;
      const state = sheetState.get(node);
      const home = state?.portalHome?.parent;
      // 宿主已脱离文档：这份抽屉确实和页面失联了
      if (!home || !home.isConnected) { disposeSheet(node); return; }
      if (home !== host && !host?.contains(home)) return;
      /*
       * 到这里说明本次 mountAll 的 context 就是这份抽屉的原宿主。这**不足以**判定
       * 它是孤儿：`mountSheet()` 会把刚建好的抽屉搬进 portal，此后宿主依旧健在，
       * 于是"打开抽屉后任何一次 mountAll(root) 都会把它当孤儿销毁"，表现就是
       * 抽屉一闪即消（实测 1 → 0，涉及抽屉的认证与管控页面几乎全中）。
       *
       * 真正的孤儿判据是宿主的**内容被换过**。页面模块关抽屉的惯用手法是重写
       * 宿主 innerHTML，那会把锚点兄弟节点一起换掉；而单纯的重复 mount 不会。
       * 所以搬迁时记下宿主当时的首个子节点，用它是否还在原位来区分两者。
       */
      const anchor = state.portalHome.hostAnchor;
      if (anchor) {
        // 探针还在原位 => 宿主没被重绘，抽屉仍然有效
        if (anchor.isConnected && anchor.parentElement === home) return;
        disposeSheet(node);
        return;
      }
      /*
       * 搬迁时宿主里除了抽屉本身没有别的子节点，拿不到探针。这种情况下无法区分
       * 重绘与重复 mount，宁可留着：误留一个抽屉用户可以自己关掉，误杀会让
       * 功能整个不可用（这正是本次修的缺陷）。宿主若真的脱离文档，上面第一条
       * 判据已经回收过了。
       */
    });
    pruneSheetPortal();
  }

  function watchSheetPortal() {
    const portal = sheetPortal();
    if (!portal || portal.dataset.dwrtPortalWatched === 'true') return;
    portal.dataset.dwrtPortalWatched = 'true';
    new MutationObserver(() => pruneSheetPortal()).observe(portal, { childList: true });
  }

  function elevateSheet(sheet, state) {
    const portal = sheetPortal();
    if (!portal || sheet.parentElement === portal) return;
    const overlay = sheetOverlay(sheet);
    // 原位锚点：优先记录一个稳定的兄弟节点，卸载时据此归位
    state.portalHome = {
      parent: (overlay || sheet).parentElement,
      before: (overlay || sheet).nextElementSibling === sheet ? sheet.nextElementSibling : (overlay || sheet).nextElementSibling,
      /*
       * 存活探针：搬迁时宿主里的第一个「不是本抽屉、也不是本遮罩」的子节点。
       * 宿主 innerHTML 被重写时它会被换掉，`reclaimStaleSheets()` 据此判定抽屉
       * 真的成了孤儿；而重复 mount 不动宿主内容，探针仍在原位，抽屉就不该被销毁。
       */
      hostAnchor: (() => {
        const parent = (overlay || sheet).parentElement;
        if (!parent) return null;
        return Array.from(parent.children).find((child) => child !== sheet && child !== overlay) || null;
      })()
    };
    state.portalScope = scopeClassesFor(sheet);
    applyPortalScope(portal, state.portalScope);
    if (overlay) portal.appendChild(overlay);
    portal.appendChild(sheet);
    sheet.dataset.dwrtSheetPortaled = 'true';
    bindSheetDelegation(sheet, state);
    watchSheetPortal();
  }

  function restoreSheetHome(sheet, state) {
    const home = state?.portalHome;
    if (!home?.parent?.isConnected) return;
    const overlay = sheetOverlay(sheet);
    const before = home.before?.isConnected ? home.before : null;
    if (overlay) home.parent.insertBefore(overlay, before);
    home.parent.insertBefore(sheet, before);
    delete sheet.dataset.dwrtSheetPortaled;
    state.releaseDelegation?.();
    // portal 里还留着别的抽屉时保留它们需要的作用域，全空了再清干净
    pruneSheetPortal();
  }

  function paintSheet(sheet, state) {
    const width = Math.max(1, sheet.getBoundingClientRect().width || state.width || 1);
    state.width = width;
    const progress = Math.max(0, Math.min(1, state.x / width));
    sheet.style.transform = `translate3d(${state.x}px, 0, 0)`;
    sheet.style.opacity = String(1 - progress * 0.18);
    const overlay = sheetOverlay(sheet);
    if (overlay) overlay.style.opacity = String(1 - progress);
  }

  function animateSheet(sheet, target, velocity = 0, onFinish = null) {
    const state = sheetState.get(sheet);
    if (!state) return;
    if (state.frame) cancelAnimationFrame(state.frame);
    state.frame = 0;
    state.v = Number.isFinite(velocity) ? velocity : state.v;
    state.target = target;
    if (reducedMotion()) {
      state.x = target;
      state.v = 0;
      paintSheet(sheet, state);
      onFinish?.();
      return;
    }
    state.last = performance.now();
    const startedAt = state.last;
    const tick = (now) => {
      const dt = Math.min(0.032, Math.max(0.001, (now - state.last) / 1000));
      state.last = now;
      [state.x, state.v] = springStep(state.x, state.v, state.target, dt, 0.3, 0.86);
      paintSheet(sheet, state);
      if (settled(state.x, state.v, state.target, 0.35) || now - startedAt >= 480 || !sheet.isConnected) {
        state.x = state.target;
        state.v = 0;
        state.frame = 0;
        if (sheet.isConnected) paintSheet(sheet, state);
        onFinish?.();
        return;
      }
      state.frame = requestAnimationFrame(tick);
    };
    state.frame = requestAnimationFrame(tick);
  }

  function restoreSheetFocus(state, attempts = 24, stableFrames = 0, stableTarget = null) {
    const selector = state.sheet?.dataset.dwrtReturnFocus || state.triggerSelector || '';
    const selected = selector ? document.querySelector(selector) : null;
    const target = selected instanceof HTMLElement ? selected : state.trigger?.isConnected ? state.trigger : null;
    if (target instanceof HTMLElement) {
      const active = document.activeElement;
      if (active !== target && active instanceof HTMLElement && active !== document.body && !state.sheet?.contains(active) && active.matches('button, [role="button"], a, input, select, textarea')) return;
      if (active !== target) target.focus({ preventScroll: true });
      const stable = document.activeElement === target && target === stableTarget ? stableFrames + 1 : document.activeElement === target ? 1 : 0;
      if (stable >= 3) {
        state.sheet?.dispatchEvent(new CustomEvent('dwrt-sheet-focus-restored', {
          bubbles: true,
          detail: { returnFocus: selector, target }
        }));
        return;
      }
      if (attempts > 0) requestAnimationFrame(() => restoreSheetFocus(state, attempts - 1, stable, target));
      return;
    }
    if (attempts > 0) requestAnimationFrame(() => restoreSheetFocus(state, attempts - 1, 0, null));
  }

  function sheetFocusable(sheet) {
    return Array.from(sheet.querySelectorAll('button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])'))
      .filter((element) => element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden');
  }

  function focusSheet(sheet) {
    requestAnimationFrame(() => requestAnimationFrame(() => {
      if (!sheet.isConnected || !sheet.classList.contains('is-open')) return;
      const target = sheet.querySelector('[autofocus], input:not(:disabled), select:not(:disabled), textarea:not(:disabled)') || sheetFocusable(sheet)[0];
      target instanceof HTMLElement && target.focus({ preventScroll: true });
    }));
  }

  function commitSheetClose(sheet, target) {
    const state = sheetState.get(sheet);
    if (!state || state.closing) return;
    state.closing = true;
    const width = Math.max(1, sheet.getBoundingClientRect().width);
    animateSheet(sheet, width, state.v, () => {
      if (!target?.isConnected) return;
      target.dataset.dwrtSheetBypass = 'true';
      target.click();
      delete target.dataset.dwrtSheetBypass;
      requestAnimationFrame(() => {
        state.closing = false;
        state.x = width;
        state.v = 0;
        restoreSheetFocus(state);
      });
    });
  }

  function syncSheetWallpaper(sheet) {
    const wallpaper = document.getElementById('appWallpaper');
    const image = sheet?.querySelector?.('[data-dwrt-sheet-wallpaper-image]');
    if (!wallpaper || !image) return;
    const src = wallpaper.currentSrc || wallpaper.getAttribute('src') || '';
    if (src && image.getAttribute('src') !== src) image.setAttribute('src', src);
    const style = getComputedStyle(wallpaper);
    image.style.objectFit = style.objectFit || 'cover';
    image.style.objectPosition = style.objectPosition || '50% 50%';
    image.style.filter = style.filter || 'none';
    image.style.opacity = style.opacity || '1';
    const rect = sheet.getBoundingClientRect();
    image.style.right = 'auto';
    image.style.left = `${-rect.left}px`;
    image.style.top = `${-rect.top}px`;
  }

  function syncMountedGlassWallpapers() {
    document.querySelectorAll('.dwrt-kit-sheet[data-dwrt-sheet-variant="copilot"], .dwrt-kit-modal[data-dwrt-modal-variant="copilot"]').forEach(syncSheetWallpaper);
  }

  function ensureSheetMaterial(sheet) {
    const explicitModalCopilot = sheet?.dataset?.dwrtModalVariant === 'copilot';
    if (!sheet || (!explicitModalCopilot && (sheet.dataset.dwrtSheetVariant === 'fullscreen' || sheet.dataset.dwrtSheetFullscreen === 'true'))) return;
    if (sheet.dataset.dwrtSheetVariant === 'copilot' || explicitModalCopilot) {
      const materialReady = sheet.querySelector(':scope > .dwrt-kit-sheet-wallpaper') && sheet.querySelector(':scope > .dwrt-kit-sheet-material');
      if (materialReady) {
        syncSheetWallpaper(sheet);
        return;
      }
    }
    const explicitCopilot = sheet.dataset.dwrtSheetVariant === 'copilot' || explicitModalCopilot;
    if (!explicitCopilot) {
      const width = sheet.getBoundingClientRect().width;
      if (width <= 0) return;
      if (width >= window.innerWidth * 0.9) {
        sheet.dataset.dwrtSheetVariant = 'fullscreen';
        return;
      }
      sheet.dataset.dwrtSheetVariant = sheet.dataset.dwrtSheetVariant || 'copilot';
    }
    const legacySurfaceClasses = ['dwrt-kit-glass-surface', 'dwrt-glass-card', 'client-stable-glass', 'policy-stable-glass'];
    const appliedLegacyClasses = legacySurfaceClasses.filter((name) => sheet.classList.contains(name));
    if (appliedLegacyClasses.length) sheet.classList.remove(...appliedLegacyClasses);
    sheet.dataset.dwrtSurface = sheet.dataset.dwrtSurface || 'stable-glass';
    if (!sheet.querySelector(':scope > .dwrt-kit-sheet-wallpaper')) {
      const wallpaper = document.createElement('div');
      wallpaper.className = 'dwrt-kit-sheet-wallpaper';
      wallpaper.setAttribute('aria-hidden', 'true');
      wallpaper.innerHTML = '<img data-dwrt-sheet-wallpaper-image alt="">';
      const material = document.createElement('div');
      material.className = 'dwrt-kit-sheet-material';
      material.setAttribute('aria-hidden', 'true');
      sheet.prepend(material);
      sheet.prepend(wallpaper);
    }
    syncSheetWallpaper(sheet);
    const appWallpaper = document.getElementById('appWallpaper');
    if (!sheetWallpaperObserver && appWallpaper && typeof MutationObserver !== 'undefined') {
      const sync = () => requestAnimationFrame(syncMountedGlassWallpapers);
      appWallpaper.addEventListener('load', sync);
      sheetWallpaperObserver = new MutationObserver(sync);
      sheetWallpaperObserver.observe(appWallpaper, { attributes: true, attributeFilter: ['src', 'style', 'class'] });
    }
  }

  function mountSheet(sheet) {
    if (!sheet || sheetState.has(sheet)) return;
    ensureSheetMaterial(sheet);
    const recentTrigger = lastTrigger && performance.now() - lastTrigger.at < 1200 ? lastTrigger : null;
    const settleImmediately = sheet.dataset.dwrtSheetMotion === 'settled';
    const state = {
      x: 0,
      v: 0, width: 0,
      target: 0, frame: 0, last: 0, dragging: false, closing: false,
      pointerId: null, startX: 0, startOffset: 0, samples: [],
      sheet,
      trigger: recentTrigger?.element || (document.activeElement?.matches?.('button, [role="button"], a') ? document.activeElement : null),
      triggerSelector: recentTrigger?.selector || (document.activeElement?.matches?.('button, [role="button"], a') ? triggerSelector(document.activeElement) : '')
    };
    // 先搬到 body 层再量宽度：在被重锚定的祖先里量出来的是错的
    elevateSheet(sheet, state);
    const initialWidth = sheet.getBoundingClientRect().width;
    state.width = initialWidth;
    state.x = settleImmediately ? 0 : initialWidth;
    sheetState.set(sheet, state);
    state.observer = new MutationObserver(() => syncSheetOpenState(sheet));
    state.observer.observe(sheet, { attributes: true, attributeFilter: ['class'] });
    if (state.triggerSelector) sheet.dataset.dwrtReturnFocus = state.triggerSelector;
    sheet.setAttribute('role', sheet.getAttribute('role') || 'dialog');
    sheet.setAttribute('aria-modal', sheet.getAttribute('aria-modal') || 'true');
    const header = sheet.querySelector('.dwrt-kit-sheet-header');
    const close = sheet.querySelector('.dwrt-kit-sheet-close');
    const interceptClose = (event) => {
      /*
       * 关闭分两拍：第一拍拦下点击、放完滑出动画，第二拍带 bypass 标记重放，让页面自己的
       * 处理器去清状态。抽屉被搬进 portal 后已经不是路由根的后代，第二拍的冒泡到不了页面那条
       * 委托，于是把它显式转发到原宿主上，否则表现为「抽屉滑走了但选中状态还在、再点无反应」。
       */
      if (event.currentTarget.dataset.dwrtSheetBypass === 'true') {
        state.relayToHost?.(event);
        return;
      }
      if (!sheet.classList.contains('is-open')) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      commitSheetClose(sheet, event.currentTarget);
    };
    const onDocumentKeydown = (event) => {
      if (event.key !== 'Escape' || !sheet.classList.contains('is-open')) return;
      const openSheets = Array.from(document.querySelectorAll('.dwrt-kit-sheet.is-open'));
      if (openSheets.at(-1) !== sheet) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      commitSheetClose(sheet, close || sheetOverlay(sheet));
    };
    state.interceptClose = interceptClose;
    state.onDocumentKeydown = onDocumentKeydown;
    const bindOverlay = () => {
      const overlay = sheetOverlay(sheet);
      if (!overlay || overlay.dataset.dwrtSheetBound === 'true') return overlay;
      overlay.dataset.dwrtSheetBound = 'true';
      overlay.classList.add('is-open');
      requestAnimationFrame(() => {
        if (overlay.isConnected) overlay.addEventListener('click', interceptClose, true);
      });
      return overlay;
    };
    state.bindOverlay = bindOverlay;
    bindOverlay();
    close?.addEventListener('click', interceptClose, true);
    document.addEventListener('keydown', onDocumentKeydown, true);
    sheet.addEventListener('keydown', (event) => {
      if (event.key !== 'Tab') return;
      const controls = sheetFocusable(sheet);
      if (!controls.length) {
        event.preventDefault();
        sheet.focus({ preventScroll: true });
        return;
      }
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus({ preventScroll: true });
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus({ preventScroll: true });
      }
    });
    header?.classList.add('dwrt-kit-sheet-drag-handle');
    header?.addEventListener('pointerdown', (event) => {
      if (event.button !== 0 || event.target.closest('button, input, select, textarea, a')) return;
      if (state.frame) cancelAnimationFrame(state.frame);
      state.frame = 0;
      state.dragging = true;
      state.closing = false;
      state.pointerId = event.pointerId;
      state.startX = event.clientX;
      state.startOffset = state.x;
      state.samples = [{ x: event.clientX, t: performance.now() }];
      header.setPointerCapture(event.pointerId);
      sheet.classList.add('is-direct-manipulation');
      event.preventDefault();
    });
    header?.addEventListener('pointermove', (event) => {
      if (!state.dragging || event.pointerId !== state.pointerId) return;
      const raw = state.startOffset + event.clientX - state.startX;
      const width = Math.max(1, state.width);
      state.x = raw < 0 ? -((-raw * width * 0.22) / (width + 0.22 * -raw)) : raw;
      const now = performance.now();
      state.samples.push({ x: event.clientX, t: now });
      state.samples = state.samples.filter((sample) => now - sample.t <= 90).slice(-6);
      paintSheet(sheet, state);
    });
    const endDrag = (event) => {
      if (!state.dragging || event.pointerId !== state.pointerId) return;
      state.dragging = false;
      sheet.classList.remove('is-direct-manipulation');
      const first = state.samples[0];
      const last = state.samples[state.samples.length - 1];
      const velocity = first && last && last.t > first.t ? ((last.x - first.x) / (last.t - first.t)) * 1000 : 0;
      state.v = velocity;
      const projected = state.x + (velocity / 1000) * 0.99 / (1 - 0.99);
      const dismiss = projected > state.width * 0.42 || velocity > 720;
      if (dismiss) commitSheetClose(sheet, sheetOverlay(sheet) || close);
      else animateSheet(sheet, 0, velocity);
    };
    header?.addEventListener('pointerup', endDrag);
    header?.addEventListener('pointercancel', endDrag);
    if (sheet.classList.contains('is-open')) {
      sheet.setAttribute('aria-hidden', 'false');
      paintSheet(sheet, state);
      if (!settleImmediately) animateSheet(sheet, 0, 0);
      focusSheet(sheet);
    }
  }

  function syncSheetOpenState(sheet) {
    const state = sheetState.get(sheet);
    if (!state || state.dragging || state.closing) return;
    state.bindOverlay?.();
    if (sheet.classList.contains('is-open') && state.x >= state.width * 0.95) {
      ensureSheetMaterial(sheet);
      const recent = lastTrigger && performance.now() - lastTrigger.at < 1200 ? lastTrigger : null;
      const candidate = recent?.element || (document.activeElement?.matches?.('button, [role="button"], a') ? document.activeElement : null);
      state.trigger = candidate || state.trigger;
      state.triggerSelector = recent?.selector || triggerSelector(candidate) || state.triggerSelector;
      if (state.triggerSelector) sheet.dataset.dwrtReturnFocus = state.triggerSelector;
      sheet.setAttribute('aria-hidden', 'false');
      paintSheet(sheet, state);
      animateSheet(sheet, 0, 0);
      focusSheet(sheet);
    }
  }

  function unmountSheet(sheet) {
    const state = sheetState.get(sheet);
    if (!state) return;
    if (state.frame) cancelAnimationFrame(state.frame);
    state.observer?.disconnect();
    document.removeEventListener('keydown', state.onDocumentKeydown, true);
    restoreSheetHome(sheet, state);
    sheetState.delete(sheet);
  }

  function syncMountedSheetGeometry() {
    document.querySelectorAll('.dwrt-kit-sheet, [data-dwrt-component="sheet"], [data-dwrt-component="filter-sheet"]').forEach((sheet) => {
      const state = sheetState.get(sheet);
      if (!state || state.dragging) return;
      const width = Math.max(1, sheet.offsetWidth || Number.parseFloat(getComputedStyle(sheet).width) || state.width || 1);
      state.width = width;
      if (sheet.classList.contains('is-open')) {
        state.target = state.closing ? width : 0;
        if (!state.frame && !state.closing) {
          state.x = 0;
          state.v = 0;
        }
      } else {
        if (state.frame) cancelAnimationFrame(state.frame);
        state.frame = 0;
        state.closing = false;
        state.target = width;
        state.x = width;
        state.v = 0;
      }
      paintSheet(sheet, state);
    });
  }

  function componentRoots(context, name) {
    const selector = `[data-dwrt-component="${name}"]`;
    const roots = context instanceof Element && context.matches(selector) ? [context] : [];
    return roots.concat(Array.from(context.querySelectorAll?.(selector) || []));
  }

  function matchingRoots(context, selector) {
    const roots = context instanceof Element && context.matches(selector) ? [context] : [];
    return roots.concat(Array.from(context.querySelectorAll?.(selector) || []));
  }

  function collectComponentRoots(context) {
    const buckets = new Map();
    matchingRoots(context, '[data-dwrt-component], .dwrt-kit-tabs, .dwrt-kit-sheet, .dwrt-kit-modal-layer').forEach((root) => {
      let name = root.dataset.dwrtComponent || '';
      if (!name && root.classList.contains('dwrt-kit-tabs')) name = 'tabs';
      else if (!name && root.classList.contains('dwrt-kit-sheet')) name = 'sheet';
      else if (!name && root.classList.contains('dwrt-kit-modal-layer')) name = 'modal';
      if (!name) return;
      root.dataset.dwrtComponent = name;
      if (!buckets.has(name)) buckets.set(name, []);
      buckets.get(name).push(root);
    });
    return buckets;
  }

  function ensureElementId(element, prefix) {
    if (element.id) return element.id;
    const token = Math.random().toString(36).slice(2, 9);
    element.id = `${prefix}-${token}`;
    return element.id;
  }

  function setLoadingState(button) {
    const declaredState = button.dataset.dwrtState;
    const loading = declaredState ? declaredState === 'loading' : button.getAttribute('aria-busy') === 'true';
    button.classList.toggle('is-loading', loading);
    const busy = loading ? 'true' : 'false';
    if (button.getAttribute('aria-busy') !== busy) button.setAttribute('aria-busy', busy);
    if (loading && button.getAttribute('aria-disabled') !== 'true') button.setAttribute('aria-disabled', 'true');
    else if (!loading && !button.disabled && button.hasAttribute('aria-disabled')) button.removeAttribute('aria-disabled');
  }

  function mountButton(button) {
    if (!(button instanceof HTMLButtonElement) || componentState.has(button)) return;
    button.classList.add('dwrt-kit-button');
    const kind = button.dataset.dwrtComponent;
    if (kind === 'icon-button') {
      button.classList.add('dwrt-kit-icon-button');
      if (!button.getAttribute('aria-label') && !button.getAttribute('aria-labelledby')) {
        console.warn('[DWRT UI Kit] icon-button requires an accessible name', button);
      }
    }
    if (kind === 'async-button') setLoadingState(button);
    const observer = kind === 'async-button' ? new MutationObserver(() => setLoadingState(button)) : null;
    observer?.observe(button, { attributes: true, attributeFilter: ['data-dwrt-state', 'aria-busy', 'disabled'] });
    componentState.set(button, { observer });
  }

  function mountSelect(select) {
    if (!(select instanceof HTMLSelectElement) || componentState.has(select)) return;
    select.classList.add('dwrt-kit-select');
    select.dataset.dwrtEnhanced = 'true';
    componentState.set(select, {});
  }

  function mountCombobox(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    const trigger = root.querySelector('[data-dwrt-combobox-trigger]');
    const popover = root.querySelector('[data-dwrt-combobox-popover]');
    const listbox = root.querySelector('[data-dwrt-combobox-listbox]');
    const search = root.querySelector('[data-dwrt-combobox-search]');
    if (!(trigger instanceof HTMLButtonElement) || !(popover instanceof HTMLElement) || !(listbox instanceof HTMLElement)) return;
    root.classList.add('dwrt-kit-combobox');
    const listboxId = ensureElementId(listbox, 'dwrt-combobox-listbox');
    const multiple = root.dataset.dwrtMultiple === 'true';
    const fieldLabel = root.closest('[data-dwrt-component="field"]')?.querySelector('[data-dwrt-field-label]');
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-controls', listboxId);
    if (fieldLabel) trigger.setAttribute('aria-labelledby', ensureElementId(fieldLabel, 'dwrt-field-label'));
    listbox.setAttribute('role', 'listbox');
    if (multiple) listbox.setAttribute('aria-multiselectable', 'true');

    const options = () => Array.from(listbox.querySelectorAll('[data-dwrt-combobox-option]'));
    const selectedValues = () => options()
      .filter((option) => option.getAttribute('aria-selected') === 'true')
      .map((option) => option.dataset.value || '');
    const syncLabel = () => {
      const selected = options().filter((option) => option.getAttribute('aria-selected') === 'true');
      const label = trigger.querySelector('[data-dwrt-combobox-value]') || trigger;
      const placeholder = root.dataset.dwrtPlaceholder || '请选择';
      label.textContent = selected.length
        ? selected.map((option) => option.dataset.label || option.textContent.trim()).join('、')
        : placeholder;
      root.dataset.dwrtEmpty = selected.length ? 'false' : 'true';
    };
    const setOpen = (open, focus = false) => {
      popover.hidden = !open;
      trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
      root.dataset.dwrtOpen = open ? 'true' : 'false';
      if (!open && search instanceof HTMLInputElement) {
        search.value = '';
        options().forEach((option) => { option.hidden = false; });
      }
      if (open && focus) (search || options()[0])?.focus({ preventScroll: true });
    };
    const onTrigger = () => setOpen(popover.hidden, popover.hidden);
    const onListClick = (event) => {
      const option = event.target.closest('[data-dwrt-combobox-option]');
      if (!(option instanceof HTMLButtonElement) || option.disabled) return;
      if (!multiple) options().forEach((item) => item.setAttribute('aria-selected', item === option ? 'true' : 'false'));
      else option.setAttribute('aria-selected', option.getAttribute('aria-selected') === 'true' ? 'false' : 'true');
      syncLabel();
      root.dispatchEvent(new CustomEvent('dwrt-combobox-change', {
        bubbles: true,
        detail: { values: selectedValues(), value: selectedValues()[0] || '' }
      }));
      if (!multiple) setOpen(false);
    };
    const onSearch = () => {
      const query = String(search?.value || '').trim().toLocaleLowerCase();
      options().forEach((option) => {
        option.hidden = Boolean(query) && !String(option.dataset.label || option.textContent).toLocaleLowerCase().includes(query);
      });
    };
    const onKeydown = (event) => {
      if (event.key === 'Escape' && !popover.hidden) {
        event.preventDefault();
        setOpen(false);
        trigger.focus();
      } else if (event.key === 'ArrowDown' && document.activeElement === trigger) {
        event.preventDefault();
        setOpen(true, true);
      } else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key) && !popover.hidden) {
        const visible = options().filter((option) => !option.hidden && !option.disabled);
        if (!visible.length) return;
        const current = visible.indexOf(document.activeElement);
        const index = event.key === 'Home' ? 0
          : event.key === 'End' ? visible.length - 1
            : (Math.max(0, current) + (event.key === 'ArrowDown' ? 1 : -1) + visible.length) % visible.length;
        event.preventDefault();
        visible[index].focus();
      }
    };
    const onFocusout = (event) => {
      if (event.relatedTarget instanceof Node && root.contains(event.relatedTarget)) return;
      setOpen(false);
    };
    options().forEach((option) => {
      option.type = 'button';
      option.setAttribute('role', 'option');
      option.setAttribute('aria-selected', option.getAttribute('aria-selected') === 'true' || option.dataset.selected === 'true' ? 'true' : 'false');
    });
    trigger.addEventListener('click', onTrigger);
    listbox.addEventListener('click', onListClick);
    search?.addEventListener('input', onSearch);
    root.addEventListener('keydown', onKeydown);
    root.addEventListener('focusout', onFocusout);
    setOpen(false);
    syncLabel();
    componentState.set(root, { trigger, popover, listbox, search, onTrigger, onListClick, onSearch, onKeydown, onFocusout, setOpen });
  }

  function mountField(field) {
    if (!(field instanceof HTMLElement) || componentState.has(field)) return;
    field.classList.add('dwrt-kit-field');
    const control = field.querySelector('input:not([type="hidden"]), select, textarea');
    const label = field.matches('label') ? field : field.querySelector('[data-dwrt-field-label], label, :scope > span:first-child');
    if (control && label && !field.matches('label') && !control.getAttribute('aria-label') && !control.getAttribute('aria-labelledby')) {
      const labelId = ensureElementId(label, 'dwrt-field-label');
      control.setAttribute('aria-labelledby', labelId);
    }
    const description = field.querySelector('[data-dwrt-field-description]');
    const error = field.querySelector('[data-dwrt-field-error]');
    const describedBy = [description, error].filter(Boolean).map((node) => ensureElementId(node, 'dwrt-field-help'));
    if (control && describedBy.length) control.setAttribute('aria-describedby', describedBy.join(' '));
    if (control && error) control.setAttribute('aria-invalid', 'true');
    componentState.set(field, {});
  }

  function mountSwitch(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    root.classList.add('dwrt-kit-switch');
    const input = root.matches('input[type="checkbox"]') ? root : root.querySelector('input[type="checkbox"]');
    if (!(input instanceof HTMLInputElement)) return;
    input.setAttribute('role', 'switch');
    const controls = root.dataset.dwrtControls || input.dataset.dwrtControls;
    if (controls) input.setAttribute('aria-controls', controls);
    const sync = () => {
      root.dataset.dwrtChecked = input.checked ? 'true' : 'false';
      input.setAttribute('aria-checked', input.checked ? 'true' : 'false');
    };
    input.addEventListener('change', sync);
    sync();
    componentState.set(root, { input, sync });
  }

  function mountSegmented(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    const segments = () => Array.from(root.querySelectorAll('[data-dwrt-segment]'))
      .filter((segment) => segment instanceof HTMLButtonElement && !segment.disabled);
    root.classList.add('dwrt-kit-segmented');
    root.setAttribute('role', root.getAttribute('role') || 'radiogroup');
    const activate = (target, notify = true, focus = false) => {
      if (!(target instanceof HTMLButtonElement) || target.disabled) return '';
      Array.from(root.querySelectorAll('[data-dwrt-segment]')).forEach((segment) => {
        const active = segment === target;
        segment.classList.toggle('is-active', active);
        segment.setAttribute('role', 'radio');
        segment.setAttribute('aria-checked', active ? 'true' : 'false');
        segment.tabIndex = active ? 0 : -1;
      });
      root.dataset.dwrtValue = target.dataset.value || '';
      if (focus) target.focus({ preventScroll: true });
      if (notify) root.dispatchEvent(new CustomEvent('dwrt-segment-change', {
        bubbles: true,
        detail: { value: root.dataset.dwrtValue, segment: target }
      }));
      return root.dataset.dwrtValue;
    };
    const onClick = (event) => {
      const target = event.target.closest('[data-dwrt-segment]');
      if (target && root.contains(target)) activate(target);
    };
    const onKeydown = (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
      const available = segments();
      if (!available.length) return;
      const current = available.indexOf(event.target.closest('[data-dwrt-segment]'));
      const next = event.key === 'Home' ? 0
        : event.key === 'End' ? available.length - 1
          : (Math.max(0, current) + (['ArrowRight', 'ArrowDown'].includes(event.key) ? 1 : -1) + available.length) % available.length;
      event.preventDefault();
      activate(available[next], true, true);
    };
    root.addEventListener('click', onClick);
    root.addEventListener('keydown', onKeydown);
    const declared = root.dataset.dwrtValue;
    const initial = Array.from(root.querySelectorAll('[data-dwrt-segment]')).find((segment) => segment.dataset.value === declared || segment.getAttribute('aria-checked') === 'true') || segments()[0];
    if (initial) activate(initial, false);
    componentState.set(root, { onClick, onKeydown, activate });
  }

  function mountSlider(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    const input = root.matches('input[type="range"]') ? root : root.querySelector('input[type="range"]');
    if (!(input instanceof HTMLInputElement)) return;
    root.classList.add('dwrt-kit-slider');
    const output = root.querySelector('[data-dwrt-slider-output]');
    const labels = String(root.dataset.dwrtSliderLabels || '').split('|');
    const field = root.closest('[data-dwrt-component="field"]');
    const label = field?.querySelector('[data-dwrt-field-label]');
    if (label && !input.getAttribute('aria-label') && !input.getAttribute('aria-labelledby')) {
      input.setAttribute('aria-labelledby', ensureElementId(label, 'dwrt-field-label'));
    }
    const sync = () => {
      const min = Number(input.min || 0);
      const max = Number(input.max || 100);
      const value = Number(input.value || min);
      const progress = max > min ? ((value - min) / (max - min)) * 100 : 0;
      root.style.setProperty('--dwrt-slider-progress', `${Math.max(0, Math.min(100, progress))}%`);
      root.dataset.dwrtValue = input.value;
      const index = Math.round(value - min);
      const text = labels[index] || `${input.value}${root.dataset.dwrtSliderUnit || ''}`;
      if (output) output.textContent = text;
      input.setAttribute('aria-valuetext', text);
    };
    input.addEventListener('input', sync);
    input.addEventListener('change', sync);
    sync();
    componentState.set(root, { input, output, sync });
  }

  function unmountSegmented(root) {
    const state = componentState.get(root);
    if (!state?.onClick || !state?.onKeydown) return;
    root.removeEventListener('click', state.onClick);
    root.removeEventListener('keydown', state.onKeydown);
    componentState.delete(root);
  }

  function unmountSlider(root) {
    const state = componentState.get(root);
    if (!state?.input || !state?.sync) return;
    state.input.removeEventListener('input', state.sync);
    state.input.removeEventListener('change', state.sync);
    componentState.delete(root);
  }

  function mountDisclosure(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    root.classList.add('dwrt-kit-disclosure');
    const trigger = root.querySelector('[data-dwrt-disclosure-trigger], :scope > button');
    const panel = root.querySelector('[data-dwrt-disclosure-panel]');
    if (!(trigger instanceof HTMLButtonElement) || !(panel instanceof HTMLElement)) return;
    const panelId = ensureElementId(panel, 'dwrt-disclosure-panel');
    trigger.setAttribute('aria-controls', panelId);
    const setOpen = (open, notify = true) => {
      trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
      panel.hidden = !open;
      root.dataset.dwrtOpen = open ? 'true' : 'false';
      if (notify) root.dispatchEvent(new CustomEvent('dwrt-disclosure-change', { bubbles: true, detail: { open } }));
    };
    const onClick = () => setOpen(trigger.getAttribute('aria-expanded') !== 'true');
    trigger.addEventListener('click', onClick);
    setOpen(trigger.getAttribute('aria-expanded') === 'true' || !panel.hidden, false);
    componentState.set(root, { trigger, panel, onClick, setOpen });
  }

  function mountDependencyGroup(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    root.classList.add('dwrt-kit-dependency-group');
    const master = root.querySelector('[data-dwrt-dependency-master] input, input[data-dwrt-dependency-master], input[type="checkbox"]');
    const panel = root.querySelector('[data-dwrt-dependency-panel]');
    if (!(master instanceof HTMLInputElement) || !(panel instanceof HTMLElement)) return;
    const panelId = ensureElementId(panel, 'dwrt-dependency-panel');
    master.setAttribute('aria-controls', panelId);
    const sync = () => {
      const state = root.dataset.dwrtAvailability === 'unavailable' ? 'unavailable' : master.checked ? 'active' : 'inactive';
      root.dataset.dwrtDependencyState = state;
      panel.hidden = state !== 'active';
      panel.inert = state !== 'active';
      panel.setAttribute('aria-hidden', state === 'active' ? 'false' : 'true');
    };
    master.addEventListener('change', sync);
    sync();
    componentState.set(root, { master, panel, sync });
  }

  function mountStatePanel(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    root.classList.add('dwrt-kit-state-panel');
    const state = root.dataset.dwrtState || 'empty';
    root.setAttribute('role', ['error', 'forbidden', 'unavailable'].includes(state) ? 'alert' : 'status');
    if (state === 'loading' || state === 'refreshing') root.setAttribute('aria-busy', 'true');
    componentState.set(root, {});
  }

  function mountDataTable(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    root.classList.add('dwrt-kit-table-wrap');
    root.dataset.dwrtSurface ||= 'dense-surface';
    const table = root.matches('table') ? root : root.querySelector('table');
    if (!(table instanceof HTMLTableElement)) return;
    table.classList.add('dwrt-kit-table');
    const onClick = (event) => {
      const header = event.target.closest('th[data-sort-key]');
      if (!header || !table.contains(header)) return;
      const next = header.getAttribute('aria-sort') === 'ascending' ? 'descending' : 'ascending';
      table.querySelectorAll('th[aria-sort]').forEach((node) => node.removeAttribute('aria-sort'));
      header.setAttribute('aria-sort', next);
      root.dispatchEvent(new CustomEvent('dwrt-table-sort', { bubbles: true, detail: { key: header.dataset.sortKey, direction: next } }));
    };
    table.addEventListener('click', onClick);
    componentState.set(root, { table, onClick });
  }

  function mountDataGrid(root) {
    if (!(root instanceof HTMLElement) || dataGridState.has(root)) return;
    root.classList.add('dwrt-kit-data-grid');
    root.setAttribute('role', root.getAttribute('role') || 'grid');
    const cells = () => Array.from(root.querySelectorAll('[data-dwrt-grid-cell], [role="gridcell"]'))
      .filter((cell) => cell instanceof HTMLElement && !cell.hidden && cell.getAttribute('aria-disabled') !== 'true');
    const coordinates = (cell) => ({
      row: Number(cell.dataset.dwrtGridRow ?? cell.getAttribute('aria-rowindex')) || 1,
      column: Number(cell.dataset.dwrtGridColumn ?? cell.getAttribute('aria-colindex')) || 1
    });
    const activate = (cell, focus = false) => {
      const available = cells();
      if (!available.includes(cell)) return;
      available.forEach((item) => { item.tabIndex = item === cell ? 0 : -1; });
      if (focus) cell.focus({ preventScroll: false });
    };
    const nearest = (row, column) => cells().find((cell) => {
      const point = coordinates(cell);
      return point.row === row && point.column === column;
    }) || null;
    const onFocus = (event) => {
      const cell = event.target.closest?.('[data-dwrt-grid-cell], [role="gridcell"]');
      if (cell && root.contains(cell)) activate(cell);
    };
    const onClick = (event) => {
      const cell = event.target.closest?.('[data-dwrt-grid-cell], [role="gridcell"]');
      if (!cell || !root.contains(cell)) return;
      activate(cell);
      root.dispatchEvent(new CustomEvent('dwrt-grid-select', { bubbles: true, detail: { cell } }));
    };
    const onKeyDown = (event) => {
      const cell = event.target.closest?.('[data-dwrt-grid-cell], [role="gridcell"]');
      if (!cell || !root.contains(cell)) return;
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        root.dispatchEvent(new CustomEvent('dwrt-grid-activate', { bubbles: true, detail: { cell } }));
        return;
      }
      if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
      const current = coordinates(cell);
      const available = cells();
      const rowCells = available.filter((item) => coordinates(item).row === current.row);
      let target = null;
      if (event.key === 'Home') target = rowCells[0] || available[0];
      else if (event.key === 'End') target = rowCells[rowCells.length - 1] || available[available.length - 1];
      else target = nearest(
        current.row + (event.key === 'ArrowDown' ? 1 : event.key === 'ArrowUp' ? -1 : 0),
        current.column + (event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0)
      );
      if (!target) return;
      event.preventDefault();
      activate(target, true);
    };
    const available = cells();
    const initial = available.find((cell) => cell.tabIndex === 0) || available[0];
    if (initial) activate(initial);
    root.addEventListener('focusin', onFocus);
    root.addEventListener('click', onClick);
    root.addEventListener('keydown', onKeyDown);
    dataGridState.set(root, { onFocus, onClick, onKeyDown, activate });
  }

  function unmountDataGrid(root) {
    const state = dataGridState.get(root);
    if (!state) return;
    root.removeEventListener('focusin', state.onFocus);
    root.removeEventListener('click', state.onClick);
    root.removeEventListener('keydown', state.onKeyDown);
    dataGridState.delete(root);
  }

  function virtualWindow(root, force = false) {
    const state = virtualTableState.get(root);
    if (!state) return null;
    const rowCount = Math.max(0, Number(root.dataset.dwrtRowCount) || 0);
    const rowHeight = Math.max(32, Number(root.dataset.dwrtRowHeight) || 48);
    const overscan = Math.max(2, Number(root.dataset.dwrtOverscan) || 6);
    const height = Math.max(rowHeight, state.scroller.clientHeight || Number(root.dataset.dwrtViewportHeight) || rowHeight * 10);
    const start = Math.max(0, Math.floor(state.scroller.scrollTop / rowHeight) - overscan);
    const end = Math.min(rowCount, Math.ceil((state.scroller.scrollTop + height) / rowHeight) + overscan);
    const signature = `${rowCount}:${rowHeight}:${start}:${end}`;
    if (!force && signature === state.signature) return state.window;
    state.signature = signature;
    state.window = { start, end, rowCount, rowHeight, overscan, top: start * rowHeight, bottom: Math.max(0, (rowCount - end) * rowHeight) };
    root.dispatchEvent(new CustomEvent('dwrt-virtual-window-change', { bubbles: true, detail: state.window }));
    return state.window;
  }

  function updateVirtualDataTable(root, force = true) {
    return virtualWindow(root, force);
  }

  function mountVirtualDataTable(root) {
    if (!(root instanceof HTMLElement) || virtualTableState.has(root)) return;
    root.classList.add('dwrt-kit-virtual-table');
    root.dataset.dwrtSurface ||= 'dense-surface';
    const scroller = root.querySelector('[data-dwrt-virtual-scroller], .dwrt-kit-table-scroll');
    if (!(scroller instanceof HTMLElement)) return;
    mountDataTable(root);
    let frame = 0;
    const schedule = () => {
      if (frame) return;
      frame = requestAnimationFrame(() => { frame = 0; virtualWindow(root); });
    };
    const observer = typeof ResizeObserver === 'function' ? new ResizeObserver(schedule) : null;
    scroller.addEventListener('scroll', schedule, { passive: true });
    observer?.observe(scroller);
    virtualTableState.set(root, { scroller, schedule, observer, signature: '', window: null, get frame() { return frame; }, cancel: () => { if (frame) cancelAnimationFrame(frame); frame = 0; } });
    requestAnimationFrame(() => virtualWindow(root, true));
  }

  function unmountVirtualDataTable(root) {
    const state = virtualTableState.get(root);
    if (!state) return;
    state.cancel();
    state.observer?.disconnect();
    state.scroller.removeEventListener('scroll', state.schedule);
    virtualTableState.delete(root);
  }

  function mountFilterSheet(root) {
    if (!(root instanceof HTMLElement)) return;
    root.classList.add('dwrt-kit-sheet', 'dwrt-kit-filter-sheet');
    root.dataset.dwrtSurface ||= 'stable-glass';
    root.setAttribute('aria-label', root.getAttribute('aria-label') || '高级筛选');
    mountSheet(root);
  }

  function mountPageShell(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    root.classList.add('dwrt-kit-page-shell');
    root.dataset.dwrtSurface ||= root.dataset.dwrtPageShell === 'data-workbench' ? 'dense-surface' : 'stable-glass';
    const heading = root.querySelector('h1, [data-dwrt-page-title]');
    if (heading && !heading.hasAttribute('tabindex')) heading.tabIndex = -1;
    componentState.set(root, { heading });
  }

  function mountToolbar(root) {
    if (!(root instanceof HTMLElement) || componentState.has(root)) return;
    root.classList.add('dwrt-kit-toolbar');
    root.setAttribute('role', 'toolbar');
    componentState.set(root, {});
  }

  function mountAll(context = document) {
    mountLucide(context);
    reclaimStaleSheets(context);
    const components = collectComponentRoots(context);
    const roots = (name) => components.get(name) || [];
    roots('tabs').forEach((root) => {
      root.classList.add('dwrt-kit-tabs');
      mountTabs(root);
    });
    roots('sheet').forEach((root) => {
      root.classList.add('dwrt-kit-sheet');
      mountSheet(root);
    });
    roots('filter-sheet').forEach(mountFilterSheet);
    roots('modal').forEach(mountModal);
    roots('expand-search').forEach(mountExpandSearch);
    ['button', 'icon-button', 'async-button'].forEach((name) => roots(name).forEach(mountButton));
    roots('select').forEach((root) => mountSelect(root.matches('select') ? root : root.querySelector('select')));
    roots('combobox').forEach(mountCombobox);
    ['field', 'field-group'].forEach((name) => roots(name).forEach(mountField));
    roots('switch').forEach(mountSwitch);
    roots('segmented').forEach(mountSegmented);
    roots('slider').forEach(mountSlider);
    roots('disclosure').forEach(mountDisclosure);
    roots('dependency-group').forEach(mountDependencyGroup);
    roots('state-panel').forEach(mountStatePanel);
    roots('data-table').forEach(mountDataTable);
    roots('data-grid').forEach(mountDataGrid);
    roots('virtual-data-table').forEach(mountVirtualDataTable);
    roots('page-shell').forEach(mountPageShell);
    roots('toolbar').forEach(mountToolbar);
    context.querySelectorAll('[data-dwrt-tooltip]').forEach(mountTooltip);
    mountNativeTitleTooltips(context);
  }

  function mount(context = document) {
    mountAll(context);
    return () => unmount(context);
  }

  function unmount(context) {
    if (!context?.querySelectorAll) return;
    componentRoots(context, 'segmented').forEach(unmountSegmented);
    componentRoots(context, 'slider').forEach(unmountSlider);
    matchingRoots(context, '.dwrt-kit-sheet, [data-dwrt-component="sheet"], [data-dwrt-component="filter-sheet"]').forEach(unmountSheet);
    componentRoots(context, 'virtual-data-table').forEach(unmountVirtualDataTable);
    componentRoots(context, 'data-grid').forEach(unmountDataGrid);
    matchingRoots(context, '.dwrt-kit-modal-layer, [data-dwrt-component="modal"]').forEach(unmountModal);
    if (activeTooltip && context.contains?.(activeTooltip)) closeTooltip(activeTooltip);
    matchingRoots(context, '[data-dwrt-tooltip], .dwrt-kit-tooltip-trigger').forEach(unmountTooltip);
  }

  function modalFocusable(dialog) {
    return Array.from(dialog.querySelectorAll('button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])'))
      .filter((element) => element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden');
  }

  function mountModal(layer) {
    if (!layer || modalState.has(layer)) return;
    const dialog = layer.querySelector('.dwrt-kit-modal, [role="dialog"]');
    if (!(dialog instanceof HTMLElement)) return;
    if (dialog.dataset.dwrtModalVariant === 'copilot') ensureSheetMaterial(dialog);
    const recentTrigger = lastTrigger && performance.now() - lastTrigger.at < 1600 ? lastTrigger : null;
    const state = {
      trigger: recentTrigger?.element || (document.activeElement instanceof HTMLElement ? document.activeElement : null),
      triggerSelector: recentTrigger?.selector || triggerSelector(document.activeElement),
      dialog,
      keydown: null,
      transitionend: null
    };
    if (state.triggerSelector) layer.dataset.dwrtReturnFocus = state.triggerSelector;
    dialog.setAttribute('role', dialog.getAttribute('role') || 'dialog');
    dialog.setAttribute('aria-modal', dialog.getAttribute('aria-modal') || 'true');
    state.keydown = (event) => {
      if (event.key === 'Escape') {
        const close = layer.querySelector('[data-dwrt-modal-close], .dwrt-kit-modal-close');
        if (close instanceof HTMLElement) {
          event.preventDefault();
          close.click();
        }
        return;
      }
      if (event.key !== 'Tab') return;
      const controls = modalFocusable(dialog);
      if (!controls.length) {
        event.preventDefault();
        dialog.focus({ preventScroll: true });
        return;
      }
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus({ preventScroll: true });
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus({ preventScroll: true });
      }
    };
    layer.addEventListener('keydown', state.keydown);
    state.transitionend = () => {
      if (dialog.dataset.dwrtModalVariant === 'copilot') syncSheetWallpaper(dialog);
    };
    dialog.addEventListener('transitionend', state.transitionend);
    modalState.set(layer, state);
    requestAnimationFrame(() => requestAnimationFrame(() => {
      if (!layer.isConnected) return;
      state.transitionend();
      const target = dialog.querySelector('[autofocus], input:not(:disabled), select:not(:disabled), textarea:not(:disabled)') || modalFocusable(dialog)[0];
      if (target instanceof HTMLElement) target.focus({ preventScroll: true });
    }));
  }

  function unmountModal(layer) {
    const state = modalState.get(layer);
    if (!state) return;
    layer.removeEventListener('keydown', state.keydown);
    state.dialog.removeEventListener('transitionend', state.transitionend);
    modalState.delete(layer);
  }

  function tooltipPortal() {
    let portal = document.getElementById('dwrtKitTooltip');
    if (portal) return portal;
    portal = document.createElement('div');
    portal.id = 'dwrtKitTooltip';
    portal.className = 'dwrt-kit-tooltip';
    portal.setAttribute('role', 'tooltip');
    portal.hidden = true;
    document.body.append(portal);
    return portal;
  }

  function positionTooltip(trigger, portal) {
    if (!trigger?.isConnected) {
      closeTooltip(trigger);
      return;
    }
    if (portal.hidden) return;
    const anchor = trigger.getBoundingClientRect();
    const bubble = portal.getBoundingClientRect();
    const gap = 9;
    const edge = 12;
    const above = anchor.top >= bubble.height + gap + edge;
    const top = above ? anchor.top - bubble.height - gap : anchor.bottom + gap;
    const centered = anchor.left + anchor.width / 2 - bubble.width / 2;
    const left = Math.max(edge, Math.min(centered, window.innerWidth - bubble.width - edge));
    portal.style.left = `${Math.round(left)}px`;
    portal.style.top = `${Math.round(Math.max(edge, Math.min(top, window.innerHeight - bubble.height - edge)))}px`;
    portal.dataset.placement = above ? 'top' : 'bottom';
  }

  function closeTooltip(trigger = activeTooltip) {
    if (!trigger) return;
    const portal = document.getElementById('dwrtKitTooltip');
    portal?.classList.remove('is-open');
    trigger.removeAttribute('aria-describedby');
    if (activeTooltip === trigger) activeTooltip = null;
    window.setTimeout(() => {
      if (portal && !portal.classList.contains('is-open')) portal.hidden = true;
    }, reducedMotion() ? 0 : 150);
  }

  function openTooltip(trigger) {
    const text = trigger.dataset.dwrtTooltip || trigger.dataset.dwrtTooltipText || '';
    if (!text) return;
    if (activeTooltip && activeTooltip !== trigger) closeTooltip(activeTooltip);
    const portal = tooltipPortal();
    portal.textContent = text;
    portal.hidden = false;
    trigger.setAttribute('aria-describedby', portal.id);
    activeTooltip = trigger;
    requestAnimationFrame(() => {
      if (!trigger.isConnected || activeTooltip !== trigger) {
        closeTooltip(trigger);
        return;
      }
      positionTooltip(trigger, portal);
      portal.classList.add('is-open');
    });
  }

  function mountTooltip(trigger) {
    if (!(trigger instanceof HTMLElement) || tooltipState.has(trigger)) return;
    const open = () => openTooltip(trigger);
    const close = () => closeTooltip(trigger);
    const keydown = (event) => { if (event.key === 'Escape') close(); };
    trigger.classList.add('dwrt-kit-tooltip-trigger');
    trigger.addEventListener('pointerenter', open);
    trigger.addEventListener('pointerleave', close);
    trigger.addEventListener('focus', open);
    trigger.addEventListener('blur', close);
    trigger.addEventListener('keydown', keydown);
    tooltipState.set(trigger, { open, close, keydown });
  }

  function unmountTooltip(trigger) {
    if (!(trigger instanceof HTMLElement)) return;
    const state = tooltipState.get(trigger);
    if (!state) return;
    trigger.removeEventListener('pointerenter', state.open);
    trigger.removeEventListener('pointerleave', state.close);
    trigger.removeEventListener('focus', state.open);
    trigger.removeEventListener('blur', state.close);
    trigger.removeEventListener('keydown', state.keydown);
    trigger.classList.remove('dwrt-kit-tooltip-trigger');
    if (activeTooltip === trigger) closeTooltip(trigger);
    tooltipState.delete(trigger);
  }

  function mountNativeTitleTooltip(trigger) {
    if (!(trigger instanceof HTMLElement)) return;
    const title = String(trigger.getAttribute('title') || '').trim();
    if (!title) return;
    if (!trigger.dataset.dwrtTooltip) trigger.dataset.dwrtTooltip = title;
    trigger.dataset.dwrtNativeTitle = 'true';
    trigger.removeAttribute('title');
    mountTooltip(trigger);
  }

  function mountNativeTitleTooltips(context = document) {
    const selector = '[title]';
    if (context instanceof Element && context.matches(selector)) mountNativeTitleTooltip(context);
    context.querySelectorAll?.(selector).forEach(mountNativeTitleTooltip);
  }

  function expandSearchIcon() {
    const icon = document.createElement('span');
    icon.className = 'dwrt-kit-expand-search-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.innerHTML = '<svg viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="221.09" cy="221.09" r="157.09" stroke="currentColor" stroke-width="32"/><path d="M338.29 338.29 448 448" stroke="currentColor" stroke-linecap="round" stroke-width="32"/></svg>';
    return icon;
  }

  function syncExpandSearch(root) {
    const state = expandSearchState.get(root);
    if (!state) return;
    const hasValue = Boolean(state.input.value);
    root.classList.toggle('has-value', hasValue);
    root.setAttribute('data-dwrt-search-expanded', state.expanded || hasValue ? 'true' : 'false');
  }

  function expandSearchKey(root, input) {
    const route = `${window.location.pathname}${String(window.location.hash || '').split('?')[0]}`;
    if (input.id) return `${route}|id:${input.id}`;
    const dataAttr = Array.from(input.attributes).find((attribute) => attribute.name.startsWith('data-') && !attribute.name.startsWith('data-dwrt-'));
    if (dataAttr) return `${route}|${dataAttr.name}:${dataAttr.value || 'true'}`;
    const placeholder = input.getAttribute('placeholder') || '';
    const scope = root.closest('[data-route-module], .route-workspace, main, section')?.getAttribute?.('aria-label') || '';
    return `${route}|${scope}|${root.className}|${placeholder}`;
  }

  function mountExpandSearch(root) {
    if (!(root instanceof HTMLElement) || root.dataset.dwrtExpandSearch === 'true') return;
    if (root.closest('#commandPalette, .dwrt-kit-sheet, [role="dialog"]')) return;
    const input = root.querySelector(':scope > input[type="search"], input[type="search"]');
    if (!(input instanceof HTMLInputElement)) return;
    const intentKey = expandSearchKey(root, input);
    root.dataset.dwrtExpandSearch = 'true';
    root.classList.add('dwrt-kit-expand-search');
    const existingIcons = Array.from(root.children).filter((child) => child !== input && child.matches?.('svg'));
    existingIcons.forEach((icon) => icon.classList.add('dwrt-kit-expand-search-original-icon'));
    const icon = expandSearchIcon();
    root.insertBefore(icon, input);
    const sync = () => syncExpandSearch(root);
    const expandFromPointer = (event) => {
      if (!event.isTrusted) return;
      const state = expandSearchState.get(root);
      if (!state) return;
      state.expanded = true;
      expandSearchIntent.set(state.intentKey, true);
      sync();
    };
    const collapseAfterBlur = () => requestAnimationFrame(() => {
      if (!root.isConnected || root.contains(document.activeElement)) return;
      const state = expandSearchState.get(root);
      if (!state || input.value) return;
      state.expanded = false;
      expandSearchIntent.set(state.intentKey, false);
      sync();
    });
    const onKeyDown = (event) => {
      if (event.key !== 'Escape' || !input.value) return;
      event.preventDefault();
      input.value = '';
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.blur();
      const state = expandSearchState.get(root);
      if (state) state.expanded = false;
      if (state) expandSearchIntent.set(state.intentKey, false);
      sync();
    };
    root.addEventListener('pointerdown', expandFromPointer);
    input.addEventListener('input', () => {
      const state = expandSearchState.get(root);
      if (state && input.value) {
        state.expanded = true;
        expandSearchIntent.set(state.intentKey, true);
      }
      sync();
    });
    input.addEventListener('blur', collapseAfterBlur);
    input.addEventListener('keydown', onKeyDown);
    expandSearchState.set(root, {
      input,
      icon,
      sync,
      onKeyDown,
      expandFromPointer,
      collapseAfterBlur,
      intentKey,
      expanded: Boolean(input.value) || expandSearchIntent.get(intentKey) === true
    });
    sync();
  }

  function clamp(value, min, max) {
    const number = Number(value);
    if (!Number.isFinite(number)) return min;
    return Math.max(min, Math.min(max, number));
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function overviewCardsMarkup(items = [], options = {}) {
    const cards = Array.isArray(items) ? items : [];
    const className = String(options.className || '').replace(/[^A-Za-z0-9 _-]/g, '').trim();
    const label = escapeHtml(options.label || '概览');
    return `<section class="dwrt-kit-overview-grid${className ? ` ${className}` : ''}" aria-label="${label}">${cards.map((item, index) => {
      const key = String(item && (item.key || item.id) || `metric-${index + 1}`).replace(/[^A-Za-z0-9_-]/g, '') || `metric-${index + 1}`;
      const tone = ['neutral', 'info', 'ok', 'warn', 'bad'].includes(item && item.tone) ? item.tone : 'neutral';
      return `<article class="dwrt-kit-overview-card is-${tone}" data-dwrt-overview-card="${key}">
        <div class="dwrt-kit-overview-content">
          <span class="dwrt-kit-overview-label">${escapeHtml(item && item.label)}</span>
          <strong data-dwrt-overview-value="${key}">${escapeHtml(item && item.value)}</strong>
          <small data-dwrt-overview-detail="${key}">${escapeHtml(item && item.detail)}</small>
        </div>
        <span class="dwrt-kit-overview-icon" aria-hidden="true">${normalizeOverviewIcon(item && item.icon)}</span>
      </article>`;
    }).join('')}</section>`;
  }

  function floatingSavebarMarkup(options = {}) {
    const visible = options.visible !== false;
    if (!visible && options.omitWhenHidden) return '';
    const busy = options.busy === true;
    const disabled = options.disabled === true || busy;
    return `<div class="dwrt-floating-savebar dwrt-kit-savebar${visible ? '' : ' is-hidden'}" data-dwrt-savebar data-adaptive-sample>
      <span>${escapeHtml(options.message || '配置已修改，请保存生效')}</span>
      <button class="dwrt-kit-savebar-button is-ghost" type="button" data-dwrt-savebar-discard ${disabled ? 'disabled' : ''}>${escapeHtml(options.discardLabel || '撤销更改')}</button>
      <button class="dwrt-kit-savebar-button is-primary" type="button" data-dwrt-savebar-save ${disabled ? 'disabled' : ''}>${escapeHtml(busy ? (options.busyLabel || '保存中...') : (options.saveLabel || '保存并应用'))}</button>
    </div>`;
  }

  function normalizeStatusTone(tone) {
    const value = String(tone || 'muted').trim().toLowerCase().replace(/^is-/, '');
    if (['success', 'ok', 'online', 'active', 'healthy', 'running', 'enabled', 'up'].includes(value)) return 'success';
    if (['warning', 'warn', 'beta', 'degraded', 'away', 'pending'].includes(value)) return 'warning';
    if (['error', 'bad', 'danger', 'failed', 'offline', 'down', 'stopped'].includes(value)) return 'error';
    if (['info', 'new', 'syncing', 'loading'].includes(value)) return 'info';
    return 'muted';
  }

  function statusBadgeMarkup(label, tone = 'muted', options = {}) {
    const normalized = normalizeStatusTone(tone);
    const className = String(options.className || '').replace(/[^A-Za-z0-9 _-]/g, '').trim();
    const showDot = options.dot !== false && normalized === 'success';
    return `<span class="dwrt-kit-status-badge is-${normalized}${className ? ` ${className}` : ''}" data-dwrt-status="${normalized}">${showDot ? '<i class="dwrt-kit-status-badge-dot" aria-hidden="true"></i>' : ''}<span>${escapeHtml(label)}</span></span>`;
  }

  function confirmationMarkup(options = {}) {
    const tone = ['danger', 'warning', 'reboot'].includes(options.tone) ? options.tone : 'danger';
    const id = String(options.id || 'dwrt-confirmation').replace(/[^A-Za-z0-9_-]/g, '') || 'dwrt-confirmation';
    const action = String(options.action || tone).replace(/[^A-Za-z0-9_-]/g, '') || tone;
    const iconMarkup = String(options.icon || '').trim() || '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 3.4 2.7 17a2 2 0 0 0 1.8 3h15a2 2 0 0 0 1.8-3L13.7 3.4a2 2 0 0 0-3.4 0Z"></path></svg>';
    return `<div class="dwrt-kit-modal-layer dwrt-kit-confirmation-layer is-${tone} is-open" data-dwrt-confirmation="${escapeHtml(action)}">
      <button class="dwrt-kit-modal-backdrop" type="button" data-dwrt-modal-close data-dwrt-confirm-cancel aria-label="${escapeHtml(options.cancelLabel || '取消')}"></button>
      <section class="dwrt-kit-modal dwrt-kit-confirmation" role="dialog" aria-modal="true" aria-labelledby="${id}-title" aria-describedby="${id}-description">
        <div class="dwrt-kit-confirmation-body">
          <span class="dwrt-kit-confirmation-icon" aria-hidden="true">${iconMarkup}</span>
          <div class="dwrt-kit-confirmation-copy">
            <h2 id="${id}-title">${escapeHtml(options.title || '确认此操作')}</h2>
            <p id="${id}-description">${escapeHtml(options.description || '此操作执行后可能无法撤销。')}</p>
          </div>
          <div class="dwrt-kit-confirmation-actions">
            <button class="dwrt-kit-confirmation-cancel" type="button" data-dwrt-modal-close data-dwrt-confirm-cancel>${escapeHtml(options.cancelLabel || '取消')}</button>
            <button class="dwrt-kit-confirmation-submit" type="button" data-dwrt-confirm-accept ${options.disabled ? 'disabled' : ''}>${escapeHtml(options.confirmLabel || '确认')}</button>
          </div>
        </div>
      </section>
    </div>`;
  }

  function normalizeOverviewIcon(icon) {
    const markup = String(icon || '').trim();
    if (!markup) return '';
    return markup.replace(/<svg\b([^>]*)>/i, (match, attributes) => {
      let normalized = attributes
        .replace(/\s(?:width|height|preserveAspectRatio|focusable)=(?:"[^"]*"|'[^']*')/gi, '');
      if (!/\sviewBox=(?:"[^"]*"|'[^']*')/i.test(normalized)) normalized += ' viewBox="0 0 24 24"';
      return `<svg${normalized} width="28" height="28" preserveAspectRatio="xMidYMid meet" focusable="false">`;
    });
  }

  function startOfMonth(value) {
    const date = new Date(Number(value) || Date.now());
    return new Date(date.getFullYear(), date.getMonth(), 1);
  }

  function addMonths(value, count) {
    const date = new Date(value);
    return new Date(date.getFullYear(), date.getMonth() + count, 1);
  }

  function sameDay(left, right) {
    const a = new Date(left);
    const b = new Date(right);
    return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  }

  function dayInRange(dayTs, startTs, endTs) {
    const day = new Date(dayTs);
    const start = new Date(Math.min(startTs, endTs));
    const end = new Date(Math.max(startTs, endTs));
    day.setHours(12, 0, 0, 0);
    start.setHours(0, 0, 0, 0);
    end.setHours(23, 59, 59, 999);
    return day >= start && day <= end;
  }

  function dateValue(date) {
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
  }

  function monthTitle(monthDate) {
    return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: 'long' }).format(monthDate);
  }

  function normalizeRange(range) {
    const now = Date.now();
    const start = Number(range && range.start);
    const end = Number(range && range.end);
    const safeStart = Number.isFinite(start) ? start : now - 3600000;
    const safeEnd = Number.isFinite(end) ? end : now;
    return {
      start: Math.min(safeStart, safeEnd),
      end: Math.max(safeStart, safeEnd)
    };
  }

  function presetRange(id) {
    const now = Date.now();
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (id === 'today') return { start: today.getTime(), end: now };
    if (id === 'day') return { start: now - 86400000, end: now };
    if (id === 'week') return { start: now - 7 * 86400000, end: now };
    if (id === 'month') return { start: now - 30 * 86400000, end: now };
    return { start: now - 3600000, end: now };
  }

  function datePresetItems(options) {
    const defaults = [
      ['hour', '最近 1 小时'],
      ['today', '今天'],
      ['day', '最近 24 小时'],
      ['week', '最近 7 天'],
      ['month', '最近 30 天']
    ];
    if (options && options.presets === false) return [];
    if (options && Array.isArray(options.presets)) {
      return options.presets
        .map((item) => Array.isArray(item) ? item : [item && item.id, item && item.label])
        .filter(([id, label]) => id && label);
    }
    return defaults;
  }

  function dateFieldMarkup(which, label, ts) {
    const date = new Date(ts);
    return `
      <label class="dwrt-date-field">
        <span>${escapeHtml(label)}</span>
        <input type="date" data-dwrt-date="${which}" value="${dateValue(date)}">
        <span class="dwrt-date-time">
          <input type="number" min="0" max="23" inputmode="numeric" data-dwrt-hour="${which}" value="${String(date.getHours()).padStart(2, '0')}">
          <b>:</b>
          <input type="number" min="0" max="59" inputmode="numeric" data-dwrt-minute="${which}" value="${String(date.getMinutes()).padStart(2, '0')}">
        </span>
      </label>`;
  }

  function monthMarkup(monthDate, draft) {
    const year = monthDate.getFullYear();
    const month = monthDate.getMonth();
    const first = new Date(year, month, 1);
    const offset = (first.getDay() + 6) % 7;
    const days = new Date(year, month + 1, 0).getDate();
    const cells = [];
    for (let i = 0; i < offset; i++) cells.push('<span class="dwrt-date-empty"></span>');
    for (let day = 1; day <= days; day++) {
      const ts = new Date(year, month, day).getTime();
      const inRange = dayInRange(ts, draft.start, draft.end);
      const edge = sameDay(ts, draft.start) || sameDay(ts, draft.end);
      const today = sameDay(ts, Date.now());
      cells.push(`<button type="button" data-dwrt-day="${ts}" class="${inRange ? 'is-in-range' : ''} ${edge ? 'is-edge' : ''} ${today ? 'is-today' : ''}">${day}</button>`);
    }
    return `
      <section class="dwrt-date-month" aria-label="${escapeHtml(monthTitle(monthDate))}">
        <strong>${escapeHtml(monthTitle(monthDate))}</strong>
        <div class="dwrt-date-weekdays" aria-hidden="true"><span>一</span><span>二</span><span>三</span><span>四</span><span>五</span><span>六</span><span>日</span></div>
        <div class="dwrt-date-grid">${cells.join('')}</div>
      </section>`;
  }

  function positionDatePicker(panel, anchor) {
    if (!panel) return;
    panel.style.left = '50%';
    panel.style.top = '50%';
    panel.style.setProperty('--dwrt-date-origin-x', '50%');
    panel.style.setProperty('--dwrt-date-origin-y', '50%');
  }

  function openDateRangePicker(options = {}) {
    if (activeDatePicker) activeDatePicker.close(null);
    const anchor = options.placement === 'anchor' ? options.anchor || null : null;
    const presetItems = datePresetItems(options);
    const initial = normalizeRange(options.range);
    const draft = {
      start: initial.start,
      end: initial.end,
      picking: 'start',
      month: startOfMonth(initial.end).getTime(),
      preset: ''
    };
    const shell = document.createElement('div');
    shell.className = 'dwrt-date-layer';
    shell.innerHTML = '<button class="dwrt-date-backdrop" type="button" tabindex="-1" aria-label="关闭日期选择器"></button><section class="dwrt-date-popover" role="dialog" aria-modal="false" aria-label="选择时间范围"></section>';
    const panel = shell.querySelector('.dwrt-date-popover');
    const backdrop = shell.querySelector('.dwrt-date-backdrop');

    let settled = false;
    let resolvePicker;
    const promise = new Promise((resolve) => { resolvePicker = resolve; });

    function commit(result) {
      if (settled) return;
      settled = true;
      window.removeEventListener('keydown', onKeyDown, true);
      window.removeEventListener('resize', onResize, true);
      document.removeEventListener('scroll', onResize, true);
      shell.classList.add('is-leaving');
      window.setTimeout(() => shell.remove(), 140);
      activeDatePicker = null;
      resolvePicker(result);
    }

    function close(result = null) {
      commit(result);
    }

    function orderedDraft() {
      return {
        start: Math.min(draft.start, draft.end),
        end: Math.max(draft.start, draft.end)
      };
    }

    function updateDate(which, value) {
      const current = new Date(draft[which]);
      const next = new Date(`${value}T00:00:00`);
      if (!Number.isFinite(next.getTime())) return;
      next.setHours(current.getHours(), current.getMinutes(), 0, 0);
      draft[which] = next.getTime();
      draft.preset = '';
      renderPanel();
    }

    function updateTime(which, unit, value) {
      const next = new Date(draft[which]);
      const number = clamp(value, 0, unit === 'hour' ? 23 : 59);
      if (unit === 'hour') next.setHours(number);
      else next.setMinutes(number);
      next.setSeconds(0, 0);
      draft[which] = next.getTime();
      draft.preset = '';
      renderPanel();
    }

    function applyPreset(id) {
      const next = normalizeRange(presetRange(id));
      draft.start = next.start;
      draft.end = next.end;
      draft.month = startOfMonth(next.end).getTime();
      draft.picking = 'start';
      draft.preset = id;
      renderPanel();
    }

    function pickDay(ts) {
      const previous = new Date(draft[draft.picking]);
      const next = new Date(Number(ts));
      if (!Number.isFinite(next.getTime())) return;
      next.setHours(previous.getHours(), previous.getMinutes(), 0, 0);
      if (draft.picking === 'start') {
        draft.start = next.getTime();
        if (draft.start > draft.end) draft.end = draft.start;
        draft.picking = 'end';
      } else {
        draft.end = next.getTime();
        if (draft.end < draft.start) {
          const start = draft.end;
          draft.end = draft.start;
          draft.start = start;
        }
        draft.picking = 'start';
      }
      draft.preset = '';
      renderPanel();
    }

    function renderPanel() {
      const base = startOfMonth(draft.month || draft.end);
      const prev = addMonths(base, -1);
      const current = addMonths(base, 0);
      const range = orderedDraft();
      panel.innerHTML = `
        <div class="dwrt-date-calendar">
          <button type="button" class="dwrt-date-nav dwrt-date-prev" data-dwrt-month-step="-1" aria-label="上个月">‹</button>
          <div class="dwrt-date-months">
            ${monthMarkup(prev, draft)}
            ${monthMarkup(current, draft)}
          </div>
          <button type="button" class="dwrt-date-nav dwrt-date-next" data-dwrt-month-step="1" aria-label="下个月">›</button>
        </div>
        <aside class="dwrt-date-presets" aria-label="快速范围">
          ${presetItems.map(([id, label]) => `<button type="button" data-dwrt-preset="${escapeHtml(id)}" class="${draft.preset === id ? 'is-active' : ''}">${escapeHtml(label)}</button>`).join('')}
        </aside>
        <footer class="dwrt-date-footer">
          <div class="dwrt-date-fields">
            ${dateFieldMarkup('start', '开始于', range.start)}
            ${dateFieldMarkup('end', '结束于', range.end)}
          </div>
          <div class="dwrt-date-actions">
            <button type="button" data-dwrt-cancel>取消</button>
            <button type="button" data-dwrt-apply>应用</button>
          </div>
        </footer>`;
      positionDatePicker(panel, anchor);
    }

    function onPanelClick(event) {
      const monthStep = event.target.closest('[data-dwrt-month-step]');
      if (monthStep) {
        draft.month = addMonths(draft.month || draft.end, Number(monthStep.dataset.dwrtMonthStep || 0)).getTime();
        renderPanel();
        return;
      }
      const preset = event.target.closest('[data-dwrt-preset]');
      if (preset) {
        applyPreset(preset.dataset.dwrtPreset || 'hour');
        return;
      }
      const day = event.target.closest('[data-dwrt-day]');
      if (day) {
        pickDay(day.dataset.dwrtDay);
        return;
      }
      if (event.target.closest('[data-dwrt-cancel]')) {
        close(null);
        return;
      }
      if (event.target.closest('[data-dwrt-apply]')) {
        const result = orderedDraft();
        if (typeof options.onApply === 'function') options.onApply(result);
        close(result);
      }
    }

    function onPanelInput(event) {
      if (event.target.matches('[data-dwrt-date]')) updateDate(event.target.dataset.dwrtDate, event.target.value);
      if (event.target.matches('[data-dwrt-hour]')) updateTime(event.target.dataset.dwrtHour, 'hour', event.target.value);
      if (event.target.matches('[data-dwrt-minute]')) updateTime(event.target.dataset.dwrtMinute, 'minute', event.target.value);
    }

    function onKeyDown(event) {
      if (event.key === 'Escape') close(null);
    }

    function onResize() {
      positionDatePicker(panel, anchor);
    }

    panel.addEventListener('click', onPanelClick);
    panel.addEventListener('change', onPanelInput);
    backdrop.addEventListener('click', () => close(null));
    window.addEventListener('keydown', onKeyDown, true);
    window.addEventListener('resize', onResize, true);
    document.addEventListener('scroll', onResize, true);
    document.body.append(shell);
    renderPanel();
    activeDatePicker = { close };
    window.requestAnimationFrame(() => shell.classList.add('is-open'));
    return promise;
  }

  window.DWRT_UI_KIT = {
    mount,
    unmount,
    mountTabs,
    mountAll,
    updateTabs,
    setActiveTab,
    openDateRangePicker,
    overviewCardsMarkup,
    floatingSavebarMarkup,
    statusBadgeMarkup,
    confirmationMarkup,
    mountModal,
    mountSheet,
    mountFilterSheet,
    mountVirtualDataTable,
    updateVirtualDataTable,
    mountDataGrid,
    mountSegmented,
    mountSlider,
    mountExpandSearch,
    mountTooltip,
    lucideIcon,
    mountLucide
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => mount(document.getElementById('appShell') || document));
  } else {
    mount(document.getElementById('appShell') || document);
  }

  window.addEventListener('resize', () => {
    document.querySelectorAll('.dwrt-kit-tabs').forEach((root) => updateTabs(root, false));
    syncMountedSheetGeometry();
    syncMountedGlassWallpapers();
  }, { passive: true });

  document.addEventListener('pointerdown', (event) => rememberTrigger(event.target.closest('button, [role="button"], a')), true);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') rememberTrigger(document.activeElement);
  }, true);
  window.addEventListener('resize', () => {
    const portal = document.getElementById('dwrtKitTooltip');
    if (activeTooltip && portal) positionTooltip(activeTooltip, portal);
  }, { passive: true });
  document.addEventListener('scroll', () => {
    const portal = document.getElementById('dwrtKitTooltip');
    if (activeTooltip && portal) positionTooltip(activeTooltip, portal);
  }, true);
  window.addEventListener('hashchange', () => closeTooltip());
  window.addEventListener('pagehide', () => closeTooltip());
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) closeTooltip();
  });
})();
