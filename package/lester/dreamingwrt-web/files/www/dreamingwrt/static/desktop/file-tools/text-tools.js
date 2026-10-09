(() => {
  'use strict';
  const languages = { js: 'javascript', mjs: 'javascript', cjs: 'javascript', json: 'json', css: 'css',
    html: 'markup', htm: 'markup', xml: 'markup', svg: 'markup', sh: 'bash', bash: 'bash',
    ini: 'ini', conf: 'ini', cfg: 'ini', py: 'python', yaml: 'yaml', yml: 'yaml' };
  window.DWRT_TEXT_TOOLS = ({ api, notice }) => {
    let worker, serial = 0, active, comparison, revision = 0, stopped = false;
    const pending = new Map(), documents = new Set();
    function request(type, payload) {
      if (!worker) {
        worker = new Worker('/static/desktop/file-tools/text-worker.js?v=20261005-text-01');
        worker.onmessage = ({ data }) => {
          const job = pending.get(data.id); if (!job) return;
          clearTimeout(job.timer); pending.delete(data.id);
          if (data.error) job.reject(new Error(data.error)); else job.resolve(data);
        };
        worker.onerror = () => resetWorker('文本工具加载失败，请重新选择语法或比较。');
      }
      return new Promise((resolve, reject) => {
        const id = ++serial;
        const timer = setTimeout(() => resetWorker('文本处理时间过长，已保留原文。'), 4000);
        pending.set(id, { resolve, reject, timer }); worker.postMessage({ id, type, ...payload });
      });
    }
    function resetWorker(message) {
      worker?.terminate(); worker = null;
      pending.forEach((job) => { clearTimeout(job.timer); job.reject(new Error(message)); }); pending.clear();
    }
    function align(doc) {
      if (!doc.layer) return;
      const style = getComputedStyle(doc.area), code = doc.layer.firstChild;
      for (const property of ['fontFamily', 'fontSize', 'fontWeight', 'fontStyle', 'fontStretch', 'lineHeight', 'letterSpacing', 'tabSize', 'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft']) code.style[property] = style[property];
      code.style.width = `${doc.area.clientWidth}px`;
      code.style.whiteSpace = doc.area.wrap === 'off' ? 'pre' : 'pre-wrap';
      code.style.overflowWrap = doc.area.wrap === 'off' ? 'normal' : 'break-word';
      doc.layer.style.borderWidth = style.borderWidth; doc.layer.style.borderRadius = style.borderRadius;
      code.style.transform = `translate(${-doc.area.scrollLeft}px, ${-doc.area.scrollTop}px)`;
    }
    function attach(doc) {
      if (documents.has(doc)) return;
      documents.add(doc);
      const layer = document.createElement('pre'); layer.className = 'ft-code-layer'; layer.setAttribute('aria-hidden', 'true');
      layer.append(document.createElement('code')); layer.hidden = true; doc.container.prepend(layer); doc.layer = layer;
      doc.area.addEventListener('scroll', () => align(doc));
      doc.area.addEventListener('compositionstart', () => { doc.composing = true; doc.container.classList.remove('ft-highlighted'); doc.layer.hidden = true; });
      doc.area.addEventListener('compositionend', () => { doc.composing = false; update(doc); });
      doc.resize = new ResizeObserver(() => align(doc)); doc.resize.observe(doc.area);
    }
    function update(doc) {
      if (!doc || stopped) return;
      attach(doc);
      if (doc.composing) return;
      const selected = doc.language || 'plain';
      const language = selected === 'auto' ? languages[doc.file.name.split('.').pop().toLowerCase()] : selected;
      const text = doc.area.value;
      if (doc.highlightText === text && doc.highlightLanguage === language) { align(doc); return; }
      doc.highlightText = text; doc.highlightLanguage = language;
      clearTimeout(doc.highlightTimer); const version = doc.highlightVersion = (doc.highlightVersion || 0) + 1;
      // Keep original text visible while asynchronous highlighting catches up.
      doc.container.classList.remove('ft-highlighted'); doc.layer.hidden = true;
      if (!language || language === 'plain') return;
      if (new TextEncoder().encode(text).length > 262144) return;
      doc.highlightTimer = setTimeout(async () => {
        try {
          const result = await request('highlight', { text, language });
          if (version !== doc.highlightVersion || doc.composing || !documents.has(doc) || text !== doc.area.value) return;
          if (result.html == null) return;
          doc.layer.firstChild.innerHTML = result.html + '\n';
          doc.layer.hidden = false; doc.container.classList.add('ft-highlighted'); align(doc);
        } catch (error) { if (!stopped && doc === active) notice(error.message); }
      }, 100);
    }
    const button = (label, action) => {
      const el = document.createElement('button'); el.type = 'button'; el.className = 'dwrt-kit-button';
      el.dataset.dwrtComponent = 'button'; el.textContent = label; el.addEventListener('click', action); return el;
    };
    function closeComparison(focus = true) {
      revision++; comparison?.controller?.abort(); comparison?.element.remove(); comparison = null;
      document.querySelector('#ftEditors').hidden = false;
      document.querySelector('#ftSavebar').hidden = false;
      document.querySelectorAll('.ft-edit-controls,.ft-search-panel').forEach((el) => { el.hidden = false; });
      if (focus) active?.area.focus({ preventScroll: true });
    }
    function cell(text, line, side, changed) {
      const item = document.createElement('div'); item.className = 'ft-diff-cell';
      if (text === undefined) { item.classList.add('ft-diff-empty'); return item; }
      const number = document.createElement('span'); number.className = 'ft-diff-number'; number.textContent = line;
      const sign = document.createElement('span'); sign.className = 'ft-diff-sign'; sign.textContent = changed ? (side === 'a' ? '−' : '+') : '';
      const body = document.createElement('pre'); body.textContent = text.replace(/\r?\n$/, '');
      if (!text.endsWith('\n')) {
        const eof = document.createElement('span'); eof.className = 'ft-diff-eof'; eof.textContent = ' ⏎ 无末尾换行'; body.append(eof);
      } else if (text.endsWith('\r\n')) {
        const cr = document.createElement('span'); cr.className = 'ft-diff-eof'; cr.textContent = ' ␍'; body.append(cr);
      }
      if (changed) item.classList.add(side === 'a' ? 'ft-diff-removed' : 'ft-diff-added');
      item.append(number, sign, body); return item;
    }
    async function renderComparison(view) {
      const version = ++revision;
      view.controller?.abort(); view.controller = new AbortController();
      view.body.replaceChildren(); view.more.hidden = true; view.status.textContent = '正在比较…';
      view.source.disabled = view.refresh.disabled = true;
      try {
        const disk = view.source.value === 'disk';
        const snapshot = disk ? await api.request('/content', { root_id: view.doc.file.root_id, path: view.doc.file.path }, { signal: view.controller.signal }) : { content: view.doc.baseline };
        if (version !== revision) return;
        const before = snapshot.content, after = view.doc.area.value;
        if (typeof before !== 'string') throw new Error('未读取到可比较的文本，草稿已保留。');
        view.left.textContent = disk ? '磁盘最新内容 · 本次读取' : '上次打开 / 保存的内容';
        view.right.textContent = '当前草稿';
        const result = await request('diff', { before, after });
        if (version !== revision) return;
        if (result.limited) {
          view.status.textContent = '差异较大，显示完整原文对照；未计算逐行标记。';
          const row = document.createElement('div'); row.className = 'ft-diff-row ft-diff-full';
          for (const text of [before, after]) { const pre = document.createElement('pre'); pre.textContent = text; row.append(pre); }
          view.body.append(row); return;
        }
        view.status.textContent = result.equal ? '内容一致。' : `新增 ${result.added} 行 · 删除 ${result.removed} 行`;
        let shown = 0;
        const append = () => {
          const fragment = document.createDocumentFragment();
          for (const row of result.rows.slice(shown, shown + 300)) {
            if (row.skipped) { const gap = document.createElement('div'); gap.className = 'ft-diff-gap'; gap.textContent = `… ${row.skipped} 行相同内容 …`; fragment.append(gap); }
            else { const pair = document.createElement('div'); pair.className = 'ft-diff-row'; pair.append(cell(row.a, row.left, 'a', row.changed), cell(row.b, row.right, 'b', row.changed)); fragment.append(pair); }
          }
          shown += Math.min(300, result.rows.length - shown); view.body.append(fragment);
          view.more.hidden = shown >= result.rows.length;
          view.more.textContent = `继续显示（还剩 ${result.rows.length - shown} 行）`;
        };
        view.more.onclick = append; append();
      } catch (error) {
        if (version !== revision || error.name === 'AbortError') return;
        view.status.textContent = `比较失败：${error.message}。当前草稿已保留。`;
      } finally { if (version === revision) { view.source.disabled = false; view.refresh.disabled = false; } }
    }
    function showComparison(doc) {
      if (!doc) return;
      closeComparison(false); active = doc;
      const element = document.createElement('section'); element.className = 'ft-comparison'; element.setAttribute('aria-label', '文本差异比较');
      const controls = document.createElement('div'); controls.className = 'ft-toolbar';
      const label = document.createElement('label'); label.className = 'dwrt-kit-field ft-compare-source'; label.textContent = '比较来源';
      const source = document.createElement('select'); source.className = 'dwrt-kit-select'; source.setAttribute('aria-label', '比较来源');
      for (const [value, title] of [['baseline','上次打开 / 保存'],['disk','磁盘最新内容']]) {
        const option = new Option(title,value); option.disabled = value === 'disk' && doc.fresh; source.append(option);
      }
      if (doc.conflicted && !doc.fresh) source.value = 'disk';
      label.append(source);
      const refresh = button('重新比较', () => renderComparison(view));
      const back = button('返回编辑', () => closeComparison());
      controls.append(label, refresh, back);
      const status = document.createElement('p'); status.className = 'ft-diff-status'; status.setAttribute('role','status');
      const hint = document.createElement('p'); hint.className = 'ft-diff-hint'; hint.textContent = '左右滑动查看两栏';
      const scroll = document.createElement('div'); scroll.className = 'ft-diff-scroll'; scroll.tabIndex = 0; scroll.setAttribute('aria-label','左右版本，按方向键滚动');
      const headings = document.createElement('div'); headings.className = 'ft-diff-headings';
      const left = document.createElement('strong'), right = document.createElement('strong'); headings.append(left,right);
      const body = document.createElement('div'); body.className = 'ft-diff-body';
      scroll.append(headings,body);
      const more = button('继续显示', () => {}); more.hidden = true;
      element.append(controls,status,hint,scroll,more);
      const view = comparison = { element, doc, source, refresh, status, body, left, right, more };
      source.addEventListener('change', () => renderComparison(view));
      document.querySelector('#ftEditors').hidden = true; document.querySelector('#ftSavebar').hidden = true;
      document.querySelectorAll('.ft-edit-controls,.ft-search-panel').forEach((el) => { el.hidden = true; });
      document.querySelector('#ftEditors').after(element); back.focus(); renderComparison(view);
    }
    return {
      update,
      activate(doc) { closeComparison(false); active = doc; update(doc); },
      language(doc, language) { doc.language = language; doc.highlightText = undefined; update(doc); },
      closeComparison,
      showComparison,
      dispose(doc) { doc.resize?.disconnect(); clearTimeout(doc.highlightTimer); doc.highlightVersion++; documents.delete(doc); if (active === doc) closeComparison(false); },
      destroy() { stopped = true; closeComparison(false); for (const doc of documents) { doc.resize?.disconnect(); clearTimeout(doc.highlightTimer); } resetWorker('文本工具已关闭。'); }
    };
  };
})();
