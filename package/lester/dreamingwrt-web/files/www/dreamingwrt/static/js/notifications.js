(() => {
  const REGION_ID = 'dwrtNotifyRegion';
  const TYPES = new Set(['success', 'warning', 'error', 'info']);
  const DEFAULT_DURATION = 4200;

  const icons = {
    success: '<svg viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"></path></svg>',
    warning: '<svg viewBox="0 0 24 24"><path d="M12 3 2.8 20h18.4L12 3z"></path><path d="M12 9v5M12 17h.01"></path></svg>',
    error: '<svg viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"></path></svg>',
    info: '<svg viewBox="0 0 24 24"><path d="M12 17v-6"></path><path d="M12 8h.01"></path><circle cx="12" cy="12" r="9"></circle></svg>'
  };

  const labels = {
    success: '已完成',
    warning: '需要注意',
    error: '操作失败',
    info: '通知'
  };

  function normalizeType(type) {
    const value = String(type || 'info').toLowerCase();
    if (TYPES.has(value)) return value;
    if (value === 'warn') return 'warning';
    if (value === 'danger' || value === 'failed' || value === 'failure') return 'error';
    return 'info';
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[char]));
  }

  function ensureRegion() {
    let region = document.getElementById(REGION_ID);
    if (region) return region;
    region = document.createElement('div');
    region.id = REGION_ID;
    region.className = 'dwrt-notify-region';
    region.setAttribute('role', 'region');
    region.setAttribute('aria-label', '通知');
    region.setAttribute('aria-live', 'polite');
    document.body.appendChild(region);
    return region;
  }

  function show(typeOrTitle, titleOrOptions, descMaybe, optionsMaybe) {
    let type = 'info';
    let title = '';
    let desc = '';
    let options = {};

    if (typeof titleOrOptions === 'object' && titleOrOptions !== null) {
      title = String(typeOrTitle || '');
      options = titleOrOptions;
      type = normalizeType(options.type || 'info');
      desc = String(options.desc || '');
    } else {
      type = normalizeType(typeOrTitle);
      title = String(titleOrOptions || '');
      desc = String(descMaybe || '');
      options = optionsMaybe || {};
    }

    if (!title && desc) {
      title = desc;
      desc = '';
    }
    if (!title) title = labels[type];

    const timeLabel = String(options.time || '刚刚');
    const region = ensureRegion();
    const toast = document.createElement('article');
    toast.className = `dwrt-notify dwrt-notify--${type}`;
    toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
    toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
    toast.innerHTML = `
      <span class="dwrt-notify__icon" aria-hidden="true">${icons[type] || icons.info}</span>
      <span class="dwrt-notify__body">
        <span class="dwrt-notify__head">
          <strong class="dwrt-notify__title">${escapeHtml(title)}</strong>
          <time class="dwrt-notify__time">${escapeHtml(timeLabel)}</time>
        </span>
        ${desc ? `<span class="dwrt-notify__desc">${escapeHtml(desc)}</span>` : ''}
      </span>
      <button class="dwrt-notify__close" type="button" aria-label="关闭通知">×</button>
    `;

    const dismiss = () => {
      if (!toast.isConnected || toast.classList.contains('is-exiting')) return;
      toast.classList.add('is-exiting');
      toast.addEventListener('animationend', () => toast.remove(), { once: true });
    };

    toast.querySelector('.dwrt-notify__close')?.addEventListener('click', (event) => {
      event.stopPropagation();
      dismiss();
    });
    toast.addEventListener('click', dismiss);
    region.appendChild(toast);

    const duration = Number(options.duration ?? DEFAULT_DURATION);
    if (duration !== 0) window.setTimeout(dismiss, Number.isFinite(duration) ? duration : DEFAULT_DURATION);
    return toast;
  }

  window.DreamingWrtNotify = {
    show,
    success: (title, desc, options) => show('success', title, desc, options),
    warning: (title, desc, options) => show('warning', title, desc, options),
    error: (title, desc, options) => show('error', title, desc, options),
    info: (title, desc, options) => show('info', title, desc, options)
  };
})();
