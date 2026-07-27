let oauthCallbackClaimed = false;

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const mode = context.mode === 'global-drawer' ? 'global-drawer' : 'settings-route';
  const isGlobal = mode === 'global-drawer';
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const formatInteger = utils.formatInteger || ((value) => new Intl.NumberFormat('zh-CN').format(Number(value) || 0));
  const fetchApi = api.fetch || (async (name, url) => {
    const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store' });
    const json = await response.json().catch(() => ({}));
    const ok = response.ok && json?.ok !== false;
    return { name, ok, data: json?.data ?? json, raw: json, error: ok ? null : new Error(apiErrorText(json, response.statusText)) };
  });

  const VERSION = '20260719-30';
  const INSTANCE_ID = `ai-${Math.random().toString(36).slice(2)}-${Date.now().toString(36)}`;
  const MODULE_CLASS = 'ai-assistant-route-host';
  const ACTIVE_CONVERSATION_KEY = 'dreamingwrt.ai.activeConversation';
  const ACTIVE_CONVERSATION_TTL = 60 * 60 * 1000;
  const wallpaper = isGlobal ? document.getElementById('appWallpaper') : null;
  const ENDPOINTS = {
    config: '/api/v1/ai/config',
    models: '/api/v1/ai/models',
    history: '/api/v1/ai/history',
    chat: '/api/v1/ai/chat',
    attachments: '/api/v1/ai/attachments',
    oauthProviders: '/api/v1/ai/oauth/providers',
    oauthStatus: '/api/v1/ai/oauth/status',
    oauthStart: '/api/v1/ai/oauth/start',
    oauthPoll: '/api/v1/ai/oauth/poll',
    oauthRefresh: '/api/v1/ai/oauth/refresh',
    oauthDisconnect: '/api/v1/ai/oauth/disconnect'
  };
  const PROVIDERS = [
    { id: 'openai', label: 'OpenAI', mark: 'OpenAI', base: 'https://api.openai.com/v1' },
    { id: 'anthropic', label: 'Anthropic', mark: 'Claude', base: 'https://api.anthropic.com' },
    { id: 'gemini', label: 'Google Gemini', mark: 'Gemini', base: 'https://generativelanguage.googleapis.com/v1beta' },
    { id: 'kimi', label: 'Kimi Code', mark: 'Moonshot', base: 'https://api.kimi.com/coding/v1' },
    { id: 'deepseek', label: 'DeepSeek', mark: 'DeepSeek', base: 'https://api.deepseek.com' },
    { id: 'qwen', label: '通义千问', mark: 'Qwen', base: 'https://dashscope.aliyuncs.com/compatible-mode/v1' },
    { id: 'openai_compatible', label: 'OpenAI 兼容', mark: 'API', base: '' }
  ];
  const OAUTH_REASON_LABELS = {
    requires_preconfigured_anthropic_workload_identity_federation: '需要预先配置 Anthropic Workload Identity Federation。',
    no_public_third_party_oauth_for_openai_model_api: 'OpenAI 模型 API 尚未开放第三方 OAuth 接入，请使用 API Key。',
    no_public_third_party_oauth_for_xai_model_api: 'xAI 模型 API 尚未开放可供第三方使用的 OAuth 接入，请使用 API Key。',
    antigravity_has_no_independent_public_model_api_oauth_contract_use_gemini: 'Antigravity 不是独立模型 API，请改用 Gemini。',
    not_connected: '尚未建立 OAuth 连接。',
    refresh_token_unavailable: '当前连接没有可用的刷新凭据，请重新授权。',
    oauth_state_mismatch: '授权回调校验失败，请重新开始授权。',
    expired_token: '本次授权已经过期，请重新开始。',
    oauth_not_pending: '没有等待完成的授权流程。',
    authorization_pending: '等待你在提供商页面确认授权。',
    poll_too_fast: '检查过于频繁，将按提供商要求稍后重试。'
  };
  const REASONING_LABELS = {
    auto: '自动', none: '关闭', minimal: '极简', low: '较低', medium: '中等', high: '较高', xhigh: '最高'
  };
  const TOOL_POLICIES = [
    ['confirm_medium', '中风险操作需确认'],
    ['read_only', '仅允许读取'],
    ['confirm_all', '所有操作均需确认']
  ];

  function loadOrbState() {
    try {
      const value = JSON.parse(localStorage.getItem('dreamingwrt.ai.orb') || 'null');
      return {
        x: Number.isFinite(Number(value?.x)) ? Number(value.x) : null,
        y: Number.isFinite(Number(value?.y)) ? Number(value.y) : null,
        docked: Boolean(value?.docked)
      };
    } catch (_) {
      return { x: null, y: null, docked: false };
    }
  }

  function loadActiveConversation() {
    if (!isGlobal) return { id: '', at: 0 };
    try {
      const value = JSON.parse(sessionStorage.getItem(ACTIVE_CONVERSATION_KEY) || 'null');
      const at = Number(value?.at) || 0;
      if (!firstText(value?.id) || Date.now() - at >= ACTIVE_CONVERSATION_TTL) {
        sessionStorage.removeItem(ACTIVE_CONVERSATION_KEY);
        return { id: '', at: 0 };
      }
      return { id: firstText(value.id), at };
    } catch (_) {
      return { id: '', at: 0 };
    }
  }

  const initialRequest = isGlobal ? consumeInitialRequest() : { prompt: '', autoSend: false };
  const activeConversation = loadActiveConversation();
  const state = {
    mounted: true,
    tab: isGlobal ? 'chat' : 'settings',
    drawerOpen: Boolean(initialRequest.prompt),
    historyPage: 1,
    historyPageSize: 10,
    orb: loadOrbState(),
    orbDrag: null,
    orbClickBlockedUntil: 0,
    addMenuOpen: false,
    runtimeMenuOpen: false,
    runtimePane: 'main',
    activeConversation,
    currentTouchedAt: activeConversation.at,
    config: normalizeConfig({}),
    baseline: '',
    models: [],
    history: [],
    historyQuery: '',
    current: newConversation(),
    prompt: initialRequest.prompt,
    initialAutoSend: initialRequest.autoSend,
    attachments: [],
    loading: true,
    historyLoading: true,
    settingsError: '',
    historyError: '',
    chatError: '',
    notice: '',
    saving: false,
    sending: false,
    syncingModels: false,
    oauth: {
      available: false,
      catalog: [],
      statuses: {},
      statusLoading: '',
      action: '',
      flow: null,
      confirmDisconnect: false,
      inputs: {
        gemini: {
          client_id: '',
          project_id: '',
          redirect_uri: `${window.location.origin}${window.location.pathname}`
        },
        anthropic: {
          identity_token_file: '',
          federation_rule_id: '',
          organization_id: '',
          service_account_id: '',
          workspace_id: ''
        }
      }
    },
    loadingConversation: '',
    deletingConversation: '',
    seq: 0,
    shouldStickChat: true,
    scrollPositions: {}
  };
  let oauthPollTimer = 0;

  function receiveOAuthCompletion(event) {
    if (event.origin !== window.location.origin || event.data?.type !== 'dreamingwrt:ai-oauth-complete') return;
    const provider = firstText(event.data.provider);
    if (!provider || !state.mounted) return;
    loadOAuthStatus(provider, { renderBefore: provider === state.config.provider }).then(() => notifyOAuthUpdated(provider));
  }

  async function receiveConfigUpdated(event) {
    if (event.detail?.source === INSTANCE_ID || !state.mounted) return;
    const result = await fetchApi('ai-config-update', ENDPOINTS.config);
    if (!state.mounted || !result?.ok) return;
    state.config = normalizeConfig(result.data);
    state.oauth.available = state.config.oauth.available;
    state.oauth.catalog = state.config.oauth.catalog;
    if (state.oauth.available) await loadOAuthStatus(state.config.provider, { quiet: true });
    markBaseline();
    render();
  }

  async function receiveOAuthUpdated(event) {
    if (event.detail?.source === INSTANCE_ID || !state.mounted) return;
    const provider = firstText(event.detail?.provider);
    if (!provider || !state.oauth.available) return;
    await loadOAuthStatus(provider, { quiet: true });
    if (provider === state.config.provider) render();
  }

  function notifyConfigUpdated() {
    window.dispatchEvent(new CustomEvent('dwrt:ai-config-updated', { detail: { source: INSTANCE_ID } }));
  }

  function notifyOAuthUpdated(provider) {
    window.dispatchEvent(new CustomEvent('dwrt:ai-oauth-updated', { detail: { source: INSTANCE_ID, provider } }));
  }

  window.addEventListener('message', receiveOAuthCompletion);
  window.addEventListener('dwrt:ai-config-updated', receiveConfigUpdated);
  window.addEventListener('dwrt:ai-oauth-updated', receiveOAuthUpdated);

  function consumeInitialRequest() {
    try {
      const raw = sessionStorage.getItem('dreamingwrt.ai.initialRequest');
      sessionStorage.removeItem('dreamingwrt.ai.initialRequest');
      if (!raw) return { prompt: '', autoSend: false };
      const parsed = JSON.parse(raw);
      return { prompt: firstText(parsed?.prompt).slice(0, 12000), autoSend: Boolean(parsed?.autoSend) };
    } catch (_) {
      return { prompt: '', autoSend: false };
    }
  }

  function receiveInitialRequest(event) {
    const prompt = firstText(event?.detail?.prompt).slice(0, 12000);
    if (!prompt || !state.mounted) return;
    state.prompt = prompt;
    state.initialAutoSend = Boolean(event?.detail?.autoSend);
    state.drawerOpen = true;
    setTab('chat');
    render();
    requestAnimationFrame(() => {
      const input = root.querySelector('[data-ai-prompt]');
      input?.focus();
      if (!state.loading && state.initialAutoSend && credentialReady()) {
        state.initialAutoSend = false;
        sendMessage();
      }
    });
  }

  if (isGlobal) window.addEventListener('dwrt:ai-initial-request', receiveInitialRequest);

  function syncDrawerWallpaper() {
    if (!isGlobal || !wallpaper || !root) return;
    const image = root.querySelector('[data-ai-drawer-wallpaper-image]');
    if (!image) return;
    const src = wallpaper.currentSrc || wallpaper.getAttribute('src') || '';
    if (src && image.getAttribute('src') !== src) image.setAttribute('src', src);
    const style = getComputedStyle(wallpaper);
    image.style.objectFit = style.objectFit || 'cover';
    image.style.objectPosition = style.objectPosition || '50% 50%';
    image.style.filter = style.filter || 'none';
    image.style.opacity = style.opacity || '1';
  }

  function handleWallpaperChange() {
    requestAnimationFrame(syncDrawerWallpaper);
  }

  wallpaper?.addEventListener('load', handleWallpaperChange);
  const wallpaperObserver = wallpaper && typeof MutationObserver !== 'undefined'
    ? new MutationObserver(handleWallpaperChange)
    : null;
  wallpaperObserver?.observe(wallpaper, { attributes: true, attributeFilter: ['src', 'style', 'class'] });

  function handleGlobalPointerDown(event) {
    if (!isGlobal || (!state.addMenuOpen && !state.runtimeMenuOpen)) return;
    if (event.target.closest('.ai-add-control, .ai-runtime-control')) return;
    state.addMenuOpen = false;
    state.runtimeMenuOpen = false;
    root.querySelector('.ai-add-control')?.classList.remove('is-open');
    root.querySelector('.ai-runtime-control')?.classList.remove('is-open');
    root.querySelector('.ai-add-popover')?.remove();
    root.querySelector('.ai-runtime-popover')?.remove();
    root.querySelector('[data-ai-add-toggle]')?.setAttribute('aria-expanded', 'false');
    root.querySelector('[data-ai-runtime-toggle]')?.setAttribute('aria-expanded', 'false');
  }

  if (isGlobal) document.addEventListener('pointerdown', handleGlobalPointerDown);

  function clampOrbToViewport() {
    const position = orbPosition();
    state.orb.x = position.x;
    state.orb.y = position.y;
    const orb = root?.querySelector('[data-ai-orb]');
    orb?.style.setProperty('--ai-orb-x', `${position.x}px`);
    orb?.style.setProperty('--ai-orb-y', `${position.y}px`);
    saveOrbState();
  }

  function handleViewportResize() {
    if (!state.mounted || !isGlobal) return;
    clampOrbToViewport();
  }

  if (isGlobal) window.addEventListener('resize', handleViewportResize, { passive: true });

  function setTab(value) {
    state.tab = value === 'history' && isGlobal ? 'history' : isGlobal ? 'chat' : 'settings';
  }

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function firstNumber(...values) {
    for (const value of values) {
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (Array.isArray(value?.items)) return value.items;
    if (Array.isArray(value?.models)) return value.models;
    if (Array.isArray(value?.conversations)) return value.conversations;
    return [];
  }

  function apiErrorText(payload, fallback = '请求失败') {
    return firstText(payload?.error?.message, payload?.error?.code, payload?.error, payload?.data?.error?.message, payload?.data?.error?.code, payload?.data?.error, payload?.message, payload?.data?.message, fallback);
  }

  function safeHttpUrl(value) {
    try {
      const url = new URL(firstText(value));
      return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : '';
    } catch (_) {
      return '';
    }
  }

  function unwrap(value) {
    let current = value?.data ?? value ?? {};
    for (let i = 0; i < 3; i += 1) {
      if (!current || typeof current !== 'object' || Array.isArray(current)) break;
      if (current.data && typeof current.data === 'object') current = current.data;
      else break;
    }
    return current || {};
  }

  function normalizeConfig(value = {}) {
    const data = unwrap(value);
    const caps = data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : {};
    const oauth = data.oauth && typeof data.oauth === 'object' ? data.oauth : {};
    const temperature = firstNumber(data.temperature, 0.7);
    return {
      provider: firstText(data.provider, 'openai'),
      api_base: firstText(data.api_base),
      api_key_input: '',
      api_key_set: Boolean(data.api_key_set),
      api_key_hint: firstText(data.api_key),
      clear_api_key: false,
      auth_mode: firstText(data.auth_mode, 'api_key') === 'oauth' ? 'oauth' : 'api_key',
      model: firstText(data.model, 'gpt-4o'),
      temperature: Math.max(0, Math.min(2, temperature)),
      max_tokens: Math.max(1, Math.round(firstNumber(data.max_tokens, 4096))),
      system_prompt: firstText(data.system_prompt),
      tool_policy: firstText(data.tool_policy, 'confirm_medium'),
      enabled: Boolean(data.enabled),
      reasoning_effort: firstText(data.reasoning_effort, 'auto'),
      reasoning_api_shape: firstText(data.reasoning_api_shape, caps.reasoning_api_shape, 'chat_completions'),
      capabilities: {
        reasoning_effort_supported: caps.reasoning_effort_supported !== false,
        reasoning_effort_values: asArray(caps.reasoning_effort_values).map(String),
        attachment_ids: caps.attachment_ids === true,
        attachment_upload_endpoint: firstText(caps.attachment_upload_endpoint, '/api/v1/ai/attachments')
      },
      oauth: {
        available: oauth.available === true,
        catalog: asArray(oauth.providers),
        status_endpoint: firstText(oauth.status_endpoint, ENDPOINTS.oauthStatus),
        start_endpoint: firstText(oauth.start_endpoint, ENDPOINTS.oauthStart),
        poll_endpoint: firstText(oauth.poll_endpoint, ENDPOINTS.oauthPoll),
        refresh_endpoint: firstText(oauth.refresh_endpoint, ENDPOINTS.oauthRefresh),
        disconnect_endpoint: firstText(oauth.disconnect_endpoint, ENDPOINTS.oauthDisconnect)
      }
    };
  }

  function configComparable(config = state.config) {
    return JSON.stringify({
      provider: config.provider,
      api_base: config.api_base,
      api_key_input: config.api_key_input,
      clear_api_key: Boolean(config.clear_api_key),
      auth_mode: config.auth_mode,
      model: config.model,
      temperature: Number(config.temperature),
      max_tokens: Number(config.max_tokens),
      system_prompt: config.system_prompt,
      tool_policy: config.tool_policy,
      enabled: Boolean(config.enabled),
      reasoning_effort: config.reasoning_effort,
      reasoning_api_shape: config.reasoning_api_shape
    });
  }

  function markBaseline() {
    state.baseline = configComparable();
  }

  function configDirty() {
    return Boolean(state.baseline) && state.baseline !== configComparable();
  }

  function providerDefinition(id = state.config.provider) {
    return PROVIDERS.find((item) => item.id === id) || PROVIDERS[0];
  }

  function oauthProvider(id = state.config.provider) {
    return state.oauth.catalog.find((item) => firstText(item?.provider) === id) || null;
  }

  function oauthStatus(id = state.config.provider) {
    return state.oauth.statuses[id] || null;
  }

  function credentialReady() {
    if (!state.config.enabled) return false;
    if (state.config.auth_mode !== 'oauth') return state.config.api_key_set;
    const status = oauthStatus();
    return Boolean(status?.connected) && !status?.expired;
  }

  function oauthReason(value, fallback = '') {
    const reason = firstText(value);
    return OAUTH_REASON_LABELS[reason] || fallback || reason;
  }

  function oauthProviderLabel(id) {
    return ({
      gemini: 'Google Gemini',
      kimi: 'Kimi Code',
      anthropic: 'Anthropic',
      openai: 'OpenAI',
      grok: 'Grok / xAI',
      antigravity: 'Antigravity'
    })[id] || id;
  }

  function newConversation() {
    return {
      id: '',
      title: '',
      model: '',
      reasoning_effort: '',
      tool_policy: '',
      usage: {},
      messages: []
    };
  }

  function conversationTitle() {
    return firstText(state.current.title, '新对话');
  }

  function clearActiveConversation() {
    state.activeConversation = { id: '', at: 0 };
    state.currentTouchedAt = 0;
    if (!isGlobal) return;
    try { sessionStorage.removeItem(ACTIVE_CONVERSATION_KEY); } catch (_) {}
  }

  function touchActiveConversation(id = state.current.id) {
    const conversation = firstText(id);
    if (!isGlobal || !conversation) return;
    const at = Date.now();
    state.activeConversation = { id: conversation, at };
    state.currentTouchedAt = at;
    try { sessionStorage.setItem(ACTIVE_CONVERSATION_KEY, JSON.stringify({ id: conversation, at })); } catch (_) {}
  }

  function expireInactiveConversation() {
    if (!state.current.id || !state.currentTouchedAt || Date.now() - state.currentTouchedAt < ACTIVE_CONVERSATION_TTL) return false;
    clearActiveConversation();
    state.current = newConversation();
    state.current.model = state.config.model;
    state.current.reasoning_effort = state.config.reasoning_effort;
    state.current.tool_policy = state.config.tool_policy;
    state.prompt = '';
    state.attachments = [];
    state.chatError = '';
    state.notice = '';
    state.addMenuOpen = false;
    state.runtimeMenuOpen = false;
    state.runtimePane = 'main';
    state.shouldStickChat = true;
    return true;
  }

  function normalizeMessage(value = {}, index = 0) {
    const role = firstText(value.role, value.author, 'assistant').toLowerCase();
    return {
      id: firstText(value.message_id, value.id, `${role}-${firstNumber(value.created_at, value.ts, Date.now())}-${index}`),
      role: role === 'user' ? 'user' : 'assistant',
      content: firstText(value.content, value.text, value.message),
      created_at: normalizeTimestamp(firstNumber(value.created_at, value.ts, Date.now())),
      attachments: asArray(value.attachments).map((item) => ({
        attachment_id: firstText(item.attachment_id),
        name: firstText(item.name, item.filename),
        size: firstNumber(item.size),
        type: firstText(item.type)
      }))
    };
  }

  function normalizeConversation(value = {}) {
    const data = unwrap(value);
    const item = data.item && typeof data.item === 'object' ? data.item : data;
    return {
      id: firstText(item.id),
      title: firstText(item.title, '新对话'),
      model: firstText(item.model, state.config.model),
      reasoning_effort: firstText(item.reasoning_effort, state.config.reasoning_effort),
      tool_policy: firstText(item.tool_policy, state.config.tool_policy),
      usage: item.usage && typeof item.usage === 'object' ? item.usage : {},
      messages: asArray(item.messages).map(normalizeMessage).filter((message) => message.content)
    };
  }

  function normalizeHistory(value = {}) {
    const data = unwrap(value);
    return asArray(data.items || data.conversations || data).map((item) => ({
      id: firstText(item.id),
      title: firstText(item.title, '新对话'),
      model: firstText(item.model),
      reasoning_effort: firstText(item.reasoning_effort, 'auto'),
      message_count: Math.max(0, Math.round(firstNumber(item.message_count))),
      created_at: normalizeTimestamp(firstNumber(item.created_at)),
      updated_at: normalizeTimestamp(firstNumber(item.updated_at, item.created_at)),
      usage: item.usage && typeof item.usage === 'object' ? item.usage : {}
    })).filter((item) => item.id);
  }

  function normalizeTimestamp(value) {
    const number = Number(value) || 0;
    return number > 0 && number < 100000000000 ? number * 1000 : number;
  }

  function conversationId() {
    if (state.current.id) return state.current.id;
    const random = Math.random().toString(36).slice(2, 8);
    state.current.id = `ai-web-${Date.now()}-${random}`;
    touchActiveConversation(state.current.id);
    return state.current.id;
  }

  function currentModel() {
    return firstText(state.current.model, state.config.model, state.models[0], 'gpt-4o');
  }

  function currentEffort() {
    return firstText(state.current.reasoning_effort, state.config.reasoning_effort, 'auto');
  }

  function currentToolPolicy() {
    return firstText(state.current.tool_policy, state.config.tool_policy, 'confirm_medium');
  }

  async function loadInitial() {
    const seq = ++state.seq;
    state.loading = true;
    state.historyLoading = true;
    render();
    const [configResult, modelsResult, historyResult] = await Promise.all([
      fetchApi('ai-config', ENDPOINTS.config),
      fetchApi('ai-models', ENDPOINTS.models),
      isGlobal ? fetchApi('ai-history', `${ENDPOINTS.history}?limit=100&offset=0`) : Promise.resolve({ ok: true, data: [] })
    ]);
    if (!state.mounted || seq !== state.seq) return;
    if (configResult?.ok) {
      state.config = normalizeConfig(configResult.data);
      state.oauth.available = state.config.oauth.available;
      state.oauth.catalog = state.config.oauth.catalog;
      state.settingsError = '';
      markBaseline();
    } else {
      state.settingsError = configResult?.error?.message || '无法读取 AI 接入配置';
      markBaseline();
    }
    if (modelsResult?.ok) {
      state.models = uniqueModels(asArray(unwrap(modelsResult.data).models || unwrap(modelsResult.data)));
    }
    if (!state.models.length) state.models = uniqueModels([state.config.model]);
    if (historyResult?.ok) {
      state.history = normalizeHistory(historyResult.data);
      state.historyError = '';
    } else {
      state.history = [];
      state.historyError = historyResult?.error?.message || '无法读取历史对话';
    }
    state.loading = false;
    state.historyLoading = false;
    if (state.oauth.available && state.config.provider) await loadOAuthStatus(state.config.provider, { quiet: true });
    await consumeOAuthCallback();
    const resumeId = firstText(state.activeConversation.id);
    if (isGlobal && resumeId && state.history.some((item) => item.id === resumeId)) {
      await openHistory(resumeId, { quiet: true });
    } else if (resumeId) {
      clearActiveConversation();
      render();
    } else {
      render();
    }
    if (state.prompt) requestAnimationFrame(() => {
      const prompt = root.querySelector('[data-ai-prompt]');
      prompt?.focus();
      if (state.initialAutoSend && credentialReady()) {
        state.initialAutoSend = false;
        sendMessage();
      }
    });
  }

  function clearOAuthPollTimer() {
    if (!oauthPollTimer) return;
    window.clearTimeout(oauthPollTimer);
    oauthPollTimer = 0;
  }

  function scheduleOAuthPoll(seconds) {
    clearOAuthPollTimer();
    const delay = Math.max(1, firstNumber(seconds, state.oauth.flow?.poll_after_seconds, state.oauth.flow?.interval, 5));
    oauthPollTimer = window.setTimeout(() => pollOAuth(), delay * 1000);
  }

  async function loadOAuthStatus(provider = state.config.provider, options = {}) {
    if (!provider || !state.oauth.available) return null;
    if (!options.quiet) {
      state.oauth.statusLoading = provider;
      if (options.renderBefore) render();
    }
    try {
      const result = await requestJson(`${state.config.oauth.status_endpoint}?provider=${encodeURIComponent(provider)}`);
      const status = unwrap(result);
      state.oauth.statuses[provider] = status;
      if (status.pending && provider === 'kimi' && state.oauth.flow?.provider === 'kimi') {
        scheduleOAuthPoll(state.oauth.flow.poll_after_seconds);
      }
      return status;
    } catch (error) {
      if (!options.quiet) state.settingsError = error?.message || '无法读取 OAuth 状态';
      return null;
    } finally {
      if (!options.quiet) {
        state.oauth.statusLoading = '';
        render();
      }
    }
  }

  function oauthStartPayload(provider) {
    if (provider === 'gemini') {
      const values = state.oauth.inputs.gemini;
      const redirectUri = firstText(values.redirect_uri, `${window.location.origin}${window.location.pathname}`);
      if (!firstText(values.client_id) || !firstText(values.project_id) || !redirectUri) {
        throw new Error('请填写 Google Client ID、Project ID 和回调地址');
      }
      return { provider, client_id: values.client_id.trim(), project_id: values.project_id.trim(), redirect_uri: redirectUri.trim() };
    }
    if (provider === 'anthropic') {
      const values = state.oauth.inputs.anthropic;
      for (const key of ['identity_token_file', 'federation_rule_id', 'organization_id', 'service_account_id']) {
        if (!firstText(values[key])) throw new Error('请填写完整的 Anthropic WIF 配置');
      }
      return Object.fromEntries([['provider', provider], ...Object.entries(values).filter(([, value]) => firstText(value)).map(([key, value]) => [key, value.trim()])]);
    }
    return { provider };
  }

  async function startOAuth() {
    const provider = state.config.provider;
    if (state.oauth.action || oauthProvider(provider)?.supported !== true) return;
    clearOAuthPollTimer();
    state.oauth.action = `${provider}:start`;
    state.settingsError = '';
    state.notice = '';
    render();
    try {
      const result = unwrap(await postJson(state.config.oauth.start_endpoint, oauthStartPayload(provider)));
      state.oauth.flow = { ...result, provider };
      if (provider === 'gemini') {
        const url = safeHttpUrl(result.authorization_url);
        if (!url) throw new Error('后端没有返回 Google 授权地址');
        const popup = window.open(url, 'dreamingwrt-gemini-oauth', 'popup=yes,width=720,height=820');
        if (!popup) window.location.assign(url);
        else popup.focus();
        state.notice = 'Google 授权页面已打开';
      } else if (provider === 'kimi') {
        const url = safeHttpUrl(firstText(result.verification_uri_complete, result.verification_uri));
        if (url) window.open(url, 'dreamingwrt-kimi-oauth', 'popup=yes,width=720,height=820')?.focus();
        scheduleOAuthPoll(result.poll_after_seconds);
      } else if (provider === 'anthropic' && result.connected) {
        state.notice = 'Anthropic WIF 已连接';
        notifyOAuthUpdated(provider);
      }
      await loadOAuthStatus(provider, { quiet: true });
    } catch (error) {
      state.settingsError = oauthReason(error?.payload?.error, error?.message || 'OAuth 授权启动失败');
    }
    state.oauth.action = '';
    render();
  }

  async function pollOAuth(payload = {}) {
    const provider = firstText(payload.provider, state.oauth.flow?.provider, state.config.provider);
    if (!provider || state.oauth.action === `${provider}:poll`) return;
    let shouldRender = false;
    state.oauth.action = `${provider}:poll`;
    try {
      const result = unwrap(await postJson(state.config.oauth.poll_endpoint, { provider, ...payload }));
      state.oauth.statuses[provider] = { ...(state.oauth.statuses[provider] || {}), ...result, pending: false };
      state.oauth.flow = null;
      if (provider === state.config.provider) state.notice = `${oauthProviderLabel(provider)} 已连接`;
      notifyOAuthUpdated(provider);
      clearOAuthPollTimer();
      shouldRender = true;
    } catch (error) {
      const code = firstText(error?.payload?.error?.code, error?.payload?.error, error?.payload?.data?.error);
      const retry = firstNumber(error?.payload?.retry_after_seconds, error?.payload?.data?.retry_after_seconds, state.oauth.flow?.poll_after_seconds, 5);
      if (error?.status === 202 || error?.status === 429 || code === 'authorization_pending' || code === 'slow_down' || code === 'poll_too_fast') {
        scheduleOAuthPoll(retry);
      } else {
        clearOAuthPollTimer();
        state.settingsError = oauthReason(code, error?.message || 'OAuth 授权检查失败');
        shouldRender = true;
      }
    }
    state.oauth.action = '';
    if (state.mounted && shouldRender) render();
  }

  function callbackParameters() {
    const url = new URL(window.location.href);
    const hashParams = new URLSearchParams((url.hash.split('?')[1] || '').replace(/^\?/, ''));
    return {
      code: firstText(url.searchParams.get('code'), hashParams.get('code')),
      state: firstText(url.searchParams.get('state'), hashParams.get('state')),
      error: firstText(url.searchParams.get('error'), hashParams.get('error'))
    };
  }

  function stripOAuthCallbackFromUrl() {
    const url = new URL(window.location.href);
    ['code', 'state', 'error', 'error_description', 'scope'].forEach((key) => url.searchParams.delete(key));
    if (url.hash.includes('?')) {
      const [route, query] = url.hash.split('?');
      const params = new URLSearchParams(query);
      ['code', 'state', 'error', 'error_description', 'scope'].forEach((key) => params.delete(key));
      url.hash = params.toString() ? `${route}?${params}` : route;
    }
    window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`);
  }

  async function consumeOAuthCallback() {
    const callback = callbackParameters();
    if ((!callback.code && !callback.error) || oauthCallbackClaimed) return;
    oauthCallbackClaimed = true;
    try {
      if (callback.error) throw new Error(callback.error);
      if (!callback.state) throw new Error('Google OAuth 回调缺少 state');
      const result = unwrap(await postJson(state.config.oauth.poll_endpoint, { provider: 'gemini', code: callback.code, state: callback.state }));
      state.oauth.statuses.gemini = { ...(state.oauth.statuses.gemini || {}), ...result, pending: false };
      state.oauth.flow = null;
      state.notice = 'Google Gemini 已连接';
      notifyOAuthUpdated('gemini');
      window.opener?.postMessage({ type: 'dreamingwrt:ai-oauth-complete', provider: 'gemini' }, window.location.origin);
      if (window.opener && !window.opener.closed) window.setTimeout(() => window.close(), 650);
    } catch (error) {
      state.settingsError = oauthReason(error?.payload?.error, error?.message || 'Google OAuth 回调处理失败');
    } finally {
      stripOAuthCallbackFromUrl();
      render();
    }
  }

  async function refreshOAuth() {
    const provider = state.config.provider;
    if (state.oauth.action || !oauthStatus(provider)?.connected) return;
    state.oauth.action = `${provider}:refresh`;
    state.settingsError = '';
    render();
    try {
      const result = unwrap(await postJson(state.config.oauth.refresh_endpoint, { provider }));
      state.oauth.statuses[provider] = { ...(state.oauth.statuses[provider] || {}), ...result, expired: false };
      state.notice = 'OAuth 凭据已刷新';
      notifyOAuthUpdated(provider);
    } catch (error) {
      state.settingsError = oauthReason(error?.payload?.error, error?.message || 'OAuth 凭据刷新失败');
    }
    state.oauth.action = '';
    render();
  }

  async function disconnectOAuth() {
    const provider = state.config.provider;
    if (state.oauth.action) return;
    clearOAuthPollTimer();
    state.oauth.confirmDisconnect = false;
    state.oauth.action = `${provider}:disconnect`;
    state.settingsError = '';
    render();
    try {
      await postJson(state.config.oauth.disconnect_endpoint, { provider });
      state.oauth.statuses[provider] = { ...(state.oauth.statuses[provider] || {}), connected: false, pending: false, expired: false, expires_at: 0 };
      state.oauth.flow = null;
      state.notice = 'OAuth 连接已断开';
      notifyOAuthUpdated(provider);
    } catch (error) {
      state.settingsError = error?.message || '断开 OAuth 连接失败';
    }
    state.oauth.action = '';
    render();
  }

  function uniqueModels(values) {
    const out = [];
    const seen = new Set();
    values.forEach((value) => {
      const model = firstText(value?.id, value?.name, value);
      if (!model || seen.has(model)) return;
      seen.add(model);
      out.push(model);
    });
    return out;
  }

  function render() {
    if (!root || !state.mounted) return;
    const snapshot = captureViewState();
    root.className = `${root.className.split(/\s+/).filter((item) => item && item !== MODULE_CLASS).join(' ')} ${MODULE_CLASS}`.trim();
    root.hidden = false;
    root.classList.toggle('ai-global-host', isGlobal);
    root.classList.toggle('ai-settings-route-host', !isGlobal);
    root.innerHTML = isGlobal ? globalMarkup() : `<main class="ai-assistant-shell ai-settings-route-shell"><div class="ai-view-host">${settingsView()}</div></main>`;
    ui.mountAll?.(root);
    bindEvents();
    if (isGlobal) bindGlobalEvents();
    restoreViewState(snapshot);
    if (isGlobal) {
      syncDrawerWallpaper();
      ui.scheduleAdaptiveForegroundSample?.(80, root);
    }
    else {
      ui.scheduleAdaptiveForegroundSample?.(80, root);
      ui.scheduleGlassCardsRender?.(120);
    }
  }

  function globalMarkup() {
    const position = orbPosition();
    return `<div class="ai-global-layer ${state.drawerOpen ? 'is-open' : ''} ${state.orb.docked ? 'is-docked' : ''}">
      <button class="ai-floating-orb" type="button" data-ai-orb aria-label="打开 AI 助手" style="--ai-orb-x:${position.x}px;--ai-orb-y:${position.y}px">${geminiMark()}</button>
      <button class="ai-orb-restore" type="button" data-ai-orb-restore aria-label="显示 AI 助手"><span>‹</span></button>
      <button class="ai-drawer-scrim" type="button" data-ai-drawer-close aria-label="关闭 AI 助手"></button>
      <aside class="ai-copilot-drawer" aria-label="AI 助手" aria-hidden="${state.drawerOpen ? 'false' : 'true'}">
        <div class="ai-drawer-wallpaper" aria-hidden="true"><img data-ai-drawer-wallpaper-image alt=""></div>
        <div class="ai-drawer-material" aria-hidden="true"></div>
        <header class="ai-copilot-header">
          <div class="ai-copilot-header-left">
            <button class="ai-copilot-icon-button ${state.tab === 'history' ? 'is-active' : ''}" type="button" data-ai-history-toggle title="历史对话" aria-label="历史对话">${historyIcon()}</button>
            <div class="ai-copilot-title"><strong>${state.tab === 'history' ? '历史对话' : escapeHtml(conversationTitle())}</strong></div>
          </div>
          <div class="ai-copilot-header-right">
            ${state.tab === 'history' ? `<button class="ai-copilot-icon-button" type="button" data-ai-history-exit title="退出历史" aria-label="退出历史">${icon('back')}</button>` : ''}
            ${connectionBadge()}
            <button class="ai-copilot-icon-button" type="button" data-ai-drawer-close title="关闭" aria-label="关闭 AI 助手">${icon('close')}</button>
          </div>
        </header>
        <div class="ai-copilot-body">${state.tab === 'history' ? historyView() : chatView()}</div>
      </aside>
    </div>`;
  }

  function orbPosition() {
    const size = 58;
    const margin = 22;
    const maxX = Math.max(margin, window.innerWidth - size - margin);
    const maxY = Math.max(margin, window.innerHeight - size - margin);
    return {
      x: Math.max(margin, Math.min(maxX, state.orb.x === null ? maxX : state.orb.x)),
      y: Math.max(margin, Math.min(maxY, state.orb.y === null ? maxY : state.orb.y))
    };
  }

  function saveOrbState() {
    try { localStorage.setItem('dreamingwrt.ai.orb', JSON.stringify(state.orb)); } catch (_) {}
  }

  function geminiMark() {
    return `<svg viewBox="0 0 296 298" fill="none" aria-hidden="true"><mask id="dwrt-ai-gemini-mask" width="296" height="298" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:alpha"><path fill="#3186FF" d="M141.201 4.886c2.282-6.17 11.042-6.071 13.184.148l5.985 17.37a184.004 184.004 0 0 0 111.257 113.049l19.304 6.997c6.143 2.227 6.156 10.91.02 13.155l-19.35 7.082a184.001 184.001 0 0 0-109.495 109.385l-7.573 20.629c-2.241 6.105-10.869 6.121-13.133.025l-7.908-21.296a184 184 0 0 0-109.02-108.658l-19.698-7.239c-6.102-2.243-6.118-10.867-.025-13.132l20.083-7.467A183.998 183.998 0 0 0 133.291 26.28l7.91-21.394Z"/></mask><g mask="url(#dwrt-ai-gemini-mask)"><g filter="url(#dwrt-ai-gemini-blue)"><ellipse cx="163" cy="149" fill="#3689FF" rx="196" ry="159"/></g><g filter="url(#dwrt-ai-gemini-yellow-a)"><ellipse cx="33.5" cy="142.5" fill="#F6C013" rx="68.5" ry="72.5"/></g><g filter="url(#dwrt-ai-gemini-yellow-b)"><ellipse cx="19.5" cy="148.5" fill="#F6C013" rx="68.5" ry="72.5"/></g><g filter="url(#dwrt-ai-gemini-red-a)"><path fill="#FA4340" d="M194 10.5C172 82.5 65.5 134.333 22.5 135L144-66l50 76.5Z"/></g><g filter="url(#dwrt-ai-gemini-red-b)"><path fill="#FA4340" d="M190.5-12.5C168.5 59.5 62 111.333 19 112L140.5-89l50 76.5Z"/></g><g filter="url(#dwrt-ai-gemini-green-a)"><path fill="#14BB69" d="M194.5 279.5C172.5 207.5 66 155.667 23 155l121.5 201 50-76.5Z"/></g><g filter="url(#dwrt-ai-gemini-green-b)"><path fill="#14BB69" d="M196.5 320.5C174.5 248.5 68 196.667 25 196l121.5 201 50-76.5Z"/></g></g><defs><filter id="dwrt-ai-gemini-blue" width="464" height="390" x="-69" y="-46" color-interpolation-filters="sRGB" filterUnits="userSpaceOnUse"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur result="effect1_foregroundBlur" stdDeviation="18"/></filter><filter id="dwrt-ai-gemini-yellow-a" width="265" height="273" x="-99" y="6" color-interpolation-filters="sRGB" filterUnits="userSpaceOnUse"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur result="effect1_foregroundBlur" stdDeviation="32"/></filter><filter id="dwrt-ai-gemini-yellow-b" width="265" height="273" x="-113" y="12" color-interpolation-filters="sRGB" filterUnits="userSpaceOnUse"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur result="effect1_foregroundBlur" stdDeviation="32"/></filter><filter id="dwrt-ai-gemini-red-a" width="299.5" height="329" x="-41.5" y="-130" color-interpolation-filters="sRGB" filterUnits="userSpaceOnUse"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur result="effect1_foregroundBlur" stdDeviation="32"/></filter><filter id="dwrt-ai-gemini-red-b" width="299.5" height="329" x="-45" y="-153" color-interpolation-filters="sRGB" filterUnits="userSpaceOnUse"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur result="effect1_foregroundBlur" stdDeviation="32"/></filter><filter id="dwrt-ai-gemini-green-a" width="299.5" height="329" x="-41" y="91" color-interpolation-filters="sRGB" filterUnits="userSpaceOnUse"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur result="effect1_foregroundBlur" stdDeviation="32"/></filter><filter id="dwrt-ai-gemini-green-b" width="299.5" height="329" x="-39" y="132" color-interpolation-filters="sRGB" filterUnits="userSpaceOnUse"><feFlood flood-opacity="0" result="BackgroundImageFix"/><feBlend in="SourceGraphic" in2="BackgroundImageFix" result="shape"/><feGaussianBlur result="effect1_foregroundBlur" stdDeviation="32"/></filter></defs></svg>`;
  }

  function historyIcon() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>';
  }

  function chatView() {
    const configured = credentialReady();
    const messages = state.current.messages;
    return `
      <section class="ai-chat-card ai-page-card ${isGlobal ? 'ai-drawer-chat' : 'dwrt-kit-page-surface dwrt-kit-glass-surface'}">
        <div class="ai-chat-scroll" data-ai-scroll="chat" role="log" aria-live="polite">
          ${state.loading ? loadingState('正在读取 AI 配置') : messages.length ? messages.map(messageMarkup).join('') : chatEmptyState()}
        </div>
        <footer class="ai-composer-wrap">
          ${state.chatError ? `<div class="ai-inline-message error">${icon('alert')}<span>${escapeHtml(state.chatError)}</span></div>` : ''}
          ${state.notice ? `<div class="ai-inline-message success">${icon('check')}<span>${escapeHtml(state.notice)}</span></div>` : ''}
          ${attachmentTray()}
          <div class="ai-composer ${configured ? '' : 'is-disabled'}">
            <input type="file" data-ai-file hidden multiple accept=".txt,.log,.conf,.json,.yaml,.yml,.md,text/*,application/json">
            <textarea data-ai-prompt rows="1" maxlength="12000" aria-label="AI 消息" placeholder="${configured ? '输入消息，/new 开始新对话' : 'AI 当前未配置'}" ${configured && !state.sending ? '' : 'disabled'}>${escapeHtml(state.prompt)}</textarea>
            <div class="ai-composer-bar">
              <div class="ai-composer-tools">
                ${addMenu(configured)}
              </div>
              <div class="ai-composer-options">
                ${runtimeMenu()}
                <button class="ai-send-button" type="button" data-ai-send title="发送" aria-label="发送" ${configured && !state.sending ? '' : 'disabled'}>${state.sending ? icon('loader') : icon('send')}</button>
              </div>
            </div>
          </div>
        </footer>
      </section>
    `;
  }

  function chatEmptyState() {
    return '<div class="ai-chat-empty" aria-hidden="true"></div>';
  }

  function addMenu(configured) {
    const disabled = !configured || state.sending;
    return `<div class="ai-add-control ${state.addMenuOpen ? 'is-open' : ''}">
      <button class="ai-composer-icon" type="button" data-ai-add-toggle title="添加" aria-label="添加内容" aria-haspopup="menu" aria-expanded="${state.addMenuOpen ? 'true' : 'false'}" ${disabled ? 'disabled' : ''}>${icon('plus')}</button>
      ${state.addMenuOpen ? `<div class="ai-add-popover" role="menu">
        <button type="button" role="menuitem" data-ai-add-file>${icon('paperclip')}<span><strong>上传附件</strong><small>日志、配置或文本文件</small></span></button>
        ${isGlobal ? `<button type="button" role="menuitem" data-ai-add-page>${icon('page-add')}<span><strong>添加当前页面</strong><small>发送当前页面内容</small></span></button>` : ''}
      </div>` : ''}
    </div>`;
  }

  function runtimeMenu() {
    const effort = REASONING_LABELS[currentEffort()] || currentEffort();
    return `<div class="ai-runtime-control ${state.runtimeMenuOpen ? 'is-open' : ''}">
      <button class="ai-runtime-trigger" type="button" data-ai-runtime-toggle aria-haspopup="menu" aria-expanded="${state.runtimeMenuOpen ? 'true' : 'false'}" ${state.loading ? 'disabled' : ''}>
        <span>${escapeHtml(currentModel())}</span><small>${escapeHtml(effort)}</small>${icon('chevron-down')}
      </button>
      ${state.runtimeMenuOpen ? runtimePopover() : ''}
    </div>`;
  }

  function runtimePopover() {
    if (state.runtimePane === 'model') {
      const models = uniqueModels([currentModel(), ...state.models]);
      return `<div class="ai-runtime-popover ai-runtime-choice-list" role="menu">
        <button class="ai-runtime-back" type="button" data-ai-runtime-pane="main">${icon('back')}<strong>模型</strong></button>
        <div class="ai-runtime-list">${models.map((model) => `<button type="button" role="menuitemradio" aria-checked="${model === currentModel() ? 'true' : 'false'}" data-ai-model-option="${escapeHtml(model)}"><span>${escapeHtml(model)}</span>${model === currentModel() ? icon('check') : ''}</button>`).join('')}</div>
      </div>`;
    }
    if (state.runtimePane === 'effort') {
      const provided = state.config.capabilities.reasoning_effort_values;
      const values = uniqueModels([currentEffort(), ...(provided.length ? provided : ['auto', 'none', 'minimal', 'low', 'medium', 'high', 'xhigh'])]);
      return `<div class="ai-runtime-popover ai-runtime-choice-list" role="menu">
        <button class="ai-runtime-back" type="button" data-ai-runtime-pane="main">${icon('back')}<strong>推理强度</strong></button>
        <div class="ai-runtime-list">${values.map((value) => `<button type="button" role="menuitemradio" aria-checked="${value === currentEffort() ? 'true' : 'false'}" data-ai-effort-option="${escapeHtml(value)}"><span>${escapeHtml(REASONING_LABELS[value] || value)}</span>${value === currentEffort() ? icon('check') : ''}</button>`).join('')}</div>
      </div>`;
    }
    if (state.runtimePane === 'advanced') {
      return `<div class="ai-runtime-popover ai-runtime-choice-list" role="menu">
        <button class="ai-runtime-back" type="button" data-ai-runtime-pane="main">${icon('back')}<strong>高级</strong></button>
        <div class="ai-runtime-list">${TOOL_POLICIES.map(([value, label]) => `<button type="button" role="menuitemradio" aria-checked="${value === currentToolPolicy() ? 'true' : 'false'}" data-ai-policy-option="${value}"><span>${escapeHtml(label)}</span>${value === currentToolPolicy() ? icon('check') : ''}</button>`).join('')}</div>
      </div>`;
    }
    return `<div class="ai-runtime-popover" role="menu">
      <button type="button" role="menuitem" data-ai-runtime-pane="model"><strong>模型</strong><span>${escapeHtml(currentModel())}</span>${icon('chevron-right')}</button>
      <button type="button" role="menuitem" data-ai-runtime-pane="effort" ${reasoningDisabled() ? 'disabled' : ''}><strong>推理强度</strong><span>${escapeHtml(REASONING_LABELS[currentEffort()] || currentEffort())}</span>${icon('chevron-right')}</button>
      <div class="ai-runtime-divider"></div>
      <button type="button" role="menuitem" data-ai-runtime-pane="advanced"><strong>高级</strong>${icon('chevron-right')}</button>
    </div>`;
  }

  function messageMarkup(message) {
    const attachments = asArray(message.attachments);
    return `
      <article class="ai-message ${message.role === 'user' ? 'is-user' : 'is-assistant'}">
        <div class="ai-message-author">${message.role === 'user' ? '你' : 'AI'}</div>
        <div class="ai-message-bubble">
          <div class="ai-message-content">${escapeHtml(message.content).replace(/\n/g, '<br>')}</div>
          ${attachments.length ? `<div class="ai-message-files">${attachments.map((file) => `<span>${icon('file')}${escapeHtml(file.name)}</span>`).join('')}</div>` : ''}
          <time>${formatMessageTime(message.created_at)}</time>
        </div>
      </article>
    `;
  }

  function attachmentTray() {
    if (!state.attachments.length) return '';
    return `
      <div class="ai-attachment-tray" aria-label="待发送附件">
        ${state.attachments.map((file, index) => `
          <span class="ai-attachment-chip">
            ${icon('file')}<b>${escapeHtml(file.name)}</b><small>${formatFileSize(file.size)}</small>
            <button type="button" data-ai-remove-file="${index}" title="移除附件" aria-label="移除 ${escapeHtml(file.name)}">${icon('close')}</button>
          </span>
        `).join('')}
      </div>
    `;
  }

  function historyView() {
    const rows = filteredHistory();
    if (isGlobal) {
      const totalPages = Math.max(1, Math.ceil(rows.length / state.historyPageSize));
      const page = Math.max(1, Math.min(totalPages, state.historyPage));
      const pageRows = rows.slice((page - 1) * state.historyPageSize, page * state.historyPageSize);
      return `<section class="ai-drawer-history">
        <div class="ai-drawer-history-toolbar"><label>${icon('search')}<input type="search" value="${escapeHtml(state.historyQuery)}" placeholder="搜索对话" data-ai-history-search></label><button class="ai-copilot-icon-button" type="button" data-ai-history-refresh title="刷新" aria-label="刷新历史">${icon('refresh')}</button></div>
        <div class="ai-drawer-history-list" data-ai-scroll="history">${state.historyLoading ? loadingState('正在读取历史对话') : pageRows.length ? pageRows.map(historyStrip).join('') : `<div class="ai-empty-state"><strong>${state.historyQuery ? '没有匹配的对话' : '暂无历史对话'}</strong></div>`}</div>
        <footer class="ai-history-pagination"><button type="button" data-ai-history-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>上一页</button><span>${page} / ${totalPages}</span><button type="button" data-ai-history-page="${page + 1}" ${page >= totalPages ? 'disabled' : ''}>下一页</button></footer>
      </section>`;
    }
    return `
      <section class="ai-history-card ai-page-card dwrt-kit-page-surface dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface">
        <div class="dwrt-kit-table-toolbar ai-history-toolbar">
          <div class="dwrt-kit-table-title">
            <strong>历史对话</strong>
            <span>${state.historyLoading ? '正在读取' : state.historyError ? escapeHtml(state.historyError) : '按最近更新时间排序'}</span>
          </div>
          <div class="ai-history-actions">
            <label class="ai-history-search" data-dwrt-component="expand-search">${icon('search')}<input type="search" value="${escapeHtml(state.historyQuery)}" placeholder="搜索对话" data-ai-history-search></label>
            <span class="dwrt-kit-table-count">${formatInteger(rows.length)} 条</span>
            <button class="ai-icon-button" type="button" data-ai-history-refresh title="刷新" aria-label="刷新历史">${icon('refresh')}</button>
            <button class="ai-secondary-button" type="button" data-ai-new>新建对话</button>
          </div>
        </div>
        <div class="dwrt-kit-table-scroll ai-history-scroll" data-ai-scroll="history">
          <table class="dwrt-kit-table dwrt-kit-datatable ai-history-table">
            <thead><tr><th>对话</th><th>消息</th><th>模型</th><th>用量</th><th>更新时间</th><th class="ai-actions-column">操作</th></tr></thead>
            <tbody>
              ${state.historyLoading ? `<tr><td colspan="6" class="dwrt-kit-table-empty">正在读取历史对话</td></tr>` : rows.length ? rows.map(historyRow).join('') : `<tr><td colspan="6" class="dwrt-kit-table-empty">${state.historyQuery ? '没有匹配的对话' : '暂无历史对话'}</td></tr>`}
            </tbody>
          </table>
        </div>
      </section>
    `;
  }

  function historyStrip(item) {
    const deleting = state.deletingConversation === item.id;
    return `<article class="ai-history-strip ${state.loadingConversation === item.id ? 'is-loading' : ''}"><button type="button" data-ai-open-history="${escapeHtml(item.id)}"><strong>${escapeHtml(item.title)}</strong><span>${formatHistoryDate(item.updated_at)}</span><small>${escapeHtml(item.model || '--')} · ${formatInteger(item.message_count)} 条消息</small></button><button class="ai-history-strip-delete" type="button" data-ai-delete-history="${escapeHtml(item.id)}" title="删除对话" aria-label="删除 ${escapeHtml(item.title)}" ${deleting ? 'disabled' : ''}>${deleting ? icon('loader') : icon('trash')}</button></article>`;
  }

  function historyRow(item) {
    const totalTokens = firstNumber(item.usage?.total_tokens);
    const deleting = state.deletingConversation === item.id;
    return `
      <tr class="ai-history-row ${state.loadingConversation === item.id ? 'is-loading' : ''}" data-ai-open-history="${escapeHtml(item.id)}" tabindex="0">
        <td><strong>${escapeHtml(item.title)}</strong><span class="ai-history-effort">${escapeHtml(REASONING_LABELS[item.reasoning_effort] || item.reasoning_effort || '自动')}</span></td>
        <td class="num">${formatInteger(item.message_count)}</td>
        <td><code>${escapeHtml(item.model || '--')}</code></td>
        <td class="num">${totalTokens ? formatInteger(totalTokens) : '--'}</td>
        <td><time>${formatRelativeTime(item.updated_at)}</time></td>
        <td class="ai-actions-column"><button class="ai-row-action danger" type="button" data-ai-delete-history="${escapeHtml(item.id)}" title="删除对话" aria-label="删除 ${escapeHtml(item.title)}" ${deleting ? 'disabled' : ''}>${deleting ? icon('loader') : icon('trash')}</button></td>
      </tr>
    `;
  }

  function filteredHistory() {
    const query = state.historyQuery.trim().toLowerCase();
    if (!query) return state.history;
    return state.history.filter((item) => `${item.title} ${item.model} ${item.reasoning_effort}`.toLowerCase().includes(query));
  }

  function formatHistoryDate(value) {
    const timestamp = normalizeTimestamp(value);
    if (!timestamp) return '--';
    return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' }).format(timestamp);
  }

  function oauthStatusText(status = oauthStatus()) {
    if (state.oauth.statusLoading === state.config.provider) return ['checking', '正在检查连接'];
    if (!status) return ['off', '尚未检查'];
    if (status.connected && status.expired) return ['warning', '凭据已过期'];
    if (status.connected) return ['configured', 'OAuth 已连接'];
    if (status.pending) return ['checking', '等待完成授权'];
    return ['off', '尚未连接'];
  }

  function oauthExpiryText(status = oauthStatus()) {
    const expiresAt = firstNumber(status?.expires_at, status?.pending_expires_at);
    if (!expiresAt) return '';
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
    }).format(expiresAt * (expiresAt < 100000000000 ? 1000 : 1));
  }

  function oauthInput(provider, key, label, options = {}) {
    const value = firstText(state.oauth.inputs[provider]?.[key]);
    return `<label class="ai-field ${options.wide ? 'ai-field-wide' : ''}"><span>${escapeHtml(label)}</span><input type="${options.type || 'text'}" value="${escapeHtml(value)}" placeholder="${escapeHtml(options.placeholder || '')}" autocomplete="off" data-ai-oauth-input="${escapeHtml(key)}" data-ai-oauth-provider="${escapeHtml(provider)}">${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function oauthFlowMarkup(provider) {
    const flow = state.oauth.flow;
    if (!flow || flow.provider !== provider) return '';
    if (provider === 'kimi') {
      const verificationUrl = safeHttpUrl(firstText(flow.verification_uri_complete, flow.verification_uri));
      return `<div class="ai-oauth-device-flow">
        <div><span>设备验证码</span><strong>${escapeHtml(firstText(flow.user_code, '--'))}</strong><small>验证码由 Kimi 生成，页面将按 ${Math.max(1, firstNumber(flow.poll_after_seconds, flow.interval, 5))} 秒间隔检查授权结果。</small></div>
        <div class="ai-oauth-flow-actions"><button class="ai-secondary-button" type="button" data-ai-oauth-copy="${escapeHtml(firstText(flow.user_code))}">${icon('copy')}复制验证码</button>${verificationUrl ? `<a class="ai-primary-button" href="${escapeHtml(verificationUrl)}" target="_blank" rel="noopener noreferrer">${icon('external')}打开授权页面</a>` : ''}</div>
      </div>`;
    }
    if (provider === 'gemini') {
      return `<div class="ai-oauth-flow-note">${icon('external')}<span>Google 授权页面已打开。完成授权后，Dreaming OS 会校验回调中的 state 并由后端交换凭据。</span></div>`;
    }
    return '';
  }

  function oauthPanel() {
    const provider = state.config.provider;
    const capability = oauthProvider(provider);
    const status = oauthStatus(provider);
    const [tone, statusText] = oauthStatusText(status);
    const working = state.oauth.action.startsWith(`${provider}:`);
    if (!state.oauth.available) {
      return `<div class="ai-oauth-unavailable">${icon('alert')}<div><strong>OAuth 接口不可用</strong><span>当前 webd 没有返回 ai-oauth.v1 能力，请继续使用 API Key。</span></div></div>`;
    }
    if (!capability || capability.supported !== true) {
      const reason = oauthReason(capability?.reason, '该提供商当前仅支持 API Key 接入。');
      return `<div class="ai-oauth-unavailable">${icon('key')}<div><strong>${escapeHtml(oauthProviderLabel(provider))} 使用 API Key</strong><span>${escapeHtml(reason)}</span></div></div>`;
    }
    let fields = '';
    let intro = '';
    if (capability.mode === 'authorization_code_pkce_s256') {
      intro = '使用你自己的 Google OAuth 客户端，通过授权码与 PKCE S256 建立连接。';
      fields = `<div class="ai-settings-grid ai-oauth-fields">${oauthInput('gemini', 'client_id', 'Google Client ID', { wide: true, placeholder: 'xxxx.apps.googleusercontent.com' })}${oauthInput('gemini', 'project_id', 'Google Cloud Project ID', { placeholder: 'my-gemini-project' })}${oauthInput('gemini', 'redirect_uri', '回调地址', { placeholder: `${window.location.origin}${window.location.pathname}`, help: '必须与 Google OAuth 客户端中登记的回调地址完全一致。' })}</div>`;
    } else if (capability.mode === 'device_oauth') {
      intro = '通过 Kimi Code 官方设备授权连接，不需要在路由器中输入账号密码。';
    } else if (capability.mode === 'enterprise_wif') {
      intro = '通过 Anthropic Workload Identity Federation 交换短期凭据，不是 Claude 用户账号登录。';
      const rootPath = firstText(capability.identity_token_file_root, '/etc/dreamingwrt/credentials/');
      fields = `<div class="ai-settings-grid ai-oauth-fields">${oauthInput('anthropic', 'identity_token_file', '身份令牌文件', { wide: true, placeholder: `${rootPath}identity.jwt`, help: `仅允许 ${rootPath} 下 root:root、0600 的普通文件。` })}${oauthInput('anthropic', 'federation_rule_id', 'Federation Rule ID', { placeholder: 'fdrl_...' })}${oauthInput('anthropic', 'organization_id', 'Organization ID')}${oauthInput('anthropic', 'service_account_id', 'Service Account ID', { placeholder: 'svac_...' })}${oauthInput('anthropic', 'workspace_id', 'Workspace ID（可选）', { placeholder: 'wrkspc_...' })}</div>`;
    }
    const expiry = oauthExpiryText(status);
    const startLabel = status?.connected ? '重新授权' : capability.mode === 'enterprise_wif' ? '连接 WIF' : '开始授权';
    return `<div class="ai-oauth-card">
      <div class="ai-oauth-card-head"><div><strong>${escapeHtml(oauthProviderLabel(provider))}</strong><span>${escapeHtml(intro)}</span></div>${ui.statusBadgeMarkup?.(statusText, tone === 'configured' ? 'success' : tone === 'checking' ? 'info' : tone === 'warning' ? 'warning' : 'muted') || ''}</div>
      ${status?.state_reason ? `<div class="ai-oauth-inline-error">${escapeHtml(oauthReason(status.state_reason))}</div>` : ''}
      ${fields}
      ${oauthFlowMarkup(provider)}
      <div class="ai-oauth-card-footer"><span>${expiry ? `${status?.pending && !status?.connected ? '授权流程' : '当前凭据'}有效至 ${escapeHtml(expiry)}` : status?.pending ? '存在未完成的授权流程，可以重新开始。' : '访问凭据只保存在路由器的加密存储中。'}</span><div>
        ${status?.connected ? `<button class="ai-secondary-button" type="button" data-ai-oauth-refresh ${working ? 'disabled' : ''}>${state.oauth.action === `${provider}:refresh` ? icon('loader') : icon('refresh')}刷新凭据</button>` : ''}${status?.connected || status?.pending ? `<button class="ai-secondary-button is-danger" type="button" data-ai-oauth-disconnect ${working ? 'disabled' : ''}>${status?.connected ? '断开连接' : '取消授权'}</button>` : ''}
        <button class="ai-primary-button" type="button" data-ai-oauth-start ${working ? 'disabled' : ''}>${state.oauth.action === `${provider}:start` ? icon('loader') : icon('link')}${escapeHtml(startLabel)}</button>
      </div></div>
    </div>`;
  }

  function oauthDisconnectConfirmation() {
    if (!state.oauth.confirmDisconnect) return '';
    const provider = oauthProviderLabel(state.config.provider);
    const markup = window.DWRT_UI_KIT?.confirmationMarkup?.({
      id: 'ai-oauth-disconnect', action: 'ai-oauth-disconnect', tone: 'danger',
      title: `断开 ${provider}`, description: '路由器将删除该提供商的 OAuth 凭据与未完成授权。API Key 不受影响。',
      cancelLabel: '取消', confirmLabel: '断开连接'
    });
    return markup || `<div class="ai-oauth-confirm"><button type="button" data-ai-oauth-disconnect-cancel>取消</button><button type="button" data-ai-oauth-disconnect-confirm>断开连接</button></div>`;
  }

  function settingsView() {
    const provider = providerDefinition();
    const apiBaseHelp = state.config.auth_mode === 'oauth'
      ? '留空时后端使用该 OAuth 提供商的官方模型 API 地址'
      : state.config.provider === 'openai_compatible'
        ? 'OpenAI 兼容服务需要填写完整 API Base URL'
        : '留空时后端使用该提供商的默认 API 地址';
    return `
      <form class="ai-settings-card ai-page-card dwrt-kit-page-surface dwrt-kit-glass-surface" data-ai-scroll="settings">
        <div class="ai-settings-heading">
          <div>
            <strong>LLM 接入设置</strong>
            <span>模型提供商、凭据、生成参数与工具授权由路由器统一管理</span>
          </div>
          <label class="ai-switch" title="启用 AI">
            <input type="checkbox" data-ai-config="enabled" ${state.config.enabled ? 'checked' : ''}>
            <span aria-hidden="true"></span>
          </label>
        </div>
        ${state.settingsError ? `<div class="ai-inline-message error">${icon('alert')}<span>${escapeHtml(state.settingsError)}</span></div>` : ''}
        <div class="ai-settings-section">
          <div class="ai-section-title"><strong>模型提供商</strong><span>Model provider</span></div>
          <div class="ai-provider-grid" role="radiogroup" aria-label="模型提供商">
            ${PROVIDERS.map((item) => `
              <button class="ai-provider-button ${state.config.provider === item.id ? 'is-active' : ''}" type="button" role="radio" aria-checked="${state.config.provider === item.id ? 'true' : 'false'}" data-ai-provider="${item.id}">
                <span class="ai-provider-mark">${escapeHtml(item.mark)}</span>
                <strong>${escapeHtml(item.label)}</strong>
                ${state.config.provider === item.id ? icon('check') : ''}
              </button>
            `).join('')}
          </div>
        </div>
        <div class="ai-settings-section">
          <div class="ai-section-title"><strong>认证方式</strong><span>Authentication</span></div>
          <div class="ai-auth-mode" role="radiogroup" aria-label="认证方式">
            <button type="button" role="radio" aria-checked="${state.config.auth_mode === 'api_key'}" class="${state.config.auth_mode === 'api_key' ? 'is-active' : ''}" data-ai-auth-mode="api_key">${icon('key')}<span><strong>API Key</strong><small>使用提供商密钥</small></span></button>
            <button type="button" role="radio" aria-checked="${state.config.auth_mode === 'oauth'}" class="${state.config.auth_mode === 'oauth' ? 'is-active' : ''}" data-ai-auth-mode="oauth" ${state.oauth.available && oauthProvider()?.supported === true ? '' : 'disabled'}>${icon('link')}<span><strong>OAuth</strong><small>授权连接或企业身份</small></span></button>
          </div>
          ${state.oauth.available && oauthProvider() && oauthProvider()?.supported !== true ? `<div class="ai-auth-mode-hint">${icon('key')}<span>${escapeHtml(oauthReason(oauthProvider()?.reason, '当前提供商仅支持 API Key 接入。'))}</span></div>` : ''}
          ${state.config.auth_mode === 'oauth' ? oauthPanel() : `<div class="ai-settings-grid"><label class="ai-field ai-field-wide"><span>API Key</span><input type="password" autocomplete="new-password" value="${escapeHtml(state.config.api_key_input)}" placeholder="${state.config.api_key_set ? `已保存 ${state.config.api_key_hint || ''}，留空不修改` : '输入 API Key'}" data-ai-config="api_key_input"><small>${state.config.clear_api_key ? '保存后将清除已保存密钥' : state.config.api_key_set ? '密钥已保存，页面不会回显完整内容' : '密钥仅提交到路由器配置接口'}</small></label>${state.config.api_key_set ? `<button class="ai-secondary-button ai-clear-key-button" type="button" data-ai-clear-key>${state.config.clear_api_key ? '撤销清除密钥' : '清除已保存密钥'}</button>` : ''}</div>`}
        </div>
        <div class="ai-settings-section">
          <div class="ai-section-title"><strong>模型与接口</strong><span>Model runtime</span></div>
          <div class="ai-settings-grid">
            <label class="ai-field ai-field-wide"><span>API 地址</span><input type="url" value="${escapeHtml(state.config.api_base)}" placeholder="${escapeHtml(provider.base || 'https://example.com/v1')}" data-ai-config="api_base"><small>${escapeHtml(apiBaseHelp)}</small></label>
            <label class="ai-field"><span>默认模型</span><select data-ai-config="model">${modelOptions(state.config.model)}</select></label>
            <label class="ai-field"><span>最大输出 Token</span><input type="number" min="1" max="131072" step="1" value="${state.config.max_tokens}" data-ai-config="max_tokens"></label>
          </div>
        </div>
        <div class="ai-settings-section">
          <div class="ai-section-title"><strong>生成与工具</strong><span>Generation</span></div>
          <div class="ai-settings-grid">
            <label class="ai-field ai-range-field"><span>采样温度 <output data-ai-temperature-output>${Number(state.config.temperature).toFixed(1)}</output></span><input type="range" min="0" max="2" step="0.1" value="${state.config.temperature}" data-ai-config="temperature"><small>值越低，回答越聚焦且稳定</small></label>
            <label class="ai-field"><span>思考强度</span><select data-ai-config="reasoning_effort" ${reasoningDisabled() ? 'disabled' : ''}>${reasoningOptions(state.config.reasoning_effort)}</select><small>${reasoningDisabled() ? '当前模型不支持 reasoning_effort' : `接口形态：${escapeHtml(state.config.reasoning_api_shape)}`}</small></label>
            <label class="ai-field"><span>工具授权策略</span><select data-ai-config="tool_policy">${TOOL_POLICIES.map(([value, label]) => `<option value="${value}" ${state.config.tool_policy === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}</select></label>
            <label class="ai-field ai-field-wide"><span>系统提示词</span><textarea rows="4" placeholder="可选" data-ai-config="system_prompt">${escapeHtml(state.config.system_prompt)}</textarea></label>
          </div>
        </div>
        <div class="ai-settings-footer">
          <div class="ai-settings-status">
            ${connectionBadge()}
            <span>${state.notice ? escapeHtml(state.notice) : configDirty() ? '有未保存的修改' : '配置已同步'}</span>
          </div>
          <div class="ai-settings-actions">
            <button class="ai-secondary-button" type="button" data-ai-sync-models ${state.syncingModels ? 'disabled' : ''}>${state.syncingModels ? icon('loader') : icon('refresh')}刷新模型列表</button>
            <button class="ai-primary-button" type="button" data-ai-save ${state.saving || !configDirty() ? 'disabled' : ''}>${state.saving ? icon('loader') : icon('save')}保存设置</button>
          </div>
        </div>
      </form>${oauthDisconnectConfirmation()}
    `;
  }

  function connectionBadge() {
    let stateName = 'off';
    let text = '未启用';
    if (state.loading) {
      stateName = 'checking';
      text = '读取中';
    } else if (state.config.auth_mode === 'oauth' && credentialReady()) {
      stateName = 'configured';
      text = 'OAuth 就绪';
    } else if (state.config.enabled && state.config.auth_mode === 'api_key' && state.config.api_key_set) {
      stateName = 'configured';
      text = '凭据就绪';
    } else if (state.config.enabled && state.config.auth_mode === 'oauth') {
      stateName = 'warning';
      text = oauthStatus()?.expired ? 'OAuth 已过期' : 'OAuth 未连接';
    } else if (state.config.enabled) {
      stateName = 'warning';
      text = '缺少 API Key';
    }
    const tone = stateName === 'configured' ? 'success' : stateName === 'checking' ? 'info' : stateName === 'warning' ? 'warning' : 'muted';
    return ui.statusBadgeMarkup?.(text, tone) || `<span>${escapeHtml(text)}</span>`;
  }

  function reasoningDisabled() {
    return state.loading || state.config.capabilities.reasoning_effort_supported === false;
  }

  function modelOptions(selected) {
    const models = uniqueModels([selected, ...state.models]);
    return models.map((model) => `<option value="${escapeHtml(model)}" ${model === selected ? 'selected' : ''}>${escapeHtml(model)}</option>`).join('');
  }

  function reasoningOptions(selected) {
    const provided = state.config.capabilities.reasoning_effort_values;
    const values = provided.length ? provided : ['auto', 'none', 'minimal', 'low', 'medium', 'high', 'xhigh'];
    return uniqueModels([selected, ...values]).map((value) => `<option value="${escapeHtml(value)}" ${value === selected ? 'selected' : ''}>${escapeHtml(REASONING_LABELS[value] || value)}</option>`).join('');
  }

  function toolPolicyOptions(selected) {
    return TOOL_POLICIES.map(([value, label]) => `<option value="${value}" ${value === selected ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('');
  }

  function loadingState(text) {
    return `<div class="ai-empty-state"><span class="ai-state-spinner">${icon('loader')}</span><strong>${escapeHtml(text)}</strong></div>`;
  }

  function bindEvents() {
    root.querySelector('.ai-settings-card')?.addEventListener('submit', (event) => event.preventDefault());
    root.querySelector('.ai-primary-tabs')?.addEventListener('dwrt-tab-change', (event) => {
      const value = event.detail?.value;
      if (!value || value === state.tab) return;
      setTab(value);
      state.notice = '';
      state.chatError = '';
      render();
    });
    root.querySelectorAll('[data-ai-new]').forEach((button) => button.addEventListener('click', startNewConversation));
    root.querySelector('[data-ai-add-toggle]')?.addEventListener('click', () => {
      state.addMenuOpen = !state.addMenuOpen;
      state.runtimeMenuOpen = false;
      render();
    });
    root.querySelector('[data-ai-runtime-toggle]')?.addEventListener('click', () => {
      state.runtimeMenuOpen = !state.runtimeMenuOpen;
      state.addMenuOpen = false;
      state.runtimePane = 'main';
      render();
    });
    root.querySelectorAll('[data-ai-runtime-pane]').forEach((button) => button.addEventListener('click', () => {
      state.runtimePane = button.dataset.aiRuntimePane || 'main';
      render();
    }));
    root.querySelectorAll('[data-ai-model-option]').forEach((button) => button.addEventListener('click', () => {
      state.current.model = button.dataset.aiModelOption;
      state.runtimeMenuOpen = false;
      state.runtimePane = 'main';
      render();
    }));
    root.querySelectorAll('[data-ai-effort-option]').forEach((button) => button.addEventListener('click', () => {
      state.current.reasoning_effort = button.dataset.aiEffortOption;
      state.runtimeMenuOpen = false;
      state.runtimePane = 'main';
      render();
    }));
    root.querySelectorAll('[data-ai-policy-option]').forEach((button) => button.addEventListener('click', () => {
      state.current.tool_policy = button.dataset.aiPolicyOption;
      state.runtimeMenuOpen = false;
      state.runtimePane = 'main';
      render();
    }));
    const prompt = root.querySelector('[data-ai-prompt]');
    if (prompt) {
      prompt.addEventListener('input', () => {
        state.prompt = prompt.value;
        autoSizePrompt(prompt);
      });
      prompt.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
          event.preventDefault();
          sendMessage();
        }
      });
    }
    root.querySelector('[data-ai-send]')?.addEventListener('click', sendMessage);
    root.querySelector('[data-ai-clear-key]')?.addEventListener('click', () => {
      state.config.clear_api_key = !state.config.clear_api_key;
      if (state.config.clear_api_key) state.config.api_key_input = '';
      state.notice = '';
      render();
    });
    root.querySelectorAll('[data-ai-auth-mode]').forEach((button) => button.addEventListener('click', () => {
      const mode = button.dataset.aiAuthMode;
      if (mode !== 'api_key' && mode !== 'oauth') return;
      state.config.auth_mode = mode;
      state.notice = '';
      state.settingsError = '';
      if (mode === 'oauth') loadOAuthStatus(state.config.provider, { renderBefore: true });
      else render();
    }));
    root.querySelectorAll('[data-ai-oauth-input]').forEach((field) => field.addEventListener('input', (event) => {
      const provider = event.target.dataset.aiOauthProvider;
      const key = event.target.dataset.aiOauthInput;
      if (!state.oauth.inputs[provider] || !key) return;
      state.oauth.inputs[provider][key] = event.target.value;
      state.settingsError = '';
    }));
    root.querySelector('[data-ai-oauth-start]')?.addEventListener('click', startOAuth);
    root.querySelector('[data-ai-oauth-refresh]')?.addEventListener('click', refreshOAuth);
    root.querySelector('[data-ai-oauth-disconnect]')?.addEventListener('click', () => {
      state.oauth.confirmDisconnect = true;
      render();
    });
    root.querySelector('[data-ai-oauth-copy]')?.addEventListener('click', async (event) => {
      const value = firstText(event.currentTarget.dataset.aiOauthCopy);
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        state.notice = '验证码已复制';
      } catch (_) {
        state.notice = '无法访问剪贴板，请手动复制验证码';
      }
      render();
    });
    root.querySelectorAll('[data-dwrt-confirm-cancel], [data-ai-oauth-disconnect-cancel], .dwrt-kit-modal-backdrop').forEach((button) => button.addEventListener('click', () => {
      state.oauth.confirmDisconnect = false;
      render();
    }));
    root.querySelectorAll('[data-dwrt-confirm-accept], [data-ai-oauth-disconnect-confirm]').forEach((button) => button.addEventListener('click', disconnectOAuth));
    const fileInput = root.querySelector('[data-ai-file]');
    root.querySelector('[data-ai-add-file]')?.addEventListener('click', (event) => {
      state.addMenuOpen = false;
      event.currentTarget.closest('.ai-add-popover')?.remove();
      root.querySelector('.ai-add-control')?.classList.remove('is-open');
      root.querySelector('[data-ai-add-toggle]')?.setAttribute('aria-expanded', 'false');
      fileInput?.click();
    });
    root.querySelector('[data-ai-add-page]')?.addEventListener('click', () => {
      state.addMenuOpen = false;
      attachPageContext();
    });
    fileInput?.addEventListener('change', () => addAttachments(fileInput.files));
    root.querySelectorAll('[data-ai-remove-file]').forEach((button) => button.addEventListener('click', () => {
      state.attachments.splice(Number(button.dataset.aiRemoveFile), 1);
      render();
    }));
    const historySearch = root.querySelector('[data-ai-history-search]');
    historySearch?.addEventListener('input', (event) => {
      state.historyQuery = event.target.value;
      state.historyPage = 1;
      if (isGlobal) updateDrawerHistoryView();
      else updateHistoryRows();
    });
    root.querySelector('[data-ai-history-refresh]')?.addEventListener('click', refreshHistory);
    bindHistoryItemEvents(root);
    root.querySelectorAll('[data-ai-provider]').forEach((button) => button.addEventListener('click', () => selectProvider(button.dataset.aiProvider)));
    root.querySelectorAll('[data-ai-config]').forEach((field) => {
      field.addEventListener('input', onConfigInput);
      field.addEventListener('change', onConfigInput);
    });
    root.querySelector('[data-ai-sync-models]')?.addEventListener('click', syncModels);
    root.querySelector('[data-ai-save]')?.addEventListener('click', saveConfig);
  }

  function bindHistoryItemEvents(scope) {
    scope.querySelectorAll('[data-ai-history-page]').forEach((button) => button.addEventListener('click', () => {
      const page = Number(button.dataset.aiHistoryPage);
      if (!Number.isFinite(page) || page < 1) return;
      state.historyPage = page;
      render();
    }));
    scope.querySelectorAll('[data-ai-open-history]').forEach((row) => {
      row.addEventListener('click', (event) => {
        if (event.target.closest('[data-ai-delete-history]')) return;
        openHistory(row.dataset.aiOpenHistory);
      });
      row.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          openHistory(row.dataset.aiOpenHistory);
        }
      });
    });
    scope.querySelectorAll('[data-ai-delete-history]').forEach((button) => button.addEventListener('click', (event) => {
      event.stopPropagation();
      deleteHistory(button.dataset.aiDeleteHistory);
    }));
  }

  function bindGlobalEvents() {
    root.querySelector('[data-ai-history-toggle]')?.addEventListener('click', () => {
      state.tab = state.tab === 'history' ? 'chat' : 'history';
      state.historyPage = 1;
      render();
    });
    root.querySelector('[data-ai-history-exit]')?.addEventListener('click', () => { state.tab = 'chat'; render(); });
    root.querySelectorAll('[data-ai-drawer-close]').forEach((button) => button.addEventListener('click', () => {
      touchActiveConversation();
      state.drawerOpen = false;
      state.addMenuOpen = false;
      state.runtimeMenuOpen = false;
      render();
    }));
    root.querySelector('[data-ai-orb-restore]')?.addEventListener('click', () => {
      state.orb.docked = false;
      const position = orbPosition();
      state.orb.x = position.x;
      state.orb.y = position.y;
      saveOrbState();
      render();
    });
    const orb = root.querySelector('[data-ai-orb]');
    orb?.addEventListener('pointerdown', beginOrbDrag);
    orb?.addEventListener('click', (event) => {
      if (performance.now() < state.orbClickBlockedUntil) { event.preventDefault(); return; }
      expireInactiveConversation();
      state.drawerOpen = true;
      state.tab = 'chat';
      touchActiveConversation();
      render();
    });
  }

  function beginOrbDrag(event) {
    if (event.button !== 0) return;
    const orb = event.currentTarget;
    const position = orbPosition();
    state.orbDrag = { pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, x: position.x, y: position.y, moved: false };
    orb.setPointerCapture?.(event.pointerId);
    orb.addEventListener('pointermove', moveOrbDrag);
    orb.addEventListener('pointerup', endOrbDrag);
    orb.addEventListener('pointercancel', endOrbDrag);
    event.preventDefault();
  }

  function moveOrbDrag(event) {
    const drag = state.orbDrag;
    if (!drag || drag.pointerId !== event.pointerId) return;
    const dx = event.clientX - drag.startX;
    const dy = event.clientY - drag.startY;
    if (Math.hypot(dx, dy) > 4) drag.moved = true;
    const size = 58;
    state.orb.x = Math.max(8, Math.min(window.innerWidth - size - 8, drag.x + dx));
    state.orb.y = Math.max(8, Math.min(window.innerHeight - size - 8, drag.y + dy));
    const orb = event.currentTarget;
    orb.style.setProperty('--ai-orb-x', `${state.orb.x}px`);
    orb.style.setProperty('--ai-orb-y', `${state.orb.y}px`);
  }

  function endOrbDrag(event) {
    const drag = state.orbDrag;
    if (!drag || drag.pointerId !== event.pointerId) return;
    const orb = event.currentTarget;
    orb.releasePointerCapture?.(event.pointerId);
    orb.removeEventListener('pointermove', moveOrbDrag);
    orb.removeEventListener('pointerup', endOrbDrag);
    orb.removeEventListener('pointercancel', endOrbDrag);
    state.orbDrag = null;
    if (!drag.moved) return;
    state.orbClickBlockedUntil = performance.now() + 350;
    if (state.orb.x + 58 >= window.innerWidth - 22) state.orb.docked = true;
    saveOrbState();
    render();
  }

  function attachPageContext() {
    const value = typeof context.getPageContext === 'function' ? context.getPageContext() : defaultPageContext();
    const block = pageContextPrompt(value);
    state.prompt = state.prompt ? `${state.prompt}\n\n${block}` : block;
    const prompt = root.querySelector('[data-ai-prompt]');
    if (prompt) {
      prompt.value = state.prompt;
      autoSizePrompt(prompt);
      sendMessage();
      return;
    }
    render();
    requestAnimationFrame(() => sendMessage());
  }

  function defaultPageContext() {
    const main = document.querySelector('#consoleMain');
    return { title: document.title, route: window.location.hash, text: firstText(main?.innerText).slice(0, 8000) };
  }

  function pageContextPrompt(value = {}) {
    const title = firstText(value.title, '当前页面');
    const route = firstText(value.route, window.location.hash);
    const text = firstText(value.text).slice(0, 8000);
    return `请基于我当前打开的页面指导或代替我完成操作。\n页面：${title}\n路由：${route}\n页面内容：\n${text || '当前页面没有可读取的文本内容。'}`;
  }

  function startNewConversation() {
    clearActiveConversation();
    state.current = newConversation();
    state.current.model = state.config.model;
    state.current.reasoning_effort = state.config.reasoning_effort;
    state.current.tool_policy = state.config.tool_policy;
    state.prompt = '';
    state.attachments = [];
    state.chatError = '';
    state.notice = '';
    state.addMenuOpen = false;
    state.runtimeMenuOpen = false;
    state.runtimePane = 'main';
    state.shouldStickChat = true;
    setTab('chat');
    render();
    requestAnimationFrame(() => root.querySelector('[data-ai-prompt]')?.focus());
  }

  function autoSizePrompt(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = `${Math.min(132, Math.max(24, textarea.scrollHeight))}px`;
  }

  async function addAttachments(fileList) {
    const files = Array.from(fileList || []);
    const accepted = [];
    let error = '';
    for (const file of files) {
      if (file.size > 512 * 1024) {
        error = `${file.name} 超过 512 KB`;
        continue;
      }
      try {
        accepted.push({ name: file.name, size: file.size, type: file.type || 'text/plain', content: await file.text() });
      } catch (_) {
        error = `${file.name} 无法读取`;
      }
    }
    state.attachments = [...state.attachments, ...accepted].slice(0, 8);
    state.chatError = error;
    render();
    requestAnimationFrame(() => root.querySelector('[data-ai-prompt]')?.focus());
  }

  async function sendMessage() {
    if (state.sending || !credentialReady()) return;
    const prompt = root.querySelector('[data-ai-prompt]');
    const content = firstText(prompt?.value);
    if (content === '/new') {
      startNewConversation();
      return;
    }
    if (!content && !state.attachments.length) return;
    const now = Date.now();
    const selectedAttachments = state.attachments.map(({ name, size, type, content: fileContent }) => ({ name, size, type, content: fileContent }));
    const attachments = selectedAttachments.map(({ name, size, type }) => ({ name, size, type }));
    const userMessage = { id: `user-${now}`, role: 'user', content: content || '请分析附件。', created_at: now, attachments };
    state.current.messages.push(userMessage);
    state.current.model = currentModel();
    state.current.reasoning_effort = currentEffort();
    state.current.tool_policy = currentToolPolicy();
    conversationId();
    touchActiveConversation();
    state.attachments = [];
    state.prompt = '';
    state.sending = true;
    state.chatError = '';
    state.notice = '';
    state.shouldStickChat = true;
    render();
    try {
      let outboundAttachments = selectedAttachments;
      if (state.config.capabilities.attachment_ids && selectedAttachments.length) {
        const uploadEndpoint = state.config.capabilities.attachment_upload_endpoint || ENDPOINTS.attachments;
        const uploaded = await Promise.all(selectedAttachments.map(async ({ name, size, type, content: fileContent }) => {
          const result = await postJson(uploadEndpoint, { name, size, type, content: fileContent });
          const data = unwrap(result);
          if (!firstText(data.attachment_id)) throw new Error(`${name} 上传后缺少 attachment_id`);
          return {
            attachment_id: firstText(data.attachment_id),
            name: firstText(data.name, name),
            size: firstNumber(data.size, size),
            type: firstText(data.type, type)
          };
        }));
        userMessage.attachments = uploaded;
        outboundAttachments = uploaded;
      }
      const result = await postJson(ENDPOINTS.chat, {
        conversation_id: conversationId(),
        model: currentModel(),
        reasoning_effort: currentEffort(),
        tool_policy: currentToolPolicy(),
        messages: state.current.messages.map(({ role, content: text }) => ({ role, content: text })),
        attachments: outboundAttachments
      });
      if (!state.mounted) return;
      const data = unwrap(result);
      state.current.id = firstText(data.conversation_id, data.conversation?.id, state.current.id);
      state.current.title = firstText(data.conversation_title, data.title, data.conversation?.title, state.current.title);
      touchActiveConversation();
      const reply = extractAssistantReply(data);
      if (!reply) {
        const pending = firstText(data.message).toLowerCase().includes('integration pending') || data.status === 'ready';
        throw new Error(pending ? '模型运行时尚未接入，后端未生成回答' : firstText(data.error, '后端未返回 AI 回答'));
      }
      state.current.messages.push({ id: `assistant-${Date.now()}`, role: 'assistant', content: reply, created_at: Date.now(), attachments: [] });
      state.current.usage = data.usage && typeof data.usage === 'object' ? data.usage : state.current.usage;
      await persistCurrentConversation();
      state.notice = '对话已保存';
    } catch (error) {
      state.chatError = error?.message || 'AI 请求失败';
      await persistCurrentConversation().catch(() => {});
    } finally {
      if (!state.mounted) return;
      state.sending = false;
      state.shouldStickChat = true;
      render();
      requestAnimationFrame(() => root.querySelector('[data-ai-prompt]')?.focus());
    }
  }

  function extractAssistantReply(data = {}) {
    const direct = firstText(data.reply, data.response, data.output_text, data.assistant?.content, data.assistant?.text);
    if (direct) return direct;
    const choices = asArray(data.choices);
    return firstText(choices[0]?.message?.content, choices[0]?.text);
  }

  async function persistCurrentConversation() {
    if (!state.current.messages.length) return;
    const result = await postJson(ENDPOINTS.history, {
      id: conversationId(),
      title: conversationTitle(),
      model: currentModel(),
      reasoning_effort: currentEffort(),
      tool_policy: currentToolPolicy(),
      usage: state.current.usage || {},
      messages: state.current.messages.map(({ id: message_id, role, content, created_at, attachments }) => ({
        message_id,
        role,
        content,
        created_at: Math.floor(normalizeTimestamp(created_at) / 1000),
        attachments: asArray(attachments).map(({ attachment_id, name, type, size }) => ({ attachment_id, name, type, size }))
      }))
    });
    const data = unwrap(result);
    state.current.id = firstText(data.id, state.current.id);
    state.current.title = firstText(data.conversation_title, data.title, data.conversation?.title, state.current.title);
    touchActiveConversation();
    await refreshHistory(false);
  }

  async function refreshHistory(shouldRender = true) {
    state.historyLoading = true;
    state.historyError = '';
    if (shouldRender) render();
    const result = await fetchApi('ai-history', `${ENDPOINTS.history}?limit=100&offset=0`);
    if (!state.mounted) return;
    if (result?.ok) state.history = normalizeHistory(result.data);
    else state.historyError = result?.error?.message || '无法读取历史对话';
    state.historyLoading = false;
    if (shouldRender && document.activeElement?.matches('[data-ai-history-search]')) {
      if (isGlobal) updateDrawerHistoryView();
      else updateHistoryView();
    }
    else if (shouldRender) render();
  }

  async function openHistory(id, options = {}) {
    if (!id || state.loadingConversation) return;
    state.loadingConversation = id;
    if (!options.quiet) render();
    const result = await fetchApi('ai-history-detail', `${ENDPOINTS.history}/${encodeURIComponent(id)}`);
    if (!state.mounted) return;
    state.loadingConversation = '';
    if (!result?.ok) {
      state.historyError = result?.error?.message || '无法读取该对话';
      render();
      return;
    }
    state.current = normalizeConversation(result.data);
    touchActiveConversation(state.current.id);
    state.attachments = [];
    state.chatError = '';
    state.notice = '';
    state.shouldStickChat = true;
    setTab('chat');
    render();
  }

  async function deleteHistory(id) {
    if (!id || state.deletingConversation) return;
    state.deletingConversation = id;
    render();
    try {
      await requestJson(`${ENDPOINTS.history}/${encodeURIComponent(id)}`, { method: 'DELETE' });
      state.history = state.history.filter((item) => item.id !== id);
      if (state.current.id === id) {
        clearActiveConversation();
        state.current = newConversation();
      }
    } catch (error) {
      state.historyError = error?.message || '删除失败';
    }
    state.deletingConversation = '';
    render();
  }

  function updateHistoryRows() {
    const tbody = root.querySelector('.ai-history-table tbody');
    const count = root.querySelector('.ai-history-toolbar .dwrt-kit-table-count');
    if (!tbody) return;
    const rows = filteredHistory();
    tbody.innerHTML = rows.length ? rows.map(historyRow).join('') : `<tr><td colspan="6" class="dwrt-kit-table-empty">${state.historyQuery ? '没有匹配的对话' : '暂无历史对话'}</td></tr>`;
    if (count) count.textContent = `${formatInteger(rows.length)} 条`;
    tbody.querySelectorAll('[data-ai-open-history]').forEach((row) => row.addEventListener('click', (event) => {
      if (!event.target.closest('[data-ai-delete-history]')) openHistory(row.dataset.aiOpenHistory);
    }));
    tbody.querySelectorAll('[data-ai-delete-history]').forEach((button) => button.addEventListener('click', (event) => {
      event.stopPropagation();
      deleteHistory(button.dataset.aiDeleteHistory);
    }));
  }

  function updateHistoryView() {
    const status = root.querySelector('.ai-history-toolbar .dwrt-kit-table-title span');
    if (status) status.textContent = state.historyLoading ? '正在读取' : state.historyError || '按最近更新时间排序';
    updateHistoryRows();
  }

  function updateDrawerHistoryView() {
    const history = root.querySelector('.ai-drawer-history');
    const list = history?.querySelector('.ai-drawer-history-list');
    const pagination = history?.querySelector('.ai-history-pagination');
    if (!history || !list || !pagination) return;
    const rows = filteredHistory();
    const totalPages = Math.max(1, Math.ceil(rows.length / state.historyPageSize));
    const page = Math.max(1, Math.min(totalPages, state.historyPage));
    state.historyPage = page;
    const pageRows = rows.slice((page - 1) * state.historyPageSize, page * state.historyPageSize);
    list.innerHTML = state.historyLoading
      ? loadingState('正在读取历史对话')
      : pageRows.length
        ? pageRows.map(historyStrip).join('')
        : `<div class="ai-empty-state"><strong>${state.historyQuery ? '没有匹配的对话' : '暂无历史对话'}</strong></div>`;
    pagination.innerHTML = `<button type="button" data-ai-history-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>上一页</button><span>${page} / ${totalPages}</span><button type="button" data-ai-history-page="${page + 1}" ${page >= totalPages ? 'disabled' : ''}>下一页</button>`;
    bindHistoryItemEvents(history);
  }

  function selectProvider(id) {
    const next = PROVIDERS.find((item) => item.id === id);
    if (!next || state.config.provider === id) return;
    state.config.provider = id;
    if (!state.config.api_base || PROVIDERS.some((item) => item.base === state.config.api_base)) state.config.api_base = next.base;
    state.oauth.flow = null;
    state.oauth.confirmDisconnect = false;
    if (state.config.auth_mode === 'oauth' && oauthProvider(id)?.supported !== true) state.config.auth_mode = 'api_key';
    state.notice = '';
    render();
    if (state.config.auth_mode === 'oauth') loadOAuthStatus(id);
  }

  function onConfigInput(event) {
    const key = event.target.dataset.aiConfig;
    if (!key) return;
    if (event.target.type === 'checkbox') state.config[key] = event.target.checked;
    else if (key === 'temperature') state.config[key] = Number(event.target.value);
    else if (key === 'max_tokens') state.config[key] = Math.max(1, Math.round(Number(event.target.value) || 1));
    else state.config[key] = event.target.value;
    state.notice = '';
    if (key === 'temperature') {
      const output = root.querySelector('[data-ai-temperature-output]');
      if (output) output.textContent = Number(state.config.temperature).toFixed(1);
    }
    const save = root.querySelector('[data-ai-save]');
    if (save) save.disabled = state.saving || !configDirty();
    const status = root.querySelector('.ai-settings-status > span:last-child');
    if (status) status.textContent = configDirty() ? '有未保存的修改' : '配置已同步';
  }

  async function syncModels() {
    if (state.syncingModels) return;
    state.syncingModels = true;
    state.settingsError = '';
    render();
    const result = await fetchApi('ai-models', ENDPOINTS.models);
    if (!state.mounted) return;
    if (result?.ok) {
      state.models = uniqueModels(asArray(unwrap(result.data).models || unwrap(result.data)));
      state.notice = `已读取 ${state.models.length} 个模型`;
    } else {
      state.settingsError = result?.error?.message || '模型列表读取失败';
    }
    state.syncingModels = false;
    render();
  }

  async function saveConfig() {
    if (state.saving || !configDirty()) return;
    state.saving = true;
    state.settingsError = '';
    state.notice = '';
    render();
    const apiKey = state.config.api_key_input.trim();
    try {
      await postJson(ENDPOINTS.config, {
        provider: state.config.provider,
        api_base: state.config.api_base.trim(),
        ...(apiKey ? { api_key: apiKey } : {}),
        clear_api_key: Boolean(state.config.clear_api_key),
        auth_mode: state.config.auth_mode,
        model: state.config.model,
        temperature: Number(state.config.temperature),
        max_tokens: Number(state.config.max_tokens),
        system_prompt: state.config.system_prompt,
        tool_policy: state.config.tool_policy,
        enabled: Boolean(state.config.enabled),
        reasoning_effort: state.config.reasoning_effort,
        reasoning_api_shape: state.config.reasoning_api_shape
      });
      const result = await fetchApi('ai-config', ENDPOINTS.config);
      if (!result?.ok) throw result?.error || new Error('保存后无法读取配置');
      state.config = normalizeConfig(result.data);
      state.oauth.available = state.config.oauth.available;
      state.oauth.catalog = state.config.oauth.catalog;
      if (state.config.auth_mode === 'oauth') await loadOAuthStatus(state.config.provider, { quiet: true });
      markBaseline();
      state.notice = '设置已保存';
      notifyConfigUpdated();
    } catch (error) {
      state.settingsError = error?.message || '设置保存失败';
    }
    state.saving = false;
    render();
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { ...(api.authHeaders ? api.authHeaders() : {}), ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) },
      ...options
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    if (!response.ok || json?.ok === false) {
      const error = new Error(apiErrorText(json, `${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return json;
  }

  function postJson(url, body) {
    return requestJson(url, { method: 'POST', body: JSON.stringify(body || {}) });
  }

  function captureViewState() {
    if (!root) return null;
    root.querySelectorAll('[data-ai-scroll]').forEach((element) => {
      state.scrollPositions[element.dataset.aiScroll] = { top: element.scrollTop, left: element.scrollLeft };
    });
    return { scroll: { ...state.scrollPositions } };
  }

  function restoreViewState(snapshot) {
    requestAnimationFrame(() => {
      if (!state.mounted || !root) return;
      root.querySelectorAll('[data-ai-scroll]').forEach((element) => {
        const value = snapshot?.scroll?.[element.dataset.aiScroll] || state.scrollPositions[element.dataset.aiScroll];
        if (value) {
          element.scrollTop = value.top;
          element.scrollLeft = value.left;
        }
      });
      const chat = root.querySelector('[data-ai-scroll="chat"]');
      if (chat && state.shouldStickChat) {
        chat.scrollTop = chat.scrollHeight;
        state.shouldStickChat = false;
      }
    });
  }

  function formatRelativeTime(value) {
    const timestamp = normalizeTimestamp(value);
    if (!timestamp) return '--';
    const delta = Date.now() - timestamp;
    if (delta < 60000) return '刚刚';
    if (delta < 3600000) return `${Math.floor(delta / 60000)} 分钟前`;
    if (delta < 86400000) return `${Math.floor(delta / 3600000)} 小时前`;
    if (delta < 604800000) return `${Math.floor(delta / 86400000)} 天前`;
    return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(timestamp);
  }

  function formatMessageTime(value) {
    const timestamp = normalizeTimestamp(value);
    if (!timestamp) return '';
    return new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit' }).format(timestamp);
  }

  function formatFileSize(value) {
    const size = Number(value) || 0;
    if (size < 1024) return `${size} B`;
    return `${(size / 1024).toFixed(size > 10240 ? 0 : 1)} KB`;
  }

  function icon(name) {
    const paths = {
      plus: '<path d="M12 5v14M5 12h14"/>',
      back: '<path d="m15 18-6-6 6-6"/>',
      'chevron-down': '<path d="m6 9 6 6 6-6"/>',
      'chevron-right': '<path d="m9 18 6-6-6-6"/>',
      'new-chat': '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L8 18l-4 1 1-4Z"/>',
      paperclip: '<path d="m21.4 11.6-8.9 8.9a6 6 0 0 1-8.5-8.5l9.6-9.6a4 4 0 0 1 5.7 5.7l-9.6 9.6a2 2 0 0 1-2.8-2.8l8.9-8.9"/>',
      'page-add': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M12 18v-6M9 15h6"/>',
      shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/>',
      send: '<path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>',
      loader: '<path d="M21 12a9 9 0 1 1-6.2-8.6"/>',
      alert: '<path d="M10.3 2.9 1.8 17a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 2.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/>',
      check: '<path d="m20 6-11 11-5-5"/>',
      file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/>',
      close: '<path d="m18 6-12 12M6 6l12 12"/>',
      search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
      refresh: '<path d="M20 6v5h-5M4 18v-5h5"/><path d="M18.5 9A7 7 0 0 0 6 5.5L4 8m2 7.5A7 7 0 0 0 18 18l2-2.5"/>',
      trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 15H6L5 6M10 11v6M14 11v6"/>',
      save: '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2Z"/><path d="M17 21v-8H7v8M7 3v5h8"/>',
      key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15 8l3 3M18 5l3 3"/>',
      link: '<path d="M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.1-.1l-2 2A5 5 0 0 0 12 20l1.1-1.1"/>',
      copy: '<rect width="14" height="14" x="8" y="8" rx="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
      external: '<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
      spark: '<path d="m12 3-1.4 3.6a3 3 0 0 1-1.7 1.7L5.3 9.7l3.6 1.4a3 3 0 0 1 1.7 1.7L12 16.4l1.4-3.6a3 3 0 0 1 1.7-1.7l3.6-1.4-3.6-1.4a3 3 0 0 1-1.7-1.7Z"/><path d="m19 17-.5 1.3a1.5 1.5 0 0 1-.8.8l-1.3.5 1.3.5a1.5 1.5 0 0 1 .8.8L19 22l.5-1.1a1.5 1.5 0 0 1 .8-.8l1.3-.5-1.3-.5a1.5 1.5 0 0 1-.8-.8Z"/>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.spark}</svg>`;
  }

  render();
  loadInitial();

  return {
    open(options = {}) {
      if (!isGlobal) return;
      const prompt = firstText(options.prompt).slice(0, 12000);
      expireInactiveConversation();
      state.drawerOpen = true;
      state.tab = options.history ? 'history' : 'chat';
      touchActiveConversation();
      if (prompt) {
        state.prompt = prompt;
        state.initialAutoSend = Boolean(options.autoSend);
      }
      render();
      if (prompt && state.initialAutoSend && !state.loading && credentialReady()) {
        state.initialAutoSend = false;
        sendMessage();
      }
    },
    close() {
      if (!isGlobal) return;
      touchActiveConversation();
      state.drawerOpen = false;
      render();
    },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      clearOAuthPollTimer();
      window.removeEventListener('message', receiveOAuthCompletion);
      window.removeEventListener('dwrt:ai-config-updated', receiveConfigUpdated);
      window.removeEventListener('dwrt:ai-oauth-updated', receiveOAuthUpdated);
      if (isGlobal) {
        window.removeEventListener('dwrt:ai-initial-request', receiveInitialRequest);
        window.removeEventListener('resize', handleViewportResize);
        document.removeEventListener('pointerdown', handleGlobalPointerDown);
        wallpaper?.removeEventListener('load', handleWallpaperChange);
        wallpaperObserver?.disconnect();
      }
      if (root) root.classList.remove(MODULE_CLASS);
    }
  };
}
