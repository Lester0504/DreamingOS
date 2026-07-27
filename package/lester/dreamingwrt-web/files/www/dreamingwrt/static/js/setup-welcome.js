(() => {
  const VERSION = '20260718-05';
  const CONTROL_URL = '/app/';
  const BACKGROUND_FADE_MS = 2800;
  const DETECT_POLL_MS = 1400;

  const LIQUID_GLASS = {
    cornerRadius: 25,
    mode: 'shader',
    baseBlur: 3.2,
    neutralDensity: 0.06,
    neutralColor: '10 16 25',
    saturation: 140,
    displacementScale: 80,
    aberrationIntensity: 2,
    refractionOffset: 80,
    refractionHeight: 12,
    borderWidth: 1,
    highlight: 0.28,
    highlightAngle: 135,
    preserveCenter: true,
    borderColor: '#25FFFFFF'
  };

  const SETUP_SHELL_HTML = `<main class="setup-page" id="setupPage">
      <div class="setup-backdrop" aria-hidden="true">
        <div class="setup-wallpaper" id="setupWallpaper"></div>
        <div class="setup-wallpaper next" id="setupWallpaperNext"></div>
        <div class="setup-scrim"></div>
      </div>

      <section class="wizard-shell" aria-labelledby="setupTitle">
        <header class="wizard-header">
          <a class="setup-brand" href="/" aria-label="Dreaming OS">
            <img src="/static/images/logo-64.png" alt="" width="32" height="32">
            <span>Dreaming OS</span>
          </a>
          <div class="wizard-status" id="topStatus">
            <span></span>
            <strong>正在准备</strong>
          </div>
        </header>

	        <aside class="wizard-stage" aria-label="初始化进度">
	          <div class="stage-media" id="stageMedia">
	            <img id="stageImage" src="/static/images/gateway-wide.svg" alt="Dreaming OS 设备预览">
	            <div class="device-glow" aria-hidden="true"></div>
	          </div>

          <div class="stage-caption">
            <p class="setup-kicker" id="setupKicker">DreamingOS guided setup</p>
            <h1 id="setupTitle">准备配置你的 Dreaming OS</h1>
            <p id="setupSubtitle">向导会先识别设备和上级网络，再带你完成 WAN、LAN 与基础服务配置。</p>
          </div>

          <ol class="step-rail" id="stepRail" aria-label="初始化步骤">
            <li data-step="hostname"><span>1</span><b>主机名</b></li>
            <li data-step="usage"><span>2</span><b>使用场景</b></li>
            <li data-step="security"><span>3</span><b>安全接入</b></li>
            <li data-step="network"><span>4</span><b>网络</b></li>
            <li data-step="llm"><span>5</span><b>LLM</b></li>
            <li data-step="review"><span>6</span><b>完成</b></li>
          </ol>
        </aside>

        <section class="wizard-panel" aria-live="polite">
          <form class="wizard-form" id="setupForm" autocomplete="on">
            <section class="wizard-step active" data-step-panel="intro">
              <div class="panel-heading">
                <p>首次启动</p>
                <h2>初次使用，请跟随向导指引完成配置</h2>
                <span>WAN口类型会在后台完成检测</span>
              </div>

	              <div class="intro-card">
	                <div class="intro-device">
	                  <img src="/static/images/logo-64.png" alt="Dreaming OS">
                </div>
                <div>
                  <strong id="introDeviceName">Dreaming OS</strong>
                  <span id="introDeviceModel">正在读取设备信息</span>
                </div>
              </div>

              <div class="signal-grid">
                <article>
                  <span>状态</span>
                  <strong id="statusInitialized">读取中</strong>
                </article>
                <article>
                  <span>WAN口类型</span>
                  <strong id="statusDetect">等待中</strong>
                </article>
                <article>
                  <span>Wi-Fi</span>
                  <strong id="statusWifi">读取中</strong>
                </article>
              </div>

              <div class="intro-path" aria-label="向导包含的配置">
                <article><span>01</span><strong>主机名</strong><em>命名设备</em></article>
                <article><span>02</span><strong>使用场景</strong><em>个人或企业</em></article>
                <article><span>03</span><strong>安全接入</strong><em>APP、SSH、2FA</em></article>
                <article><span>04</span><strong>网络</strong><em>WAN 与 LAN</em></article>
                <article><span>05</span><strong>LLM</strong><em>可跳过</em></article>
              </div>
            </section>

            <section class="wizard-step" data-step-panel="hostname">
              <div class="panel-heading">
                <p>第一步</p>
                <h2>先给这台路由器命名</h2>
                <span>主机名会用于本机识别、日志、设备卡片和后续管理入口。</span>
              </div>

              <label class="field">
                <span>主机名</span>
                <input id="hostname" name="hostname" type="text" placeholder="DreamingOS" autocomplete="organization">
              </label>
              <label class="field">
                <span>备注</span>
                <input id="deviceNote" name="deviceNote" type="text" placeholder="例如：客厅弱电箱 / 主拨号路由">
              </label>
            </section>

            <section class="wizard-step" data-step-panel="usage">
              <div class="panel-heading">
                <p>第二步</p>
                <h2>选择使用场景</h2>
                <span>个人模式会启用家庭网络默认策略；企业模式会预留多站点、权限和审计能力。</span>
              </div>

              <div class="choice-grid two usage-grid">
                <label class="choice active">
                  <input type="radio" name="usageMode" value="personal" checked>
                  <strong>个人使用</strong>
                  <span>适合家庭、工作室和单台主路由。</span>
                </label>
                <label class="choice disabled">
                  <input type="radio" name="usageMode" value="enterprise" disabled>
                  <strong>企业使用 <em>敬请期待</em></strong>
                  <span>面向多用户、多站点和集中权限控制。</span>
                </label>
              </div>
            </section>

            <section class="wizard-step" data-step-panel="security">
              <div class="panel-heading">
                <p>第三步</p>
                <h2>设置安全接入</h2>
                <span>APP 绑定可跳过；SSH 端口必须确认。2FA 可选，但不绑定时，Web 密码丢失将无法找回，部分安全场景会降级。</span>
              </div>
              <div class="security-grid">
                <article class="setup-card app-pair-card">
                  <div class="card-heading">
                    <span>APP 绑定</span>
                    <strong id="pairStatus">未生成</strong>
                  </div>
                  <div class="pair-code" id="pairCode">----</div>
                  <p id="pairHint">可跳过。生成后用 APP 输入绑定码，后端补二维码后这里会显示二维码。</p>
                  <button type="button" class="setup-button secondary compact" id="pairInitButton">生成绑定码</button>
                </article>

                <article class="setup-card ssh-card">
                  <div class="card-heading">
                    <span>SSH 端口</span>
                    <strong id="sshStatus">等待后端接口</strong>
                  </div>
                  <label class="field inline-field">
                    <span>端口</span>
                    <input id="sshPort" name="sshPort" type="number" min="1" max="65535" value="11504" inputmode="numeric">
                  </label>
                  <p>当前 setup 状态没有返回 SSH 端口；保存时会记录为待后端接入。</p>
                </article>

                <article class="setup-card twofa-card">
                  <div class="card-heading">
                    <span>2FA 验证器</span>
                    <strong id="twofaStatus">可选</strong>
                  </div>
                  <div class="secret-box" id="twofaSecret">等待后端会话</div>
                  <p>绑定后登录需要动态验证码。不绑定时请妥善保存 Web 密码。</p>
                  <button type="button" class="setup-button secondary compact" id="twofaPrepareButton">准备绑定</button>
                </article>
              </div>
            </section>

            <section class="wizard-step" data-step-panel="network">
              <div class="panel-heading">
                <p>第四步</p>
                <h2>配置 WAN 和 LAN</h2>
                <span id="wanHint">WAN 口类型和候选接口会根据后端证据自动选择；多 WAN / 多 LAN 先保留框架，后续由后端补完整草稿能力。</span>
              </div>

              <div class="network-section">
                <div class="section-title"><span>WAN</span><strong>上级网络</strong></div>
              </div>

              <div class="wan-detect-card">
                <div>
                  <span>推荐线路</span>
                  <strong id="detectDevice">--</strong>
                </div>
                <div>
                  <span>推荐协议</span>
                  <strong id="detectProto">--</strong>
                </div>
                <div>
                  <span>置信度</span>
                  <strong id="detectConfidence">--</strong>
                </div>
                <button type="button" class="icon-button" id="rerunDetect" title="重新探测 WAN">重新探测</button>
              </div>

              <div class="wan-extra-grid">
                <article class="mini-status-card">
                  <span>运营商</span>
                  <strong id="detectIsp">等待后端</strong>
                </article>
                <article class="mini-status-card">
                  <span>WAN 候选</span>
                  <strong id="detectCandidates">--</strong>
                </article>
              </div>

              <div class="proto-box" role="radiogroup" aria-label="WAN 协议">
                <label><input type="radio" name="wanProto" value="dhcp"><span>DHCP</span></label>
                <label><input type="radio" name="wanProto" value="pppoe"><span>PPPoE</span></label>
                <label><input type="radio" name="wanProto" value="static"><span>静态 IP</span></label>
              </div>

              <div class="proto-fields active" data-proto-fields="dhcp">
                <div class="well-note">多数家庭网关、光猫路由模式和上级 DHCP 网络使用这个选项。</div>
              </div>

              <div class="proto-fields" data-proto-fields="pppoe">
                <div class="field-row">
                  <label class="field">
                    <span>宽带账号</span>
                    <input id="pppoeUsername" name="pppoeUsername" type="text" autocomplete="username" placeholder="PPPoE username">
                  </label>
                  <label class="field">
                    <span>宽带密码</span>
                    <input id="pppoePassword" name="pppoePassword" type="password" autocomplete="current-password" placeholder="PPPoE password">
                  </label>
                </div>
              </div>

              <div class="proto-fields" data-proto-fields="static">
                <div class="field-row three">
                  <label class="field"><span>IP 地址</span><input id="staticIp" type="text" placeholder="192.168.1.2"></label>
                  <label class="field"><span>前缀</span><input id="staticPrefix" type="number" min="1" max="32" value="24"></label>
                  <label class="field"><span>网关</span><input id="staticGateway" type="text" placeholder="192.168.1.1"></label>
                </div>
              </div>

              <details class="evidence-box" open>
                <summary>探测证据</summary>
                <pre id="wanEvidence">等待后端返回探测结果</pre>
              </details>

              <div class="network-section lan-section">
                <div class="section-title"><span>LAN</span><strong>本地网络</strong></div>
                <p>默认值按常见家庭网络给出。更复杂的 VLAN、桥接和多 LAN 可以之后进入控制台细调。</p>
              </div>

              <div class="field-row three">
                <label class="field"><span>LAN 地址</span><input id="lanIp" type="text" value="192.168.1.1"></label>
                <label class="field"><span>前缀</span><input id="lanPrefix" type="number" min="1" max="32" value="24"></label>
                <label class="field"><span>DHCP 租期（分钟）</span><input id="lanLease" type="number" min="10" value="120"></label>
              </div>
              <div class="field-row">
                <label class="field"><span>地址池起始</span><input id="poolStart" type="number" min="2" max="253" value="100"></label>
                <label class="field"><span>地址池结束</span><input id="poolEnd" type="number" min="3" max="254" value="249"></label>
              </div>
              <label class="switch-line">
                <input id="dhcpEnabled" type="checkbox" checked>
                <span>启用 DHCP 服务</span>
              </label>

              <div class="wifi-inline-status" id="wifiInlineStatus">
                <strong id="wifiTitle">Wi-Fi 能力</strong>
                <span id="wifiHint">后端会告诉前端设备是否支持 Wi-Fi；不支持时自动跳过。</span>
              </div>
            </section>

            <section class="wizard-step" data-step-panel="llm">
              <div class="panel-heading">
                <p>第五步</p>
                <h2>配置 LLM 提供商</h2>
                <span>可以跳过。API Key 只应由后端保存和脱敏展示；OAuth 先作为后端缺口记录。</span>
              </div>

              <div class="field-row">
                <label class="field">
                  <span>模型提供商</span>
                  <input id="llmProvider" name="llmProvider" type="text" placeholder="OpenAI / Anthropic / 自定义">
                </label>
                <label class="field">
                  <span>API Key</span>
                  <input id="llmApiKey" name="llmApiKey" type="password" placeholder="可跳过" autocomplete="off">
                </label>
              </div>

              <div class="choice-grid">
                <label class="choice active">
                  <input type="radio" name="assistMode" value="manual" checked>
                  <strong>跳过，随后手动配置</strong>
                  <span>完成基础网络设置后进入 dashboard。</span>
                </label>
                <label class="choice">
                  <input type="radio" name="assistMode" value="ai">
                  <strong>启用 LLM 辅助</strong>
                  <span>需要互联网和后端 provider 保存接口。</span>
                </label>
                <label class="choice">
                  <input type="radio" name="assistMode" value="oauth" disabled>
                  <strong>OAuth 连接 <em>后端待补</em></strong>
                  <span>需要 webd 提供 OAuth provider 与授权流程。</span>
                </label>
              </div>
            </section>

            <section class="wizard-step" data-step-panel="review">
              <div class="panel-heading">
                <p>应用配置</p>
                <h2>确认并应用初始化草稿</h2>
                <span>这里会调用后端真实保存、应用和测试接口。失败时会保留在当前页面显示原因。</span>
              </div>

              <div class="review-list" id="reviewList"></div>

	              <div class="apply-card">
	                <img src="/static/images/logo-64.png" alt="">
                <div>
                  <strong id="applyTitle">等待应用</strong>
                  <span id="applyText">点击“保存并应用”后开始执行。</span>
                </div>
              </div>
            </section>

            <section class="wizard-step" data-step-panel="done">
              <div class="panel-heading">
                <p>完成</p>
                <h2>Dreaming OS 已准备好</h2>
                <span>如果后端已正式写入初始化完成标记，下次会直接进入控制台。</span>
              </div>
	            <div class="done-hero">
	              <img src="/static/images/gateway-wide.svg" alt="Dreaming OS 已连接">
              </div>
            </section>

            <div class="wizard-message" id="wizardMessage" hidden></div>
          </form>

          <footer class="wizard-footer">
            <button type="button" class="setup-button secondary" id="backButton">返回</button>
            <button type="button" class="setup-button secondary" id="skipButton">跳过（随后手动配置）</button>
            <button type="button" class="setup-button secondary" id="forceContinueButton" hidden>继续测试</button>
            <button type="button" class="setup-button primary" id="nextButton"><span>继续</span><i aria-hidden="true"></i></button>
          </footer>
        </section>
      </section>
    </main>`;

  function mountSetupShell() {
    if (document.getElementById('setupPage')) return;
    const root = document.getElementById('setupRoot') || document.body;
    root.innerHTML = SETUP_SHELL_HTML;
  }

  mountSetupShell();

  const steps = ['intro', 'hostname', 'usage', 'security', 'network', 'llm', 'review', 'done'];
  const stepMeta = {
    intro: {
      kicker: 'DreamingOS guided setup',
      title: '准备配置你的 Dreaming OS',
      subtitle: '初次使用，请跟随向导指引完成配置。WAN口类型会在后台完成检测。',
      status: '正在准备',
      action: '开始初始化',
      showDevice: false
    },
    hostname: {
      kicker: 'Hostname',
      title: '先给这台路由器命名',
      subtitle: '主机名会用于本机识别、日志、设备卡片和后续管理入口。',
      status: '主机名',
      action: '保存并继续',
      showDevice: true
    },
    usage: {
      kicker: 'Usage',
      title: '选择使用场景',
      subtitle: '个人模式会启用家庭网络默认策略；企业模式会预留多站点、权限和审计能力。',
      status: '使用场景',
      action: '继续',
      showDevice: true
    },
    security: {
      kicker: 'Security',
      title: '设置安全接入',
      subtitle: 'APP 绑定可跳过；SSH 端口必须确认。2FA 可选，但不绑定时请妥善保存 Web 密码。',
      status: '安全接入',
      action: '保存安全设置',
      showDevice: true
    },
    network: {
      kicker: 'Network',
      title: '配置 WAN 和 LAN',
      subtitle: 'WAN 协议来自后端真实探测；LAN 默认适合常见家庭主路由。',
      status: '网络配置',
      action: '保存网络',
      showDevice: true
    },
    llm: {
      kicker: 'LLM',
      title: '配置 LLM 提供商',
      subtitle: '这一步可以跳过。OAuth 与 provider 持久化需要后端继续补齐。',
      status: 'LLM 配置',
      action: '保存选择',
      showDevice: true
    },
    review: {
      kicker: 'Apply changes',
      title: '确认并应用初始化草稿',
      subtitle: '这里会调用后端真实保存、应用和测试接口。失败时停在当前页面显示原因。',
      status: '等待应用',
      action: '保存并应用',
      showDevice: true
    },
    done: {
      kicker: 'Ready',
      title: 'Dreaming OS 已准备好',
      subtitle: '初始化流程已经走完。接下来进入控制台继续查看状态和细调网络。',
      status: '完成',
      action: '进入控制台',
      showDevice: true
    }
  };

  const $ = (id) => document.getElementById(id);
  const page = $('setupPage');
  const form = $('setupForm');
  const wallpaper = $('setupWallpaper');
  const wallpaperNext = $('setupWallpaperNext');
  const stageMedia = $('stageMedia');
  const title = $('setupTitle');
  const subtitle = $('setupSubtitle');
  const kicker = $('setupKicker');
  const topStatus = $('topStatus');
  const message = $('wizardMessage');
  const nextButton = $('nextButton');
  const backButton = $('backButton');
  const skipButton = $('skipButton');
  const forceContinueButton = $('forceContinueButton');
  const rerunDetect = $('rerunDetect');
  const reviewList = $('reviewList');

  const state = {
    step: 'intro',
    busy: false,
    started: false,
    session: null,
    status: null,
    detect: null,
    pair: null,
    twofa: null,
    supportedWifi: null,
    protoTouched: false,
    warned: new Set(),
    saved: {}
  };

  function numberFromTheme(data, keys, fallback) {
    for (const key of keys) {
      if (data && data[key] !== undefined && data[key] !== null && data[key] !== '') {
        const value = Number(data[key]);
        if (Number.isFinite(value)) return value;
      }
    }
    return fallback;
  }

  function stringFromTheme(data, keys, fallback) {
    for (const key of keys) {
      if (data && data[key] !== undefined && data[key] !== null && data[key] !== '') {
        return String(data[key]);
      }
    }
    return fallback;
  }

  function androidColorToCss(value) {
    const raw = String(value || '').trim();
    const hex = raw.startsWith('#') ? raw.slice(1) : raw;
    if (/^[0-9a-fA-F]{8}$/.test(hex)) {
      const alpha = hex.slice(0, 2);
      const rgb = hex.slice(2);
      return `#${rgb}${alpha}`;
    }
    return raw || '#ffffff25';
  }

  function applyLiquidGlass(data) {
    const material = data && data.material_glass && typeof data.material_glass === 'object'
      ? data.material_glass
      : null;
    const source = data && data.liquid_glass ? { ...data, ...data.liquid_glass } : (data || {});
    const vars = {
      cornerRadius: numberFromTheme(source, ['login_glass_corner_radius', 'glass_corner_radius', 'corner_radius'], LIQUID_GLASS.cornerRadius),
      baseBlur: material
        ? Math.max(0, Math.min(16, Number(material.base_blur ?? LIQUID_GLASS.baseBlur)))
        : Math.max(0, Math.min(16, numberFromTheme(source, ['login_glass_blur', 'glass_blur', 'blur_radius'], LIQUID_GLASS.baseBlur))),
      neutralDensity: material
        ? Math.max(0.025, Math.min(0.18, Number(material.neutral_density ?? LIQUID_GLASS.neutralDensity)))
        : LIQUID_GLASS.neutralDensity,
      neutralColor: material?.neutral_color || LIQUID_GLASS.neutralColor,
      saturation: material
        ? Math.max(70, Math.min(220, Number(material.saturation ?? LIQUID_GLASS.saturation)))
        : LIQUID_GLASS.saturation,
      refractionOffset: material
        ? Math.max(0, Math.min(180, Number(material.displacement_scale ?? LIQUID_GLASS.displacementScale)))
        : numberFromTheme(source, ['login_glass_refraction_offset', 'refraction_offset'], LIQUID_GLASS.refractionOffset),
      refractionHeight: numberFromTheme(source, ['login_glass_refraction_height', 'refraction_height'], LIQUID_GLASS.refractionHeight),
      borderWidth: material
        ? Math.max(0, Math.min(2, Number(material.border_width ?? LIQUID_GLASS.borderWidth)))
        : numberFromTheme(source, ['login_glass_border_width', 'border_width'], LIQUID_GLASS.borderWidth),
      highlight: material
        ? Math.max(0, Math.min(0.65, Number(material.highlight ?? LIQUID_GLASS.highlight)))
        : numberFromTheme(source, ['login_glass_highlight', 'highlight_strength', 'highlight'], LIQUID_GLASS.highlight),
      borderColor: androidColorToCss(material?.border_color || stringFromTheme(source, ['login_glass_border_color', 'border_color'], LIQUID_GLASS.borderColor))
    };
    document.documentElement.style.setProperty('--lg-corner-radius', `${vars.cornerRadius}px`);
    document.documentElement.style.setProperty('--lg-blur-radius', `${vars.baseBlur}px`);
    document.documentElement.style.setProperty('--lg-refraction-offset', `${vars.refractionOffset}px`);
    document.documentElement.style.setProperty('--lg-refraction-height', `${vars.refractionHeight}px`);
    document.documentElement.style.setProperty('--lg-border-width', `${vars.borderWidth}px`);
    document.documentElement.style.setProperty('--lg-highlight', `${vars.highlight}`);
    document.documentElement.style.setProperty('--lg-border-color', vars.borderColor);
    document.documentElement.style.setProperty('--dwrt-glass-base-blur', `${vars.baseBlur}px`);
    document.documentElement.style.setProperty('--dwrt-glass-neutral-density', `${vars.neutralDensity}`);
    document.documentElement.style.setProperty('--dwrt-glass-neutral-color', vars.neutralColor);
    document.documentElement.style.setProperty('--dwrt-glass-saturation', `${vars.saturation}%`);
    document.documentElement.style.setProperty('--dwrt-glass-highlight-strength', `${vars.highlight}`);
  }

  function setWallpaper(url, opacity = 1) {
    if (!wallpaper || !url) return;
    wallpaper.style.backgroundImage = `url("${url}")`;
    wallpaper.style.opacity = opacity;
  }

  async function readJson(url, options = {}) {
    const res = await fetch(url, {
      credentials: 'same-origin',
      cache: options.cache || 'no-store',
      ...options
    });
    const text = await res.text();
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch (_) {
      body = null;
    }
    return { ok: res.ok, status: res.status, body, text };
  }

  async function postJson(url, payload = {}) {
    return readJson(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  }

  function unwrap(body) {
    if (!body) return null;
    if (body.data !== undefined) return body.data;
    return body;
  }

  function responseOk(result) {
    if (!result || !result.ok) return false;
    const body = result.body || {};
    const data = unwrap(body);
    if (body.code !== undefined) return Number(body.code) === 2000;
    if (body.ok !== undefined) return !!body.ok;
    if (data && data.ok !== undefined) return !!data.ok;
    return result.ok;
  }

  function safeGet(obj, path, fallback) {
    let cur = obj;
    for (let i = 0; i < path.length; i++) {
      if (cur == null) return fallback;
      cur = cur[path[i]];
    }
    return cur == null ? fallback : cur;
  }

  function apiError(result, fallback = '接口返回失败') {
    const body = result && result.body ? result.body : null;
    const data = unwrap(body) || {};
    const errors = Array.isArray(data.errors) ? data.errors : [];
    if (errors.length) {
      return errors.map((item) => {
        if (typeof item === 'string') return item;
        return [item.field, item.reason, item.message].filter(Boolean).join(': ');
      }).join('\n');
    }
    return data.message || data.error || safeGet(body, ['message'], '') || safeGet(body, ['error'], '') || fallback;
  }

  function setBusy(busy, label) {
    state.busy = busy;
    page && page.classList.toggle('is-busy', busy);
    [nextButton, backButton, skipButton, forceContinueButton, rerunDetect].forEach((button) => {
      if (button) button.disabled = busy;
    });
    if (busy && label && nextButton) nextButton.querySelector('span').textContent = label;
    if (!busy) updateStep(state.step, { keepScroll: true });
  }

  function showMessage(text, type = 'info') {
    if (!message) return;
    if (!text) {
      message.hidden = true;
      message.textContent = '';
      message.className = 'wizard-message';
      return;
    }
    message.hidden = false;
    message.textContent = text;
    message.className = `wizard-message ${type}`.trim();
  }

  function setTopStatus(text, type = 'ready') {
    if (!topStatus) return;
    const strong = topStatus.querySelector('strong');
    if (strong) strong.textContent = text;
    topStatus.classList.toggle('ready', type === 'ready');
    topStatus.classList.toggle('error', type === 'error');
  }

  function val(id) {
    const el = $(id);
    return el ? el.value.trim() : '';
  }

  function setVal(id, value, force = false) {
    const el = $(id);
    if (!el) return;
    if (force || !el.value) el.value = value == null ? '' : String(value);
  }

  function selectedRadio(name) {
    return document.querySelector(`input[name="${name}"]:checked`);
  }

  function setProto(proto, options = {}) {
    const safe = ['dhcp', 'pppoe', 'static'].includes(proto) ? proto : 'dhcp';
    const radio = document.querySelector(`input[name="wanProto"][value="${safe}"]`);
    if (radio) radio.checked = true;
    document.querySelectorAll('.proto-box label').forEach((label) => {
      const input = label.querySelector('input');
      label.classList.toggle('active', !!input && input.checked);
    });
    document.querySelectorAll('[data-proto-fields]').forEach((panel) => {
      panel.classList.toggle('active', panel.dataset.protoFields === safe);
    });
    if (!options.silent) state.protoTouched = true;
    updateReview();
  }

  function currentProto() {
    const radio = selectedRadio('wanProto');
    return radio ? radio.value : 'dhcp';
  }

  function currentAssistMode() {
    const radio = selectedRadio('assistMode');
    return radio ? radio.value : 'manual';
  }

  function currentUsageMode() {
    const radio = selectedRadio('usageMode');
    return radio ? radio.value : 'personal';
  }

  function usageLabel() {
    return currentUsageMode() === 'enterprise' ? '企业使用' : '个人使用';
  }

  function assistLabel() {
    if (currentAssistMode() === 'ai') return 'LLM 辅助';
    if (currentAssistMode() === 'oauth') return 'OAuth 连接';
    return '跳过，随后手动配置';
  }

  function networkBase(ip) {
    const parts = String(ip || '').trim().split('.').map((part) => Number(part));
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return '192.168.1';
    }
    return `${parts[0]}.${parts[1]}.${parts[2]}`;
  }

  function poolAddress(octet) {
    const n = Number(octet);
    if (String(octet).includes('.')) return String(octet);
    return `${networkBase(val('lanIp'))}.${Number.isInteger(n) ? Math.min(254, Math.max(2, n)) : 100}`;
  }

  function detectDevice() {
    return safeGet(state.detect, ['recommended_device'], '') || safeGet(state.status, ['wan_detection', 'recommended_device'], '') || 'wan';
  }

  function detectIspName(data = state.detect) {
    return safeGet(data, ['recommended_isp'], '') || safeGet(data, ['isp_name'], '') || safeGet(data, ['carrier'], '') || '';
  }

  function formatEvidence(data) {
    if (!data) return '等待后端返回探测结果';
    const lines = [];
    lines.push(`状态: ${data.state || 'unknown'}`);
    if (data.recommended_device) lines.push(`推荐线路: ${data.recommended_device}`);
    if (data.recommended_proto) lines.push(`推荐协议: ${data.recommended_proto}`);
    if (data.confidence !== undefined) lines.push(`置信度: ${data.confidence}%`);
    if (Array.isArray(data.evidence) && data.evidence.length) {
      lines.push('证据:');
      data.evidence.forEach((item) => {
        if (typeof item === 'string') {
          lines.push(`- ${item}`);
        } else {
          lines.push(`- ${[item.type, item.interface, item.detail].filter(Boolean).join(' / ')}`);
        }
      });
    }
    if (Array.isArray(data.candidates) && data.candidates.length) {
      lines.push('候选接口:');
      data.candidates.forEach((item) => {
        const score = item.score !== undefined && item.score !== null ? item.score : '--';
        lines.push(`- ${item.device || '--'} carrier=${item.carrier ? 'up' : 'down'} score=${score}`);
      });
    }
    if (Array.isArray(data.errors) && data.errors.length) {
      lines.push('错误:');
      data.errors.forEach((item) => lines.push(`- ${typeof item === 'string' ? item : JSON.stringify(item)}`));
    }
    return lines.join('\n');
  }

  function updateDetect(data, options = {}) {
    if (!data || typeof data !== 'object') return;
    state.detect = data;
    const proto = data.recommended_proto || '';
    $('detectDevice') && ($('detectDevice').textContent = data.recommended_device || '--');
    $('detectProto') && ($('detectProto').textContent = proto ? proto.toUpperCase() : '--');
    $('detectConfidence') && ($('detectConfidence').textContent = data.confidence !== undefined ? `${data.confidence}%` : '--');
    $('detectIsp') && ($('detectIsp').textContent = detectIspName(data) || '后端待补');
    $('detectCandidates') && ($('detectCandidates').textContent = Array.isArray(data.candidates) ? `${data.candidates.length} 个` : '--');
    $('wanEvidence') && ($('wanEvidence').textContent = formatEvidence(data));
    $('statusDetect') && ($('statusDetect').textContent = proto ? `${proto.toUpperCase()} ${data.confidence || 0}%` : (data.state || '等待中'));
    if ((options.force || !state.protoTouched) && ['dhcp', 'pppoe', 'static'].includes(proto)) {
      setProto(proto, { silent: true });
    }
    if (data.state === 'running') setTopStatus('正在探测 WAN', 'ready');
    if (data.state === 'done') setTopStatus('WAN 探测完成', 'ready');
    updateReview();
  }

  async function initTheme() {
    applyLiquidGlass({});
    try {
      const result = await readJson('/api/v1/login/theme');
      const data = responseOk(result) ? unwrap(result.body) : null;
      if (!data) return;
      applyLiquidGlass(data);
      const images = Array.isArray(data.images) ? data.images.filter(Boolean) : [];
      const selected = data.selected && data.selected.url;
      const firstImage = selected || images[0] || '/static/background/dwrt-default-bg.jpg';
      const opacity = data.opacity !== undefined && data.opacity !== null ? data.opacity : 1;
      setWallpaper(firstImage, opacity);
      if (!wallpaperNext || images.length <= 1 || data.mode === 'fixed') return;
      let index = Math.max(0, images.indexOf(firstImage));
      const interval = Math.max(12000, Number(data.interval_ms || 18000), BACKGROUND_FADE_MS + 5000);
      setInterval(() => {
        const nextIndex = (index + 1) % images.length;
        const nextUrl = images[nextIndex];
        const img = new Image();
        img.decoding = 'async';
        img.onload = () => {
          index = nextIndex;
          wallpaperNext.style.backgroundImage = `url("${nextUrl}")`;
          requestAnimationFrame(() => { wallpaperNext.style.opacity = opacity; });
          setTimeout(() => {
            wallpaper.style.backgroundImage = wallpaperNext.style.backgroundImage;
            wallpaper.style.opacity = opacity;
            wallpaperNext.style.opacity = 0;
          }, BACKGROUND_FADE_MS);
        };
        img.src = nextUrl;
      }, interval);
    } catch (_) {}
  }

  async function loadSession() {
    try {
      const result = await readJson('/api/v1/session/init');
      if (responseOk(result)) state.session = unwrap(result.body);
    } catch (_) {
      state.session = null;
    }
    if (state.session && state.session.requires_initial_setup === false) state.saved.webUser = true;
  }

  async function loadStatus() {
    try {
      const result = await readJson('/api/setup/status');
      if (!responseOk(result)) throw new Error(apiError(result));
      const data = unwrap(result.body);
      state.status = data;
      state.supportedWifi = data.supported_wifi;
      updateStatus(data);
      if (data.wan_detection) updateDetect(data.wan_detection);
      return data;
    } catch (error) {
      setTopStatus('状态接口不可用', 'error');
      showMessage(`无法读取初始化状态：${error.message || error}`, 'error');
      return null;
    }
  }

  function updateStatus(data) {
    if (!data) return;
    const device = data.device || {};
    $('statusInitialized') && ($('statusInitialized').textContent = data.initialized ? '已完成' : '需要初始化');
    $('statusWifi') && ($('statusWifi').textContent = data.supported_wifi ? '支持' : '无硬件，跳过');
    $('introDeviceName') && ($('introDeviceName').textContent = device.hostname || 'Dreaming OS');
    $('introDeviceModel') && ($('introDeviceModel').textContent = device.model || 'Dreaming OS Router');
    setVal('hostname', device.hostname || 'DreamingOS');
    if (safeGet(data, ['security', 'ssh', 'port'], null) !== null) {
      setVal('sshPort', safeGet(data, ['security', 'ssh', 'port'], 11504), true);
      $('sshStatus') && ($('sshStatus').textContent = '已读取');
    }

    if (data.supported_wifi === false) {
      $('wifiTitle') && ($('wifiTitle').textContent = 'Wi-Fi 已跳过');
      $('wifiHint') && ($('wifiHint').textContent = '后端已返回 supported_wifi=false，这台设备没有无线硬件。');
    } else {
      $('wifiTitle') && ($('wifiTitle').textContent = 'Wi-Fi 支持');
      $('wifiHint') && ($('wifiHint').textContent = '后端返回支持 Wi-Fi，后续可在控制台继续配置无线网络。');
    }
  }

  async function startSetup() {
    if (state.started) return;
    state.started = true;
    setTopStatus('启动初始化', 'ready');
    try {
      const start = await postJson('/api/setup/start', { source: 'dreamingwrt-web', version: VERSION });
      if (!responseOk(start)) {
        const msg = apiError(start, 'setup_start 返回失败');
        if (!state.warned.has('start')) {
          state.warned.add('start');
          showMessage(`初始化 start 没有成功返回：${msg}。继续以 status/detect 真实结果为准。`, 'info');
        }
      }
    } catch (error) {
      showMessage(`初始化 start 调用失败：${error.message || error}`, 'info');
    }
    await pollDetectStatus(6);
    if (!state.detect || !state.detect.recommended_proto) await triggerDetect({ silent: true });
  }

  async function triggerDetect(options = {}) {
    setTopStatus('正在探测 WAN', 'ready');
    $('statusDetect') && ($('statusDetect').textContent = '探测中');
    if (!options.silent) showMessage('正在重新探测 WAN，上游返回后会自动刷新推荐协议。', 'info');
    try {
      const result = await postJson('/api/setup/detect-wan/start', {});
      if (!responseOk(result)) {
        const msg = apiError(result, 'detect-wan/start 返回失败');
        if (!options.silent) showMessage(`探测启动返回异常：${msg}。继续轮询 status。`, 'info');
      } else {
        updateDetect(unwrap(result.body), { force: true });
      }
    } catch (error) {
      if (!options.silent) showMessage(`探测启动失败：${error.message || error}。继续读取 status。`, 'info');
    }
    await pollDetectStatus(8, { force: true });
  }

  function localId(prefix) {
    const rand = Math.random().toString(16).slice(2, 10);
    return `${prefix}-${Date.now().toString(36)}-${rand}`;
  }

  async function initPairing() {
    const button = $('pairInitButton');
    if (button) button.disabled = true;
    try {
      const appDeviceId = localId('setup-app');
      const result = await postJson('/api/v1/auth/pair/init', {
        app_device_id: appDeviceId,
        app_device_name: 'Dreaming OS Setup',
        platform: 'web-setup',
        public_key: ''
      });
      if (!responseOk(result)) throw new Error(apiError(result, 'APP 绑定码生成失败'));
      const data = unwrap(result.body) || result.body || {};
      state.pair = data;
      $('pairCode') && ($('pairCode').textContent = data.code || '----');
      $('pairStatus') && ($('pairStatus').textContent = data.code ? '等待确认' : '已请求');
      $('pairHint') && ($('pairHint').textContent = data.expires_in ? `绑定码 ${data.expires_in} 秒内有效。` : '绑定码已生成，等待 APP 侧确认。');
      updateReview();
    } catch (error) {
      showMessage(error.message || String(error), 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function prepareTwofa() {
    const button = $('twofaPrepareButton');
    if (button) button.disabled = true;
    try {
      const result = await postJson('/api/v1/auth/2fa/prepare', {});
      if (!responseOk(result)) throw new Error(apiError(result, '2FA 准备接口当前不可用'));
      const data = unwrap(result.body) || {};
      if (data.ok === false) throw new Error(data.message || data.error || '2FA 准备失败');
      state.twofa = data;
      $('twofaSecret') && ($('twofaSecret').textContent = data.secret || data.otpauth_url || '已生成');
      $('twofaStatus') && ($('twofaStatus').textContent = '待验证启用');
      updateReview();
    } catch (error) {
      $('twofaStatus') && ($('twofaStatus').textContent = '等待后端会话');
      showMessage(`2FA 暂不能直接启用：${error.message || error}。后端需要 setup 阶段会话或 token 接口。`, 'info');
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function pollDetectStatus(attempts = 6, options = {}) {
    for (let i = 0; i < attempts; i++) {
      try {
        const result = await readJson('/api/setup/detect-wan/status');
        if (responseOk(result)) {
          const data = unwrap(result.body);
          updateDetect(data, options);
          if (data.state === 'done' || data.recommended_proto) return data;
        }
      } catch (_) {}
      try {
        const status = await readJson('/api/setup/status');
        if (responseOk(status)) {
          const data = unwrap(status.body);
          if (data && data.wan_detection) {
            updateDetect(data.wan_detection, options);
            if (data.wan_detection.state === 'done' || data.wan_detection.recommended_proto) return data.wan_detection;
          }
        }
      } catch (_) {}
      await new Promise((resolve) => setTimeout(resolve, DETECT_POLL_MS));
    }
    return state.detect;
  }

  function visibleSteps() {
    return steps;
  }

  function updateStep(step, options = {}) {
    state.step = step;
    const meta = stepMeta[step] || stepMeta.intro;
    if (kicker) kicker.textContent = meta.kicker;
    if (title) title.textContent = meta.title;
    if (subtitle) subtitle.textContent = meta.subtitle;
    if (topStatus) setTopStatus(meta.status, step === 'done' ? 'ready' : 'ready');
    if (stageMedia) stageMedia.classList.toggle('show-device', !!meta.showDevice);

    document.querySelectorAll('[data-step-panel]').forEach((panel) => {
      panel.classList.toggle('active', panel.dataset.stepPanel === step);
    });

    const nav = visibleSteps();
    const currentIndex = nav.indexOf(step);
    document.querySelectorAll('[data-step]').forEach((item) => {
      const itemStep = item.dataset.step;
      const index = nav.indexOf(itemStep);
      item.classList.toggle('active', itemStep === step);
      item.classList.toggle('done', index >= 0 && currentIndex > index);
    });

    if (backButton) backButton.hidden = step === 'intro' || step === 'done';
    if (skipButton) skipButton.hidden = step === 'done';
    if (forceContinueButton) forceContinueButton.hidden = true;
    if (nextButton) nextButton.querySelector('span').textContent = meta.action;
    if (step === 'review') updateReview();
    if (!options.keepScroll && form) form.scrollTop = 0;
  }

  function nextVisibleStep(from) {
    const nav = visibleSteps();
    const index = nav.indexOf(from);
    return nav[Math.min(index + 1, nav.length - 1)] || 'done';
  }

  function prevVisibleStep(from) {
    const nav = visibleSteps();
    const index = nav.indexOf(from);
    return nav[Math.max(index - 1, 0)] || 'intro';
  }

  function buildDevicePayload() {
    return {
      hostname: val('hostname') || 'DreamingOS',
      description: val('deviceNote'),
      note: val('deviceNote')
    };
  }

  function buildSecurityPayload() {
    const sshPort = Number(val('sshPort') || 0);
    if (!Number.isInteger(sshPort) || sshPort < 1 || sshPort > 65535) {
      throw new Error('SSH 端口必须在 1-65535 之间。');
    }
    return {
      usage_mode: currentUsageMode(),
      ssh: { port: sshPort },
      app_pairing: state.pair ? {
        pair_id: state.pair.pair_id || state.pair.id || '',
        code: state.pair.code || '',
        expires_in: state.pair.expires_in || 0
      } : null,
      twofa: state.twofa ? {
        secret: state.twofa.secret || '',
        otpauth_url: state.twofa.otpauth_url || ''
      } : null
    };
  }

  function buildLlmPayload() {
    return {
      assist_mode: currentAssistMode(),
      mode: currentAssistMode(),
      provider: val('llmProvider'),
      api_key_present: !!val('llmApiKey')
    };
  }

  function buildWanPayload() {
    const proto = currentProto();
    const payload = {
      id: 'wan',
      name: 'WAN',
      ifname: 'wan',
      device: detectDevice(),
      proto,
      access_mode: proto,
      ipv6_mode: 'auto',
      metric: 10,
      mtu: proto === 'pppoe' ? 1492 : 1500
    };
    if (proto === 'pppoe') {
      payload.username = val('pppoeUsername');
      payload.password = val('pppoePassword');
      if (!payload.username || !payload.password) throw new Error('PPPoE 需要填写宽带账号和密码。');
    }
    if (proto === 'static') {
      payload.ip = val('staticIp');
      payload.ipaddr = payload.ip;
      payload.prefix = Number(val('staticPrefix') || 24);
      payload.gateway = val('staticGateway');
      if (!payload.ip || !payload.gateway) throw new Error('静态 IP 需要填写 IP 地址和网关。');
    }
    return payload;
  }

  function buildLanPayload() {
    const ip = val('lanIp') || '192.168.1.1';
    const prefix = Number(val('lanPrefix') || 24);
    const poolStart = poolAddress(val('poolStart') || 100);
    const poolEnd = poolAddress(val('poolEnd') || 249);
    return {
      id: 'lan',
      name: 'LAN',
      ifname: 'lan',
      device: 'br-lan',
      mode: 'bridge',
      enabled: true,
      ip,
      ipaddr: ip,
      prefix,
      dhcp_enabled: $('dhcpEnabled') ? !!$('dhcpEnabled').checked : true,
      pool_start: poolStart,
      pool_end: poolEnd,
      lease: Number(val('lanLease') || 120),
      lease_minutes: Number(val('lanLease') || 120),
      gateway: ip,
      dns1: ip,
      addresses: [{ ip, prefix, is_primary: true, primary: true }],
      dhcp: {
        enabled: $('dhcpEnabled') ? !!$('dhcpEnabled').checked : true,
        pool_start: poolStart,
        pool_end: poolEnd,
        lease: Number(val('lanLease') || 120),
        gateway: ip,
        dns1: ip,
        dns2: ''
      }
    };
  }

  async function saveDevice() {
    const payload = buildDevicePayload();
    const result = await postJson('/api/setup/save-device', payload);
    if (responseOk(result)) {
      state.saved.device = true;
      return true;
    }
    const reason = apiError(result, '设备身份保存失败');
    if (reason.includes('wizard_already_initialized') && safeGet(state.session, ['requires_initial_setup'], true) === false) {
      state.saved.device = false;
      showMessage('后端拒绝写入设备身份，因为 web 管理员已初始化。这个属于 webd 初始化状态和路由器初始化状态混用的问题，已按真实失败处理，网络配置可以继续。', 'info');
      return true;
    }
    throw new Error(reason);
  }

  async function saveUsage() {
    state.saved.usage = currentUsageMode();
    return true;
  }

  async function saveSecurity() {
    buildSecurityPayload();
    state.saved.security = true;
    $('sshStatus') && ($('sshStatus').textContent = '待后端接入');
    showMessage('安全接入已记录在向导草稿。SSH 端口、2FA 启用状态需要后端提供 setup 安全接口后才能真实应用。', 'info');
    return true;
  }

  async function saveWan() {
    const payload = buildWanPayload();
    const result = await postJson('/api/setup/save-wan', payload);
    if (!responseOk(result)) throw new Error(apiError(result, 'WAN 保存失败'));
    state.saved.wan = true;
    const data = unwrap(result.body);
    if (data && data.detection) updateDetect(data.detection);
    try {
      const test = await postJson('/api/setup/test-wan', { device: payload.device });
      if (!responseOk(test)) {
        showMessage(`WAN 已保存，但联网测试没有通过：${apiError(test, 'WAN 测试失败')}`, 'info');
      }
    } catch (_) {}
    return true;
  }

  async function saveLan() {
    const result = await postJson('/api/setup/save-lan', buildLanPayload());
    if (!responseOk(result)) throw new Error(apiError(result, 'LAN 保存失败'));
    state.saved.lan = true;
    return true;
  }

  async function saveNetwork() {
    await saveWan();
    await saveLan();
    state.saved.network = true;
    return true;
  }

  async function saveLlm() {
    const payload = buildLlmPayload();
    const result = await postJson('/api/setup/assist-mode', payload);
    if (!responseOk(result)) throw new Error(apiError(result, '完成方式保存失败'));
    state.saved.llm = true;
    const data = unwrap(result.body);
    if (currentAssistMode() === 'ai' && data && data.provider_available === false) {
      showMessage('AI 辅助已记录，但当前模型提供商或互联网不可用。后端没有假装可用，完成后可以在控制台继续配置。', 'info');
    } else if (val('llmApiKey')) {
      showMessage('LLM 选择已记录。API Key 的正式保存接口尚未接入 setup 流程，已写入后端缺口。', 'info');
    }
    return true;
  }

  async function applySetup() {
    const titleEl = $('applyTitle');
    const textEl = $('applyText');
    if (titleEl) titleEl.textContent = '正在应用';
    if (textEl) textEl.textContent = '正在调用 setup_apply，请不要刷新页面。';
    const apply = await postJson('/api/setup/apply', { source: 'dreamingwrt-web', version: VERSION });
    if (!responseOk(apply)) {
      if (titleEl) titleEl.textContent = '应用失败';
      if (textEl) textEl.textContent = apiError(apply, 'setup_apply 失败');
      throw new Error(apiError(apply, 'setup_apply 失败'));
    }
    if (titleEl) titleEl.textContent = '正在完成';
    if (textEl) textEl.textContent = '配置已应用，正在写入初始化完成标记。';
    const finish = await postJson('/api/setup/finish', { completed_by: 'dreamingwrt-web', version: VERSION });
    if (!responseOk(finish)) {
      if (titleEl) titleEl.textContent = '完成标记失败';
      if (textEl) textEl.textContent = apiError(finish, 'setup_finish 失败');
      throw new Error(apiError(finish, 'setup_finish 失败'));
    }
    state.saved.done = true;
    showMessage('初始化已完成，可以进入控制台。', 'success');
    updateStep('done');
    return true;
  }

  async function saveCurrentStep(step) {
    if (step === 'hostname') return saveDevice();
    if (step === 'usage') return saveUsage();
    if (step === 'security') return saveSecurity();
    if (step === 'network') return saveNetwork();
    if (step === 'llm') return saveLlm();
    if (step === 'review') return applySetup();
    return true;
  }

  async function handleNext() {
    if (state.busy) return;
    if (state.step === 'done') {
      window.location.href = CONTROL_URL;
      return;
    }
    showMessage('');
    setBusy(true, state.step === 'review' ? '正在应用' : '保存中');
    try {
      await saveCurrentStep(state.step);
      if (state.step !== 'review') updateStep(nextVisibleStep(state.step));
    } catch (error) {
      const msg = error.message || String(error);
      state.saved[`${state.step}_error`] = msg;
      setTopStatus('继续测试模式', 'ready');
      if (state.step === 'review') {
        showMessage(`${msg}\n后端还没完全闭环，先允许继续进入控制台测试。`, 'info');
        if (forceContinueButton) forceContinueButton.hidden = false;
      } else {
        showMessage(`${msg}\n已记录为后端/保存缺口，先继续下一步测试。`, 'info');
        updateStep(nextVisibleStep(state.step));
      }
    } finally {
      setBusy(false);
    }
  }

  function forceContinue() {
    if (state.step === 'done') {
      window.location.href = CONTROL_URL;
      return;
    }
    if (state.step === 'review') {
      updateStep('done');
      showMessage('已跳过最终 apply/finish 阻塞，仅用于当前测试。', 'info');
      return;
    }
    updateStep(nextVisibleStep(state.step));
  }

  function updateReview() {
    if (!reviewList) return;
    const proto = currentProto();
    const lanIp = val('lanIp') || '192.168.1.1';
    const rows = [
      ['设备名', val('hostname') || 'DreamingOS'],
      ['使用场景', usageLabel()],
      ['APP 绑定', state.pair && state.pair.code ? `绑定码 ${state.pair.code}` : '跳过或稍后绑定'],
      ['SSH 端口', val('sshPort') || '等待后端'],
      ['2FA', state.twofa && state.twofa.secret ? '已准备，待验证启用' : '未绑定'],
      ['WAN 口', detectDevice()],
      ['WAN 协议', proto.toUpperCase()],
      ['运营商', detectIspName() || '后端待补'],
      ['探测证据', safeGet(state.detect, ['evidence', 'length'], 0) ? `${state.detect.evidence.length} 条` : '等待后端'],
      ['LAN 地址', `${lanIp}/${val('lanPrefix') || 24}`],
      ['DHCP 地址池', `${poolAddress(val('poolStart') || 100)} - ${poolAddress(val('poolEnd') || 249)}`],
      ['Wi-Fi', state.supportedWifi === false ? '无硬件，跳过' : '支持，后续配置'],
      ['LLM', assistLabel()]
    ];
    reviewList.innerHTML = rows.map(([label, value]) => (
      `<div class="review-item"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`
    )).join('');
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"]/g, (ch) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;'
    }[ch]));
  }

  function wireEvents() {
    form && form.addEventListener('submit', (event) => event.preventDefault());
    nextButton && nextButton.addEventListener('click', handleNext);
    forceContinueButton && forceContinueButton.addEventListener('click', forceContinue);
    backButton && backButton.addEventListener('click', () => {
      if (!state.busy) {
        showMessage('');
        updateStep(prevVisibleStep(state.step));
      }
    });
    skipButton && skipButton.addEventListener('click', () => {
      window.location.href = CONTROL_URL;
    });
    rerunDetect && rerunDetect.addEventListener('click', async () => {
      if (state.busy) return;
      setBusy(true, '探测中');
      try {
        await triggerDetect({ silent: false });
      } finally {
        setBusy(false);
      }
    });
    const pairInitButton = $('pairInitButton');
    pairInitButton && pairInitButton.addEventListener('click', initPairing);
    const twofaPrepareButton = $('twofaPrepareButton');
    twofaPrepareButton && twofaPrepareButton.addEventListener('click', prepareTwofa);
    document.querySelectorAll('input[name="wanProto"]').forEach((input) => {
      input.addEventListener('change', () => setProto(input.value));
    });
    document.querySelectorAll('input[name="assistMode"], input[name="usageMode"]').forEach((input) => {
      input.addEventListener('change', () => {
        document.querySelectorAll('.choice').forEach((choice) => {
          const choiceInput = choice.querySelector('input');
          choice.classList.toggle('active', !!choiceInput && choiceInput.checked);
        });
        updateReview();
      });
    });
    ['hostname', 'deviceNote', 'sshPort', 'lanIp', 'lanPrefix', 'poolStart', 'poolEnd', 'llmProvider', 'llmApiKey'].forEach((id) => {
      const el = $(id);
      if (el) el.addEventListener('input', updateReview);
    });
  }

  async function init() {
    wireEvents();
    updateStep('intro', { keepScroll: true });
    await initTheme();
    await loadSession();
    await loadStatus();
    page && page.classList.add('is-ready');
    await startSetup();
    updateReview();
  }

  init();
})();
