export const MLO_MEMBERS_OPTION = 'dreamingwrt_mlo_members';
export const EMPTY_MLO_MEMBERS = '{"version":1,"members":[]}';

const text = (...values) => values.find((value) => typeof value === 'string' && value.length) || '';
const flag = (value) => value === true || value === 1 || value === '1' || value === 'true';
const list = (value) => Array.isArray(value) ? value : (typeof value === 'string' && value ? [value] : []);
const unique = (values) => [...new Set(values)];
const named = (value) => typeof value === 'string' && /^[a-z0-9_]{1,32}$/.test(value);
const apId = (row) => text(row.ap_id, row.runtime?.ap_id);
const local = (row) => apId(row) === 'local' || row.source === 'local' || row.scope === 'controller_local';
/* UCI 段名。受管行的段名在两个端点里落在不同的键上：

   /wifi/status  运行态行带 config_id（radio0/1/2），local_id 是驱动名
                 （phy0r0、phy0.0-ap0）——后者不是 UCI 段名。
   /wifi/config  desired 行直接由 UCI 枚举而来，段名就是 local_id
                 （radio0、wifi_1788259518162_2g），没有 config_id。

   所以只认 config_id 会让配置页上的每一行都以 mlo_radio_binding_unavailable
   失败。local_id 的兜底只在后端明说这行来自 UCI 时才用
   （configuration_source=apd_desired_read_only），否则 phy0r0 这种合法字符
   但并非段名的值会被当成段名写下去。 */
const desiredRow = (row) => text(row.configuration_source) === 'apd_desired_read_only';
export function sectionOf(row = {}) {
  const explicit = text(row.config_id);
  if (named(explicit)) return explicit;
  const fallback = text(row.local_id);
  return desiredRow(row) && named(fallback) ? fallback : '';
}
const option = (row, name) => row[name] ?? row.options?.[name];
const active = (row) => flag(option(row, 'mlo'));
const disabled = (row) => option(row, 'disabled') != null
  ? (flag(option(row, 'disabled')) ? '1' : '0') : (row.enabled === false ? '1' : '0');

function fail(reason, row = {}) {
  const error = new Error(reason);
  error.reason = reason;
  error.ap_id = apId(row);
  error.section = sectionOf(row);
  throw error;
}

function flatten(rows) {
  return rows.flatMap((row) => Array.isArray(row.members) && row.members.length
    ? row.members.flatMap((member) => flatten([{
      ap_id: apId(row), name: row.name, network: row.network,
      security_mode: row.security_mode, encryption: row.encryption, ...member
    }]))
    : [row]);
}

function identity(row) {
  return JSON.stringify([
    apId(row), text(row.name, row.ssid, row.broadcast_name, row.essid),
    unique(list(option(row, 'network') ?? row.lan ?? row.network_name)).sort(),
    text(row.security_mode, row.security, row.security_protocol).toLowerCase(),
    text(option(row, 'encryption')).toLowerCase(),
    text(row.mode, 'ap'), String(row.ieee80211w ?? row.pmf ?? ''), String(row.vlan ?? row.vlan_id ?? '')
  ]);
}

function sameRow(raw, edited) {
  if (apId(edited) && apId(raw) !== apId(edited)) return false;
  const rawSection = sectionOf(raw);
  const editedSection = sectionOf(edited);
  if (rawSection && editedSection) return rawSection === editedSection;
  if (!apId(edited)) return Boolean(raw.id && raw.id.startsWith(`ap:${apId(raw)}:`) && raw.id === edited.id);
  if (edited.config_id) return text(raw.config_id) === text(edited.config_id);
  return [raw.id, raw.local_id].some((id) => id && (id === edited.id || id === edited.local_id));
}

function editsFor(raw, editedRows) {
  return editedRows.flatMap((edited) => {
    if (Array.isArray(edited.members)) {
      const member = edited.members.find((item) => sameRow(raw, { ap_id: apId(edited), ...item }));
      return member ? [{ ...member, ...edited, ap_id: apId(member) || apId(edited),
        id: member.id, config_id: member.config_id, members: undefined }] : [];
    }
    return sameRow(raw, edited) ? [edited] : [];
  });
}

function bindings(row, radios) {
  const refs = list(row.list_options?.device ?? option(row, 'device') ?? row.radio_ids ?? row.radio_id);
  if (!refs.length) fail('mlo_radio_binding_unavailable', row);
  return unique(refs.map((ref) => {
    const candidates = radios.filter((radio) => apId(radio) === apId(row) && !local(radio) &&
      [radio.config_id, radio.id, radio.local_id].includes(ref));
    const ids = unique(candidates.map(sectionOf).filter(named));
    if (ids.length !== 1) fail('mlo_radio_binding_unavailable', row);
    return ids[0];
  })).sort();
}

// Only names, bindings and enable states are persisted; never copy a read model.
export function parseMloMembers(value, row = {}) {
  if (value == null || value === '') return [];
  let saved;
  try { saved = JSON.parse(value); } catch { fail('mlo_restore_members_invalid', row); }
  if (typeof value !== 'string' || value.length > 4096 || saved?.version !== 1 ||
      Object.keys(saved).some((key) => !['version', 'members'].includes(key)) ||
      !Array.isArray(saved.members) || saved.members.length > 16) fail('mlo_restore_members_invalid', row);
  const names = new Set();
  return saved.members.map((member) => {
    if (!named(member?.section) || names.has(member.section) ||
        Object.keys(member).some((key) => !['section', 'device', 'disabled'].includes(key)) ||
        !Array.isArray(member.device) || !member.device.length || member.device.length > 32 ||
        !member.device.every(named) || unique(member.device).length !== member.device.length ||
        !['0', '1'].includes(member.disabled)) fail('mlo_restore_members_invalid', row);
    names.add(member.section);
    return { section: member.section, device: [...member.device], disabled: member.disabled };
  });
}

function knownSecrets(row) {
  return [row.key, row.password, row.wpa_passphrase, row.options?.key]
    .filter((value) => typeof value === 'string' && value && !/^[*\u2022]+$/.test(value));
}

function verifySecrets(members, edits, warnings) {
  const secrets = unique(members.flatMap(knownSecrets));
  if (secrets.length > 1) fail('mlo_credentials_differ', members[0]);
  for (const member of members) {
    const previous = knownSecrets(member);
    const proposed = unique(editsFor(member, edits).flatMap(knownSecrets));
    if (proposed.some((secret) => !previous.includes(secret))) fail('mlo_password_change_not_supported', member);
  }
  if (members.length > 1 && members.some((member) => !knownSecrets(member).length) &&
      members.some((member) => flag(member.password_present) ||
        !['none', 'open'].includes(text(member.security_mode, member.encryption, member.security)))) {
    warnings.push({ reason: 'mlo_credentials_unverified', ap_id: apId(members[0]),
      sections: members.map(sectionOf) });
  }
}

function managedMloRow(row) {
  return active(row) && option(row, MLO_MEMBERS_OPTION) != null;
}

function mloName(name) {
  const base = text(name, 'WiFi');
  const suffix = '-MLO';
  if (!base.endsWith(suffix)) {
    return `${base.slice(0, Math.max(1, 32 - suffix.length))}${suffix}`;
  }
  const alternate = '-MLO2';
  const root = base.slice(0, -suffix.length) || 'WiFi';
  return `${root.slice(0, Math.max(1, 32 - alternate.length))}${alternate}`;
}

function shortHash(value) {
  let hash = 2166136261;
  for (const character of String(value)) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36).padStart(7, '0').slice(-7);
}

function mloSectionName(primary, reserved) {
  const direct = `${primary}_mlo`;
  if (named(direct) && !reserved.has(direct)) return direct;
  const compact = `${primary.slice(0, 24)}_${shortHash(primary)}`.slice(0, 32);
  if (named(compact) && !reserved.has(compact)) return compact;
  fail('mlo_section_name_collision', { config_id: primary });
}

function savedMloMembers(row) {
  return parseMloMembers(option(row, MLO_MEMBERS_OPTION), row);
}

function mloSourceOptions(source, name, encoded) {
  const network = list(option(source, 'network') ?? source.lan ?? source.network_name)[0];
  const encryption = text(option(source, 'encryption'), source.encryption,
    source.security_mode, source.security, source.security_protocol);
  if (!network || !encryption) fail('mlo_identity_unavailable', source);
  const options = {
    mlo: '1',
    mode: 'ap',
    ssid: mloName(name),
    network,
    encryption,
    disabled: '0',
    [MLO_MEMBERS_OPTION]: encoded
  };
  return options;
}

/** Build a dual-SSID plan for standard OpenWrt/mac80211 MLO.
 *
 * Existing per-band SSIDs remain ordinary APs. Enabling MLO creates one new
 * wifi-iface bound to all eligible radios and names it `<ssid>-MLO`; disabling
 * MLO removes only that managed section.  This is intentionally different from
 * QSDK's private `wifi-mld` shape used by the 31.31 reference device.
 */
export function buildManagedMloPlan({ rawSsids = [], rawRadios = [], ssids = [], radios = [], globalMlo } = {}) {
  void radios; // Normalized radio defaults must never become UCI options.
  const rows = flatten(rawSsids).filter((row) => !local(row));
  const mloRows = rows.filter(managedMloRow);
  const ordinaryRows = rows.filter((row) => !managedMloRow(row));
  const groups = new Map();
  for (const row of ordinaryRows) {
    const key = identity(row);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  const byAp = new Map();
  const warnings = [];
  let singleRadio;
  const handledMloSections = new Set();
  const reservedByAp = new Map();
  for (const row of rows) {
    const id = apId(row);
    if (!reservedByAp.has(id)) reservedByAp.set(id, new Set());
    const section = sectionOf(row);
    if (section) reservedByAp.get(id).add(section);
  }
  for (const members of groups.values()) {
    const switches = unique(members.flatMap((member) => editsFor(member, ssids)
      .filter((edited) => edited.mlo != null && flag(edited.mlo) !== active(member))
      .map((edited) => flag(edited.mlo))));
    if (switches.length > 1) fail('mlo_intent_conflict', members[0]);
    const names = members.map(sectionOf);
    const currentMlo = mloRows.filter((row) => {
      const saved = savedMloMembers(row);
      return saved.some((member) => names.includes(member.section));
    });
    if (currentMlo.length > 1) fail('mlo_restore_members_ambiguous', currentMlo[0]);
    const desired = switches[0] ?? (globalMlo == null ? Boolean(currentMlo.length) : flag(globalMlo));
    if (desired && currentMlo.length) {
      handledMloSections.add(sectionOf(currentMlo[0]));
      continue;
    }
    if (!desired && !currentMlo.length) continue;
    if (!apId(members[0])) fail('mlo_ap_id_unavailable', members[0]);
    if (members.some((member) => !named(sectionOf(member)))) fail('mlo_config_id_unavailable', members[0]);
    if (unique(names).length !== names.length) fail('mlo_section_ambiguous', members[0]);
    if (desired) {
      if (members.some((member) => !text(member.name, member.ssid, member.broadcast_name, member.essid) ||
          !list(option(member, 'network') ?? member.lan ?? member.network_name).length ||
          !text(member.security_mode, option(member, 'encryption'), member.security, member.security_protocol))) {
        fail('mlo_identity_unavailable', members[0]);
      }
      if (members.some((member) => text(member.mode, 'ap') !== 'ap')) fail('mlo_ap_mode_required', members[0]);
      const eligible = members.filter((member) => disabled(member) === '0');
      const devices = unique(eligible.flatMap((member) => bindings(member, rawRadios))).sort();
      if (devices.length < 2) {
        if (switches.length) fail('mlo_requires_multiple_radios', members[0]);
        singleRadio = members[0];
        warnings.push({ reason: 'mlo_requires_multiple_radios', ap_id: apId(members[0]), sections: names });
        continue;
      }
      verifySecrets(eligible, ssids, warnings);
      const selected = eligible.find((member) => ssids.some((edited) =>
        !Array.isArray(edited.members) && sameRow(member, edited) && flag(edited.mlo))) || eligible[0];
      const saved = eligible.map((member) => ({ section: sectionOf(member),
        device: bindings(member, rawRadios), disabled: disabled(member) }));
      const encoded = JSON.stringify({ version: 1, members: saved });
      if (encoded.length > 4096) fail('mlo_restore_members_invalid', selected);
      const ap = apId(selected);
      const reserved = reservedByAp.get(ap) || new Set();
      const section = mloSectionName(sectionOf(selected), reserved);
      reserved.add(section);
      const name = text(selected.name, selected.ssid, selected.broadcast_name, selected.essid);
      const sections = [{ operation: 'create', section_type: 'wifi-iface', section,
        options: mloSourceOptions(selected, name, encoded),
        list_options: { device: devices } }];
      const id = apId(members[0]);
      if (!byAp.has(id)) byAp.set(id, []);
      byAp.get(id).push(...sections);
      if (byAp.get(id).length > 16) fail('mlo_candidate_sections_limit', members[0]);
    } else {
      const selected = currentMlo[0];
      if (!selected) fail('mlo_restore_members_unavailable', members[0]);
      const section = sectionOf(selected);
      if (!section) fail('mlo_config_id_unavailable', selected);
      handledMloSections.add(section);
      const id = apId(selected);
      if (!byAp.has(id)) byAp.set(id, []);
      byAp.get(id).push({ operation: 'delete', section, options: {} });
    }
  }
  for (const row of mloRows) {
    const section = sectionOf(row);
    if (!section || handledMloSections.has(section)) continue;
    const edits = editsFor(row, ssids);
    const explicit = unique(edits.filter((edit) => edit.mlo != null)
      .map((edit) => flag(edit.mlo)));
    if (explicit.length > 1) fail('mlo_intent_conflict', row);
    const desired = explicit[0] ?? (globalMlo == null ? true : flag(globalMlo));
    if (desired) continue;
    const id = apId(row);
    if (!id || !section) fail('mlo_config_id_unavailable', row);
    if (!byAp.has(id)) byAp.set(id, []);
    byAp.get(id).push({ operation: 'delete', section, options: {} });
  }
  if (!byAp.size && singleRadio) fail('mlo_requires_multiple_radios', singleRadio);
  const targets = [...byAp].map(([ap_id, sections]) => ({ ap_id, sections }));
  return { changed: targets.reduce((sum, target) => sum + target.sections.length, 0), byAp: targets, warnings };
}
