import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../files/www/dreamingwrt/plugins/native/wifi-mlo-write.js', import.meta.url), 'utf8');
const { buildManagedMloPlan: plan, parseMloMembers, MLO_MEMBERS_OPTION, EMPTY_MLO_MEMBERS } =
  await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

function fixture(ap = 'ap_a', count = 3) {
  const rawRadios = Array.from({ length: count }, (_, i) => ({
    id: `ap:${ap}:radio:phy0r${i}`, local_id: `phy0r${i}`, config_id: `radio${i}`,
    ap_id: ap, source: 'managed_ap', configuration_source: 'apd_desired_read_only'
  }));
  const rawSsids = rawRadios.map((radio, i) => ({
    id: `ap:${ap}:ssid:wlan${i}`, local_id: `wlan${i}`, config_id: `wifi${i}`,
    ap_id: ap, source: 'managed_ap', radio_id: radio.id, name: 'Existing WiFi',
    network: 'lan', encryption: 'sae+ccmp', security_mode: 'sae+ccmp',
    mode: 'ap', enabled: true, mlo: false, password_present: true
  }));
  return { rawSsids, rawRadios, ssids: rawSsids.map((row) => ({ ...row, id: row.local_id, password: '' })), radios: structuredClone(rawRadios) };
}

function apply(input, result) {
  const copy = structuredClone(input);
  for (const { ap_id, sections } of result.byAp) for (const section of sections) {
    const index = copy.rawSsids.findIndex((item) => item.ap_id === ap_id && item.config_id === section.section);
    if (section.operation === 'delete') { assert.ok(index >= 0); copy.rawSsids.splice(index, 1); continue; }
    if (section.operation === 'create') {
      assert.equal(index, -1);
      copy.rawSsids.push({ id: `ap:${ap_id}:ssid:${section.section}`, local_id: section.section, config_id: section.section,
        ap_id, source: 'managed_ap', radio_id: section.list_options.device[0], ...section.options,
        device: [...section.list_options.device], enabled: true, password_present: true });
    }
  }
  copy.ssids = copy.rawSsids.map((row) => ({ ...row, id: row.local_id, password: '' }));
  return copy;
}

const reason = (code) => (error) => { assert.equal(error.reason, code); return true; };

test('global enable creates one independent MLO SSID', () => {
  const input = fixture();
  const result = plan({ ...input, globalMlo: true });
  assert.equal(result.changed, 1);
  const section = result.byAp[0].sections[0];
  assert.deepEqual([section.operation, section.section, section.section_type], ['create', 'wifi0_mlo', 'wifi-iface']);
  assert.equal(section.options.ssid, 'Existing WiFi-MLO');
  assert.deepEqual(section.list_options.device, ['radio0', 'radio1', 'radio2']);
  assert.equal(parseMloMembers(section.options[MLO_MEMBERS_OPTION]).length, 3);
  assert.doesNotMatch(JSON.stringify(result), /password|known-passphrase|dreamingwrt_key_source/);
});

test('disable removes only the independent MLO section', () => {
  const input = fixture();
  const enabled = apply(input, plan({ ...input, globalMlo: true }));
  const result = plan({ ...enabled, globalMlo: false });
  assert.deepEqual(result.byAp[0].sections, [{ operation: 'delete', section: 'wifi0_mlo', options: {} }]);
  const restored = apply(enabled, result);
  assert.deepEqual(restored.rawSsids.map((row) => row.config_id).sort(), ['wifi0', 'wifi1', 'wifi2']);
  assert.equal(plan({ ...restored, globalMlo: false }).changed, 0);
});

test('per-SSID switch still creates a separate MLO section', () => {
  const input = fixture(); input.ssids[1].mlo = true;
  const result = plan({ ...input, globalMlo: false });
  assert.equal(result.byAp[0].sections[0].section, 'wifi1_mlo');
});

test('same names on separate APs remain separate', () => {
  const a = fixture('ap_a'); const b = fixture('ap_b');
  const input = Object.fromEntries(Object.keys(a).map((key) => [key, [...a[key], ...b[key]]]));
  const result = plan({ ...input, globalMlo: true });
  assert.deepEqual(result.byAp.map((item) => [item.ap_id, item.sections.length]), [['ap_a', 1], ['ap_b', 1]]);
});

test('single radio cannot enable MLO', () => {
  const input = fixture('ap_a', 1);
  assert.throws(() => plan({ ...input, globalMlo: true }), reason('mlo_requires_multiple_radios'));
});

test('groups do not cross identity fields', () => {
  for (const [field, value] of [['name', 'Other'], ['network', 'guest'], ['encryption', 'psk2+ccmp'], ['pmf', 'optional'], ['vlan', '20']]) {
    const input = fixture('ap_a', 2); input.rawSsids[1][field] = value;
    assert.throws(() => plan({ ...input, globalMlo: true }), reason('mlo_requires_multiple_radios'));
  }
});

test('different known keys reject without exposing secrets', () => {
  const input = fixture(); input.rawSsids[0].key = 'known-passphrase'; input.rawSsids[1].key = 'different-passphrase';
  assert.throws(() => plan({ ...input, globalMlo: true }), reason('mlo_credentials_differ'));
});

test('typed password changes are rejected', () => {
  const input = fixture(); input.ssids[0].password = 'known-passphrase';
  assert.throws(() => plan({ ...input, globalMlo: true }), reason('mlo_password_change_not_supported'));
});

test('plans are empty when unchanged and idempotent after enable', () => {
  assert.deepEqual(plan(), { changed: 0, byAp: [], warnings: [] });
  const input = fixture(); const enabled = apply(input, plan({ ...input, globalMlo: true }));
  assert.equal(plan({ ...enabled, globalMlo: true }).changed, 0);
});

test('runtime PHY ids resolve only inside the same AP', () => {
  const input = fixture('ap_a', 2); input.rawSsids[1].radio_id = 'phy0r1';
  assert.deepEqual(plan({ ...input, globalMlo: true }).byAp[0].sections[0].list_options.device, ['radio0', 'radio1']);
  input.rawRadios[1].ap_id = 'ap_b';
  assert.throws(() => plan({ ...input, globalMlo: true }), reason('mlo_radio_binding_unavailable'));
});

test('missing config ids are rejected', () => {
  const input = fixture(); delete input.rawSsids[0].config_id;
  assert.throws(() => plan({ ...input, globalMlo: true }), reason('mlo_config_id_unavailable'));
});

test('desired rows use local_id as UCI section name', () => {
  const input = fixture();
  input.rawSsids.forEach((row) => { delete row.config_id; row.local_id = `wifi_${row.local_id}`; });
  input.rawRadios.forEach((row) => { delete row.config_id; row.local_id = `radio_${row.local_id}`; });
  input.rawSsids.forEach((row, index) => { row.radio_id = input.rawRadios[index].id; });
  input.rawSsids.forEach((row) => { row.configuration_source = 'apd_desired_read_only'; });
  const result = plan({ ...input, globalMlo: true });
  assert.equal(result.byAp[0].sections[0].section, 'wifi_wlan0_mlo');
});

test('names already ending in -MLO receive a distinct suffix', () => {
  const input = fixture(); input.rawSsids.forEach((row) => { row.name = 'Already-MLO'; });
  assert.equal(plan({ ...input, globalMlo: true }).byAp[0].sections[0].options.ssid, 'Already-MLO2');
});

test('restoration records stay bounded and secret-free', () => {
  assert.deepEqual(parseMloMembers(EMPTY_MLO_MEMBERS), []);
  assert.throws(() => parseMloMembers('{"version":1,"members":[{"section":"wifi0","device":["radio0"],"disabled":"0","password":"secret"}]}'), reason('mlo_restore_members_invalid'));
});
