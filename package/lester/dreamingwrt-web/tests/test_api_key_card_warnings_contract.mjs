/*
 * API-Key 管理卡片契约测试。
 *
 * 钉住 2026-08-07/Handoff/Acceptance-to-Front-api-key-card-with-warnings.md
 * 里用户点名要求的几条，以免日后重构时被静默改掉：
 *   1. 创建流程必须有数据安全/破坏性操作的风险告知，且不硬编码能力清单；
 *   2. 长期 key 必须有「建议定期更换」提示，列表能看出已使用天数；
 *   3. IP 白名单可填可空；
 *   4. 不出现数量上限文案；
 *   5. 明文 key 只显示一次，且不落任何前端持久化；
 *   6. 权限档里没有终端/shell 选项，也没有后端会拒的 admin 档；
 *   7. 破坏性操作的边界如实告知（后端硬禁，前端不画勾不上的开关）。
 *
 * 走源码契约而不是 DOM：该模块 `mount()` 依赖 document/portal/ui-kit 一整套宿主，
 * 在 node 里立起来的成本远高于它能验到的东西，而这几条要求本身是「文案与字段在不在」，
 * 源码断言足以钉住。真实渲染由上机核验负责（见交接单接管记录）。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';

const path = new URL('../files/www/dreamingwrt/plugins/native/system-users.js', import.meta.url);
const src = fs.readFileSync(path, 'utf8');

/* 1. 风险告知：创建抽屉里要同时讲到数据安全与破坏性后果。 */
assert.match(src, /改配置、下发规则、删除数据/, '创建抽屉缺少写操作后果的告知');
assert.match(src, /按最小权限选档/, '创建抽屉缺少最小权限建议');

/* 2. 定期更换提示 + 已使用天数。 */
assert.match(src, /建议定期更换/, '缺少「建议定期更换」提示');
assert.match(src, /泄漏/, '更换提示未说明泄漏风险');
assert.match(src, /const API_KEY_ROTATE_AFTER_DAYS = \d+/, '缺少更换天数门槛常量');
assert.match(src, /function apiKeyAgeDays\(/, '缺少已使用天数计算');
assert.match(src, /function apiKeyRotationHint\(/, '缺少列表级更换提醒');
/* 提醒要柔和：不得做成强制弹窗（用户明确要求分寸）。 */
assert.doesNotMatch(src, /window\.confirm\([^)]*密钥/, '更换提醒不得用强制弹窗');

/* 3. IP 白名单可填可空。 */
assert.match(src, /data-api-key-draft="allow_ips"/, '缺少来源 IP 输入项');
assert.match(src, /留空表示不限制来源/, 'IP 白名单未说明留空即不限制');
/* 留空时不提交该字段，交给后端默认「不限制」。 */
assert.match(src, /if \(allowIps\) body\.allow_ips = allowIps;/, '留空的 allow_ips 不应提交');

/* 4. 不设数量上限，也不显示剩余额度。 */
assert.doesNotMatch(src, /还可创建/, '不应出现数量上限相关文案');
assert.doesNotMatch(src, /密钥数量上限|已达上限/, '不应出现数量上限相关文案');

/* 5. 明文只出现一次，且不写入任何前端持久化。 */
assert.match(src, /唯一一次显示密钥明文/, '缺少「只显示一次」的明确告知');
/* 关抽屉时必须清掉明文，否则「只显示一次」不成立。 */
assert.match(src, /state\.apiKeys\.created = null;/, '关闭抽屉未清除明文');
const persistCalls = src.match(/(localStorage|sessionStorage)\.setItem\([^)]*\)/g) || [];
for (const call of persistCalls) {
  assert.doesNotMatch(call, /api.?key|plaintext/i, `明文/密钥不得写入前端持久化：${call}`);
}
/* 明文只在创建后的一次性展示里渲染，不进列表行。 */
assert.doesNotMatch(src, /data-system-api-key-row[\s\S]{0,400}plaintext/, '列表行不得回显明文');

/* 6. 权限档：两档、无 admin、无终端/shell。 */
const tierLabels = src.match(/const API_KEY_TIER_LABELS = \{[^}]*\}/);
assert.ok(tierLabels, '缺少档位标签表');
assert.doesNotMatch(tierLabels[0], /admin/, '档位表不得含 admin（后端会拒）');
assert.doesNotMatch(tierLabels[0], /read_write/, 'read_write 不是后端接受的档位');
assert.match(tierLabels[0], /control/, '缺少后端真实存在的 control 档');
/* 档位选项优先用后端下发的枚举，避免前端自己维护一张会漂移的表。 */
assert.match(src, /state\.apiKeys\.capabilities\.tiers/, '档位选项未优先取后端能力位');
/* 终端/ttyd 不得成为可勾选项（用户底线）。 */
const tierChoiceBlock = src.slice(src.indexOf('function apiKeyTierChoices'), src.indexOf('function apiKeyCreateBlockedReason'));
assert.doesNotMatch(tierChoiceBlock, /terminal|ttyd|shell/i, '权限档选项里不得出现终端/shell');

/* 7. 破坏性边界如实告知，且不画一个后端不接受的开关。 */
assert.match(src, /API_KEY_HARD_LIMIT_TEXT/, '缺少破坏性/shell 边界告知');
assert.match(src, /恢复出厂/, '边界告知未点明恢复出厂');
assert.match(src, /重启/, '边界告知未点明重启');
/* 后端 g_api_key_forbidden[] 硬禁这些路由，没有 allow_destructive 字段可提交，
 * 所以前端不得提交该键，也不得画一个勾了不生效的复选框。 */
assert.doesNotMatch(src, /data-api-key-draft="allow_destructive"/, '后端无 allow_destructive 字段，不应提供该开关');
assert.doesNotMatch(src, /body\.allow_destructive/, '不得向后端提交 allow_destructive');

/* 创建请求体只放后端真的会读的键。 */
const saveStart = src.indexOf('function saveApiKey');
assert.ok(saveStart > 0, '找不到 saveApiKey');
const saveBlock = src.slice(saveStart, saveStart + 1800);
assert.match(saveBlock, /name:/, '创建请求缺少 name');
assert.match(saveBlock, /tier:/, '创建请求缺少 tier');
assert.match(saveBlock, /expires_at:/, '创建请求缺少 expires_at');

console.log('api-key card warnings contract: OK');
