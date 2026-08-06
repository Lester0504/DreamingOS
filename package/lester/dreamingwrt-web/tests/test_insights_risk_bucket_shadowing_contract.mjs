#!/usr/bin/env node
/*
 * 风险卡片三档取值契约（挂真实模块的 summaryCounts，不复制逻辑）。
 *
 * 缺陷形状：:289 原先用 firstNumber(...) 取第三档，而 firstNumber 返回「第一个
 * 有限值」，0 是有限值。后端同时下发 concerning=0 与 high=28，于是 all.concern=0
 * 命中即返回，all.high 永远轮不到，卡片第三档恒为 0。
 *
 * 断言钉的是「第三档 == concerning_or_high」这个关系，而不是某个具体数字：
 * 窗口滚动会让 high 变化，钉死数字明天就是假绿。
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MODULE = path.join(ROOT, 'files/www/dreamingwrt/static/js/insights-flows.js');
const src = fs.readFileSync(MODULE, 'utf8');

/* 从真实模块里截出 countFromObject..summaryCounts 这一段，保证测的是线上代码。 */
function sliceHelpers() {
  const start = src.indexOf('function countFromObject(');
  const end = src.indexOf('function topList(', start);
  assert.ok(start > 0 && end > start, 'summaryCounts 区段未找到，模块结构已变，请更新本契约');
  return src.slice(start, end);
}

const firstNumber = (...values) => {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) return number;
  }
  return 0;
};

const makeSummaryCounts = new Function('state', 'firstNumber', `${sliceHelpers()}\nreturn summaryCounts;`);
const counts = (summary, flows = []) => makeSummaryCounts({ summary, flows }, firstNumber)();

/* 1. 遮蔽本体：concerning=0 且 high>0，且没有合计键（旧后端） */
{
  const c = counts({ all_count_by_risk: { low: 98, suspicious: 0, concerning: 0, concern: 0, high: 31 } });
  assert.equal(c.concern, 31, 'concerning=0 不得再遮蔽 high');
}

/* 2. 有合计键时以合计键为准（当前线上形状） */
{
  const all = { unknown: 264165, low: 98, suspicious: 0, concerning: 0, concern: 0, high: 28, concerning_or_high: 28 };
  const c = counts({ all_count_by_risk: all });
  assert.equal(c.concern, all.concerning_or_high, '第三档应等于 concerning_or_high');
  assert.equal(c.low, all.low, 'low 档不受影响');
}

/* 3. concerning 与 high 同时非零：既不互相覆盖，也不重复计数。
 *    concern 只是 concerning 的别名，不能被再加一次（否则会得到 25 而非 18）。 */
{
  const withCombined = counts({ all_count_by_risk: { concerning: 7, concern: 7, high: 11, concerning_or_high: 18 } });
  assert.equal(withCombined.concern, 18, '有合计键时应取 18');

  const noCombined = counts({ all_count_by_risk: { concerning: 7, concern: 7, high: 11 } });
  assert.equal(noCombined.concern, 18, '无合计键时应显式相加为 18，别名不得重复计数');
}

/* 4. 真实的零仍然是零，且不得退化成「后端未提供」 */
{
  const c = counts({ all_count_by_risk: { low: 0, suspicious: 0, concerning: 0, concern: 0, high: 0, concerning_or_high: 0 } });
  assert.equal(c.concern, 0, '真实零应保持为零');
  assert.equal(c.supported, true, '有风险源时 supported 必须为真');
}

/* 5. 完全没有风险源时仍要能说「后端未提供」，不能假装是 0 条风险 */
{
  const c = counts({});
  assert.equal(c.supported, false, '无风险源时 supported 必须为假');
}

/* 6. null / '' 不得截断候选链（Number(null) 是 0，正是原缺陷的同类形状） */
{
  assert.equal(counts({ all_count_by_risk: { concerning: null, concern: null, high: 14 } }).concern, 14,
    'null concerning 不得遮蔽 high');
  assert.equal(counts({ all_count_by_risk: { low: '', LOW: 9 } }).low, 9,
    "空串不得遮蔽同档别名");
}

/* 7. low / suspicious 的同类加固：某档在前一个 scope 里整键缺失时应继续往后找，
 *    但该 scope 里存在的真实 0 必须胜出，不能被后面的 scope 顶掉。 */
{
  assert.equal(counts({ all_count_by_risk: { suspicious: 3 }, allowed_count_by_risk: { low: 12 } }).low, 12,
    'all 里没有 low 时应回退到 allowed');
  assert.equal(counts({ all_count_by_risk: { low: 0, suspicious: 0 }, allowed_count_by_risk: { low: 12 } }).low, 0,
    'all 里 low 显式为 0 时应保留 0');
}

/* 8. blocked 档叠加时同样不得重复计数 */
{
  const c = counts({
    all_count_by_risk: { concerning_or_high: 4 },
    blocked_count_by_risk: { concerning: 3, concern: 3, high: 2 }
  });
  assert.equal(c.concern, 9, 'blocked 侧应为 concerning+high=5，与 all 侧 4 相加为 9');
}

/* 9. 防回归：第三档不得再退回单条 firstNumber 择一链 */
{
  const line = src.split('\n').find((l) => l.includes('const concern = ') && l.includes('summaryCounts') === false);
  assert.ok(line, 'concern 赋值行未找到');
  assert.ok(!/const concern = firstNumber\(/.test(line),
    '第三档不得再用 firstNumber 择一：0 会遮蔽 high');
}

console.log('insights risk bucket shadowing contract: 9 groups PASS');
