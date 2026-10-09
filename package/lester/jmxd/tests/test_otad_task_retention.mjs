// Exercise the actual TaskCenter consumer against actual SQLite OTA projections.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {execFileSync} from 'node:child_process';
const rows = execFileSync(process.argv[2], {encoding:'utf8'}).trim().split('\n').map(JSON.parse);
assert.deepEqual(rows.map(x=>x.data.state), ['in_progress','cooldown','success','failed','rolled_back','success']);
assert.equal(rows[0].data.completed_at, 0);
assert.equal(rows[0].data.started_at, 100000, 'started_at must come from journal started_at, not created_at');
const context = {window:{},Date,Map,Set};
vm.createContext(context);
vm.runInContext(fs.readFileSync(new URL('../../dreamingwrt-web/files/www/dreamingwrt/static/js/task-center.js',import.meta.url),'utf8'),context);
const source = {key:'ota.task',label:'OTA'};
for (const row of rows.slice(2,5)) {
    let now = 200000000;
    const store = new context.window.DWRTTaskCenterStore(()=>now);
    store.accept(source,row);
    assert.equal(store.list().length,1);
    assert.equal(store.list()[0].finishedAt,199000000);
    now = 199000000 + 86400000;
    assert.equal(store.list().length,1, 'terminal task retained through 24h boundary');
    now++;
    assert.equal(store.list().length,0);
    store.accept(source,row);
    assert.equal(store.list().length,0, 'polling old journal result must not extend retention');
    const reloaded = new context.window.DWRTTaskCenterStore(()=>now);
    reloaded.accept(source,row);
    assert.equal(reloaded.list().length,0, 'page reload must not resurrect expired journal task');
}
const fresh = new context.window.DWRTTaskCenterStore(()=>200000000);
fresh.accept(source,rows[5]);
assert.equal(fresh.list().length,0,'old completion hidden immediately on first fetch');
fresh.accept(source,rows[0]);
assert.equal(fresh.list().length,1,'old start time does not hide a still active task');
console.log('PASS: real OTA SQLite projection and TaskCenter 24h boundary, polling, reload, failed/rolled_back and active retention');
