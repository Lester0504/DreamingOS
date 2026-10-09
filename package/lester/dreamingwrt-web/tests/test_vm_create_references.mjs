import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(new URL('../files/www/dreamingwrt/', import.meta.url).pathname);
const output = process.env.VM_BROWSER_OUTPUT;
const pool = '5e36f1ba-268c-4c31-950c-a0c3f027cdbb';
const net = 'dd8fe884-a827-4cbd-8af5-1ee2708a7f65';
const server = http.createServer(async (req,res) => {
  const file = path.join(root, new URL(req.url,'http://localhost').pathname);
  try { const body=await fs.readFile(file);res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.html')?'text/html':'application/octet-stream');res.end(body); }
  catch { res.statusCode=404;res.end(); }
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const browser = await chromium.launch({headless:true,channel:process.env.PLAYWRIGHT_CHANNEL || 'chrome'});
const report=[];
try {
for (const viewport of [{width:1280,height:900},{width:390,height:844}]) {
  const page=await browser.newPage({viewport});const errors=[];const writes=[];let mode='ready',failCreate=true,slow=false,release;
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/dwrt-session-gate.js*',r=>r.fulfill({contentType:'text/javascript',body:''}));
  await page.route('**/api/v1/vm/**',async r=>{
    const req=r.request(),u=new URL(req.url());const suffix=u.pathname.replace('/api/v1/vm','');let data={};let status=200;
    if (req.method()==='POST') writes.push({suffix,body:req.postDataJSON()});
    if (suffix==='/status') data={installed:true,enabled:true,service_state:'ready'};
    else if(suffix==='/capabilities') data={host_arch:'x86_64',capabilities:{create:true,firmware:['uefi'],machines:['q35']}};
    else if(suffix==='/pools' || suffix==='/networks') {
      if(slow && suffix==='/pools') await new Promise(r=>release=r);
      if(mode==='error') return r.fulfill({status:503,json:{ok:false,error:{code:'service_unavailable'}}});
      const isPool=suffix==='/pools';const selected={id:isPool?pool:net,name:isPool?'生产存储池':'default',active:true,available_bytes:107374182400,mode:'nat'};
      // Force real pagination; inactive/name-only rows must never become a selectable reference.
      data=mode==='empty'?{items:[],total:0}:u.searchParams.get('page')==='1'?{items:[{id:'default',name:'invalid',active:true},{id:'11111111-1111-1111-1111-111111111111',name:'inactive',active:false}],total:3}:{items:[selected],total:3};
    } else if(suffix==='/instances/validate') data={valid:true};
    else if(suffix==='/instances' && req.method()==='POST') {
      if(failCreate) {failCreate=false;return r.fulfill({status:503,json:{ok:false,error:{code:'service_unavailable'}}});}
      data={task_id:'created-task'};status=202;
    } else if(suffix==='/tasks/created-task') data={task_id:'created-task',state:'succeeded'};
    else if(suffix==='/instances') data={items:[],total:0};
    return r.fulfill({status,json:{ok:true,data}});
  });
  await page.goto(`http://127.0.0.1:${server.address().port}/app/virtual-machine.html`);
  const open=()=>page.locator('[data-action="new-vm"]').click();
  const advance=async()=>{await page.locator('[name="name"]').fill('draft-kept');await page.locator('[data-wiz="next"]').click();await page.locator('[name="disk_gb"]').fill('31');await page.locator('[data-wiz="next"]').click();};
  const choose=async()=>{await page.locator('[name="pool_id"]').selectOption(pool);await page.locator('[name="network"]').selectOption(net);};
  slow=true;await open();await page.locator('[name="name"]').fill('async-draft');await page.waitForFunction(()=>document.querySelector('.vm-sheet'));
  while(!release) await new Promise(r=>setTimeout(r,10));slow=false;release();
  await advance();await page.waitForFunction(id=>!!document.querySelector(`[name="pool_id"] option[value="${id}"]`),pool);
  assert.equal(await page.locator('[data-wiz="submit"]').isDisabled(),true);
  assert.deepEqual(await page.locator('[name="network"] option').evaluateAll(xs=>xs.map(x=>x.value)),['',net]);
  await choose();assert.equal(await page.locator('[data-wiz="submit"]').isEnabled(),true);
  await page.locator('[data-wiz="references"]').click();await page.waitForFunction(()=>!document.querySelector('[data-wiz="submit"]').disabled);
  assert.equal(await page.locator('[name="pool_id"]').inputValue(),pool);
  await page.locator('[data-wiz="back"]').click();assert.equal(await page.locator('[name="disk_gb"]').inputValue(),'31');await page.locator('[data-wiz="next"]').click();
  const bounds=await page.locator('.vm-sheet').boundingBox();assert(bounds.x>=-1 && bounds.x+bounds.width<=viewport.width+1);
  if(output) await page.screenshot({path:path.join(output,`vm-${viewport.width}.png`)});
  await page.locator('[data-wiz="submit"]').click();await page.locator('[data-wiz-error]:visible').waitFor();
  await page.locator('[data-wiz="submit"]').click();await page.waitForFunction(()=>!document.querySelector('.vm-sheet'));
  const creates=writes.filter(x=>x.suffix==='/instances');assert.equal(creates.length,2);assert.equal(creates[0].body.request_id,creates[1].body.request_id);
  assert.equal(creates[0].body.config.disks[0].pool_id,pool);assert.equal(creates[0].body.config.nics[0].network_id,net);assert.equal(creates[0].body.config.disks[0].capacity_bytes,31*1024**3);
  for(const nextMode of ['empty','error']) {console.log('gate',viewport.width,nextMode);mode=nextMode;await open();await advance();await page.locator('[data-wiz="references"]').waitFor();assert.equal(await page.locator('[data-wiz="submit"]').isDisabled(),true);await page.locator('[data-wiz="submit"]').dispatchEvent('click');assert.equal(writes.filter(x=>x.suffix==='/instances').length,2);await page.locator('.vm-sheet [data-wiz="cancel"]').first().click();await page.waitForFunction(()=>!document.querySelector('.vm-sheet'));}
  assert.deepEqual(errors,[]);report.push({viewport,passed:true,creates:creates.map(x=>x.body),bounds,pageErrors:errors});await page.close();
}
if(output) await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));
console.log('VM browser: UUID pagination, inactive filtering, loading/empty/503 gates, retained draft/selection, retry request_id and two viewport layouts passed');
} finally {await browser.close();server.close();}
