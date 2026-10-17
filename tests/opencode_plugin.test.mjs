import test from 'node:test';
import assert from 'node:assert/strict';
import BabelWake from '../integrations/opencode/babel-wake.mjs';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const sid = 'ses_1234567890AbCdEfGhIjKlMnOp';
const mid = 'msg_babel12345678901234567890123456789012';
async function fixture(options = {}) {
  let tick;
  const interval = globalThis.setInterval;
  globalThis.setInterval = fn => { tick = fn; return { unref() {} }; };
  const calls = [], nativeCalls = [];
  const info = { id:sid, directory:'/synthetic', time:{}, ...options.info };
  const request = {message_id:'synthetic-wake', native_message_id:mid, text:'Babel mailbox notification for worker',reconcile:!!options.reconcile};
  let confirmed = false;
  const client = {
    app:{ log:async () => {} },
    session:{
      get:async () => ({data:info}),
      status:async () => ({data:options.busy ? {[sid]:{type:'busy'}} : {}}),
      promptAsync:async input => {nativeCalls.push(input);return {response:{status:204}};},
      message:async () => options.missing ? {error:'not found'} : {data:{info:{id:mid,sessionID:sid,role:'user'},parts:[{type:'text',text:request.text}]}},
    },
  };
  const bridge=async (action,data) => {
    calls.push([action,data]);
    if(action==='poll')return {notifications:confirmed ? [] : [request]};
    if(action==='confirm')confirmed=true;
    return {};
  };
  const hooks=await BabelWake({client,directory:'/synthetic'},{bridge});
  globalThis.setInterval=interval;
  const event=()=>hooks.event({event:{type:'session.created',properties:{info}}});
  const runTick=async ()=>{ tick(); await new Promise(resolve=>setImmediate(resolve)); };
  return {hooks,event,runTick,calls,nativeCalls};
}

test('native creation enrolls exact session, idle wake confirmed once, no permission overrides',async()=>{
  const f=await fixture();await f.event();await f.runTick();await f.runTick();
  assert.equal(f.calls[0][0],'event');assert.equal(f.calls[0][1].session_id,sid);
  assert.equal(f.nativeCalls.length,1);
  assert.ok(f.nativeCalls[0].signal instanceof AbortSignal);
  const {signal,...nativeRequest}=f.nativeCalls[0];
  assert.deepEqual(nativeRequest,{path:{id:sid},body:{messageID:mid,parts:[{type:'text',text:'Babel mailbox notification for worker'}]}});
  assert.equal(f.calls.filter(c=>c[0]==='confirm').length,1);
  await f.hooks.dispose();
});

test('busy, subagent, archived and other-directory sessions never admit wake',async()=>{
  for(const options of [{busy:true},{info:{parentID:'ses_parent'}},{info:{time:{archived:1}}},{info:{directory:'/other'}}]){
    const f=await fixture(options);await f.event();await f.runTick();assert.equal(f.nativeCalls.length,0);await f.hooks.dispose();
  }
});

test('uncertain native admission is reconciled, never resent, only confirmed exact message',async()=>{
  const f=await fixture({reconcile:true});await f.event();await f.runTick();assert.equal(f.nativeCalls.length,0);assert.equal(f.calls.at(-1)[0],'confirm');await f.hooks.dispose();
  const missing=await fixture({reconcile:true,missing:true});await missing.event();await missing.runTick();await missing.runTick();assert.equal(missing.nativeCalls.length,0);assert.equal(missing.calls.filter(c=>c[0]==='confirm').length,0);await missing.hooks.dispose();
});

test('native prompts carry IDs without text persistence; Babel wakes are never activity',async()=>{
  const f=await fixture();
  await f.hooks['chat.message']({sessionID:sid},{message:{id:'msg_real12345678'},parts:[{type:'text',text:'Implement feature'},{type:'text',text:'synthetic',synthetic:true}]});
  assert.deepEqual(f.calls[0],['event',{session_id:sid,hook_event_name:'chat.message',message_id:'msg_real12345678',prompt:'Implement feature'}]);
  await f.hooks['chat.message']({sessionID:sid},{message:{id:mid},parts:[{type:'text',text:'Babel wake'}]});
  assert.equal(f.calls.length,1);
  const output={system:[]};await f.hooks['experimental.chat.system.transform']({sessionID:sid},output);assert.match(output.system[0],/native babel tool/);assert.doesNotMatch(output.system[0],/account_session_helper.py|WORKER-INSTRUCTIONS.md/);assert.match(output.system[0],new RegExp(sid));
  await f.hooks.dispose();await f.runTick();assert.equal(f.nativeCalls.length,0);
});

test('hanging native reads time out and a healthy session progresses in parallel',async()=>{
  const slow='ses_slow12345678', healthy='ses_healthy12345678';
  let tick, hang=false, abortSignal, polls=0;
  const original=globalThis.setInterval;
  globalThis.setInterval=fn=>{tick=fn;return {unref(){}};};
  const client={app:{log:async()=>({})},session:{
    get:async request=>{
      if(hang && request.path.id===slow){abortSignal=request.signal;return new Promise(()=>{});}
      return {data:{id:request.path.id,directory:'/synthetic',time:{}}};
    },status:async()=>({data:{}}),
  }};
  const hooks=await BabelWake({client,directory:'/synthetic'},{nativeTimeoutMs:10,bridge:async(action,data)=>{
    if(action==='poll'){assert.equal(data.session_id,healthy);polls++;}
    return {notifications:[]};
  }});
  globalThis.setInterval=original;
  for(const id of [slow,healthy])await hooks.event({event:{type:'session.created',properties:{info:{id}}}});
  hang=true;tick();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(polls,1); // Healthy peer finishes before the slow read's deadline.
  await new Promise(resolve=>setTimeout(resolve,25));assert.equal(abortSignal.aborted,true);
  tick();await new Promise(resolve=>setImmediate(resolve));assert.equal(polls,2);await hooks.dispose();
});

test('mutating native timeout leaves intent pending and never confirms absent admission',async()=>{
  let tick, sent=0, confirmed=0, reconcile=false;
  const original=globalThis.setInterval;
  globalThis.setInterval=fn=>{tick=fn;return {unref(){}};};
  const client={app:{log:async()=>({})},session:{
    get:async()=>({data:{id:sid,directory:'/synthetic',time:{}}}),status:async()=>({data:{}}),
    promptAsync:async()=>{sent++;return new Promise(()=>{});},message:async()=>({error:'not found'}),
  }};
  const hooks=await BabelWake({client,directory:'/synthetic'},{nativeTimeoutMs:10,bridge:async(action)=>{
    if(action==='poll'){const result={notifications:[{message_id:'synthetic-wake',native_message_id:mid,text:'Babel notification',reconcile}]};reconcile=true;return result;}
    if(action==='confirm')confirmed++;
    return {};
  }});
  globalThis.setInterval=original;
  await hooks.event({event:{type:'session.created',properties:{info:{id:sid}}}});
  tick();await new Promise(resolve=>setTimeout(resolve,25));tick();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(sent,1);assert.equal(confirmed,0);await hooks.dispose();
});

test('native disposal clears polling and an in-flight read cannot start mailbox work',async()=>{
  let tick, pending=false, finishRead, polls=0, reads=0;
  const original=globalThis.setInterval;
  globalThis.setInterval=fn=>{tick=fn;return {unref(){}};};
  const info={id:sid,directory:'/synthetic',time:{}};
  const client={app:{log:async()=>({})},session:{
    get:async()=>{reads++;if(pending)return new Promise(resolve=>{finishRead=()=>resolve({data:info});});return {data:info};},
    status:async()=>({data:{}}),
  }};
  const hooks=await BabelWake({client,directory:'/synthetic'},{bridge:async action=>{if(action==='poll')polls++;return {notifications:[]};}});
  globalThis.setInterval=original;
  await hooks.event({event:{type:'session.created',properties:{info}}});
  pending=true;tick();await new Promise(resolve=>setImmediate(resolve));assert.ok(finishRead);
  await hooks.dispose();finishRead();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(polls,0);const before=reads;
  tick();await new Promise(resolve=>setImmediate(resolve));assert.equal(reads,before);
});


test('session-bound native tool obeys permission before helper work and rejects caller routing',async()=>{
  const f=await fixture();await f.event();
  const calls=f.calls.length;let asked=[];
  const context={sessionID:sid,directory:'/synthetic',abort:new AbortController().signal,
    ask:async request=>{asked.push(request);}};
  await f.hooks.tool.babel.execute({operation:'list_contacts',arguments:{}},context);
  assert.equal(asked[0].permission,'babel');assert.deepEqual(asked[0].patterns,['list_contacts']);
  assert.deepEqual(f.calls.at(-1),['tool',{session_id:sid,operation:'list_contacts',arguments:{}}]);
  const count=f.calls.length;
  context.ask=async()=>{throw new Error('Native permission denied');};
  await assert.rejects(f.hooks.tool.babel.execute({operation:'stage_message',arguments:{text:'test'}},context),/permission denied/);
  assert.equal(f.calls.length,count);
  await assert.rejects(f.hooks.tool.babel.execute({operation:'list_contacts',arguments:{},session_id:'another'},context),/routing/);
  await assert.rejects(f.hooks.tool.babel.execute({operation:'list_contacts',arguments:{}},{...context,sessionID:'ses_other12345678'}),/observed/);
  await assert.rejects(f.hooks.tool.babel.execute({operation:'bootstrap',arguments:{}},context),/routing/);
  assert.equal(f.calls.length,count);await f.hooks.dispose();
});


test('native bridge subprocess uses trusted project directory instead of server launch cwd',async()=>{
  const root=await mkdtemp(join(tmpdir(),'babel-native-cwd-'));
  const workspace=join(root,'actual-session-workspace');await mkdir(workspace);
  await writeFile(join(root,'python3'),`#!${process.execPath}\nprocess.stdin.resume();process.stdin.on('end',()=>process.stdout.write(JSON.stringify({cwd:process.cwd()})));\n`,{mode:0o700});
  const originalPath=process.env.PATH;const originalInterval=globalThis.setInterval;
  process.env.PATH=root+':'+originalPath;
  globalThis.setInterval=()=>({unref(){}});
  try{
    const client={app:{log:async()=>({})},session:{get:async()=>({data:{id:sid,directory:workspace,time:{}}})}};
    const hooks=await BabelWake({client,directory:workspace});
    await hooks.event({event:{type:'session.created',properties:{info:{id:sid}}}});
    const output=JSON.parse(await hooks.tool.babel.execute({operation:'stage_report',arguments:{}},{sessionID:sid,directory:workspace,ask:async()=>{}}));
    assert.equal(output.cwd,workspace);assert.notEqual(output.cwd,process.cwd());await hooks.dispose();
  }finally{process.env.PATH=originalPath;globalThis.setInterval=originalInterval;await rm(root,{recursive:true,force:true});}
});


test('stage_message contract rejects message aliases before helper work without silently renaming',async()=>{
  const f=await fixture();await f.event();const before=f.calls.length;let asks=0;
  const context={sessionID:sid,directory:'/synthetic',ask:async()=>{asks++;}};
  for(const args of [{message:'wrong body key'},{text:'correct',message:'ambiguous'}]){
    await assert.rejects(f.hooks.tool.babel.execute({operation:'stage_message',arguments:args},context),/requires arguments.text/);
  }
  assert.equal(asks,0);assert.equal(f.calls.length,before);
  const args={recipient:'synthetic.ember',conversation_id:'synthetic-conversation',message_id:'synthetic-stable-message',text:'exact body'};
  await f.hooks.tool.babel.execute({operation:'stage_message',arguments:args},context);
  assert.deepEqual(f.calls.at(-1),['tool',{session_id:sid,operation:'stage_message',arguments:args}]);
  assert.equal(asks,1);assert.match(f.hooks.tool.babel.description,/text, message_id/);await f.hooks.dispose();
});
