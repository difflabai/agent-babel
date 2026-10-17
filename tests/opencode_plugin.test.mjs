import test from 'node:test';
import assert from 'node:assert/strict';
import BabelWake from '../integrations/opencode/babel-wake.mjs';

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
  const output={system:[]};await f.hooks['experimental.chat.system.transform']({sessionID:sid},output);assert.match(output.system[0],/--client' 'opencode/);assert.match(output.system[0],new RegExp(sid));
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
