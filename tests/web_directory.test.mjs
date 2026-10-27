import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../web/app.js', import.meta.url), 'utf8');
const coordinator = 'owner_a.dots.coordinator';
const first = 'owner_a.codex.run_01';
const second = 'owner_a.codex.run_02';
const cid = 'directory-ui-chat';

class Element {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.handlers = {}; this.hidden = false; this._value = null; this.selectedIndex = 0; }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren() { this.children = []; this._value = null; this.selectedIndex = 0; }
  addEventListener(name, action) { this.handlers[name] = action; }
  get value() { return this._value ?? this.children[this.selectedIndex]?.value ?? ''; }
  set value(value) { this._value = value; }
  querySelector(tag) { return this.children.find(child => child.tag === tag); }
  scrollIntoView() {}
  focus() {}
}
const descendants = node => [node, ...node.children.flatMap(descendants)];

async function fixture() {
  const ids = ['source','recipient','inbox_agent','conversation_id','compose','messages','list_title','older','notice',
    'refresh','receive','copy','copy_text','close_handoff','handoff','text','reply_to','conversation_label',
    'source_identity','recipient_identity','conversation_identity','inbox_identity'];
  const elements = Object.fromEntries(ids.map(id => [id, new Element(['source','recipient','inbox_agent','conversation_id'].includes(id) ? 'select' : 'div')]));
  elements.compose.appendChild(new Element('button'));
  const state = {
    session: {csrf: 'synthetic-csrf', agents: [coordinator,first,second], conversations: [cid], directory: {
      [coordinator]: 'Coordinator · dots · owner_a',
      [first]: 'Juniper · codex · Build worker · owner_a [#11111111]',
      [second]: 'Juniper · codex · Build worker · owner_a [#22222222]'}},
    messages: [first,second].map((recipient,index) => ({id:'ui-draft-'+index, source:coordinator,recipient,
      status:'draft',text:'Same selected text',hops:1,provenance:'manual',conversation_id:cid})),
    calls: [],
  };
  const context = vm.createContext({document: {getElementById: id => elements[id], createElement: tag => new Element(tag)},
    TextEncoder, crypto: {randomUUID: () => 'synthetic-ui-id-'+state.calls.length}, window: {confirm: () => true},
    fetch: async (path, options) => {
      const body = options?.body ? JSON.parse(options.body) : undefined;
      state.calls.push({path,body});
      let result;
      if (path === '/api/session') result = structuredClone(state.session);
      else if (path.startsWith('/api/history')) result = {messages: structuredClone(state.messages)};
      else if (path === '/api/stage') result = {message: body, duplicate: false};
      else if (path === '/api/approve') result = {message: state.messages.find(row => row.id === body.message_id)};
      else throw new Error('Unexpected route '+path);
      return {ok:true, json:async () => result};
    }});
  vm.runInContext(source, context);
  await new Promise(setImmediate);
  return {state,e:elements,context};
}

test('duplicate worker labels stay distinct in compose, approval cards, and inspectable identity details', async () => {
  const {state,e} = await fixture();
  for (const field of ['source','recipient','inbox_agent']) {
    const one = e[field].children.find(option => option.value === first);
    const two = e[field].children.find(option => option.value === second);
    assert.notEqual(one.textContent,two.textContent);
    assert.equal(one.title,'Canonical identity: '+first);
    assert.equal(two.title,'Canonical identity: '+second);
  }
  e.recipient.value = second; e.recipient.handlers.change();
  assert.equal(e.recipient_identity.textContent,'To: '+second);
  assert.equal(e.recipient.title,'Canonical identity: '+second);
  const cards = e.messages.children;
  const headings = cards.map(card => card.children.find(node => node.tag === 'strong'));
  assert.notEqual(headings[0].textContent,headings[1].textContent);
  for (let index=0;index<2;index++) {
    const details = cards[index].children.find(node => node.tag === 'details');
    assert.ok(descendants(details).some(node => node.textContent === 'To: '+[first,second][index]));
    assert.ok(descendants(details).some(node => node.textContent === 'Conversation: '+cid));
  }
  const approve = descendants(cards[1]).find(node => node.tag === 'button' && node.textContent === 'Approve into local queue');
  await approve.handlers.click();
  assert.equal(state.calls.find(call => call.path === '/api/approve').body.message_id,'ui-draft-1');
});

test('refresh and rename retain the explicitly selected canonical sender and recipient when staging', async () => {
  const {state,e} = await fixture();
  e.source.value = coordinator; e.recipient.value = second; e.text.value = 'Selected text';
  state.session.directory[second] = 'Cypress · codex · Build worker · owner_a';
  await e.compose.handlers.submit({preventDefault(){},target:e.compose});
  const sent = state.calls.find(call => call.path === '/api/stage').body;
  assert.equal(sent.source,coordinator); assert.equal(sent.recipient,second);
  assert.equal(sent.conversation_id,cid); assert.equal(sent.text,'Selected text');
  assert.equal(e.recipient_identity.textContent,'To: '+second);
  assert.equal(e.recipient.children.find(option => option.value === second).textContent,state.session.directory[second]);
});

test('inactive selected worker remains visibly unavailable and is never replaced with its namesake', async () => {
  const {state,e,context} = await fixture();
  e.recipient.value = second;
  state.session.agents = [coordinator,first];
  await vm.runInContext('reload()',context);
  assert.equal(e.recipient.value,second);
  const retired = e.recipient.children.find(option => option.value === second);
  assert.equal(retired.disabled,true); assert.match(retired.textContent,/^Unavailable:/);
  assert.equal(e.recipient_identity.textContent,'To: '+second);
  e.text.value = 'Selected text';
  await e.compose.handlers.submit({preventDefault(){},target:e.compose});
  assert.equal(state.calls.filter(call => call.path === '/api/stage').length,0);
  assert.match(e.notice.textContent,/Selected identity is unavailable/);
  const headings = e.messages.children.map(card => card.children.find(node => node.tag === 'strong').textContent);
  assert.notEqual(headings[0],headings[1]);
});

test('reply to an inactive worker keeps the exact canonical route inspectable and cannot substitute another worker', async () => {
  const {state,e,context} = await fixture();
  state.session.agents = [coordinator,first]; state.messages[1].status = 'queued';
  await vm.runInContext('reload()',context);
  const reply = descendants(e.messages.children[1]).find(node => node.tag === 'button' && node.textContent === 'Draft an explicit reply');
  await reply.handlers.click();
  assert.equal(e.source.value,second); assert.equal(e.recipient.value,coordinator);
  assert.equal(e.source_identity.textContent,'From: '+second);
  assert.equal(e.source.children.find(option => option.value === second).disabled,true);
  assert.equal(e.reply_to.value,'ui-draft-1');
  e.text.value = 'Reply selected text';
  await e.compose.handlers.submit({preventDefault(){},target:e.compose});
  assert.equal(state.calls.filter(call => call.path === '/api/stage').length,0);
});
