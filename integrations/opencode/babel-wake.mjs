// OpenCode 1.18.33 native server plugin. No npm dependencies or service units.
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import { join } from 'node:path';

function helper(action, data) {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', [join(homedir(), '.local/lib/agent-babel/opencode_account_bridge.py'),
      '--account-file', join(homedir(), '.config/255bits/agent-babel/trusted-account.json'), '--action', action],
      { stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '';
    const timer = setTimeout(() => child.kill(), 35000);
    child.stdout.on('data', chunk => { output += chunk; if (output.length > 65536) child.kill(); });
    child.stderr.resume(); // Never forward private helper/provider errors into a transcript.
    child.on('error', reject);
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error('Babel helper unavailable; pending evidence retained.'));
      try { resolve(JSON.parse(output)); } catch { reject(new Error('Invalid Babel helper response.')); }
    });
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify(data));
  });
}

export default async function BabelWake({ client, directory }, options = {}) {
  // Exported runtime injection is useful for contract tests; ordinary native
  // loading always uses the local Python bridge and real SDK client.
  const call = options.bridge ?? helper;
  const timeoutMs = options.nativeTimeoutMs ?? 10000;
  const controllers = new Set();
  async function nativeRequest(method, request = {}) {
    const controller = new AbortController();
    controllers.add(controller);
    let timer;
    try {
      return await Promise.race([method({ ...request, signal: controller.signal }),
        new Promise((resolve, reject) => { timer = setTimeout(() => {
          controller.abort(); reject(new Error('Native request timed out; reconcile exact admission ID.'));
        }, timeoutMs); })]);
    } finally { clearTimeout(timer); controllers.delete(controller); }
  }
  const sdk = (method, request) => nativeRequest(client.session[method].bind(client.session), request);
  const sessions = new Set();
  let disposed = false;
  let running = false;
  let warned = false;
  const warning = async () => {
    if (warned) return;
    warned = true;
    await nativeRequest(client.app.log.bind(client.app), { body: { service: 'babel', level: 'warn',
      message: 'Babel wake unavailable; pending evidence retained. Check account enrollment and integration logs.' } }).catch(() => {});
  };
  async function observed(sid) {
    const response = await sdk('get', { path: { id: sid } });
    const info = response.data;
    if (response.error || info?.id !== sid || info.parentID || info.time?.archived || info.directory !== directory) return;
    return info;
  }
  async function deliver(sid, status) {
    if (disposed) return;
    if (status[sid] && status[sid].type !== 'idle') return;
    if (!await observed(sid)) { sessions.delete(sid); return; }
    if (disposed) return;
    const result = await call('poll', { session_id: sid });
    for (const request of result.notifications ?? []) {
      if (disposed) return;
      if (!request.reconcile) {
        const admitted = await sdk('promptAsync', { path: { id: sid }, body: {
          messageID: request.native_message_id, parts: [{ type: 'text', text: request.text }],
        } });
        if (admitted.error) throw new Error('Native admission uncertain');
      }
      // HTTP 204 is insufficient: verify the exact persisted native message.
      const native = await sdk('message', { path: { id: sid, messageID: request.native_message_id } });
      const message = native.data;
      if (native.error || message?.info?.id !== request.native_message_id || message.info.sessionID !== sid ||
          message.info.role !== 'user' || message.parts.filter(p => p.type === 'text').map(p => p.text).join('') !== request.text) {
        await warning(); // Next tick reconciles; it will never resubmit.
        continue;
      }
      await call('confirm', { session_id: sid, ...request });
    }
  }
  async function tick() {
    if (disposed || running || !sessions.size) return;
    running = true;
    try {
      const response = await sdk('status');
      if (response.error || !response.data) throw new Error('Native status unavailable');
      const batch = [...sessions].slice(0, 128);
      await Promise.all(Array.from({ length: Math.min(4, batch.length) }, async () => {
        while (!disposed && batch.length) {
          const sid = batch.shift();
          sessions.delete(sid); sessions.add(sid); // Fair rotation across batches.
          try { await deliver(sid, response.data); }
          catch { await warning(); } // Unenrolled mailboxes cannot starve peers.
        }
      }));
    } catch { await warning(); }
    finally { running = false; }
  }
  const timer = setInterval(() => void tick(), 20000);
  timer.unref?.();
  return {
    dispose: async () => { disposed = true; clearInterval(timer); sessions.clear();
      for (const controller of controllers) controller.abort(); },
    event: async ({ event }) => {
      try {
        if (event.type === 'session.deleted') { sessions.delete(event.properties.info.id); return; }
        if (event.type !== 'session.created') return;
        const sid = event.properties.info.id;
        if (!await observed(sid) || disposed) return;
        await call('event', { hook_event_name: 'session.created', session_id: sid });
        sessions.add(sid);
      } catch { await warning(); }
    },
    'chat.message': async (input, output) => {
      try {
        const sid = input.sessionID;
        if (!await observed(sid) || disposed) return;
        // Babel-generated prompts are transport maintenance, never activity.
        if (output.message.id.startsWith('msg_babel')) return;
        await call('event', { hook_event_name: 'chat.message', session_id: sid,
          message_id: output.message.id,
          prompt: output.parts.filter(p => p.type === 'text' && !p.synthetic).map(p => p.text).join('\n') });
        sessions.add(sid);
      } catch { await warning(); }
    },
    'experimental.chat.system.transform': async (input, output) => {
      if (!sessions.has(input.sessionID)) return;
      const command = ['python3', join(homedir(), '.local/lib/agent-babel/account_session_helper.py'), 'tool',
        '--client', 'opencode', '--account-file', join(homedir(), '.config/255bits/agent-babel/trusted-account.json'),
        '--native-session', input.sessionID, '--tool', 'list_contacts'].map(x => "'" + x.replaceAll("'", "'\\''") + "'").join(' ');
      output.system.push('Babel prepared this exact OpenCode session mailbox; enrollment and wake are not yet verified. ' +
        'Use ' + command + ' with JSON on stdin. Read ~/.config/255bits/agent-babel/WORKER-INSTRUCTIONS.md. ' +
        'Use your own mailbox; authenticate Ember/Ada, claim notifications and acknowledge receipt with the exact reserved claim. ' +
        'Use local stage_report for substantive completion, failure, blocker and question notices. Receipt is not task completion.');
    },
  };
}
