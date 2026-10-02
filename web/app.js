let csrf = "";
let pendingSubmission = null;
let displayed = [];
let inboxMode = false;
const $ = id => document.getElementById(id);
const label = name => ({ada: "Ada / ChatGPT", grokbot: "Grokbot", muse: "Muse (future)"}[name] || name);
function tell(message, bad = false) { $("notice").textContent = message; $("notice").className = bad ? "error" : ""; }
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {
    method: "POST", headers: {"Content-Type": "application/json", "X-Babel-CSRF": csrf}, body: JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Bridge request failed");
  return result;
}
function add(parent, tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  parent.appendChild(node); return node;
}
function button(parent, text, action, kind = "secondary") {
  const node = add(parent, "button", text, kind);
  node.addEventListener("click", async () => {
    node.disabled = true;
    try { await action(); } catch (error) { tell(error.message, true); }
    finally { node.disabled = false; }
  });
}
async function reload() {
  inboxMode = false;
  displayed = (await api("/api/history")).messages;
  $("list_title").textContent = "Bridge history";
  render(displayed);
  $("older").hidden = displayed.length < 100;
}
function render(messages) {
  $("messages").replaceChildren();
  if (!messages.length) { add($("messages"), "p", "No bridge messages here yet.", "empty"); return; }
  for (const message of messages) {
    const card = add($("messages"), "article", undefined, "message");
    add(card, "strong", label(message.source) + " → " + label(message.recipient));
    add(card, "span", message.status, "badge " + message.status);
    add(card, "pre", message.text);
    add(card, "small", message.id + " · hop " + message.hops + "/4 · " + message.provenance);
    if (message.conversation_id) add(card,"small","Conversation: "+message.conversation_id);
    if (message.reply_to) add(card, "small", "Reply to " + message.reply_to);
    if (message.receipt) add(card, "small", "Receipt evidence: " + message.receipt + " (does not confirm task completion)");
    const actions = add(card, "div", undefined, "actions");
    if (message.status === "draft") button(actions, "Approve into local queue", async () => {
      await api("/api/approve", {message_id: message.id});
      await reload(); tell("Approved into the bridge queue. Configured recipients can fetch it; approval does not prove receipt.");
    }, "primary");
    if (message.status === "queued") {
      button(actions, "Prepare copy/paste handoff", async () => {
        const result = await api("/api/export", {message_id: message.id});
        $("copy_text").value = result.copy_text;
        $("handoff").hidden = false; tell(result.notice);
        $("handoff").scrollIntoView({behavior: "smooth"});
      });
      button(actions, "Mark manually received", async () => {
        if (!window.confirm("Confirm that YOU pasted message " + message.id + " into " + label(message.recipient) +
          " and saw it there. This records your confirmation; Babel cannot verify the app.")) return;
        await api("/api/acknowledge", {message_id: message.id, recipient: message.recipient});
        await reload(); tell("Your manual receipt was recorded.");
      });
      button(actions, "Test mock receipt", async () => {
        const result = await api("/api/mock", {message_id: message.id}); tell(result.notice);
      });
    }
    if (message.status === "queued" || message.status === "acknowledged") button(actions, "Draft an explicit reply", () => {
      if (message.conversation_id) $("conversation_id").value=message.conversation_id;
      $("source").value = message.recipient; $("recipient").value = message.source;
      $("reply_to").value = message.id; $("text").value = ""; $("text").focus();
      $("compose").scrollIntoView({behavior: "smooth"}); tell("Select the reply text yourself, then create a new draft.");
    });
    if (message.status === "draft" || message.status === "queued") button(actions, "Cancel locally", async () => {
      await api("/api/cancel", {message_id: message.id}); await reload();
      tell("Canceled in the bridge. This cannot undo any copy/paste you already performed.");
    });
    button(actions, "Show bridge audit", async () => {
      const result = await api("/api/events", {message_id: message.id});
      tell(result.events.map(event => event.action + " · " + event.actor).join(" | "));
    });
  }
}
$("compose").addEventListener("submit", async event => {
  event.preventDefault();
  const submit = event.target.querySelector("button"); submit.disabled = true;
  try {
    const text = $("text").value;
    if (new TextEncoder().encode(text).length > 16384) throw new Error("Message exceeds 16 KiB in UTF-8.");
    const input = {source: $("source").value, recipient: $("recipient").value, text};
    if (!$("conversation_label").hidden) input.conversation_id=$("conversation_id").value;
    if ($("reply_to").value.trim()) input.reply_to = $("reply_to").value.trim();
    const fingerprint = JSON.stringify(input);
    if (!pendingSubmission || pendingSubmission.fingerprint !== fingerprint)
      pendingSubmission = {fingerprint, message_id: crypto.randomUUID()};
    const result = await api("/api/stage", {...input, message_id: pendingSubmission.message_id});
    $("text").value = ""; $("reply_to").value = ""; pendingSubmission = null;
    await reload();
    tell(result.duplicate ? "Existing draft recovered safely." : "Draft created. Review its exact content before approval.");
  } catch (error) { tell(error.message, true); } finally { submit.disabled = false; }
});
$("refresh").onclick = () => reload().catch(error => tell(error.message, true));
$("older").onclick = async () => {
  try {
    const messages = (await api("/api/history?before=" + displayed[displayed.length - 1].seq)).messages;
    displayed.push(...messages); render(displayed); $("older").hidden = messages.length < 100;
  } catch (error) { tell(error.message, true); }
};
$("receive").onclick = async () => {
  try {
    const result = await api("/api/receive", {recipient: $("inbox_agent").value});
    inboxMode = true; $("older").hidden = true;
    $("list_title").textContent = label($("inbox_agent").value) + " — local queued inbox";
    render(result.messages); tell("Read local approved messages. None were acknowledged automatically.");
  } catch (error) { tell(error.message, true); }
};
$("copy").onclick = async () => {
  try { await navigator.clipboard.writeText($("copy_text").value);
    tell("Copied to your clipboard. Paste into the chosen agent yourself; no message was sent.");
  } catch (_) { $("copy_text").select(); tell("Select and copy this text manually with Ctrl/Cmd+C."); }
};
$("close_handoff").onclick = () => { $("handoff").hidden = true; $("copy_text").value = ""; };
(async () => { const session=await api("/api/session"); csrf=session.csrf;
  for (const field of ["source","recipient","inbox_agent"]) { $(field).replaceChildren(); for (const name of session.agents) { const option=add($(field),"option",label(name)); option.value=name; } }
  if (session.agents.length>1) $("recipient").selectedIndex=1;
  if (session.conversations && session.conversations.length) { $("conversation_label").hidden=false; for (const cid of session.conversations) { const option=add($("conversation_id"),"option",cid); option.value=cid; } }
  await reload(); })().catch(error => tell(error.message, true));
