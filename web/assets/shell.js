/* Shared page shell: nav rail, sticky page header, chat dock, sign-out.
   Each page declares itself via <body data-page="findings" data-title="Findings"
   data-sub="..."> and provides its content in <main id="page"> — shell.js
   wraps it at load. */

const NAV_ITEMS = [
  { group: "Monitor" },
  { key: "overview", href: "/", label: "Overview",
    icon: '<rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="5" rx="1.5"/><rect x="13" y="10" width="8" height="11" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/>' },
  { key: "findings", href: "/findings", label: "Findings",
    icon: '<path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9.5 12l1.8 1.8 3.2-3.6" stroke-linecap="round" stroke-linejoin="round"/>' },
  { key: "cost", href: "/cost", label: "Cost & usage",
    icon: '<path d="M4 20V10M11 20V4M18 20v-7" stroke-linecap="round"/>' },
  { key: "resources", href: "/resources", label: "Resources",
    icon: '<path d="M12 3l8 4-8 4-8-4 8-4z"/><path d="M4 11l8 4 8-4M4 16l8 4 8-4" stroke-linecap="round" stroke-linejoin="round"/>' },
  { key: "architecture", href: "/architecture", label: "Architecture",
    icon: '<circle cx="5" cy="6" r="2.2"/><circle cx="19" cy="6" r="2.2"/><circle cx="12" cy="18" r="2.2"/><path d="M6.8 7.4L11 16M17.2 7.4L13 16"/>' },
  { group: "Manage" },
  { key: "accounts", href: "/accounts", label: "Accounts & settings",
    icon: '<circle cx="9" cy="8" r="3.2"/><path d="M3.5 20c0-3.6 2.5-6 5.5-6s5.5 2.4 5.5 6" stroke-linecap="round"/><circle cx="18" cy="9" r="2.4"/><path d="M14.8 14.3c2.6.3 4.5 2.4 4.7 5.4" stroke-linecap="round"/>' },
];

const LOGO_SVG =
  '<svg width="26" height="26" viewBox="0 0 24 24" fill="none">' +
  '<circle cx="12" cy="12" r="9" stroke="#2fb8c4" stroke-width="1.8"/>' +
  '<path d="M8.5 12.5l2.3 2.3 4.7-5.2" stroke="#2fb8c4" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function buildShell() {
  const body = document.body;
  const active = body.dataset.page || "overview";
  const title = body.dataset.title || "Clearsky";
  const sub = body.dataset.sub || "";
  const page = document.getElementById("page");

  const who = AUTH.claims() || {};
  const email = who.email || who["cognito:username"] || "signed in";
  const initials = email.slice(0, 2).toUpperCase();

  const navHtml = NAV_ITEMS.map(it => it.group
    ? `<div class="group">${it.group}</div>`
    : `<a class="item${it.key === active ? " active" : ""}" href="${it.href}">
         <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7">${it.icon}</svg>
         ${it.label}</a>`).join("");

  const shell = document.createElement("div");
  shell.className = "shell";
  shell.innerHTML = `
    <aside class="navrail">
      <div class="brand">${LOGO_SVG}
        <div><div class="name">Clearsky</div><div class="tag">AWS Cloud posture</div></div>
      </div>
      <nav>${navHtml}</nav>
      <div class="foot">
        <div class="avatar">${esc(initials)}</div>
        <div class="who"><div class="n">${esc(email)}</div><div class="id">${esc(CONFIG.accountId || "")}</div></div>
        <button class="out" title="Sign out" onclick="AUTH.signOut()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" stroke-linecap="round"/><path d="M16 17l5-5-5-5M21 12H9" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
      </div>
    </aside>
    <div class="main">
      <div class="pagehead">
        <div class="titles"><h1>${esc(title)}</h1><div class="sub" id="page-sub">${esc(sub)}</div></div>
        <div id="page-actions"></div>
      </div>
      <div class="content" id="shell-content"></div>
    </div>`;

  body.prepend(shell);
  if (page) document.getElementById("shell-content").appendChild(page);
  buildChatDock();
}

function setSub(text) { document.getElementById("page-sub").textContent = text; }
function setActions(html) { document.getElementById("page-actions").innerHTML = html; }

/* ---------- chat dock (Ask the Detective) ---------- */

let CHAT_ID = null;
let CHAT_MSGS = [];

function buildChatDock() {
  const dock = document.createElement("div");
  dock.className = "chatdock";
  dock.id = "chatdock";
  dock.innerHTML = `
    <div class="chatwin">
      <div class="chead">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#a98af0" stroke-width="1.8"><path d="M12 3v3M12 18v3M4.2 6.2l2.1 2.1M17.7 15.7l2.1 2.1M3 12h3M18 12h3M4.2 17.8l2.1-2.1M17.7 8.3l2.1-2.1" stroke-linecap="round"/><circle cx="12" cy="12" r="3.2"/></svg>
        <div class="grow"><div class="t">Ask the Detective</div><div class="s">Read-only · investigates your live accounts</div></div>
        <button class="out" style="background:none;border:0;color:var(--dim);cursor:pointer" onclick="toggleChat()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 6l12 12M18 6L6 18" stroke-linecap="round"/></svg>
        </button>
      </div>
      <div class="clog" id="chat-log"><div class="empty">Ask anything about your accounts' security, cost, or architecture.</div></div>
      <div class="sugs">
        <button class="sug" onclick="chatSuggest(this)">Which security groups are exposed to the internet?</button>
        <button class="sug" onclick="chatSuggest(this)">What should I fix first?</button>
      </div>
      <form id="chat-form">
        <input id="chat-input" type="text" maxlength="2000" autocomplete="off"
               placeholder="Ask about security, cost, architecture…">
        <button type="submit">Ask</button>
      </form>
    </div>
    <button class="chatfab" data-cd-chat-fab title="Ask the Detective" onclick="toggleChat()">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><path d="M21 11.5a8.4 8.4 0 01-8.9 8.4c-1.2-.1-2-.3-3-.7L4 20l1-4.6c-.6-1-1-2.3-1-3.9A8.4 8.4 0 0112.9 3a8.5 8.5 0 018.1 8.5z" stroke-linejoin="round"/></svg>
    </button>`;
  document.body.appendChild(dock);
  document.getElementById("chat-form").addEventListener("submit", sendChat);
}

function toggleChat() {
  document.getElementById("chatdock").classList.toggle("open");
}

function chatSuggest(el) {
  const input = document.getElementById("chat-input");
  input.value = el.textContent;
  document.getElementById("chat-form").requestSubmit();
}

/* open the dock and fire a question — used by per-page "Ask AI" buttons */
function askChatAbout(text) {
  document.getElementById("chatdock").classList.add("open");
  const input = document.getElementById("chat-input");
  input.value = text;
  document.getElementById("chat-form").requestSubmit();
}

function renderChat(thinking) {
  const log = document.getElementById("chat-log");
  log.innerHTML = CHAT_MSGS.map(m =>
    `<div class="msg ${m.role}">${esc(m.text)}${
      m.tools_used && m.tools_used.length
        ? `<div class="tools">checked: ${esc(m.tools_used.join(" · "))}</div>` : ""}</div>`).join("")
    + (thinking ? '<div class="msg assistant" style="color:var(--dim)">thinking…</div>' : "");
  log.scrollTop = log.scrollHeight;
}

async function sendChat(ev) {
  ev.preventDefault();
  const input = document.getElementById("chat-input");
  const text = input.value.trim();
  if (!text) return;
  input.value = "";
  CHAT_MSGS.push({ role: "user", text });
  renderChat(true);
  try {
    const body = { message: text };
    if (CHAT_ID) body.conversation_id = CHAT_ID;
    const context = window.CHAT_CONTEXT || {};
    if (Object.keys(context).length) body.context = context;
    const r = await apiPost("/api/chat", body);
    const data = await r.json();
    CHAT_ID = data.conversation_id || CHAT_ID;
    // poll until the agent answers
    for (let i = 0; i < 90; i++) {
      await new Promise(res => setTimeout(res, 2000));
      const conv = await apiJson(`/api/chat?id=${CHAT_ID}`);
      const msgs = conv.messages || [];
      if (msgs.length && msgs[msgs.length - 1].role === "assistant") {
        CHAT_MSGS = msgs;
        renderChat(false);
        return;
      }
    }
    CHAT_MSGS.push({ role: "assistant", text: "Still working — reopen the panel in a moment." });
  } catch (e) {
    CHAT_MSGS.push({ role: "assistant", text: "Sorry — the investigation failed. Is a provider key configured in Accounts & settings?" });
  }
  renderChat(false);
}

/* ---------- boot ---------- */

(async () => {
  if (await AUTH.requireAuth()) {
    buildShell();
    if (typeof pageInit === "function") {
      pageInit().catch(err => { if (err.message !== "auth") console.error(err); });
    }
  }
})();
