import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./styles.css";

// ---------------------------------------------------------------------------
// Types (mirror the Rust views)
// ---------------------------------------------------------------------------

type AppStateView = {
  profileExists: boolean; username?: string; displayName?: string;
  keyBackend: string; coordinator: string; workerUrl: string;
  relayEnabled: boolean; shortcutOk: boolean; alwaysOnTop: boolean; connection: string;
};
type ChatSummary = {
  id: string; kind: string; name: string; members: string[];
  preview?: string; updatedAtMs: number; unread: number;
};
type ChatMessage = {
  id: string; conversationId: string; senderDeviceId: string; senderUsername: string;
  messageType: string; body: string; sequence: number; status: string;
  replyTo?: string; createdAtMs: number; editedAtMs?: number;
};
type FileRow = {
  id: string; conversationId: string; filename: string; mimeType: string;
  sizeBytes: number; sha256Hex: string; state: string; bytesDone: number; localPath?: string;
};
type ChatDetail = { conversation: ChatSummary; messages: ChatMessage[]; files: FileRow[]; typists: string[] };
type FriendEntry = { username: string; displayName: string; status: string; seen: boolean };
type FriendRequest = { id: string; direction: string; peerUsername: string; peerDisplayName: string; status: string };
type FriendsView = { contacts: FriendEntry[]; incoming: FriendRequest[]; outgoing: FriendRequest[] };
type ImportResult = { username: string; delivered: boolean; surfaced: number };
type PeerPresence = { username: string; status: string; label: string; fresh: boolean };
type PresenceView = { status: string; label: string; peers: PeerPresence[] };
type Tab = "chats" | "friends";

const app = document.querySelector<HTMLElement>("#app")!;
let tab: Tab = "chats";
let state: AppStateView | null = null;
let chats: ChatSummary[] = [];
let detail: ChatDetail | null = null;
let friends: FriendsView | null = null;
let toast: string | null = null;
let toastTimer: number | undefined;
let addingFriend = false;
let presence: PresenceView | null = null;
let searchOpen = false;
let searchQuery = "";
let searchResults: ChatMessage[] | null = null;
let searchTimer: number | undefined;
let quickOpen = false;
let quickQuery = "";
let menuFor: { id: string; x: number; y: number; mine: boolean } | null = null;
let loadingChat = false;
let editingId: string | null = null;
let replyTo: { id: string; body: string; from: string } | null = null;
let showGroupPanel = false;
let showSettings = false;
let newGroupMembers = new Set<string>();
let composerDraft = "";
let typingSent = false;
let typingTimer: number | undefined;
// Onboarding form state survives re-renders so typing is never wiped.
let onboardDraft = { username: "", displayName: "" };
let creating = false;

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

async function loadAll() {
  try {
    state = await invoke<AppStateView>("app_state");
  } catch { state = null; render(); return; }
  if (!state?.profileExists) { render(); return; }
  try { chats = await invoke<ChatSummary[]>("list_chats"); } catch { chats = []; }
  try { presence = await invoke<PresenceView>("get_presence"); } catch { presence = null; }
  try { friends = await invoke<FriendsView>("list_friends"); } catch { friends = null; }
  if (detail) {
    try { detail = await invoke<ChatDetail>("open_chat", { conversationId: detail.conversation.id }); }
    catch { detail = null; }
  }
  render();
}

function showToast(text: string) {
  toast = text;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => { toast = null; render(); }, 3500);
  render();
}

async function selectChat(id: string | null) {
  replyTo = null; editingId = null; showGroupPanel = false; composerDraft = "";
  searchOpen = false; searchQuery = ""; searchResults = null; menuFor = null;
  if (id) { loadingChat = true; render(); }
  if (!id) { detail = null; loadingChat = false; render(); return; }
  try { detail = await invoke<ChatDetail>("open_chat", { conversationId: id }); }
  catch (e) { loadingChat = false; showToast(String(e)); return; }
  loadingChat = false;
  render();
  focusComposer();
}

function focusComposer() {
  requestAnimationFrame(() => {
    const input = document.querySelector<HTMLInputElement>("#composer-input")
      ?? document.querySelector<HTMLInputElement>("#chat-search");
    input?.focus();
  });
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function esc(value: string) {
  const el = document.createElement("span");
  el.textContent = value;
  return el.innerHTML;
}

function timeOf(ms: number) {
  const date = new Date(ms);
  const now = new Date();
  if (date.toDateString() === now.toDateString()) {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return date.toLocaleDateString([], { month: "short", day: "numeric" });
}

function statusTick(status: string) {
  if (status === "read") return `<span class="tick read" title="Read">✓✓</span>`;
  if (status === "delivered") return `<span class="tick" title="Delivered">✓</span>`;
  if (status === "queued") return `<span class="tick dim" title="Queued — will retry">◷</span>`;
  return `<span class="tick dim" title="On this device">•</span>`;
}

function render() {
  if (!state) { app.innerHTML = `<div class="overlay"><p class="err pad">Backend unavailable. Restart Hearth.</p></div>`; return; }
  app.innerHTML = state.profileExists ? shell() : onboarding();
  bind();
  paintToast();
}

function paintToast() {
  if (!toast) return;
  const toastEl = document.createElement("div");
  toastEl.className = "toast";
  toastEl.setAttribute("role", "status");
  toastEl.textContent = toast;
  app.appendChild(toastEl);
}

function onboarding() {
  return `<section class="overlay onboard">
    <div class="login-card">
      <div class="login-orb" aria-hidden="true">H</div>
      <p class="login-eyebrow">Hearth · private overlay chat</p>
      <h1>Welcome in.</h1>
      <p class="muted login-sub">Claim your local identity — your keys never leave this device.</p>
      <form id="identity-form">
        <label>Username<input id="ob-username" name="username" placeholder="ada_lovelace" required minlength="3" maxlength="32" pattern="[a-zA-Z0-9_]+" autocomplete="username" value="${esc(onboardDraft.username)}" /></label>
        <label>Display name<input id="ob-display" name="displayName" placeholder="Ada" required maxlength="64" autocomplete="name" value="${esc(onboardDraft.displayName)}" /></label>
        <p id="form-error" class="err" role="alert"></p>
        <button type="submit" ${creating ? "disabled" : ""}>${creating ? "Creating…" : "Create identity →"}</button>
      </form>
    </div>
    <p class="login-hint"><kbd>Alt</kbd> + <kbd>/</kbd> summons Hearth from anywhere</p>
  </section>`;
}

function connDot() {
  const label = state?.connection ?? "Offline";
  const cls = label === "Ready" ? "ok" : "off";
  return `<span class="conn ${cls}" title="Transport: ${esc(label)}"></span>`;
}

function windowBar() {
  return `<header class="titlebar" data-tauri-drag-region>
    <div class="brand sm" data-tauri-drag-region><span class="dot"></span><strong>Hearth</strong>${connDot()}</div>
    <div class="winbtns">
      <button class="icon" id="hide-btn" title="Hide (tray icon brings it back)" aria-label="Hide window">–</button>
      <button class="icon danger" id="quit-btn" title="Quit" aria-label="Quit Hearth">✕</button>
    </div>
  </header>`;
}

function bottomPill() {
  const reqCount = friends?.incoming.length ?? 0;
  return `<nav class="pillnav" aria-label="Main">
    <button class="${tab === "chats" ? "active" : ""}" data-tab="chats">💬<small>Chats</small></button>
    <button class="${tab === "friends" ? "active" : ""}" data-tab="friends">👥<small>Friends</small>${reqCount ? `<b class="badge">${reqCount}</b>` : ""}</button>
    <button id="pin-btn" title="Always on top: ${state?.alwaysOnTop ? "on" : "off"}" aria-label="Toggle always on top" aria-pressed="${state?.alwaysOnTop ? "true" : "false"}">${state?.alwaysOnTop ? "📌" : "📍"}</button>
  </nav>`;
}

function shell() {
  return `<section class="overlay">
    ${windowBar()}
    <div class="bodypad">${tab === "chats" ? chatsScreen() : friendsScreen()}</div>
    ${bottomPill()}
    ${quickOpen ? quickSwitcher() : ""}
  </section>`;
}

function chatsScreen() {
  if (!detail) {
    const rows = chats.map((c) => `
      <button class="row" data-chat="${c.id}">
        <span class="avatar">${esc(initials(c.name))}</span>
        <span class="row-main"><strong>${esc(c.name)} ${c.kind === "group" ? '<span class="tag">group</span>' : ""}</strong>
        <small>${esc(c.preview ?? "No messages yet")}</small></span>
        <span class="row-side"><small>${c.preview ? timeOf(c.updatedAtMs) : ""}</small>${c.unread ? `<b class="badge">${c.unread}</b>` : ""}</span>
      </button>`).join("");
    return `<div class="screen">
      <div class="rowbar"><input id="chat-search" placeholder="Search chats…" /></div>
      <div class="list">${rows || `<p class="muted pad">No chats yet. Add a friend, then start chatting.</p>`}</div>
      <footer class="hint">Alt+/ focuses Hearth · stays on top while you play</footer>
    </div>`;
  }
  const c = detail.conversation;
  const me = state?.username ?? "";
  const bubbles = detail.messages.map((m) => {
    const mine = m.senderUsername === me;
    const reply = m.replyTo ? detail!.messages.find((x) => x.id === m.replyTo) : undefined;
    return `<div class="msg ${mine ? "mine" : ""}" data-mid="${m.id}">
      ${!mine ? `<small class="from">@${esc(m.senderUsername)}</small>` : ""}
      ${reply ? `<div class="quote">${esc(reply.body.slice(0, 80))}</div>` : ""}
      <div class="bubble">${esc(m.body)}${m.editedAtMs ? ' <small class="edited">(edited)</small>' : ""}</div>
      <div class="meta"><small>${timeOf(m.createdAtMs)}</small>${mine ? statusTick(m.status) : ""}
      ${mine ? `<button class="link" data-reply="${m.id}" title="Reply">↩</button><button class="link" data-edit="${m.id}" title="Edit">✎</button><button class="link danger" data-del="${m.id}" title="Delete">✕</button>` : `<button class="link" data-reply="${m.id}" title="Reply">↩</button>`}</div>
    </div>`;
  }).join("");
  const files = detail.files.map((f) => `
    <div class="file"><span>📎 ${esc(f.filename)}</span>
    <small>${fileLabel(f)}</small>
    ${f.state === "incoming" ? `<small>receiving…</small>` : ""}
    ${["incoming", "sending"].includes(f.state) ? `<button class="link danger" data-cancel-file="${f.id}">cancel</button>` : ""}</div>`).join("");
  const typists = detail.typists.length ? `<div class="typing">${detail.typists.map((t) => `@${esc(t)}`).join(", ")} typing…</div>` : "";
  if (loadingChat) {
    return `<div class="screen thread-screen"><div class="thread-head">
      <button class="icon" data-chat="" aria-label="Back">←</button>
      <div class="thread-title"><strong>…</strong></div></div>
      <p class="muted pad">Loading…</p></div>`;
  }
  return `<div class="screen thread-screen">
    <div class="thread-head">
      <button class="icon" data-chat="" aria-label="Back to chats">←</button>
      <div class="thread-title"><strong>${esc(c.name)}</strong><small>${c.kind === "group" ? `${c.members.length} members` : dmPeerStatus(c)}</small></div>
      <button class="icon" id="search-btn" title="Search in chat (/)" aria-label="Search in chat">🔍</button>
      ${c.kind === "group" ? `<button class="icon" id="group-btn" title="Group settings" aria-label="Group settings">⋯</button>` : ""}
    </div>
    ${searchOpen ? searchBar() : ""}
    ${showGroupPanel ? groupPanel(c) : ""}
    <div class="feed" id="feed" role="log" aria-label="Messages" aria-live="off">${searchResults ? searchResultsView() : `${bubbles || `<p class="muted pad">Say hi — messages are end-to-end encrypted.</p>`}${files ? `<div class="files">${files}</div>` : ""}${typists}`}</div>
    ${menuFor ? contextMenu() : ""}
    ${replyTo ? `<div class="replybar">Replying to <strong>@${esc(replyTo.from)}</strong>: ${esc(replyTo.body.slice(0, 60))} <button class="link" id="reply-cancel">✕</button></div>` : ""}
    ${editingId ? `<div class="replybar">Editing message <button class="link" id="edit-cancel">✕</button></div>` : ""}
    <form class="composer" id="composer">
      <label class="icon attach" title="Send file (≤25 MB)" aria-label="Send file">+<input type="file" id="file-input" hidden /></label>
      <input id="composer-input" name="message" autocomplete="off" maxlength="2000" placeholder="${editingId ? "Edit message…" : "Message…"}" value="${esc(composerDraft)}" />
      <button type="submit" title="Send" aria-label="Send message">↑</button>
    </form>
  </div>`;
}

function connLabel() {
  if (state?.coordinator === "cloudflare") return "P2P · cloud backup";
  return "P2P · local mode";
}

function fileLabel(f: FileRow) {
  const kb = Math.max(1, Math.round(f.sizeBytes / 1024));
  return `${f.state} · ${kb} KB`;
}

function searchBar() {
  return `<div class="searchbar">
    <input id="thread-search" placeholder="Search (min 2 chars)…" value="${esc(searchQuery)}" aria-label="Search messages" />
    <button class="icon" id="search-clear" aria-label="Close search">✕</button>
  </div>`;
}

function searchResultsView() {
  if (!searchResults) return "";
  const rows = searchResults.map((m) => `
    <div class="msg ${m.senderUsername === (state?.username ?? "") ? "mine" : ""}" data-mid="${m.id}">
      <small class="from">@${esc(m.senderUsername)} · ${timeOf(m.createdAtMs)}</small>
      <div class="bubble">${esc(m.body)}</div>
    </div>`).join("");
  return `<p class="muted pad">${searchResults.length} result${searchResults.length === 1 ? "" : "s"} for “${esc(searchQuery)}”</p>${rows || `<p class="muted pad">No matches.</p>`}`;
}

function contextMenu() {
  const m = menuFor!;
  return `<div class="ctxback" id="ctxback"></div><div class="ctxmenu" id="ctxmenu" style="left:${m.x}px;top:${m.y}px" role="menu">
    <button data-ctx="copy" role="menuitem">Copy text</button>
    <button data-ctx="reply" role="menuitem">Reply</button>
    ${m.mine ? `<button data-ctx="edit" role="menuitem">Edit</button><button data-ctx="del" role="menuitem" class="danger"> Delete</button>` : ""}
  </div>`;
}

function quickSwitcher() {
  const q = quickQuery.toLowerCase();
  const matches = chats.filter((c) => (c.name + " " + c.members.join(" ")).toLowerCase().includes(q)).slice(0, 8);
  return `<div class="quickwrap" id="quickwrap">
    <div class="quick" role="dialog" aria-label="Jump to chat">
      <input id="quick-input" placeholder="Jump to chat… (Esc closes)" value="${esc(quickQuery)}" aria-label="Jump to chat" />
      <div class="list">${matches.map((c, i) => `
        <button class="row" data-quick="${c.id}">
          <span class="avatar">${esc(initials(c.name))}</span>
          <span class="row-main"><strong>${esc(c.name)}</strong></span>
          ${i === 0 ? `<small>↵</small>` : ""}
        </button>`).join("") || `<p class="muted pad">No match.</p>`}</div>
    </div>
  </div>`;
}

function groupPanel(c: ChatSummary) {
  const memberRows = c.members.map((m) => `
    <div class="member"><span>@${esc(m)}</span>
    ${m !== state?.username ? `<button class="link danger" data-kick="${esc(m)}">remove</button>` : `<small>you</small>`}</div>`).join("");
  const friendOptions = (friends?.contacts ?? [])
    .filter((f) => f.status === "friend" && !c.members.includes(f.username))
    .map((f) => `<label class="check"><input type="checkbox" data-add-member="${esc(f.username)}" /> @${esc(f.username)}</label>`).join("");
  return `<div class="panel">
    <label class="rowlabel">Group name</label>
    <form id="rename-form" class="inline"><input name="name" value="${esc(c.name)}" maxlength="64" /><button>Save</button></form>
    <label class="rowlabel">Members</label><div class="members">${memberRows}</div>
    ${friendOptions ? `<label class="rowlabel">Add friends</label><div class="members">${friendOptions}</div><button id="add-members-btn">Add selected</button>` : ""}
    <div class="panel-actions">
      <button id="leave-btn" class="danger-btn">Leave group</button>
      <button id="delete-chat-btn" class="danger-btn">Delete locally</button>
    </div>
  </div>`;
}

function peerPresence(username: string): PeerPresence | null {
  return presence?.peers.find((p) => p.username === username) ?? null;
}

function presenceDot(username: string) {
  const p = peerPresence(username);
  if (!p || !p.fresh) return `<span class="pdot off" title="offline"></span>`;
  const cls = p.status === "online" ? "ok" : p.status === "away" ? "idle" : "dnd";
  return `<span class="pdot ${cls}" title="${esc(p.label)}"></span>`;
}

function dmPeerStatus(c: ChatSummary) {
  if (c.kind !== "dm") return `${c.members.length} members`;
  const peer = c.members[0] ?? "?";
  const p = peerPresence(peer);
  if (p && p.fresh) return `@${esc(peer)} · ${esc(p.label)}`;
  return `@${esc(peer)} · ${esc(connLabel())}`;
}

function initials(name: string) {
  return name.replace(/^@/, "").split(/\s+/).map((w) => w[0] ?? "").join("").slice(0, 2).toUpperCase() || "?";
}

function friendsScreen() {
  const f = friends;
  const contactRows = (f?.contacts ?? []).map((c) => `
    <div class="member">
      <span>${presenceDot(c.username)}<strong>@${esc(c.username)}</strong> <small>${esc(c.displayName)} · ${esc(c.status)}${c.seen ? " · seen" : ""}</small></span>
      <span class="acts">
        ${c.status === "friend" ? `<button class="link" data-dm="${esc(c.username)}">chat</button>` : ""}
        ${c.status === "requested" ? `<button class="link" data-ask="${esc(c.username)}">resend ask</button>` : ""}
        ${c.status !== "blocked" ? `<button class="link danger" data-block="${esc(c.username)}">block</button>` : `<button class="link" data-unblock="${esc(c.username)}">unblock</button>`}
        <button class="link danger" data-remove="${esc(c.username)}">✕</button>
      </span>
    </div>`).join("");
  const incoming = (f?.incoming ?? []).map((r) => `
    <div class="member"><span><strong>@${esc(r.peerUsername)}</strong> <small>${esc(r.peerDisplayName)}</small></span>
    <span class="acts"><button class="link" data-accept="${r.id}">accept</button><button class="link danger" data-reject="${r.id}">decline</button></span></div>`).join("");
  const outgoing = (f?.outgoing ?? []).map((r) => `
    <div class="member"><span><strong>@${esc(r.peerUsername)}</strong> <small>ask sent</small></span></div>`).join("");
  const groupFriends = (f?.contacts ?? []).filter((c) => c.status === "friend").map((c) => `
    <label class="check"><input type="checkbox" data-new-group-member="${esc(c.username)}" ${newGroupMembers.has(c.username) ? "checked" : ""} /> @${esc(c.username)}</label>`).join("");
  return `<div class="screen">
    <div class="fsection">
      <label class="rowlabel">My invite code</label>
      <div class="inline"><input id="my-invite" readonly placeholder="loading…" /><button id="copy-invite" type="button">Copy</button></div>
      <form id="import-form" class="inline"><input name="code" placeholder="Paste friend's invite…" /><button id="add-btn" ${addingFriend ? "disabled" : ""}>${addingFriend ? "Adding…" : "Add"}</button></form>
      <small class="muted">Both ways: they need your code, and you need theirs. Asks send automatically when you're both online.</small>
    </div>
    ${incoming ? `<div class="fsection"><label class="rowlabel">Requests</label>${incoming}</div>` : ""}
    ${outgoing ? `<div class="fsection"><label class="rowlabel">Sent</label>${outgoing}</div>` : ""}
    <div class="fsection"><label class="rowlabel">Friends & blocked</label>${contactRows || `<p class="muted">Nobody yet.</p>`}</div>
    <div class="fsection"><label class="rowlabel">New group</label>
      <form id="group-form" class="inline"><input name="name" placeholder="Squad name" maxlength="64" /><button>Create</button></form>
      <div class="members">${groupFriends || `<small class="muted">Add friends first.</small>`}</div>
    </div>
    <div class="fsection"><button id="settings-btn" class="ghost" type="button">${showSettings ? "Hide settings ▲" : "Settings ▼"}</button>${showSettings ? settingsBlock() : ""}</div>
  </div>`;
}

function settingsBlock() {
  return `<div class="settings">
    <div class="srow"><span>Connection</span><small>${esc(state?.connection ?? "?")} · ${esc(connLabel())}</small></div>
    <div class="srow"><span>Keys</span><small>${esc(state?.keyBackend ?? "?")}</small></div>
    <div class="srow"><span>Shortcut</span><small>${state?.shortcutOk ? "Alt+/ active" : "unavailable (use tray)"}</small></div>
    <div class="srow"><span>Signed in as</span><small>@${esc(state?.username ?? "?")}</small></div>
    <div class="srow"><span>You appear</span><small>${esc(presence?.label ?? "…")}</small></div>
    <div class="inline" role="group" aria-label="Set status">
      ${["online", "away", "dnd"].map((s) => `<button data-status="${s}" type="button" class="${presence?.status === s ? "activebtn" : ""}">${s === "dnd" ? "Do not disturb" : s[0].toUpperCase() + s.slice(1)}</button>`).join("")}
    </div>
    <form id="coord-form" class="inline">
      <select name="kind">
        <option value="local" ${state?.coordinator === "local" ? "selected" : ""}>Local (no account)</option>
        <option value="cloudflare" ${state?.coordinator === "cloudflare" ? "selected" : ""}>Cloudflare worker</option>
      </select>
      <input name="url" placeholder="worker URL" value="${esc(state?.workerUrl ?? "")}" />
      <button>Save</button>
    </form>
    <div class="inline"><button id="mailbox-btn" type="button">Check mailbox</button><button id="diag-btn" type="button">Diagnostics</button></div>
    <div class="inline"><button id="logout-btn" type="button" class="danger-btn">Log out</button></div>
    <small class="muted">Logging out removes your profile, friends and chats from this device.</small>
    <div id="diag-out"></div>
  </div>`;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

let keysBound = false;

function restoreEphemeralFocus() {
  const quick = document.querySelector<HTMLInputElement>("#quick-input");
  if (quickOpen && quick) {
    quick.focus();
    quick.setSelectionRange(quick.value.length, quick.value.length);
    return;
  }
  const search = document.querySelector<HTMLInputElement>("#thread-search");
  if (searchOpen && search && document.activeElement?.tagName !== "INPUT") {
    search.focus();
    search.setSelectionRange(search.value.length, search.value.length);
  }
}

function bindGlobalKeys() {
  if (keysBound) return;
  keysBound = true;
  document.addEventListener("keydown", (e) => {
    const modK = (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k";
    if (modK && state?.profileExists) {
      e.preventDefault();
      quickOpen = !quickOpen;
      quickQuery = "";
      render();
      return;
    }
    if (e.key !== "Escape") return;
    if (menuFor) { menuFor = null; render(); }
    else if (searchOpen) { searchOpen = false; searchQuery = ""; searchResults = null; render(); }
    else if (quickOpen) { quickOpen = false; quickQuery = ""; render(); }
    else if (showGroupPanel) { showGroupPanel = false; render(); }
    else if (detail) { selectChat(null); }
  });
}

function bind() {
  bindGlobalKeys();
  restoreEphemeralFocus();
  // Onboarding: keep drafts so re-renders never eat typing.
  document.querySelector<HTMLInputElement>("#ob-username")?.addEventListener("input", (e) => {
    onboardDraft.username = (e.currentTarget as HTMLInputElement).value;
  });
  document.querySelector<HTMLInputElement>("#ob-display")?.addEventListener("input", (e) => {
    onboardDraft.displayName = (e.currentTarget as HTMLInputElement).value;
  });
  document.querySelector<HTMLFormElement>("#identity-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (creating) return;
    const form = e.currentTarget as HTMLFormElement;
    const username = (form.querySelector<HTMLInputElement>("#ob-username")?.value ?? "").trim();
    const displayName = (form.querySelector<HTMLInputElement>("#ob-display")?.value ?? "").trim();
    onboardDraft = { username, displayName };
    const errEl = document.querySelector("#form-error");
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
      if (errEl) errEl.textContent = "Username must be 3–32 letters, numbers, or underscores.";
      return;
    }
    if (!displayName || displayName.length > 64) {
      if (errEl) errEl.textContent = "Display name must be 1–64 characters.";
      return;
    }
    creating = true;
    render();
    try {
      await invoke("create_profile", { username, displayName });
      onboardDraft = { username: "", displayName: "" };
      creating = false;
      await loadAll();
      showToast(`Welcome, @${username}!`);
    } catch (reason) {
      creating = false;
      render();
      const err = document.querySelector("#form-error");
      if (err) err.textContent = String(reason);
      else showToast(String(reason));
    }
  });
  // Window controls (borderless).
  document.querySelector("#hide-btn")?.addEventListener("click", () => invoke("hide_app").catch((e) => showToast(String(e))));
  document.querySelector("#quit-btn")?.addEventListener("click", () => invoke("quit_app").catch((e) => showToast(String(e))));
  document.querySelectorAll<HTMLElement>("[data-tab]").forEach((b) =>
    b.addEventListener("click", () => {
      tab = b.dataset.tab as Tab;
      if (tab === "chats") detail = null;
      render();
    }));
  document.querySelector("#pin-btn")?.addEventListener("click", async () => {
    try { await invoke("set_always_on_top", { enabled: !(state?.alwaysOnTop ?? true) }); await loadAll(); }
    catch (e) { showToast(String(e)); }
  });
  document.querySelectorAll<HTMLElement>("[data-chat]").forEach((b) =>
    b.addEventListener("click", () => selectChat(b.dataset.chat || null)));
  document.querySelector<HTMLFormElement>("#composer")?.addEventListener("submit", sendComposer);
  document.querySelector<HTMLInputElement>("#composer-input")?.addEventListener("input", (e) => {
    composerDraft = (e.currentTarget as HTMLInputElement).value;
    sendTyping(true);
  });
  document.querySelector<HTMLInputElement>("#file-input")?.addEventListener("change", sendFile);
  document.querySelector("#reply-cancel")?.addEventListener("click", () => { replyTo = null; render(); focusComposer(); });
  document.querySelector("#edit-cancel")?.addEventListener("click", () => { editingId = null; composerDraft = ""; render(); focusComposer(); });
  document.querySelectorAll<HTMLElement>("[data-reply]").forEach((b) =>
    b.addEventListener("click", () => {
      const msg = detail?.messages.find((m) => m.id === b.dataset.reply);
      if (msg) { replyTo = { id: msg.id, body: msg.body, from: msg.senderUsername }; render(); focusComposer(); }
    }));
  document.querySelectorAll<HTMLElement>("[data-edit]").forEach((b) =>
    b.addEventListener("click", () => {
      const msg = detail?.messages.find((m) => m.id === b.dataset.edit);
      if (msg) { editingId = msg.id; composerDraft = msg.body; replyTo = null; render(); focusComposer(); }
    }));
  document.querySelectorAll<HTMLElement>(".feed .msg").forEach((el) => {
    el.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      const id = el.dataset.mid;
      const msg = detail?.messages.find((m) => m.id === id) ?? searchResults?.find((m) => m.id === id);
      if (!msg) return;
      menuFor = {
        id: msg.id,
        x: Math.min(e.clientX, window.innerWidth - 150),
        y: Math.min(e.clientY, window.innerHeight - 140),
        mine: msg.senderUsername === (state?.username ?? ""),
      };
      render();
    });
  });
  document.querySelector("#ctxback")?.addEventListener("click", () => { menuFor = null; render(); });
  document.querySelectorAll<HTMLElement>("[data-ctx]").forEach((b) =>
    b.addEventListener("click", async () => {
      const id = menuFor?.id;
      const action = b.dataset.ctx;
      menuFor = null;
      if (!id || !action) { render(); return; }
      const msg = detail?.messages.find((m) => m.id === id);
      if (action === "copy" && msg) {
        try { await navigator.clipboard.writeText(msg.body); } catch { /* clipboard denied */ }
        render();
      } else if (action === "reply" && msg) {
        replyTo = { id: msg.id, body: msg.body, from: msg.senderUsername };
        render(); focusComposer();
      } else if (action === "edit" && msg) {
        editingId = msg.id; composerDraft = msg.body; replyTo = null;
        render(); focusComposer();
      } else if (action === "del") {
        if (!confirm("Delete this message for everyone?")) { render(); return; }
        try { await invoke("delete_message", { messageId: id }); await reloadDetail(); }
        catch (err) { showToast(String(err)); }
      } else { render(); }
    }));
  document.querySelectorAll<HTMLElement>("[data-del]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!b.dataset.del || !confirm("Delete this message for everyone?")) return;
      try { await invoke("delete_message", { messageId: b.dataset.del }); await reloadDetail(); }
      catch (e) { showToast(String(e)); }
    }));
  document.querySelector("#group-btn")?.addEventListener("click", () => { showGroupPanel = !showGroupPanel; render(); });
  document.querySelector("#search-btn")?.addEventListener("click", () => {
    searchOpen = true; searchQuery = ""; searchResults = null; render();
  });
  document.querySelector("#search-clear")?.addEventListener("click", () => {
    searchOpen = false; searchQuery = ""; searchResults = null; render(); focusComposer();
  });
  document.querySelector<HTMLInputElement>("#thread-search")?.addEventListener("input", (e) => {
    searchQuery = (e.currentTarget as HTMLInputElement).value;
    window.clearTimeout(searchTimer);
    if (searchQuery.trim().length < 2 || !detail) { searchResults = null; return; }
    const convId = detail.conversation.id;
    const query = searchQuery;
    searchTimer = window.setTimeout(async () => {
      try {
        const results = await invoke<ChatMessage[]>("search_messages", { conversationId: convId, query });
        if (query !== searchQuery) return; // stale
        searchResults = results;
        render();
      } catch (err) { showToast(String(err)); }
    }, 250);
  });
  document.querySelector<HTMLFormElement>("#rename-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = new FormData(e.currentTarget as HTMLFormElement).get("name");
    try { await invoke("rename_group", { groupId: detail?.conversation.id, name }); await reloadDetail(); }
    catch (err) { showToast(String(err)); }
  });
  document.querySelector("#add-members-btn")?.addEventListener("click", async () => {
    const members = Array.from(document.querySelectorAll<HTMLInputElement>("[data-add-member]:checked")).map((i) => i.dataset.addMember!);
    if (!members.length || !detail) return;
    try { await invoke("add_group_members", { groupId: detail.conversation.id, members }); await reloadDetail(); }
    catch (e) { showToast(String(e)); }
  });
  document.querySelectorAll<HTMLElement>("[data-kick]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!detail || !b.dataset.kick || !confirm(`Remove @${b.dataset.kick}?`)) return;
      try { await invoke("remove_group_members", { groupId: detail.conversation.id, members: [b.dataset.kick] }); await reloadDetail(); }
      catch (e) { showToast(String(e)); }
    }));
  document.querySelector("#leave-btn")?.addEventListener("click", async () => {
    if (!detail || !confirm("Leave this group?")) return;
    try { await invoke("leave_group", { groupId: detail.conversation.id }); detail = null; await loadAll(); }
    catch (e) { showToast(String(e)); }
  });
  document.querySelector("#delete-chat-btn")?.addEventListener("click", async () => {
    if (!detail || !confirm("Delete this chat locally?")) return;
    try { await invoke("delete_chat", { conversationId: detail.conversation.id }); detail = null; await loadAll(); }
    catch (e) { showToast(String(e)); }
  });
  // Friends tab
  document.querySelector("#copy-invite")?.addEventListener("click", async () => {
    try {
      const code = await invoke<string>("my_invite");
      await navigator.clipboard.writeText(code);
      showToast("Invite copied — send it to your friend.");
    } catch (e) { showToast(String(e)); }
  });
  document.querySelector<HTMLFormElement>("#import-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (addingFriend) return;
    const code = new FormData(e.currentTarget as HTMLFormElement).get("code");
    addingFriend = true;
    render();
    try {
      const res = await invoke<ImportResult>("import_invite", { code });
      if (res.surfaced > 0) {
        showToast(`@${res.username} added — ${res.surfaced} waiting request${res.surfaced === 1 ? "" : "s"} opened!`);
      } else if (res.delivered) {
        showToast(`Ask sent to @${res.username}.`);
      } else {
        showToast(`Saved @${res.username} — ask queued, sends automatically when they're reachable.`);
      }
      newGroupMembers.clear();
      await loadAll();
    } catch (err) { showToast(String(err)); }
    addingFriend = false;
    render();
  });
  document.querySelectorAll<HTMLElement>("[data-dm]").forEach((b) =>
    b.addEventListener("click", async () => {
      const username = b.dataset.dm!;
      const existing = chats.find((c) => c.kind === "dm" && c.members.includes(username));
      if (existing) { tab = "chats"; await selectChat(existing.id); return; }
      showToast("Say hi after they accept your request.");
    }));
  document.querySelectorAll<HTMLElement>("[data-ask]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        const delivered = await invoke<boolean>("send_friend_request", { username: b.dataset.ask });
        showToast(delivered ? "Ask sent." : "Peer unreachable — ask queued, retries automatically.");
        await loadAll();
      }
      catch (e) { showToast(String(e)); }
    }));
  document.querySelectorAll<HTMLElement>("[data-accept]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        const id = await invoke<string>("accept_request", { requestId: b.dataset.accept });
        tab = "chats"; await loadAll(); await selectChat(id);
      } catch (e) { showToast(String(e)); }
    }));
  document.querySelectorAll<HTMLElement>("[data-reject]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await invoke("reject_request", { requestId: b.dataset.reject }); await loadAll(); }
      catch (e) { showToast(String(e)); }
    }));
  document.querySelectorAll<HTMLElement>("[data-remove]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm(`Remove @${b.dataset.remove}?`)) return;
      try { await invoke("remove_friend", { username: b.dataset.remove }); await loadAll(); }
      catch (e) { showToast(String(e)); }
    }));
  document.querySelectorAll<HTMLElement>("[data-block]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await invoke("block_user", { username: b.dataset.block }); await loadAll(); }
      catch (e) { showToast(String(e)); }
    }));
  document.querySelectorAll<HTMLElement>("[data-unblock]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await invoke("unblock_user", { username: b.dataset.unblock }); await loadAll(); }
      catch (e) { showToast(String(e)); }
    }));
  document.querySelectorAll<HTMLInputElement>("[data-new-group-member]").forEach((box) =>
    box.addEventListener("change", () => {
      const username = box.dataset.newGroupMember!;
      if (box.checked) newGroupMembers.add(username); else newGroupMembers.delete(username);
    }));
  document.querySelector<HTMLFormElement>("#group-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = new FormData(e.currentTarget as HTMLFormElement).get("name");
    if (!newGroupMembers.size) { showToast("Pick at least one friend."); return; }
    try {
      const id = await invoke<string>("create_group", { name, members: [...newGroupMembers] });
      newGroupMembers.clear();
      tab = "chats"; await loadAll(); await selectChat(id);
    } catch (err) { showToast(String(err)); }
  });
  document.querySelector("#settings-btn")?.addEventListener("click", () => { showSettings = !showSettings; render(); });
  document.querySelectorAll<HTMLElement>("[data-status]").forEach((b) =>
    b.addEventListener("click", async () => {
      try {
        const label = await invoke<string>("set_presence", { status: b.dataset.status });
        showToast(`You appear ${label}.`);
        await loadAll();
      } catch (err) { showToast(String(err)); }
    }));
  document.querySelector<HTMLFormElement>("#coord-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const values = new FormData(e.currentTarget as HTMLFormElement);
    try {
      await invoke("set_coordinator", { kind: values.get("kind"), workerUrl: values.get("url") });
      await loadAll();
      showToast("Coordinator updated.");
    } catch (err) { showToast(String(err)); }
  });
  document.querySelector("#mailbox-btn")?.addEventListener("click", async () => {
    try {
      const count = await invoke<number>("check_mailbox");
      showToast(count ? `Mailbox: ${count} new.` : "Mailbox checked — nothing new.");
      await loadAll();
    } catch (e) { showToast(String(e)); }
  });
  document.querySelector("#logout-btn")?.addEventListener("click", async () => {
    if (!confirm("Log out? This removes your profile, friends and chats from this device.")) return;
    try {
      await invoke("logout");
      detail = null; chats = []; friends = null; presence = null;
      newGroupMembers.clear(); tab = "chats";
      await loadAll();
      showToast("Logged out.");
    } catch (e) { showToast(String(e)); }
  });
  document.querySelector("#diag-btn")?.addEventListener("click", async () => {
    try {
      const diag = await invoke("transport_diagnostics");
      const out = document.querySelector("#diag-out");
      if (out) out.innerHTML = `<pre>${esc(JSON.stringify(diag, null, 1))}</pre>`;
    } catch (e) { showToast(String(e)); }
  });
  document.querySelectorAll<HTMLElement>("[data-cancel-file]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await invoke("cancel_file", { fileId: b.dataset.cancelFile }); await reloadDetail(); }
      catch (e) { showToast(String(e)); }
    }));
  document.querySelector("#quickwrap")?.addEventListener("click", (e) => {
    if ((e.target as HTMLElement).id === "quickwrap") { quickOpen = false; quickQuery = ""; render(); }
  });
  document.querySelector<HTMLInputElement>("#quick-input")?.addEventListener("input", (e) => {
    quickQuery = (e.currentTarget as HTMLInputElement).value;
    render();
  });
  document.querySelector<HTMLInputElement>("#quick-input")?.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter") return;
    const q = quickQuery.toLowerCase();
    const first = chats.find((c) => (c.name + " " + c.members.join(" ")).toLowerCase().includes(q));
    if (first) { quickOpen = false; quickQuery = ""; await selectChat(first.id); }
  });
  document.querySelectorAll<HTMLElement>("[data-quick]").forEach((b) =>
    b.addEventListener("click", async () => { quickOpen = false; quickQuery = ""; await selectChat(b.dataset.quick || null); }));
  const inviteField = document.querySelector<HTMLInputElement>("#my-invite");
  if (inviteField) {
    invoke<string>("my_invite").then((code) => { inviteField.value = code; }).catch(() => {});
  }
  const feed = document.querySelector("#feed");
  if (feed) feed.scrollTop = feed.scrollHeight;
}

async function reloadDetail() {
  if (detail) {
    try { detail = await invoke<ChatDetail>("open_chat", { conversationId: detail.conversation.id }); } catch { /* keep old */ }
  }
  await loadAll();
}

async function sendComposer(e: SubmitEvent) {
  e.preventDefault();
  if (!detail) return;
  const input = document.querySelector<HTMLInputElement>("#composer-input");
  const text = (input?.value ?? composerDraft).trim();
  if (!text) return;
  composerDraft = "";
  sendTyping(false);
  try {
    if (editingId) {
      await invoke("edit_message", { messageId: editingId, body: text });
      editingId = null;
    } else {
      await invoke("send_text", {
        conversationId: detail.conversation.id,
        body: text,
        replyTo: replyTo?.id ?? null,
      });
      replyTo = null;
    }
    await reloadDetail();
    focusComposer();
  } catch (err) { showToast(String(err)); }
}

function sendTyping(typing: boolean) {
  if (!detail) return;
  if (typing === typingSent) return;
  if (typing) {
    typingSent = true;
    invoke("send_typing", { conversationId: detail.conversation.id, typing: true }).catch(() => {});
    window.clearTimeout(typingTimer);
    typingTimer = window.setTimeout(() => {
      typingSent = false;
      if (detail) invoke("send_typing", { conversationId: detail.conversation.id, typing: false }).catch(() => {});
    }, 4000);
  } else if (typingSent) {
    typingSent = false;
    window.clearTimeout(typingTimer);
    invoke("send_typing", { conversationId: detail.conversation.id, typing: false }).catch(() => {});
  }
}

async function sendFile(e: Event) {
  const input = e.currentTarget as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (!file || !detail) return;
  if (file.size > 25 * 1024 * 1024) { showToast("Files are capped at 25 MB in V1."); return; }
  try {
    const buffer = await file.arrayBuffer();
    await invoke("send_file", {
      conversationId: detail.conversation.id,
      filename: file.name,
      mimeType: file.type || "application/octet-stream",
      data: Array.from(new Uint8Array(buffer)),
    });
    showToast(`Sending ${file.name}…`);
    await reloadDetail();
  } catch (err) { showToast(String(err)); }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

listen("hearth://refresh", () => loadAll()).catch(() => {});
listen("focus-composer", () => focusComposer()).catch(() => {});
listen<string>("hearth://toast", (e) => showToast(e.payload)).catch(() => {});
listen("hearth://file-progress", () => loadAll()).catch(() => {});
// Refresh live state, but never while onboarding (typing):
// re-rendering there wipes form drafts and steals focus.
window.setInterval(() => {
  if (!state?.profileExists) return;
  const active = document.activeElement;
  if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.tagName === "SELECT")) return;
  loadAll();
}, 8000);

loadAll();
