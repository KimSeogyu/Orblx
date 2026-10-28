"use strict";

const STEP_MS = 480;
const LEVEL_TITLE = {
  city_breeze: "City Breeze",
  agent_jit: "Agent JIT",
  radioactive_nat: "Radioactive NAT",
};
const PLAY_BUTTON = {
  city_breeze: "play-city",
  agent_jit: "play-agent",
  radioactive_nat: "play-hard",
};
const RESET_KINDS = {
  difficulty_selected: true,
  level_selected: true,
  smash_udp_block: true,
  smash_agent_spawn: true,
};

let lastPayload = "";
let seenSeq = 0;
let inflight = false;
let busy = false;
const seenFeed = new Set();
const queue = [];

function showError(message) {
  document.getElementById("error").textContent = message;
}

function clearError() {
  document.getElementById("error").textContent = "";
}

async function readJson(response) {
  const text = await response.text();
  if (!response.ok) {
    throw new Error(text || "The harness request failed.");
  }
  return JSON.parse(text);
}

function latestSeq(state) {
  if (state.events.length === 0) {
    return 0;
  }
  return state.events[state.events.length - 1].seq;
}

function isCurrent(state) {
  const seq = latestSeq(state);
  if (seq < seenSeq) {
    return false;
  }
  seenSeq = seq;
  return true;
}

async function loadState() {
  try {
    const response = await fetch("/api/state");
    const state = await readJson(response);
    if (!isCurrent(state)) {
      return;
    }
    clearError();
    render(state);
  } catch (error) {
    showError(error.message || "The harness request failed.");
  }
}

async function postJson(url, id) {
  if (inflight) {
    return;
  }
  inflight = true;
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: id }),
    });
    const state = await readJson(response);
    if (!isCurrent(state)) {
      return;
    }
    clearError();
    render(state);
  } catch (error) {
    showError(error.message || "The harness request failed.");
  } finally {
    inflight = false;
  }
}

function render(state) {
  const payload = JSON.stringify(state);
  if (payload !== lastPayload) {
    lastPayload = payload;
    document.getElementById("mark").textContent = state.skeleton ? "skeleton" : "live";
    document.getElementById("notice").textContent = state.notice;
    renderAudit(state.audit);
    renderLevels(state.levels);
    renderDifficulties(state.difficulties);
    document.getElementById("hook").textContent = state.fault_detail;
    renderSession(state.session);
    renderSteps(state.levels);
    renderEvents(state.events);
    markSelected(state);
  }
  ingestState(state);
}

function markSelected(state) {
  let selected = "";
  for (const level of state.levels) {
    if (level.selected) {
      selected = level.id;
    }
  }
  const buttons = PLAY_BUTTON;
  const ids = Object.keys(buttons);
  for (let index = 0; index < ids.length; index += 1) {
    const id = ids[index];
    const button = document.getElementById(buttons[id]);
    const on = id === selected;
    button.className = on ? "choice selected" : "choice";
    button.setAttribute("aria-pressed", on ? "true" : "false");
  }
  if (selected && LEVEL_TITLE[selected]) {
    document.getElementById("level-name").textContent = LEVEL_TITLE[selected];
  }
}

function ingestState(state) {
  for (let index = 0; index < state.events.length; index += 1) {
    ingest(state.events[index].detail);
  }
}

function ingest(raw) {
  if (typeof raw !== "string" || seenFeed.has(raw)) {
    return;
  }
  let body;
  try {
    body = JSON.parse(raw);
  } catch (error) {
    return;
  }
  if (!body || body.v !== 1 || typeof body.kind !== "string") {
    return;
  }
  seenFeed.add(raw);
  queue.push(body);
  pump();
}

function pump() {
  if (busy) {
    return;
  }
  const next = queue.shift();
  if (!next) {
    return;
  }
  busy = true;
  applyFeed(next);
  window.setTimeout(function () {
    busy = false;
    pump();
  }, STEP_MS);
}

function applyFeed(body) {
  if (RESET_KINDS[body.kind]) {
    resetBoard();
  }
  const game = document.getElementById("game");
  game.dataset.seq = String(body.seq);
  game.dataset.kind = body.kind;
  if (LEVEL_TITLE[body.level]) {
    document.getElementById("level-name").textContent = LEVEL_TITLE[body.level];
  }
  document.getElementById("beat").textContent = beatText(body);
  pushTape(body);
  applyIdentity(body);
  applyPath(body);
  applyApps(body);
  applyPacket(body);
}

function beatText(body) {
  if (typeof body.detail === "string" && body.detail.length > 0) {
    return body.detail;
  }
  const note = fieldNote(body);
  if (note.length > 0) {
    return body.kind + " " + note;
  }
  return body.kind;
}

function fieldNote(body) {
  const parts = [];
  if (typeof body.ok === "boolean") {
    parts.push(body.ok ? "ok" : "not ok");
  }
  if (body.hop) {
    parts.push("hop " + body.hop);
  }
  if (body.path) {
    parts.push("path " + body.path);
  }
  if (body.mode) {
    parts.push(body.mode);
  }
  if (body.overlay_ip) {
    parts.push("overlay " + body.overlay_ip);
  }
  if (body.from && body.to) {
    parts.push(body.from + " to " + body.to);
  }
  if (body.host) {
    parts.push(body.host);
  }
  if (body.status !== undefined) {
    parts.push("status " + String(body.status));
  }
  if (body.within_s !== undefined) {
    parts.push("within_s " + String(body.within_s));
  }
  if (body.peer_uri) {
    parts.push(body.peer_uri);
  }
  if (body.reason) {
    parts.push(body.reason);
  }
  if (body.rtt_ms !== undefined) {
    parts.push("rtt_ms " + String(body.rtt_ms));
  }
  return parts.join(" ");
}

function pushTape(body) {
  const item = document.createElement("li");
  const kind = document.createElement("span");
  kind.className = "kind";
  kind.textContent = String(body.seq) + " " + body.kind;
  const note = typeof body.detail === "string" && body.detail.length > 0
    ? body.detail
    : fieldNote(body);
  item.append(kind, document.createTextNode(note.length > 0 ? " " + note : ""));
  const tape = document.getElementById("tape");
  tape.append(item);
  tape.scrollTop = tape.scrollHeight;
}

function resetBoard() {
  document.getElementById("tape").replaceChildren();
  document.getElementById("spoke-name").textContent = "Human";
  setChip("svid-chip", "none", "SVID");
  setChip("ticket-chip", "none", "Ticket");
  setPath("idle", "No path yet.");
  document.getElementById("relay-status").textContent = "Idle";
  setApp("app-a", "idle", "Waiting");
  setApp("app-b", "idle", "Waiting");
  const packet = document.getElementById("packet");
  packet.className = "packet idle";
  packet.hidden = true;
  const clear = document.getElementById("clear");
  clear.hidden = true;
  clear.textContent = "";
}

function setChip(id, state, text) {
  const chip = document.getElementById(id);
  chip.dataset.state = state;
  chip.textContent = text;
}

function setPath(mode, label) {
  document.getElementById("mesh-link").dataset.mode = mode;
  const path = document.getElementById("path-state");
  path.dataset.mode = mode;
  path.textContent = label;
  document.getElementById("node-relay").dataset.lit = mode === "relay" ? "true" : "false";
}

function setApp(id, acl, text) {
  const node = document.getElementById(id);
  node.dataset.acl = acl;
  document.getElementById(id + "-status").textContent = text;
}

function applyIdentity(body) {
  if (body.peer_uri) {
    document.getElementById("spoke-name").textContent = body.peer_uri;
  }
  if (body.kind === "svid.issued" || body.kind === "agent.spawned") {
    setChip("svid-chip", "up", "SVID up");
  }
  if (body.kind === "svid.revoked") {
    setChip("svid-chip", "revoked", "SVID revoked");
    setPath("down", "SVID revoked");
  }
  if (body.kind === "svid.expired") {
    setChip("svid-chip", "expired", "SVID expired");
    setPath("down", "SVID expired");
  }
  if (body.kind === "ticket.verified") {
    const hash = body.ticket_hash ? String(body.ticket_hash).slice(0, 8) : "";
    setChip("ticket-chip", "up", hash.length > 0 ? "Ticket " + hash : "Ticket");
  }
  if (body.kind === "session.dropped") {
    setPath("down", body.within_s !== undefined ? "Dropped within_s " + String(body.within_s) : "Dropped");
  }
  const clear = document.getElementById("clear");
  if (body.kind === "session_up" && typeof body.detail === "string") {
    clear.hidden = false;
    clear.textContent = body.detail;
  }
  if (body.kind === "session_down" || body.kind === "svid.revoked") {
    clear.hidden = true;
    clear.textContent = "";
  }
}

function applyPath(body) {
  if (body.kind === "quic_hello") {
    setPath("mesh", body.path ? "Path " + body.path : "quic_hello");
  }
  if (body.kind === "path.direct") {
    if (body.ok === true) {
      setPath("direct", "Direct ok");
    } else {
      setPath("fault", "Direct not ok");
    }
  }
  if (body.kind === "path.switch" && body.from && body.to) {
    document.getElementById("relay-status").textContent = body.from + " to " + body.to;
  }
  if (body.kind === "relay.hop") {
    const label = body.ok === true ? "Relay hop ok" : "Relay hop";
    setPath("relay", label);
    document.getElementById("relay-status").textContent = label;
  }
  if (body.kind === "path.relay") {
    const label = body.hop ? "Relay hop " + body.hop : "Relay";
    setPath("relay", label);
    document.getElementById("relay-status").textContent = label;
  }
  if (body.kind === "path.up") {
    if (body.path === "relay") {
      setPath("relay", "Up relay");
      document.getElementById("relay-status").textContent = "Up relay";
    } else if (body.path) {
      setPath("mesh", "Up " + body.path);
    }
  }
  if (body.kind === "path.down") {
    setPath("down", body.path ? "Down " + body.path : "Down");
  }
  if (body.kind === "session_down") {
    setPath("down", body.reason ? "Session down " + body.reason : "Session down");
  }
  if (body.kind === "session_up" && body.reason === "connector") {
    setPath("mesh", "Session up");
  }
  if (body.kind === "nat.inject" && body.mode) {
    document.getElementById("relay-status").textContent = body.mode;
  }
  if (body.kind === "path.allocate" && body.overlay_ip) {
    document.getElementById("relay-status").textContent = "Allocate " + body.overlay_ip;
  }
}

function namedHost(body) {
  const text = (typeof body.detail === "string" ? body.detail : "") + " " + (body.host || "");
  if (text.indexOf("app-b.orblx.test") !== -1) {
    return "app-b";
  }
  if (text.indexOf("app-a.orblx.test") !== -1) {
    return "app-a";
  }
  return "";
}

function applyApps(body) {
  const host = namedHost(body);
  if (body.kind === "connector_https" && host.length > 0) {
    const status = body.status !== undefined ? String(body.status) : "";
    setApp(host, "open", (body.host || host) + (status.length > 0 ? " " + status : ""));
  }
  if (body.kind === "jit.allow" && host.length > 0) {
    setApp(host, "allow", "Allow");
  }
  if (body.kind === "jit.deny" && host.length > 0) {
    setApp(host, "deny", "Deny");
  }
}

function applyPacket(body) {
  let lane = "";
  const text = typeof body.detail === "string" ? body.detail : "";
  if (body.kind === "frame_rx" || text.indexOf("came back") !== -1) {
    lane = "spoke";
  } else if (text.indexOf("app-b.orblx.test") !== -1) {
    lane = "b";
  } else if (text.indexOf("app-a.orblx.test") !== -1) {
    lane = "a";
  } else if (body.kind === "frame_tx" && text.indexOf("ping") !== -1) {
    lane = "hub";
  } else if (body.kind === "frame_tx") {
    lane = "hub";
  } else if (body.kind === "path.relay" || body.kind === "relay.hop" || (body.kind === "path.up" && body.path === "relay")) {
    lane = "relay";
  } else if (body.kind === "path.direct" && body.ok === false) {
    lane = "hub";
  }
  if (lane.length === 0) {
    return;
  }
  const packet = document.getElementById("packet");
  packet.hidden = false;
  packet.className = "packet at-" + lane;
}

function renderLevels(levels) {
  const root = document.getElementById("levels");
  root.replaceChildren();
  for (const level of levels) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = level.selected ? "choice selected" : "choice";
    button.setAttribute("aria-pressed", level.selected ? "true" : "false");
    button.textContent = level.title;
    button.addEventListener("click", function () {
      if (level.id === "city_breeze") {
        startOidcLogin();
        return;
      }
      postJson("/api/level", level.id);
    });
    const goal = document.createElement("p");
    goal.className = "goal";
    goal.textContent = level.goal;
    const block = document.createElement("div");
    block.className = "level";
    block.append(button, goal);
    root.append(block);
  }
}

function renderDifficulties(items) {
  const root = document.getElementById("difficulties");
  root.replaceChildren();
  let note = "";
  for (const item of items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = item.selected ? "choice selected" : "choice";
    button.setAttribute("aria-pressed", item.selected ? "true" : "false");
    button.textContent = item.label;
    button.addEventListener("click", function () {
      if (item.id === "easy") {
        startOidcLogin();
        return;
      }
      postJson("/api/difficulty", item.id);
    });
    root.append(button);
    if (item.selected) {
      note = item.note;
    }
  }
  document.getElementById("difficulty-note").textContent = note;
}

function renderSession(session) {
  fillList(document.getElementById("peers"), session.peers, session.peer_empty, function (row) {
    return row.name + ". " + row.detail;
  });
  fillList(document.getElementById("packets"), session.packets, session.packet_empty, function (row) {
    return String(row.seq) + ". " + row.detail;
  });
  fillPanel(document.getElementById("quic"), session.quic);
  fillPanel(document.getElementById("svid"), session.svid);
  fillPanel(document.getElementById("ticket"), session.ticket);
}

function fillList(root, rows, emptyText, line) {
  root.replaceChildren();
  if (rows.length === 0) {
    const paragraph = document.createElement("p");
    paragraph.textContent = emptyText;
    root.append(paragraph);
    return;
  }
  const list = document.createElement("ul");
  for (const row of rows) {
    const item = document.createElement("li");
    item.textContent = line(row);
    list.append(item);
  }
  root.append(list);
}

function fillPanel(root, panel) {
  root.replaceChildren();
  const state = document.createElement("p");
  state.className = "state";
  state.textContent = "State: " + panel.state + ".";
  const detail = document.createElement("p");
  detail.textContent = panel.detail;
  root.append(state, detail);
}

function renderSteps(levels) {
  const root = document.getElementById("steps");
  root.replaceChildren();
  let selected = null;
  for (const level of levels) {
    if (level.selected) {
      selected = level;
    }
  }
  if (!selected) {
    const paragraph = document.createElement("p");
    paragraph.textContent = "Select Easy, Medium, or Hard.";
    root.append(paragraph);
    return;
  }
  const title = document.createElement("p");
  const live = selected.body === "live" ? "The level is live." : "The level has not run.";
  title.textContent = selected.title + ". " + live;
  const list = document.createElement("ol");
  for (const step of selected.steps) {
    const item = document.createElement("li");
    item.textContent = step.text + " Status: " + statusLabel(step.status) + ".";
    list.append(item);
  }
  root.append(title, list);
}

function statusLabel(status) {
  if (status === "not_run") {
    return "not run";
  }
  if (status === "pass") {
    return "pass";
  }
  if (status === "fail") {
    return "fail";
  }
  return status;
}

function renderAudit(audit) {
  const root = document.getElementById("audit");
  if (!audit) {
    root.textContent = "";
    return;
  }
  const chain = audit.ok ? "The audit chain is valid." : "The audit chain check failed.";
  root.textContent = "Audit start " + audit.start + ". Audit end " + audit.end + ". Audit deny " + audit.deny + ". " + chain;
}

function eventSummary(body) {
  return fieldNote(body);
}

function eventLine(event) {
  let detail = event.detail;
  let kind = event.kind;
  try {
    const body = JSON.parse(event.detail);
    if (body.kind) {
      kind = body.kind;
    }
    detail = body.detail || eventSummary(body) || event.detail;
  } catch (error) {
    detail = event.detail;
  }
  return event.seq + " " + sourceLabel(event.source) + " " + kind + " " + detail;
}

function sourceLabel(source) {
  if (source === "harness") {
    return "Harness";
  }
  if (source === "identity") {
    return "Identity";
  }
  if (source === "edge_nat") {
    return "EdgeNAT";
  }
  if (source === "datapath") {
    return "Datapath";
  }
  return source;
}

function renderEvents(events) {
  const root = document.getElementById("events");
  const atBottom = root.scrollTop + root.clientHeight >= root.scrollHeight - 4;
  root.replaceChildren();
  if (events.length === 0) {
    const item = document.createElement("li");
    item.textContent = "The event log is empty.";
    root.append(item);
    return;
  }
  for (const event of events) {
    const item = document.createElement("li");
    item.textContent = eventLine(event);
    root.append(item);
  }
  if (atBottom) {
    root.scrollTop = root.scrollHeight;
  }
}

function startOidcLogin() {
  const state = randomHex(16);
  const redirect = window.location.origin + "/oidc/callback";
  const params = new URLSearchParams({
    client_id: "gyeol-sim",
    response_type: "code",
    redirect_uri: redirect,
    state: state,
    scope: "openid",
  });
  window.location.assign("/oidc/authorize?" + params.toString());
}

function randomHex(size) {
  const values = new Uint8Array(size);
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(values);
  } else {
    for (let index = 0; index < values.length; index += 1) {
      values[index] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(values, function (value) {
    return value.toString(16).padStart(2, "0");
  }).join("");
}

document.getElementById("play-city").addEventListener("click", function () {
  startOidcLogin();
});
document.getElementById("play-agent").addEventListener("click", function () {
  postJson("/api/difficulty", "medium");
});
document.getElementById("play-hard").addEventListener("click", function () {
  postJson("/api/difficulty", "hard");
});
document.getElementById("smash-revoke").addEventListener("click", function () {
  postJson("/api/smash", "revoke");
});
document.getElementById("smash-udp-block").addEventListener("click", function () {
  postJson("/api/smash", "udp_block");
});
document.getElementById("smash-agent-spawn").addEventListener("click", function () {
  postJson("/api/smash", "agent_spawn");
});
document.getElementById("eng-toggle").addEventListener("click", function () {
  const eng = document.getElementById("eng");
  const open = eng.hasAttribute("hidden");
  if (open) {
    eng.removeAttribute("hidden");
  } else {
    eng.setAttribute("hidden", "");
  }
  this.setAttribute("aria-pressed", open ? "true" : "false");
});

loadState();
setInterval(loadState, 1000);

if (window.EventSource) {
  const stream = new EventSource("/events");
  stream.onmessage = function (message) {
    ingest(message.data);
  };
}
