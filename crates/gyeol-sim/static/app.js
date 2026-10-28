"use strict";

let lastPayload = "";
let seenSeq = 0;

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
  }
}

function render(state) {
  const payload = JSON.stringify(state);
  if (payload === lastPayload) {
    return;
  }
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
  const parts = [];
  if (body.mode) {
    parts.push(body.mode);
  }
  if (body.overlay_ip) {
    parts.push("overlay " + body.overlay_ip);
  }
  if (body.reflexive) {
    parts.push("reflexive " + body.reflexive);
  }
  if (typeof body.ok === "boolean") {
    parts.push(body.ok ? "ok" : "not ok");
  }
  if (body.hop) {
    parts.push("hop " + body.hop);
  }
  if (body.path) {
    parts.push("path " + body.path);
  }
  if (body.from && body.to) {
    parts.push(body.from + " to " + body.to);
  }
  if (body.rtt_ms !== undefined) {
    parts.push(String(body.rtt_ms) + " ms");
  }
  if (body.peer_uri) {
    parts.push(body.peer_uri);
  }
  if (parts.length === 0) {
    return "";
  }
  return parts.join(". ") + ".";
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

document.getElementById("smash-revoke").addEventListener("click", function () {
  postJson("/api/smash", "revoke");
});
document.getElementById("smash-udp-block").addEventListener("click", function () {
  postJson("/api/smash", "udp_block");
});
document.getElementById("smash-agent-spawn").addEventListener("click", function () {
  postJson("/api/smash", "agent_spawn");
});

loadState();
setInterval(loadState, 1000);

if (window.EventSource) {
  const stream = new EventSource("/events");
  stream.onmessage = function () {
    loadState();
  };
}
