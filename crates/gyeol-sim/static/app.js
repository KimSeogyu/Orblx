"use strict";

const RUN_MS = 35000;
const STEP_MIN = 800;
const STEP_MAX = 4000;
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
const BLURB_FOR = {
  easy: "blurb-easy",
  medium: "blurb-medium",
  hard: "blurb-hard",
};
const NEXT_DIFFICULTY = {
  city_breeze: "medium",
  agent_jit: "hard",
};
const RESET_KINDS = {
  difficulty_selected: true,
  level_selected: true,
  smash_udp_block: true,
  smash_agent_spawn: true,
};
const BREAK_KINDS = {
  difficulty_selected: true,
  level_selected: true,
  smash_udp_block: true,
  smash_agent_spawn: true,
  smash_revoke: true,
};
const FIELD_KEYS = [
  "kind",
  "seq",
  "ts_ms",
  "source",
  "level",
  "difficulty",
  "session_id",
  "path",
  "ok",
  "hop",
  "mode",
  "host",
  "status",
  "reason",
  "peer_uri",
  "within_s",
  "rtt_ms",
  "ticket_hash",
  "overlay_ip",
  "from",
  "to",
  "frame_type",
  "flags",
  "ipv4_len",
  "bytes",
  "detail",
];
const NODE_IDS = ["node-spoke", "actor-agent", "node-hub", "app-a", "app-b", "node-relay"];
const FX_ANCHOR = {
  "node-spoke": ["18%", "18%"],
  "actor-agent": ["18%", "48%"],
  "node-hub": ["46%", "44%"],
  "app-a": ["74%", "16%"],
  "app-b": ["74%", "70%"],
  "node-relay": ["18%", "74%"],
};
const BOND_POS = {
  "node-spoke": [18, 22],
  "actor-agent": [18, 50],
  "node-hub": [50, 50],
  "app-a": [82, 20],
  "app-b": [82, 78],
  "node-relay": [18, 80],
};

let lastPayload = "";
let seenSeq = 0;
let inflight = false;
let busy = false;
let booted = false;
let pacePending = false;
let stepMs = STEP_MIN;
let runTotal = 0;
let runDone = 0;
let inspectTarget = "";
let runResult = null;
const seenFeed = new Set();
const queue = [];
const bootBuffer = [];
const lastByNode = {};

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
    finishBoot();
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
    renderCurve(state.difficulties, state.fault_detail);
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
    button.parentElement.dataset.selected = on ? "true" : "false";
  }
  if (selected && LEVEL_TITLE[selected]) {
    document.getElementById("level-name").textContent = LEVEL_TITLE[selected];
    document.getElementById("game").dataset.level = selected;
  }
}

function renderCurve(items, faultDetail) {
  const root = document.getElementById("curve");
  root.replaceChildren();
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    const step = document.createElement("li");
    step.className = item.selected ? "step selected" : "step";
    step.dataset.difficulty = item.id;
    step.style.setProperty("--rank", String(index + 1));
    step.textContent = item.label;
    if (item.selected) {
      step.setAttribute("aria-current", "step");
    }
    root.append(step);
    const blurb = document.getElementById(BLURB_FOR[item.id]);
    if (blurb && item.note) {
      blurb.textContent = item.note;
    }
  }
  document.getElementById("fault-line").textContent = faultDetail;
}

function ingestState(state) {
  for (let index = 0; index < state.events.length; index += 1) {
    ingest(state.events[index].detail);
  }
}

function parseFeed(raw) {
  if (typeof raw !== "string" || seenFeed.has(raw)) {
    return null;
  }
  let body;
  try {
    body = JSON.parse(raw);
  } catch (error) {
    return null;
  }
  if (!body || body.v !== 1 || typeof body.kind !== "string") {
    return null;
  }
  seenFeed.add(raw);
  return body;
}

function ingest(raw) {
  const body = parseFeed(raw);
  if (!body) {
    return;
  }
  if (!booted) {
    bootBuffer.push(body);
    return;
  }
  enqueue(body);
}

function finishBoot() {
  if (booted) {
    return;
  }
  booted = true;
  const fresh = bootBuffer.splice(0, bootBuffer.length);
  let start = 0;
  for (let index = 0; index < fresh.length; index += 1) {
    if (RESET_KINDS[fresh[index].kind]) {
      start = index;
    }
  }
  for (let index = 0; index < start; index += 1) {
    applyFeed(fresh[index], false);
  }
  for (let index = start; index < fresh.length; index += 1) {
    enqueue(fresh[index]);
  }
}

function enqueue(body) {
  if (BREAK_KINDS[body.kind]) {
    queue.splice(0, queue.length);
    runDone = 0;
    runResult = null;
    document.getElementById("endcard").hidden = true;
  }
  queue.push(body);
  schedulePace();
}

function schedulePace() {
  if (pacePending) {
    return;
  }
  pacePending = true;
  window.setTimeout(function () {
    pacePending = false;
    if (queue.length > 0) {
      const raw = Math.round(RUN_MS / queue.length);
      stepMs = Math.max(STEP_MIN, Math.min(STEP_MAX, raw));
      runTotal = runDone + queue.length;
      updateBar();
    }
    if (!busy) {
      pump();
    }
  }, 0);
}

function pump() {
  if (busy) {
    return;
  }
  const next = queue.shift();
  if (!next) {
    showEnd();
    return;
  }
  busy = true;
  applyFeed(next);
  runDone += 1;
  if (runTotal < runDone) {
    runTotal = runDone;
  }
  updateBar();
  window.setTimeout(function () {
    busy = false;
    pump();
  }, stepMs);
}

function updateBar() {
  const bar = document.getElementById("runbar");
  const label = document.getElementById("run-count");
  if (runTotal <= 0) {
    bar.max = 1;
    bar.value = 0;
    bar.textContent = "Feed 0 of 0";
    label.textContent = "";
    return;
  }
  bar.max = runTotal;
  bar.value = runDone;
  const text = "Feed " + String(runDone) + " of " + String(runTotal);
  bar.textContent = text;
  label.textContent = text;
}

function applyFeed(body, live) {
  if (RESET_KINDS[body.kind]) {
    resetBoard();
  }
  const game = document.getElementById("game");
  game.dataset.seq = String(body.seq);
  game.dataset.kind = body.kind;
  if (LEVEL_TITLE[body.level]) {
    document.getElementById("level-name").textContent = LEVEL_TITLE[body.level];
    game.dataset.level = body.level;
  }
  document.getElementById("beat").textContent = beatText(body);
  pushTape(body);
  applyIdentity(body);
  applyPath(body);
  applyApps(body);
  paintNodes(body);
  placeMarker(laneFor(body), labelFor(body));
  remember(body);
  noteResult(body);
  if (live !== false) {
    linkCast(body);
    spawnFx(body);
  }
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
  document.getElementById("fx").replaceChildren();
  const game = document.getElementById("game");
  game.dataset.result = "";
  const mesh = document.getElementById("mesh-link");
  mesh.dataset.link = "idle";
  clearReach();
  setChip("svid-chip", "none");
  setChip("ticket-chip", "none");
  setPath("idle", "No path yet.");
  document.getElementById("relay-status").textContent = "Idle";
  setApp("app-a", "idle", "Waiting");
  setApp("app-b", "idle", "Waiting");
  for (let index = 0; index < NODE_IDS.length; index += 1) {
    setNode(NODE_IDS[index], "idle");
  }
  const packet = document.getElementById("packet");
  packet.className = "packet idle";
  packet.hidden = true;
  const floatLabel = document.getElementById("float-label");
  floatLabel.className = "float-label";
  floatLabel.hidden = true;
  floatLabel.textContent = "";
  const clear = document.getElementById("clear");
  clear.hidden = true;
  clear.textContent = "";
  runResult = null;
  document.getElementById("endcard").hidden = true;
}

function setChip(id, state) {
  document.getElementById(id).dataset.state = state;
}

function setNode(id, state) {
  const node = document.getElementById(id);
  node.dataset.state = state;
  document.getElementById(id + "-state").textContent = state;
  if (id === "node-relay") {
    node.dataset.lit = state === "up" ? "true" : "false";
  }
}

function setPath(mode, label) {
  document.getElementById("mesh-link").dataset.mode = mode;
  const path = document.getElementById("path-state");
  path.dataset.mode = mode;
  path.textContent = label;
  const relay = document.getElementById("node-relay");
  if (mode === "relay" && relay.dataset.state !== "down" && relay.dataset.state !== "revoked") {
    setNode("node-relay", "up");
  }
}

function setApp(id, acl, text) {
  const node = document.getElementById(id);
  node.dataset.acl = acl;
  document.getElementById(id + "-status").textContent = text;
}

function applyIdentity(body) {
  if (body.kind === "svid.issued" || body.kind === "agent.spawned") {
    setChip("svid-chip", "up");
  }
  if (body.kind === "svid.revoked") {
    setChip("svid-chip", "revoked");
    setPath("down", "SVID revoked");
  }
  if (body.kind === "svid.expired") {
    setChip("svid-chip", "expired");
    setPath("down", "SVID expired");
  }
  if (body.kind === "ticket.verified") {
    setChip("ticket-chip", "up");
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

function paintNodes(body) {
  const kind = body.kind;
  if (kind === "svid.issued" || kind === "agent.spawned" || kind === "ticket.verified") {
    const spoke = document.getElementById("node-spoke");
    if (spoke.dataset.state === "idle") {
      setNode("node-spoke", "up");
    }
  }
  if (kind === "svid.issued" || kind === "agent.spawned") {
    setNode("node-spoke", "up");
  }
  if (kind === "svid.expired") {
    setNode("node-spoke", "down");
  }
  if (kind === "svid.revoked") {
    setNode("node-spoke", "revoked");
  }
  if (kind === "session.dropped") {
    const spoke = document.getElementById("node-spoke");
    if (spoke.dataset.state !== "revoked") {
      setNode("node-spoke", "down");
    }
    setNode("node-hub", "down");
  }
  if (kind === "quic_hello" || kind === "session_up") {
    setNode("node-hub", "up");
  }
  if (kind === "path.direct") {
    setNode("node-hub", body.ok === true ? "up" : "degraded");
  }
  if (kind === "nat.inject" || kind === "nat.probe" || kind === "path.switch") {
    setNode("node-hub", "degraded");
  }
  if (kind === "path.down") {
    setNode("node-hub", "down");
    if (body.reason === "revoked") {
      setNode("node-relay", "down");
    }
  }
  if (kind === "path.up") {
    setNode("node-hub", "up");
    if (body.path === "relay") {
      setNode("node-relay", "up");
    }
  }
  if (kind === "path.relay" || kind === "relay.hop") {
    setNode("node-relay", body.ok === false ? "degraded" : "up");
  }
  if (kind === "session_down") {
    if (body.reason === "destination") {
      setNode("app-b", "down");
    } else if (body.reason === "expired") {
      setNode("node-spoke", "down");
      setNode("node-hub", "down");
    } else if (body.reason === "revoked") {
      setNode("node-spoke", "revoked");
      setNode("node-hub", "down");
      setNode("node-relay", "down");
    } else {
      setNode("node-hub", "down");
    }
  }
  const host = namedHost(body);
  if (kind === "connector_https" && host.length > 0) {
    const bad = typeof body.status === "number" && body.status >= 400;
    setNode(host, bad ? "down" : "up");
  }
  if (kind === "jit.allow" && host.length > 0) {
    setNode(host, "up");
  }
  if (kind === "jit.deny" && host.length > 0) {
    setNode(host, "down");
  }
  paintAgent(body);
}

function paintAgent(body) {
  const agent = document.getElementById("actor-agent");
  const kind = body.kind;
  if (kind === "agent.spawned") {
    setNode("actor-agent", "up");
    return;
  }
  if (kind === "jit.allow" || kind === "jit.deny") {
    if (agent.dataset.state === "idle") {
      setNode("actor-agent", "up");
    }
    return;
  }
  if (kind === "svid.expired" && body.level === "agent_jit") {
    setNode("actor-agent", "down");
    return;
  }
  if (
    kind === "svid.revoked" ||
    kind === "session.dropped" ||
    (kind === "session_down" && body.reason === "revoked")
  ) {
    if (agent.dataset.state !== "idle") {
      setNode("actor-agent", "revoked");
    }
  }
}

function laneFor(body) {
  const text = typeof body.detail === "string" ? body.detail : "";
  const host = namedHost(body);
  if (host === "app-b" || (body.kind === "session_down" && body.reason === "destination")) {
    return "b";
  }
  if (host === "app-a") {
    return "a";
  }
  if (body.kind === "agent.spawned") {
    return "agent";
  }
  if (body.kind === "frame_rx" || text.indexOf("came back") !== -1) {
    return "spoke";
  }
  if (
    body.kind === "path.relay" ||
    body.kind === "relay.hop" ||
    (body.kind === "path.up" && body.path === "relay") ||
    body.kind === "path.allocate"
  ) {
    return "relay";
  }
  if (
    body.kind === "svid.issued" ||
    body.kind === "svid.revoked" ||
    body.kind === "svid.expired" ||
    body.kind === "agent.spawned" ||
    body.kind === "ticket.verified" ||
    body.kind === "session.dropped"
  ) {
    return "spoke";
  }
  if (
    body.kind === "quic_hello" ||
    body.kind === "frame_tx" ||
    body.kind === "path.direct" ||
    body.kind === "path.switch" ||
    body.kind === "path.down" ||
    body.kind === "path.up" ||
    body.kind === "nat.inject" ||
    body.kind === "nat.probe" ||
    body.kind === "session_up" ||
    body.kind === "session_down"
  ) {
    return "hub";
  }
  return "";
}

function labelFor(body) {
  const kind = body.kind;
  if (kind === "ticket.verified") {
    return "ticket";
  }
  if (kind.indexOf("svid.") === 0 || kind === "agent.spawned") {
    return "SVID";
  }
  if (kind === "path.direct") {
    return "Direct";
  }
  if (kind === "path.relay" || kind === "relay.hop" || (kind === "path.up" && body.path === "relay")) {
    return "Relay";
  }
  if (kind === "jit.allow") {
    return "Allow";
  }
  if (kind === "jit.deny") {
    return "Deny";
  }
  if (kind === "nat.inject" && body.mode) {
    return String(body.mode);
  }
  if (kind === "connector_https") {
    const status = body.status !== undefined ? " " + String(body.status) : "";
    return (body.host || kind) + status;
  }
  if (kind === "path.switch" && body.from && body.to) {
    return String(body.from) + " to " + String(body.to);
  }
  if (kind === "path.allocate" && body.overlay_ip) {
    return String(body.overlay_ip);
  }
  if (kind === "session_up" || kind === "session_down" || kind === "session.dropped") {
    return body.reason ? kind + " " + String(body.reason) : kind;
  }
  if (kind === "quic_hello" || kind === "frame_tx" || kind === "frame_rx" || kind === "path.down" || kind === "nat.probe") {
    return kind;
  }
  return "";
}

function placeMarker(lane, label) {
  const packet = document.getElementById("packet");
  const floatLabel = document.getElementById("float-label");
  if (lane.length === 0) {
    return;
  }
  packet.hidden = false;
  packet.className = "packet at-" + lane;
  if (label.length === 0) {
    floatLabel.hidden = true;
    floatLabel.textContent = "";
    return;
  }
  floatLabel.hidden = false;
  floatLabel.className = "float-label at-" + lane;
  floatLabel.textContent = label;
}

function targetsFor(body) {
  const targets = [];
  const kind = body.kind;
  if (
    kind.indexOf("svid.") === 0 ||
    kind === "agent.spawned" ||
    kind === "ticket.verified" ||
    kind === "session.dropped"
  ) {
    targets.push("node-spoke");
  }
  if (kind === "agent.spawned" || kind === "jit.allow" || kind === "jit.deny") {
    targets.push("actor-agent");
  }
  if (
    kind === "quic_hello" ||
    kind === "path.direct" ||
    kind === "path.switch" ||
    kind === "path.down" ||
    kind === "path.up" ||
    kind === "path.allocate" ||
    kind === "nat.inject" ||
    kind === "nat.probe" ||
    kind === "session_up" ||
    kind === "session_down" ||
    kind === "frame_tx" ||
    kind === "frame_rx"
  ) {
    targets.push("node-hub");
  }
  if (
    kind === "path.relay" ||
    kind === "relay.hop" ||
    (kind === "path.up" && body.path === "relay") ||
    (kind === "path.down" && body.reason === "revoked")
  ) {
    targets.push("node-relay");
  }
  const host = namedHost(body);
  if (host.length > 0) {
    targets.push(host);
  }
  if (kind === "session_down" && body.reason === "destination") {
    targets.push("app-b");
  }
  return targets;
}

function remember(body) {
  const targets = targetsFor(body);
  targets.push("inspect-path");
  for (let index = 0; index < targets.length; index += 1) {
    lastByNode[targets[index]] = body;
  }
  if (inspectTarget.length > 0 && targets.indexOf(inspectTarget) !== -1) {
    renderInspector();
  }
}

function renderInspector() {
  const target = document.getElementById("inspect-target");
  const fields = document.getElementById("inspect-fields");
  fields.replaceChildren();
  if (inspectTarget.length === 0) {
    target.textContent = "Click a node or the path.";
    return;
  }
  let name = "Path";
  let state = document.getElementById("path-state").dataset.mode || "idle";
  if (inspectTarget !== "inspect-path") {
    const node = document.getElementById(inspectTarget);
    const heading = node.querySelector(".node-title");
    name = heading ? heading.textContent : inspectTarget;
    state = node.dataset.state || "idle";
  }
  target.textContent = name + " " + state;
  const body = lastByNode[inspectTarget];
  if (!body) {
    return;
  }
  for (let index = 0; index < FIELD_KEYS.length; index += 1) {
    const key = FIELD_KEYS[index];
    if (body[key] === undefined) {
      continue;
    }
    const term = document.createElement("dt");
    term.textContent = key;
    const value = document.createElement("dd");
    value.textContent = String(body[key]);
    fields.append(term, value);
  }
}

function selectInspect(id) {
  inspectTarget = id;
  const buttons = document.querySelectorAll(".node, #inspect-path");
  for (let index = 0; index < buttons.length; index += 1) {
    const button = buttons[index];
    button.setAttribute("aria-pressed", button.id === id ? "true" : "false");
  }
  document.getElementById("inspector").dataset.open = "true";
  renderInspector();
}

function classify(body) {
  if (body.kind === "session_down" && body.reason === "destination") {
    return "";
  }
  if (body.kind === "session_up" || body.kind === "path.up" || body.kind === "svid.expired") {
    return "win";
  }
  if (body.kind === "session_down" && body.reason === "expired") {
    return "win";
  }
  if (body.kind === "svid.revoked" || body.kind === "session.dropped") {
    return "loss";
  }
  if (body.kind === "session_down" && body.reason === "revoked") {
    return "loss";
  }
  if (body.kind === "path.down" && body.reason === "revoked") {
    return "loss";
  }
  if (body.kind === "path.direct" && body.ok === false) {
    return "loss";
  }
  return "";
}

function quip(body) {
  if (body.kind === "session_up") {
    return "The session is up. Watching was enough.";
  }
  if (body.kind === "svid.expired" || (body.kind === "session_down" && body.reason === "expired")) {
    return "The ticket got old on purpose.";
  }
  if (body.kind === "path.up") {
    return "The direct path failed. The Relay path is up.";
  }
  if (body.kind === "svid.revoked" || body.kind === "session.dropped" || body.reason === "revoked") {
    return "Revoke won. The mesh can try the next level.";
  }
  if (body.kind === "path.direct" && body.ok === false) {
    return "Direct is not ok. Wait for the next feed line.";
  }
  return "";
}

function noteResult(body) {
  const tone = classify(body);
  if (tone.length === 0) {
    return;
  }
  runResult = { tone: tone, body: body };
  document.getElementById("game").dataset.result = tone;
}

function clearReach() {
  const nodes = document.querySelectorAll(".node");
  for (let index = 0; index < nodes.length; index += 1) {
    nodes[index].classList.remove("reach");
  }
}

function pairFor(body) {
  const kind = body.kind;
  const host = namedHost(body);
  if (kind === "agent.spawned") {
    return ["node-spoke", "actor-agent"];
  }
  if (kind === "jit.allow") {
    return ["actor-agent", "app-a"];
  }
  if (kind === "jit.deny") {
    return ["actor-agent", "app-b"];
  }
  if (kind === "svid.expired" && body.level === "agent_jit") {
    return ["actor-agent", "node-spoke"];
  }
  if ((kind === "connector_https" || kind === "frame_tx" || kind === "frame_rx") && host.length > 0) {
    return ["node-hub", host];
  }
  if (kind === "path.relay" || kind === "relay.hop" || (kind === "path.up" && body.path === "relay")) {
    return ["node-hub", "node-relay"];
  }
  if (kind === "path.switch" || kind === "path.allocate") {
    return ["node-hub", "node-relay"];
  }
  if (
    kind === "path.direct" ||
    kind === "path.down" ||
    kind === "nat.inject" ||
    kind === "nat.probe" ||
    kind === "quic_hello" ||
    kind === "frame_tx" ||
    kind === "frame_rx" ||
    kind === "session_up" ||
    kind === "svid.issued" ||
    kind === "ticket.verified" ||
    kind === "svid.revoked" ||
    kind === "svid.expired" ||
    kind === "session.dropped"
  ) {
    return ["node-spoke", "node-hub"];
  }
  if (kind === "session_down" && (body.reason === "revoked" || body.reason === "expired")) {
    return ["node-spoke", "node-hub"];
  }
  return [];
}

function linkCast(body) {
  clearReach();
  const mesh = document.getElementById("mesh-link");
  const line = document.getElementById("bond-live");
  const pair = pairFor(body);
  if (pair.length < 2) {
    mesh.dataset.link = "idle";
    return;
  }
  for (let index = 0; index < pair.length; index += 1) {
    const actor = document.getElementById(pair[index]);
    if (actor) {
      actor.classList.add("reach");
    }
  }
  const start = BOND_POS[pair[0]];
  const end = BOND_POS[pair[1]];
  if (!start || !end) {
    mesh.dataset.link = "idle";
    return;
  }
  line.setAttribute("x1", String(start[0]));
  line.setAttribute("y1", String(start[1]));
  line.setAttribute("x2", String(end[0]));
  line.setAttribute("y2", String(end[1]));
  mesh.dataset.link = "live";
}

function fxSpec(body) {
  const kind = body.kind;
  if (kind === "svid.issued") {
    return { at: "node-spoke", tone: "mint", count: 7 };
  }
  if (kind === "agent.spawned") {
    return { at: "actor-agent", tone: "mint", count: 7 };
  }
  if (kind === "ticket.verified") {
    return { at: "node-spoke", tone: "ticket", count: 5 };
  }
  if (kind === "path.direct" && body.ok === false) {
    return { at: "node-hub", tone: "break", count: 8 };
  }
  if (kind === "nat.inject" || kind === "path.down") {
    return { at: "node-hub", tone: "break", count: 6 };
  }
  if (kind === "path.relay" || kind === "relay.hop" || (kind === "path.up" && body.path === "relay")) {
    return { at: "node-relay", tone: "relay", count: 7 };
  }
  if (kind === "jit.allow") {
    return { at: "app-a", tone: "allow", count: 6 };
  }
  if (kind === "jit.deny") {
    return { at: "app-b", tone: "deny", count: 6 };
  }
  if (kind === "svid.revoked" || kind === "session.dropped") {
    return { at: "node-spoke", tone: "revoke", count: 8 };
  }
  if (kind === "session_down" && body.reason === "revoked") {
    return { at: "node-spoke", tone: "revoke", count: 6 };
  }
  if (kind === "svid.expired") {
    return { at: body.level === "agent_jit" ? "actor-agent" : "node-spoke", tone: "break", count: 5 };
  }
  if (kind === "connector_https") {
    const host = namedHost(body);
    if (host.length > 0) {
      const bad = typeof body.status === "number" && body.status >= 400;
      return { at: host, tone: bad ? "deny" : "allow", count: 4 };
    }
  }
  if (kind === "quic_hello" || kind === "frame_tx" || kind === "frame_rx" || kind === "path.switch") {
    const lane = laneFor(body);
    return { at: nodeForLane(lane), tone: "ticket", count: 3 };
  }
  return null;
}

function nodeForLane(lane) {
  if (lane === "spoke") {
    return "node-spoke";
  }
  if (lane === "agent") {
    return "actor-agent";
  }
  if (lane === "hub") {
    return "node-hub";
  }
  if (lane === "a") {
    return "app-a";
  }
  if (lane === "b") {
    return "app-b";
  }
  if (lane === "relay") {
    return "node-relay";
  }
  return "node-hub";
}

function spawnFx(body) {
  const spec = fxSpec(body);
  if (!spec) {
    return;
  }
  const origin = FX_ANCHOR[spec.at] || FX_ANCHOR["node-hub"];
  const layer = document.getElementById("fx");
  for (let index = 0; index < spec.count; index += 1) {
    const mote = document.createElement("span");
    mote.className = "mote " + spec.tone;
    mote.style.left = origin[0];
    mote.style.top = origin[1];
    const angle = (Math.PI * 2 * index) / spec.count;
    const dist = 26 + (index % 3) * 14;
    mote.style.setProperty("--dx", String(Math.round(Math.cos(angle) * dist)) + "px");
    mote.style.setProperty("--dy", String(Math.round(Math.sin(angle) * dist)) + "px");
    layer.append(mote);
    window.setTimeout(function () {
      mote.classList.add("go");
    }, 30);
    window.setTimeout(function () {
      mote.remove();
    }, 780);
  }
}

function showEnd() {
  if (!runResult) {
    return;
  }
  const card = document.getElementById("endcard");
  document.getElementById("end-tone").textContent = runResult.tone === "win" ? "Soft win" : "Soft loss";
  const line = quip(runResult.body);
  const detail = beatText(runResult.body);
  document.getElementById("end-copy").textContent = line.length > 0 ? line + " " + detail : detail;
  card.hidden = false;
}

function nextLevel() {
  const level = document.getElementById("game").dataset.level;
  const difficulty = NEXT_DIFFICULTY[level];
  if (difficulty) {
    postJson("/api/difficulty", difficulty);
    return;
  }
  startOidcLogin();
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
document.getElementById("next-level").addEventListener("click", nextLevel);
document.getElementById("eng-toggle").addEventListener("click", function () {
  const eng = document.getElementById("eng");
  const open = eng.hasAttribute("hidden");
  if (open) {
    eng.removeAttribute("hidden");
    document.body.classList.add("eng-open");
  } else {
    eng.setAttribute("hidden", "");
    document.body.classList.remove("eng-open");
  }
  this.setAttribute("aria-pressed", open ? "true" : "false");
});
for (let index = 0; index < NODE_IDS.length; index += 1) {
  const id = NODE_IDS[index];
  document.getElementById(id).addEventListener("click", function () {
    selectInspect(id);
  });
}
document.getElementById("inspect-path").addEventListener("click", function () {
  selectInspect("inspect-path");
});

loadState();
setInterval(loadState, 1000);

if (window.EventSource) {
  const stream = new EventSource("/events");
  stream.onmessage = function (message) {
    ingest(message.data);
  };
}
