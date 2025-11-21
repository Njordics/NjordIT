const DEFAULT_URL = "https://example.com";
const DEFAULT_DOMAIN = "example.com";
const DEFAULT_SCAN_PORTS = "80,443,3389,22";

const urlInput = document.getElementById("urlInput");
const domainInput = document.getElementById("domainInput");
const runBtn = document.getElementById("runBtn");
const runBtnHero = document.getElementById("runBtnHero");
const httpResEl = document.getElementById("httpRes");
const dnsResEl = document.getElementById("dnsRes");
const latencyResEl = document.getElementById("latencyRes");
const httpResHero = document.getElementById("httpResHero");
const dnsResHero = document.getElementById("dnsResHero");
const latencyResHero = document.getElementById("latencyResHero");
const localIpEl = document.getElementById("localIpEl");
const localIpHero = document.getElementById("localIpHero");
const logsEl = document.getElementById("logs");
const statusBadgeEl = document.getElementById("statusBadge");
const ipConfigCard = document.getElementById("ipConfigCard");
const runIpConfigBtn = document.getElementById("runIpConfigBtn");
const rerunIpConfigBtn = document.getElementById("rerunIpConfigBtn");
const ipConfigHint = document.getElementById("ipConfigHint");
const ipConfigOutput = document.getElementById("ipConfigOutput");
const closeIpConfigBtn = document.getElementById("closeIpConfigBtn");
const openIpConfigBtn = document.getElementById("openIpConfigBtn");
const ipConfigButtons = [runIpConfigBtn, rerunIpConfigBtn].filter(Boolean);
const ipScanRangeInput = document.getElementById("ipScanRangeInput");
const ipScanPortsInput = document.getElementById("ipScanPortsInput");
const ipScanBtn = document.getElementById("ipScanBtn");
const ipScanUseLocalBtn = document.getElementById("ipScanUseLocalBtn");
const ipScanSummary = document.getElementById("ipScanSummary");
const ipScanResults = document.getElementById("ipScanResults");
const ipScanCard = document.getElementById("ipScanCard");
const closeIpScanBtn = document.getElementById("closeIpScanBtn");
const openIpScanBtn = document.getElementById("openIpScanBtn");
const serialCard = document.getElementById("serialCard");
const closeSerialBtn = document.getElementById("closeSerialBtn");
const openSerialBtn = document.getElementById("openSerialBtn");
const serialPortSelect = document.getElementById("serialPortSelect");
const serialBaudInput = document.getElementById("serialBaudInput");
const serialCommandInput = document.getElementById("serialCommandInput");
const serialOutput = document.getElementById("serialOutput");
const serialSendBtn = document.getElementById("serialSendBtn");
const serialClearBtn = document.getElementById("serialClearBtn");
const serialRefreshBtn = document.getElementById("serialRefreshBtn");
const tabs = Array.from(document.querySelectorAll(".tab"));
const tabPanels = Array.from(document.querySelectorAll(".tab-panel"));
const audioCheckBtn = document.getElementById("audioCheckBtn");
const audioResults = document.getElementById("audioResults");

let suggestedRange = null;

async function fetchPublicIp() {
  if (!httpResEl && !httpResHero) return;

  const setIp = (msg) => {
    if (httpResEl) httpResEl.textContent = msg;
    if (httpResHero) httpResHero.textContent = msg;
  };

  try {
    const resp = await fetch("https://api.ipify.org?format=json");
    if (!resp.ok) throw new Error(`ipify ${resp.status}`);
    const json = await resp.json();
    if (json?.ip) {
      setIp(json.ip);
      return;
    }
    throw new Error("no ip");
  } catch (publicErr) {
    // Fall back to server-reported IP if public lookup fails.
    try {
      const resp = await fetch("/api/ip");
      const json = await resp.json();
      setIp(json.ip || "unknown");
    } catch (err) {
      setIp(`IP lookup failed (${err.message || publicErr.message})`);
    }
  }
}

function applySuggestedRange(range) {
  if (ipScanRangeInput && range && !ipScanRangeInput.value) {
    ipScanRangeInput.value = range;
    if (ipScanSummary) ipScanSummary.textContent = `Detected local /24: ${range}. Adjust if needed.`;
  }
}

function guessRangeFromCurrentIp() {
  const ipText = (localIpHero?.textContent || localIpEl?.textContent || "").trim();
  const match = ipText.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return null;
  const [a, b, c] = match.slice(1, 4).map(Number);
  if (a === 10 || a === 192 || (a === 172 && b >= 16 && b <= 31)) {
    return `${a}.${b}.${c}.0/24`;
  }
  return null;
}

async function fetchLocalIp() {
  if (!localIpHero && !localIpEl) return;

  const setLocalIp = (msg) => {
    if (localIpEl) localIpEl.textContent = msg;
    if (localIpHero) localIpHero.textContent = msg;
  };

  try {
    const resp = await fetch("/api/ip");
    const json = await resp.json();
    setLocalIp(json.ip || "Unavailable");
    if (json.suggested_range) {
      suggestedRange = json.suggested_range;
      applySuggestedRange(json.suggested_range);
    }
  } catch (err) {
    setLocalIp("Unavailable");
  }
}

function applyIpConfigButtonState(running, trigger) {
  ipConfigButtons.forEach((btn) => {
    btn.disabled = running;
    if (!running) {
      btn.textContent = btn === rerunIpConfigBtn ? "Rerun" : "Run";
    }
  });
  if (running && trigger) {
    trigger.textContent = trigger === rerunIpConfigBtn ? "Rerunning..." : "Running...";
  }
}

async function runIpConfig(event) {
  if (!runIpConfigBtn) return;
  const trigger = event?.currentTarget || runIpConfigBtn;
  if (ipConfigCard) {
    ipConfigCard.classList.remove("collapsed");
    ipConfigCard.classList.add("expanded");
  }
  if (ipConfigHint) ipConfigHint.classList.add("hidden");
  if (ipConfigOutput) ipConfigOutput.textContent = "Running IP configuration...";
  rerunIpConfigBtn?.classList.remove("hidden");
  applyIpConfigButtonState(true, trigger);

  try {
    const resp = await fetch("/api/ipconfig");
    const json = await resp.json();
    if (json.ok) {
      if (ipConfigOutput) ipConfigOutput.textContent = json.output || "No output returned.";
    } else {
      if (ipConfigOutput) ipConfigOutput.textContent = `Error: ${json.error ?? "unknown"}`;
    }
  } catch (err) {
    if (ipConfigOutput) ipConfigOutput.textContent = `Request failed: ${err.message}`;
  } finally {
    applyIpConfigButtonState(false);
  }
}

function collapseIpConfig() {
  if (ipConfigCard) {
    ipConfigCard.classList.remove("expanded");
    ipConfigCard.classList.add("collapsed");
  }
  if (ipConfigOutput) ipConfigOutput.textContent = "Press Run to show interface details.";
  if (ipConfigHint) ipConfigHint.classList.remove("hidden");
  rerunIpConfigBtn?.classList.add("hidden");
  applyIpConfigButtonState(false);
}

function expandIpConfig() {
  if (ipConfigCard) {
    ipConfigCard.classList.remove("collapsed");
    ipConfigCard.classList.add("expanded");
  }
  if (ipConfigHint) ipConfigHint.classList.add("hidden");
}

function logLine(text) {
  if (!logsEl) return;
  const ts = new Date().toLocaleTimeString();
  const line = document.createElement("div");
  line.innerHTML = `<span style="color: var(--muted)">${ts}</span> -> ${text}`;
  logsEl.appendChild(line);
}

function resetLogs() {
  if (logsEl) logsEl.innerHTML = "";
}

function setStatus(ok) {
  const dotClass = ok ? "ok" : "fail";
  const text = ok ? "Healthy" : "Check results";
  statusBadgeEl.innerHTML = `<div class="status"><span class="dot ${dotClass}"></span>${text}</div>`;
}

async function runChecks() {
  const url = (urlInput?.value || "").trim() || DEFAULT_URL;
  const domain = (domainInput?.value || "").trim() || DEFAULT_DOMAIN;

  if (runBtn) runBtn.disabled = true;
  if (runBtnHero) runBtnHero.disabled = true;
  resetLogs();
  logLine("Starting checks...");
  setStatus(false);

  try {
    // HTTP
    logLine(`HTTP probe -> ${url}`);
    const httpResp = await fetch(`/api/http?url=${encodeURIComponent(url)}`);
    const httpJson = await httpResp.json();
    if (httpJson.ok) {
      const msg = `OK (${httpJson.status}) in ${httpJson.duration_ms?.toFixed(1)} ms`;
      if (httpResEl) httpResEl.textContent = msg;
      if (httpResHero) httpResHero.textContent = msg;
      logLine(`HTTP: ${msg}`);
    } else {
      const msg = `Fail ${httpJson.status ?? ""} ${httpJson.error ?? ""}`;
      if (httpResEl) httpResEl.textContent = msg;
      if (httpResHero) httpResHero.textContent = msg;
      logLine(`HTTP: ${msg}`);
    }

    // DNS
    logLine(`DNS lookup -> ${domain}`);
    const dnsResp = await fetch(`/api/dns?domain=${encodeURIComponent(domain)}`);
    const dnsJson = await dnsResp.json();
    if (dnsJson.ok && dnsJson.answers?.length) {
      const addresses = [];
      dnsJson.answers.forEach((a) => {
        if (a?.address && !addresses.includes(a.address)) addresses.push(a.address);
      });
      const primary = addresses[0] || "n/a";
      const secondary = addresses[1] || "-";
      const msg = `Primary: ${primary}\nSecondary: ${secondary}`;
      if (dnsResEl) dnsResEl.textContent = msg;
      if (dnsResHero) dnsResHero.textContent = msg;
      logLine(`DNS: ${msg}`);
    } else {
      const resolverText = dnsJson.resolvers?.length ? ` via ${dnsJson.resolvers.join(", ")}` : "";
      const msg = `Fail${resolverText} ${dnsJson.error ?? "no answer"}`;
      if (dnsResEl) dnsResEl.textContent = msg;
      if (dnsResHero) dnsResHero.textContent = msg;
      logLine(`DNS: ${msg}`);
    }

    // Latency
    logLine(`Latency samples -> ${url}`);
    const latResp = await fetch(`/api/latency?url=${encodeURIComponent(url)}&attempts=3`);
    const latJson = await latResp.json();
    if (latJson.ok) {
      const msg = `OK avg ${latJson.average_ms} ms [${(latJson.samples_ms || []).join(" | ")}]`;
      if (latencyResEl) latencyResEl.textContent = msg;
      if (latencyResHero) latencyResHero.textContent = msg;
      logLine(`Latency: ${msg}`);
    } else {
      const msg = `Fail ${latJson.error ?? ""}`;
      if (latencyResEl) latencyResEl.textContent = msg;
      if (latencyResHero) latencyResHero.textContent = msg;
      logLine(`Latency: ${msg}`);
    }

    const allOk =
      httpJson.ok &&
      dnsJson.ok &&
      latJson.ok;
    setStatus(allOk);
  } catch (err) {
    logLine(`Error: ${err.message}`);
    setStatus(false);
  } finally {
    if (runBtn) runBtn.disabled = false;
    if (runBtnHero) runBtnHero.disabled = false;
  }
}

function renderIpScanResults(hosts) {
  if (!ipScanResults) return;
  ipScanResults.innerHTML = "";

  if (!hosts?.length) {
    ipScanResults.innerHTML = '<div class="ip-scan-empty">No responsive hosts.</div>';
    return;
  }

  const header = document.createElement("div");
  header.className = "ip-scan-row header";
  header.innerHTML = "<div>IP</div><div>Hostname</div><div>Status</div><div>Ports</div>";
  ipScanResults.appendChild(header);

  const sorted = [...hosts].sort((a, b) => Number(b.alive) - Number(a.alive));
  sorted.forEach((host) => {
    const row = document.createElement("div");
    row.className = "ip-scan-row";
    const hostname = host.hostname || "-";
    const statusText = host.alive ? `Alive ${host.rtt_ms ? `(${host.rtt_ms} ms)` : ""}` : "No reply";
    const statusClass = host.alive ? "pill status" : "pill status offline";
    const ports = (host.open_ports || []).map((p) => `<span class=\"port-chip\">${p}</span>`).join("");
    const portsHtml = ports || "<span class=\"hostname\">No open ports found</span>";
    row.innerHTML = `
      <div class="ip">${host.ip}</div>
      <div class="hostname">${hostname}</div>
      <div><span class="${statusClass}">${statusText}</span></div>
      <div class="ip-scan-ports">${portsHtml}</div>
    `;
    ipScanResults.appendChild(row);
  });
}

async function runIpScanner(event) {
  if (!ipScanBtn || !ipScanRangeInput) return;
  if (ipScanCard) ipScanCard.classList.remove("collapsed");
  const trigger = event?.currentTarget || ipScanBtn;
  const target = ipScanRangeInput.value.trim();
  const portsRaw = (ipScanPortsInput?.value || DEFAULT_SCAN_PORTS).trim();

  if (!target) {
    if (ipScanSummary) ipScanSummary.textContent = "Enter a CIDR or range to scan.";
    return;
  }

  trigger.disabled = true;
  trigger.textContent = "Scanning...";
  if (ipScanSummary) ipScanSummary.textContent = "Scanning network... this can take a few seconds.";

  try {
    const params = new URLSearchParams({ target });
    if (portsRaw) params.append("ports", portsRaw);
    const resp = await fetch(`/api/ip-scan?${params.toString()}`);
    const json = await resp.json();
    if (!json.ok) {
      if (ipScanSummary) ipScanSummary.textContent = `Scan failed: ${json.error || "unknown error"}`;
      renderIpScanResults([]);
      return;
    }
    renderIpScanResults(json.hosts || []);
    const stats = json.stats || {};
    const alive = stats.alive ?? 0;
    const total = stats.total_hosts ?? target;
    const elapsed = stats.elapsed_ms ?? "?";
    const ports = Array.isArray(json.ports) ? json.ports.join(", ") : portsRaw;
    if (ipScanSummary) {
      ipScanSummary.textContent = `Found ${alive} responsive host(s) out of ${total} in ${elapsed} ms. Ports checked: ${ports}.`;
    }
  } catch (err) {
    if (ipScanSummary) ipScanSummary.textContent = `Scan failed: ${err.message}`;
    renderIpScanResults([]);
  } finally {
    trigger.disabled = false;
    trigger.textContent = "Scan network";
  }
}

function useLocalRange() {
  const guessed = suggestedRange || guessRangeFromCurrentIp();
  if (guessed && ipScanRangeInput) {
    ipScanRangeInput.value = guessed;
    if (ipScanSummary) ipScanSummary.textContent = `Using detected /24: ${guessed}`;
  } else if (ipScanSummary) {
    ipScanSummary.textContent = "Could not infer a private IP range. Enter one manually.";
  }
}

function collapseIpScan() {
  if (ipScanCard) ipScanCard.classList.add("collapsed");
  if (ipScanSummary) ipScanSummary.textContent = "Scanner collapsed. Hit Scan to reopen.";
}

function expandIpScan() {
  if (ipScanCard) ipScanCard.classList.remove("collapsed");
  if (ipScanSummary && !ipScanRangeInput.value) {
    ipScanSummary.textContent = "Enter a range and hit Scan.";
  }
}

function collapseSerial() {
  if (serialCard) serialCard.classList.add("collapsed");
  if (serialOutput) serialOutput.textContent = "Console collapsed. Use the arrow to expand.";
}

function expandSerial() {
  if (serialCard) serialCard.classList.remove("collapsed");
  if (serialOutput && serialOutput.textContent === "Console collapsed. Use the arrow to expand.") {
    serialOutput.textContent = "Waiting to connect.";
  }
}

async function refreshSerialPorts() {
  if (!serialPortSelect) return;
  try {
    const resp = await fetch("/api/serial/ports");
    const json = await resp.json();
    if (!json.ok) throw new Error(json.error || "port list failed");
    serialPortSelect.innerHTML = "";
    if (!json.ports || !json.ports.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "No ports found";
      serialPortSelect.appendChild(opt);
      return;
    }
    json.ports.forEach((p) => {
      const opt = document.createElement("option");
      opt.value = p.device;
      opt.textContent = `${p.device} - ${p.description || p.hwid || "serial"}`;
      serialPortSelect.appendChild(opt);
    });
  } catch (err) {
    if (serialOutput) serialOutput.textContent = `Port scan failed: ${err.message}`;
  }
}

async function sendSerialCommand() {
  if (!serialPortSelect || !serialSendBtn || !serialCommandInput || !serialOutput) return;
  const port = serialPortSelect.value;
  const baud = parseInt(serialBaudInput?.value || "9600", 10) || 9600;
  const command = serialCommandInput.value.trim();
  if (!port) {
    serialOutput.textContent = "Select a port first.";
    return;
  }
  if (!command) {
    serialOutput.textContent = "Enter a command to send.";
    return;
  }

  serialSendBtn.disabled = true;
  serialSendBtn.textContent = "Sending...";
  expandSerial();

  try {
    const resp = await fetch("/api/serial/exec", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ port, baud, command }),
    });
    const json = await resp.json();
    if (!json.ok) {
      serialOutput.textContent = `Serial error: ${json.error || "unknown"}`;
      return;
    }
    const ts = new Date().toLocaleTimeString();
    const prior = serialOutput.textContent === "Waiting to connect." ? "" : serialOutput.textContent + "\n";
    serialOutput.textContent = `${prior}[${ts}] > ${command}\n${json.output || "(no response)"}`.trim();
  } catch (err) {
    serialOutput.textContent = `Serial error: ${err.message}`;
  } finally {
    serialSendBtn.disabled = false;
    serialSendBtn.textContent = "Send";
  }
}

function clearSerialOutput() {
  if (serialOutput) serialOutput.textContent = "";
}

function activateTab(targetId) {
  tabs.forEach((tab) => {
    const isActive = tab.dataset.target === targetId;
    tab.classList.toggle("active", isActive);
  });
  tabPanels.forEach((panel) => {
    panel.classList.toggle("active", panel.id === targetId);
  });
}

async function checkAudioDrivers() {
  if (!audioResults) return;
  audioResults.textContent = "Checking audio drivers...";
  try {
    const resp = await fetch("/api/drivers/audio");
    const json = await resp.json();
    if (!json.ok) throw new Error(json.error || "audio check failed");
    audioResults.innerHTML = "";
    const devices = json.devices || [];
    if (!devices.length) {
      audioResults.textContent = "No audio devices found.";
      return;
    }
    devices.forEach((dev) => {
      const block = document.createElement("div");
      block.className = "audio-device";
      const name = dev.name || "Unknown device";
      const manufacturer = dev.manufacturer || "Unknown vendor";
      const version = dev.driver_version || "Unknown version";
      const status = dev.status || "unknown";
      const currency = dev.is_current === true ? "Current" : dev.is_current === false ? "Outdated" : "Unknown";
      block.innerHTML = `<strong>${name}</strong><div class="muted">${manufacturer}</div><div>Driver: ${version}</div><div>Status: ${status}</div><div>Currency: ${currency}</div>`;
      audioResults.appendChild(block);
    });
  } catch (err) {
    audioResults.textContent = `Audio check failed: ${err.message}`;
  }
}

if (runBtn) runBtn.addEventListener("click", runChecks);
if (runBtnHero) runBtnHero.addEventListener("click", runChecks);
if (runIpConfigBtn) runIpConfigBtn.addEventListener("click", runIpConfig);
if (rerunIpConfigBtn) rerunIpConfigBtn.addEventListener("click", runIpConfig);
if (closeIpConfigBtn) closeIpConfigBtn.addEventListener("click", collapseIpConfig);
if (openIpConfigBtn) openIpConfigBtn.addEventListener("click", expandIpConfig);
if (ipScanBtn) ipScanBtn.addEventListener("click", runIpScanner);
if (ipScanUseLocalBtn) ipScanUseLocalBtn.addEventListener("click", useLocalRange);
if (closeIpScanBtn) closeIpScanBtn.addEventListener("click", collapseIpScan);
if (openIpScanBtn) openIpScanBtn.addEventListener("click", expandIpScan);
if (closeSerialBtn) closeSerialBtn.addEventListener("click", collapseSerial);
if (openSerialBtn) openSerialBtn.addEventListener("click", expandSerial);
if (serialSendBtn) serialSendBtn.addEventListener("click", sendSerialCommand);
if (serialClearBtn) serialClearBtn.addEventListener("click", clearSerialOutput);
if (serialRefreshBtn) serialRefreshBtn.addEventListener("click", refreshSerialPorts);
if (audioCheckBtn) audioCheckBtn.addEventListener("click", checkAudioDrivers);
tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const target = tab.dataset.target;
    if (target) activateTab(target);
  });
});

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/static/sw.js").catch((err) => console.warn("SW registration failed", err));
  });
}

window.addEventListener("DOMContentLoaded", () => {
  fetchPublicIp();
  fetchLocalIp();
  runChecks();
  if (ipScanPortsInput && !ipScanPortsInput.value) {
    ipScanPortsInput.value = DEFAULT_SCAN_PORTS;
  }
  const guessed = guessRangeFromCurrentIp();
  if (guessed) applySuggestedRange(guessed);

  refreshSerialPorts();
});
