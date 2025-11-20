const DEFAULT_URL = "https://example.com";
const DEFAULT_DOMAIN = "example.com";

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
const ipConfigHint = document.getElementById("ipConfigHint");
const ipConfigOutput = document.getElementById("ipConfigOutput");

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
  } catch (err) {
    setLocalIp("Unavailable");
  }
}

async function runIpConfig() {
  if (!runIpConfigBtn) return;
  if (ipConfigCard) ipConfigCard.classList.add("expanded");
  if (ipConfigHint) ipConfigHint.classList.add("hidden");
  if (ipConfigOutput) ipConfigOutput.textContent = "Running IP configuration…";
  runIpConfigBtn.disabled = true;
  runIpConfigBtn.textContent = "Running…";

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
    runIpConfigBtn.disabled = false;
    runIpConfigBtn.textContent = "Run";
  }
}

function logLine(text) {
  if (!logsEl) return;
  const ts = new Date().toLocaleTimeString();
  const line = document.createElement("div");
  line.innerHTML = `<span style="color: var(--muted)">${ts}</span> — ${text}`;
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
    logLine(`HTTP probe → ${url}`);
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
    logLine(`DNS lookup → ${domain}`);
    const dnsResp = await fetch(`/api/dns?domain=${encodeURIComponent(domain)}`);
    const dnsJson = await dnsResp.json();
    if (dnsJson.ok && dnsJson.answers?.length) {
      const records = Array.from(
        new Set(dnsJson.answers.map((a) => `${a.family}:${a.address}`))
      ).join(" | ");
      const resolverText = dnsJson.resolvers?.length ? `via ${dnsJson.resolvers.join(", ")}` : "resolver unknown";
      const msg = `OK (${resolverText}) -> ${records}`;
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
    logLine(`Latency samples → ${url}`);
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

if (runBtn) runBtn.addEventListener("click", runChecks);
if (runBtnHero) runBtnHero.addEventListener("click", runChecks);
if (runIpConfigBtn) runIpConfigBtn.addEventListener("click", runIpConfig);

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/static/sw.js").catch((err) => console.warn("SW registration failed", err));
  });
}

window.addEventListener("DOMContentLoaded", () => {
  fetchPublicIp();
  fetchLocalIp();
  runChecks();
});
