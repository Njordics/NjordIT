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
const logsEl = document.getElementById("logs");
const statusBadgeEl = document.getElementById("statusBadge");

function logLine(text) {
  const ts = new Date().toLocaleTimeString();
  const line = document.createElement("div");
  line.innerHTML = `<span style="color: var(--muted)">${ts}</span> — ${text}`;
  logsEl.appendChild(line);
}

function resetLogs() {
  logsEl.innerHTML = "";
}

function setStatus(ok) {
  const dotClass = ok ? "ok" : "fail";
  const text = ok ? "Healthy" : "Check results";
  statusBadgeEl.innerHTML = `<div class="status"><span class="dot ${dotClass}"></span>${text}</div>`;
}

async function runChecks() {
  if (!urlInput.value || !domainInput.value) return;
  runBtn.disabled = true;
  if (runBtnHero) runBtnHero.disabled = true;
  resetLogs();
  logLine("Starting checks...");
  setStatus(false);

  try {
    // HTTP
    logLine(`HTTP probe → ${urlInput.value}`);
    const httpResp = await fetch(`/api/http?url=${encodeURIComponent(urlInput.value)}`);
    const httpJson = await httpResp.json();
    if (httpJson.ok) {
      const msg = `OK (${httpJson.status}) in ${httpJson.duration_ms?.toFixed(1)} ms`;
      httpResEl.textContent = msg;
      if (httpResHero) httpResHero.textContent = msg;
      logLine(`HTTP: ${msg}`);
    } else {
      const msg = `Fail ${httpJson.status ?? ""} ${httpJson.error ?? ""}`;
      httpResEl.textContent = msg;
      if (httpResHero) httpResHero.textContent = msg;
      logLine(`HTTP: ${msg}`);
    }

    // DNS
    logLine(`DNS lookup → ${domainInput.value}`);
    const dnsResp = await fetch(`/api/dns?domain=${encodeURIComponent(domainInput.value)}`);
    const dnsJson = await dnsResp.json();
    if (dnsJson.ok && dnsJson.answers?.length) {
      const records = dnsJson.answers.map((a) => `${a.family}:${a.address}`).join(" | ");
      const msg = `OK -> ${records}`;
      dnsResEl.textContent = msg;
      if (dnsResHero) dnsResHero.textContent = msg;
      logLine(`DNS: ${msg}`);
    } else {
      const msg = `Fail ${dnsJson.error ?? "no answer"}`;
      dnsResEl.textContent = msg;
      if (dnsResHero) dnsResHero.textContent = msg;
      logLine(`DNS: ${msg}`);
    }

    // Latency
    logLine(`Latency samples → ${urlInput.value}`);
    const latResp = await fetch(`/api/latency?url=${encodeURIComponent(urlInput.value)}&attempts=3`);
    const latJson = await latResp.json();
    if (latJson.ok) {
      const msg = `OK avg ${latJson.average_ms} ms [${(latJson.samples_ms || []).join(" | ")}]`;
      latencyResEl.textContent = msg;
      if (latencyResHero) latencyResHero.textContent = msg;
      logLine(`Latency: ${msg}`);
    } else {
      const msg = `Fail ${latJson.error ?? ""}`;
      latencyResEl.textContent = msg;
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
    runBtn.disabled = false;
    if (runBtnHero) runBtnHero.disabled = false;
  }
}

runBtn.addEventListener("click", runChecks);
if (runBtnHero) runBtnHero.addEventListener("click", runChecks);

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/static/sw.js").catch((err) => console.warn("SW registration failed", err));
  });
}
