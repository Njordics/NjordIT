from __future__ import annotations

import platform
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from typing import List
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__, static_folder="static", template_folder="templates")


def _run_server() -> None:
    """Start the Flask dev server (reloader handled by watchfiles when available)."""
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=5000)


@dataclass
class HttpCheckResult:
    ok: bool
    status: int | None = None
    duration_ms: float | None = None
    error: str | None = None


@dataclass
class DnsAnswer:
    family: str
    address: str


@dataclass
class DnsResult:
    ok: bool
    answers: List[DnsAnswer] | None = None
    resolvers: List[str] | None = None
    error: str | None = None


@dataclass
class LatencyResult:
    ok: bool
    samples_ms: List[float] | None = None
    average_ms: float | None = None
    error: str | None = None


def _clean_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"https://{url}"
    return url


def _system_resolvers() -> List[str]:
    resolvers: List[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        if ip not in resolvers:
                            resolvers.append(ip)
                            if len(resolvers) >= 2:
                                break
    except Exception:
        # Best-effort; ignore if resolv.conf missing or unreadable.
        pass
    return resolvers


MAX_IP_CONFIG_OUTPUT = 16_000


def _detect_ipconfig_command() -> list[str] | None:
    system = platform.system().lower()
    if system == "windows":
        return ["ipconfig", "/all"]
    if system == "linux":
        if shutil.which("ip"):
            return ["ip", "addr"]
        if shutil.which("ifconfig"):
            return ["ifconfig"]
    if system in {"darwin", "freebsd"}:
        return ["ifconfig"]
    return None


def _run_ipconfig() -> str:
    cmd = _detect_ipconfig_command()
    if not cmd:
        raise RuntimeError("no ipconfig/ifconfig utility available")
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"{cmd[0]} not installed") from exc
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"command failed: {cmd[0]}")
    output = completed.stdout or completed.stderr
    trimmed = (
        (output[:MAX_IP_CONFIG_OUTPUT] + "\n…output truncated…")
        if len(output) > MAX_IP_CONFIG_OUTPUT
        else output
    )
    return trimmed.strip()


@app.route("/")
def index():
    return render_template("index.html")


@app.get("/api/http")
def http_probe():
    url = request.args.get("url")
    if not url:
        return jsonify({"ok": False, "error": "missing url"}), 400

    url = _clean_url(url)
    start = time.perf_counter()
    try:
        resp = requests.head(url, timeout=5, allow_redirects=True)
        duration_ms = (time.perf_counter() - start) * 1000
        result = HttpCheckResult(ok=resp.ok, status=resp.status_code, duration_ms=duration_ms)
    except Exception as exc:  # noqa: BLE001
        duration_ms = (time.perf_counter() - start) * 1000
        result = HttpCheckResult(ok=False, error=str(exc), duration_ms=duration_ms)
    return jsonify(asdict(result))


@app.get("/api/dns")
def dns_lookup():
    import socket

    domain = request.args.get("domain")
    if not domain:
        return jsonify({"ok": False, "error": "missing domain"}), 400

    answers: List[DnsAnswer] = []
    resolvers = _system_resolvers()
    try:
        infos = socket.getaddrinfo(domain, None)
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                answers.append(DnsAnswer(family="IPv4", address=sockaddr[0]))
            elif family == socket.AF_INET6:
                answers.append(DnsAnswer(family="IPv6", address=sockaddr[0]))
        if not answers:
            raise RuntimeError("no records returned")
        result = DnsResult(ok=True, answers=answers, resolvers=resolvers)
    except Exception as exc:  # noqa: BLE001
        result = DnsResult(ok=False, error=str(exc), resolvers=resolvers)
    return jsonify(
        {
            "ok": result.ok,
            "answers": [asdict(a) for a in (result.answers or [])],
            "resolvers": result.resolvers or [],
            "error": result.error,
        }
    )


@app.get("/api/latency")
def latency():
    url = request.args.get("url")
    attempts_raw = request.args.get("attempts", "3")
    attempts = max(1, min(5, int(attempts_raw))) if attempts_raw.isdigit() else 3
    if not url:
        return jsonify({"ok": False, "error": "missing url"}), 400
    url = _clean_url(url)

    samples: List[float] = []
    try:
        for _ in range(attempts):
            start = time.perf_counter()
            requests.get(url, timeout=5)
            samples.append((time.perf_counter() - start) * 1000)
        avg = sum(samples) / len(samples)
        result = LatencyResult(ok=True, samples_ms=samples, average_ms=avg)
    except Exception as exc:  # noqa: BLE001
        result = LatencyResult(ok=False, samples_ms=samples, error=str(exc))

    return jsonify(
        {
            "ok": result.ok,
            "samples_ms": [round(s, 1) for s in (result.samples_ms or [])],
            "average_ms": round(result.average_ms, 1) if result.average_ms else None,
            "error": result.error,
        }
    )


@app.get("/api/ip")
def current_ip():
    header_candidates = (
        "CF-Connecting-IP",
        "True-Client-IP",
        "X-Real-IP",
        "X-Forwarded-For",
    )
    client_ip: str | None = None
    for header in header_candidates:
        value = request.headers.get(header)
        if value:
            client_ip = value.split(",")[0].strip()
            break
    if not client_ip:
        client_ip = request.remote_addr
    return jsonify({"ok": True, "ip": client_ip})


@app.get("/api/ipconfig")
def ip_config():
    try:
        output = _run_ipconfig()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "output": output})


if __name__ == "__main__":
    try:
        from watchfiles import run_process
    except Exception:
        # watchfiles not installed; run normally
        _run_server()
    else:
        # Automatically restart on file changes for a smoother dev loop.
        run_process(".", target=_run_server)
