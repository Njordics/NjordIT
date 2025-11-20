from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import List
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__, static_folder="static", template_folder="templates")


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
    try:
        infos = socket.getaddrinfo(domain, None)
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                answers.append(DnsAnswer(family="IPv4", address=sockaddr[0]))
            elif family == socket.AF_INET6:
                answers.append(DnsAnswer(family="IPv6", address=sockaddr[0]))
        if not answers:
            raise RuntimeError("no records returned")
        result = DnsResult(ok=True, answers=answers)
    except Exception as exc:  # noqa: BLE001
        result = DnsResult(ok=False, error=str(exc))
    return jsonify(
        {
            "ok": result.ok,
            "answers": [asdict(a) for a in (result.answers or [])],
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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
