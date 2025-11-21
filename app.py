from __future__ import annotations

import platform
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from dataclasses import asdict, dataclass
from ipaddress import ip_address, ip_network
from typing import List
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request
import serial
from serial.tools import list_ports
import os

app = Flask(__name__, static_folder="static", template_folder="templates")


def _run_server() -> None:
    """Start the Flask dev server (reloader handled by watchfiles when available)."""
    app.run(debug=True, use_reloader=False, host="0.0.0.0", port=51000)


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


@dataclass
class IpScanHost:
    ip: str
    hostname: str | None = None
    alive: bool = False
    rtt_ms: float | None = None
    open_ports: List[int] | None = None


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
PING_TIMEOUT_MS = 800
MAX_SCAN_HOSTS = 512
DEFAULT_SCAN_PORTS = [80, 443, 3389, 22]
MAX_SCAN_WORKERS = 64
SERIAL_READ_TIMEOUT = 2.0
SERIAL_WRITE_TIMEOUT = 1.0
MAX_AUDIO_OUTPUT = 8000


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
        (output[:MAX_IP_CONFIG_OUTPUT] + "\n...output truncated...")
        if len(output) > MAX_IP_CONFIG_OUTPUT
        else output
    )
    return trimmed.strip()


def _ping_command(ip: str, timeout_ms: int) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    # Linux / macOS use "-c 1" (count) and "-W" (timeout seconds)
    return ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip]


def _ping_host(ip: str, timeout_ms: int = PING_TIMEOUT_MS) -> tuple[bool, float | None]:
    if not shutil.which("ping"):
        raise RuntimeError("ping utility is unavailable on this system")
    cmd = _ping_command(ip, timeout_ms)
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(1.5, timeout_ms / 500),
        )
        alive = completed.returncode == 0
    except subprocess.TimeoutExpired:
        alive = False
    duration_ms = (time.perf_counter() - start) * 1000
    return alive, duration_ms if alive else None


def _reverse_dns(ip: str) -> str | None:
    import socket

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def _check_open_ports(ip: str, ports: list[int], timeout: float = 0.5) -> list[int]:
    import socket

    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            continue
    return open_ports


def _parse_ports(raw: str | None) -> list[int]:
    if not raw:
        return DEFAULT_SCAN_PORTS
    ports: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            value = int(part)
        except ValueError:
            continue
        if 1 <= value <= 65535 and value not in ports:
            ports.append(value)
    return ports or DEFAULT_SCAN_PORTS


def _expand_targets(target: str) -> list[str]:
    target = target.strip()
    hosts: list[str] = []
    if "/" in target:
        network = ip_network(target, strict=False)
        if network.version != 4:
            raise ValueError("only IPv4 ranges are supported")
        hosts = [str(ip) for ip in network.hosts()]
    elif "-" in target:
        start_raw, end_raw = target.split("-", maxsplit=1)
        start_ip = ip_address(start_raw.strip())
        end_ip = ip_address(end_raw.strip())
        if start_ip.version != 4 or end_ip.version != 4:
            raise ValueError("only IPv4 ranges are supported")
        if int(end_ip) < int(start_ip):
            raise ValueError("end IP is before start IP")
        hosts = [str(ip_address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]
    else:
        single = ip_address(target)
        if single.version != 4:
            raise ValueError("only IPv4 ranges are supported")
        hosts = [str(single)]

    if not hosts:
        raise ValueError("no hosts to scan")
    if len(hosts) > MAX_SCAN_HOSTS:
        raise ValueError(f"too many hosts ({len(hosts)}); limit is {MAX_SCAN_HOSTS}")
    return hosts


def _scan_host(ip: str, ports: list[int]) -> IpScanHost:
    alive, rtt_ms = _ping_host(ip)
    hostname = _reverse_dns(ip) if alive else None
    open_ports = _check_open_ports(ip, ports) if alive and ports else []
    return IpScanHost(
        ip=ip,
        hostname=hostname,
        alive=alive,
        rtt_ms=round(rtt_ms, 1) if rtt_ms else None,
        open_ports=open_ports or None,
    )


def _scan_hosts(hosts: list[str], ports: list[int]) -> list[IpScanHost]:
    worker_count = min(MAX_SCAN_WORKERS, max(1, len(hosts)))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        return list(pool.map(lambda ip: _scan_host(ip, ports), hosts))


def _list_serial_ports() -> list[dict[str, str]]:
    ports: list[dict[str, str]] = []
    for port in list_ports.comports():
        ports.append(
            {
                "device": port.device,
                "description": port.description or "",
                "hwid": port.hwid or "",
            }
        )
    return ports


def _serial_exec(port: str, baud: int, command: str) -> str:
    # One-shot session: open port, send command with newline, read response.
    try:
        with serial.Serial(
            port=port,
            baudrate=baud,
            timeout=SERIAL_READ_TIMEOUT,
            write_timeout=SERIAL_WRITE_TIMEOUT,
        ) as ser:
            payload = command.strip() + "\r\n"
            ser.write(payload.encode("utf-8", errors="ignore"))
            # Read until timeout; keep it simple to avoid blocking.
            output = ser.read(4096)
            return output.decode("utf-8", errors="ignore")
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"serial error: {exc}") from exc


def _audio_info_windows() -> list[dict[str, str | bool]]:
    cmd = ["wmic", "PATH", "Win32_SoundDevice", "get", "Name,Manufacturer,Status,DriverVersion", "/format:list"]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except Exception as exc:  # noqa: BLE001
        return [{"name": "Audio scan failed", "status": "error", "manufacturer": "", "driver_version": str(exc), "is_current": False}]
    if completed.returncode != 0:
        return [{"name": "Audio scan failed", "status": "error", "manufacturer": "", "driver_version": completed.stderr.strip(), "is_current": False}]
    output = completed.stdout[:MAX_AUDIO_OUTPUT]
    devices: list[dict[str, str | bool]] = []
    current: dict[str, str | bool] = {}
    for line in output.splitlines():
        if not line.strip():
            if current:
                devices.append(current)
                current = {}
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        val = value.strip()
        if key == "name":
            current["name"] = val
        elif key == "manufacturer":
            current["manufacturer"] = val
        elif key == "status":
            current["status"] = val or "unknown"
        elif key == "driverversion":
            current["driver_version"] = val or "unknown"
    if current:
        devices.append(current)
    # We cannot verify "current" without vendor lookup; mark as unknown.
    for dev in devices:
        dev.setdefault("status", "unknown")
        dev.setdefault("driver_version", "unknown")
        dev["is_current"] = None
    return devices or [{"name": "No audio devices reported", "status": "unknown", "manufacturer": "", "driver_version": "", "is_current": None}]


def _audio_info_linux() -> list[dict[str, str | bool]]:
    devices: list[dict[str, str | bool]] = []
    try:
        completed = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=5)
        if completed.returncode == 0:
            for line in completed.stdout.splitlines():
                if "card" in line.lower() and ":" in line:
                    devices.append({"name": line.strip(), "manufacturer": "", "status": "ok", "driver_version": "", "is_current": None})
    except Exception:
        pass
    if not devices:
        try:
            cards = Path("/proc/asound/cards").read_text(encoding="utf-8")
            for line in cards.splitlines():
                if line.strip():
                    devices.append({"name": line.strip(), "manufacturer": "", "status": "ok", "driver_version": "", "is_current": None})
        except Exception:
            pass
    return devices or [{"name": "No audio devices found", "status": "unknown", "manufacturer": "", "driver_version": "", "is_current": None}]


def _audio_info() -> list[dict[str, str | bool]]:
    system = platform.system().lower()
    if system == "windows":
        return _audio_info_windows()
    if system == "linux":
        return _audio_info_linux()
    return [{"name": f"Audio check not implemented for {system}", "status": "unknown", "manufacturer": "", "driver_version": "", "is_current": None}]


def _guess_default_cidr(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        parsed = ip_address(ip)
    except ValueError:
        return None
    if parsed.version != 4:
        return None
    parts = ip.split(".")
    if parts[0] in {"10", "192"} or (parts[0] == "172" and 16 <= int(parts[1]) <= 31):
        return ".".join(parts[:3] + ["0"]) + "/24"
    return None


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
    return jsonify({"ok": True, "ip": client_ip, "suggested_range": _guess_default_cidr(client_ip)})


@app.get("/api/ipconfig")
def ip_config():
    try:
        output = _run_ipconfig()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "output": output})


@app.get("/api/ip-scan")
def ip_scan():
    target = request.args.get("target") or request.args.get("range")
    if not target:
        return jsonify({"ok": False, "error": "missing target (CIDR or start-end)"}), 400

    try:
        hosts = _expand_targets(target)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"parse failed: {exc}"}), 400

    ports = _parse_ports(request.args.get("ports"))
    start = time.perf_counter()
    try:
        results = _scan_hosts(hosts, ports)
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
    alive = sum(1 for h in results if h.alive)

    return jsonify(
        {
            "ok": True,
            "stats": {"total_hosts": len(hosts), "alive": alive, "elapsed_ms": elapsed_ms},
            "ports": ports,
            "hosts": [asdict(h) for h in results],
        }
    )


@app.get("/api/serial/ports")
def serial_ports():
    try:
        ports = _list_serial_ports()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "ports": ports})


@app.post("/api/serial/exec")
def serial_exec():
    data = request.get_json(silent=True) or {}
    port = (data.get("port") or "").strip()
    baud = int(data.get("baud") or 9600)
    command = (data.get("command") or "").strip()
    if not port:
        return jsonify({"ok": False, "error": "missing port"}), 400
    if not command:
        return jsonify({"ok": False, "error": "missing command"}), 400
    baud = baud if baud > 0 else 9600
    try:
        output = _serial_exec(port, baud, command)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "output": output})


@app.get("/api/drivers/audio")
def audio_drivers():
    try:
        devices = _audio_info()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "devices": devices})


if __name__ == "__main__":
    try:
        from watchfiles import run_process
    except Exception:
        # watchfiles not installed; run normally
        _run_server()
    else:
        # Automatically restart on file changes for a smoother dev loop.
        run_process(".", target=_run_server)
