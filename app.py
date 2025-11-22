from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from dataclasses import asdict, dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import List
from urllib.parse import urlparse

import requests
import serial
from flask import Flask, jsonify, render_template, request
from serial.tools import list_ports

try:
    import sounddevice as sd  # Optional PortAudio wrapper
except Exception:
    sd = None

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
MAX_SCRAPER_BODY = 120_000
JUCE_SCAN_TIMEOUT = 8
PIPEWIRE_SCAN_TIMEOUT = 6
PULSEAUDIO_SCAN_TIMEOUT = 4
DRIVER_MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024  # 150 MB cap
DRIVER_DOWNLOAD_TIMEOUT = 45
PCAP_MAX_DURATION = 30
PCAP_MAX_COUNT = 5000
PCAP_MAX_FILE_BYTES = 10 * 1024 * 1024
PCAP_INSTALL_SENTINEL = Path(tempfile.gettempdir()) / "pcap_tools_installed.txt"


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


def _normalize_driver_date(date_raw: str | None) -> tuple[str | None, int | None]:
    """Parse diverse driver date strings and return ISO date plus age in days."""
    if not date_raw:
        return None, None
    text = str(date_raw).strip()
    if not text:
        return None, None

    parsed: datetime | None = None

    # Try straightforward ISO-like parsing first.
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
        parsed = None

    if not parsed:
        digits = "".join(ch for ch in text if ch.isdigit())
        # Handle Windows WMI-style "20240212" or "20240212000000" values.
        if len(digits) >= 8:
            try:
                parsed = datetime.strptime(digits[:8], "%Y%m%d").replace(tzinfo=timezone.utc)
            except Exception:
                parsed = None

    if not parsed:
        return text, None

    today = datetime.now(parsed.tzinfo or timezone.utc).date()
    age_days = max(0, (today - parsed.date()).days)
    return parsed.date().isoformat(), age_days


def _is_driver_current(age_days: int | None) -> bool | None:
    """Heuristic: consider drivers older than ~8 years as outdated."""
    if age_days is None:
        return None
    if age_days <= 365 * 5:
        return True
    if age_days > 365 * 8:
        return False
    return None


def _compare_versions(installed: str | None, latest: str | None) -> bool | None:
    """Return True if latest is newer than installed, False if not, None if unknown."""
    if not installed or not latest:
        return None

    def _parts(version: str) -> list[int]:
        cleaned = re.sub(r"[^0-9.]", ".", version)
        return [int(p) for p in cleaned.split(".") if p.isdigit()]

    inst_parts = _parts(installed)
    latest_parts = _parts(latest)
    if not inst_parts or not latest_parts:
        return None
    max_len = max(len(inst_parts), len(latest_parts))
    inst_parts += [0] * (max_len - len(inst_parts))
    latest_parts += [0] * (max_len - len(latest_parts))
    return latest_parts > inst_parts


def _run_powershell_json(script: str, timeout: float = 8.0) -> list[dict[str, object]] | None:
    """Execute a PowerShell script that returns JSON and parse it safely."""
    if not shutil.which("powershell"):
        return None
    cmd = ["powershell", "-NoProfile", "-Command", script]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None
    if completed.returncode != 0:
        return None
    raw = (completed.stdout or "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return None


def _http_get_text(url: str, timeout: float = 6.0) -> str | None:
    """Best-effort HTTP GET that returns trimmed text body."""
    try:
        resp = requests.get(url, timeout=timeout)
        if not resp.ok:
            return None
        text = resp.text
        if len(text) > MAX_SCRAPER_BODY:
            text = text[:MAX_SCRAPER_BODY]
        return text
    except Exception:
        return None


def _safe_filename(name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", name) or "driver"
    return base[:120]


def _download_driver(url: str, vendor: str | None = None) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise RuntimeError("download_url must be http or https")
    filename = Path(parsed.path).name or f"{vendor or 'driver'}-installer"
    dest = Path(tempfile.gettempdir()) / _safe_filename(filename)
    try:
        with requests.get(url, stream=True, timeout=DRIVER_DOWNLOAD_TIMEOUT) as resp:
            if not resp.ok:
                raise RuntimeError(f"download failed ({resp.status_code})")
            size = 0
            with open(dest, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > DRIVER_MAX_DOWNLOAD_BYTES:
                        raise RuntimeError("download exceeded size limit")
                    fh.write(chunk)
    except Exception as exc:
        # Clean up partial file
        if dest.exists():
            try:
                dest.unlink()
            except Exception:
                pass
        raise RuntimeError(f"download failed: {exc}") from exc
    return str(dest)


def _install_driver(installer_path: str) -> tuple[bool, str]:
    system = platform.system().lower()
    if system != "windows":
        return False, f"Automatic install not implemented for {system}. File saved at {installer_path}"

    installer_lower = installer_path.lower()
    if installer_lower.endswith(".msi"):
        cmd = ["msiexec.exe", "/i", installer_path, "/qn", "/norestart"]
    else:
        # Best-effort silent flags for typical driver installers.
        cmd = [installer_path, "/quiet", "/qn", "/norestart"]

    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    except Exception as exc:
        return False, f"Installer execution failed: {exc}"

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        return False, f"Installer exit code {completed.returncode}: {stderr or 'no error output'}"
    return True, "Installation completed"


def _ensure_pcap_tools() -> None:
    """Best-effort install of tcpdump/tshark when missing; skips if already present."""
    if PCAP_INSTALL_SENTINEL.exists():
        return
    have_tcpdump = shutil.which("tcpdump") is not None
    have_tshark = shutil.which("tshark") is not None
    if have_tcpdump or have_tshark:
        try:
            PCAP_INSTALL_SENTINEL.write_text("present", encoding="utf-8")
        except Exception:
            pass
        return

    system = platform.system().lower()
    cmds: list[list[str]] = []
    if system == "windows":
        cmds.append(["choco", "install", "wireshark", "-y", "--no-progress"])
        cmds.append(
            [
                "winget",
                "install",
                "--id",
                "WiresharkFoundation.Wireshark",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ]
        )
    elif system == "linux":
        # Requires root; if unavailable, this will fail quietly.
        cmds.append(["apt-get", "update"])
        cmds.append(["apt-get", "install", "-y", "tcpdump", "tshark"])
    elif system == "darwin":
        cmds.append(["brew", "install", "tcpdump", "wireshark"])

    for cmd in cmds:
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=400)
            if completed.returncode == 0:
                have_tcpdump = shutil.which("tcpdump") is not None
                have_tshark = shutil.which("tshark") is not None
                if have_tcpdump or have_tshark:
                    try:
                        PCAP_INSTALL_SENTINEL.write_text("installed", encoding="utf-8")
                    except Exception:
                        pass
                    return
        except Exception:
            continue

def _detect_pcap_command(interface: str | None, duration: int, count: int, outfile: Path) -> list[str] | None:
    iface_args: list[str] = []
    if interface:
        iface_args = ["-i", interface]
    def _find_tool(name: str) -> str | None:
        path = shutil.which(name)
        if path:
            return path
        if platform.system().lower() == "windows":
            candidates = [
                Path("C:/Program Files/Wireshark") / name,
                Path("C:/Program Files/Wireshark") / f"{name}.exe",
                Path("C:/Program Files (x86)/Wireshark") / name,
                Path("C:/Program Files (x86)/Wireshark") / f"{name}.exe",
            ]
            for cand in candidates:
                if cand.exists():
                    return str(cand)
        return None

    tcpdump_path = _find_tool("tcpdump")
    tshark_path = _find_tool("tshark")

    if tcpdump_path:
        # Use timeout via subprocess timeout; limit packets via -c.
        base = [tcpdump_path, "-nn", "-s", "0", "-w", str(outfile), "-c", str(count)]
        if iface_args:
            base[1:1] = iface_args
        else:
            if platform.system().lower() == "linux":
                base[1:1] = ["-i", "any"]
        return base
    if tshark_path:
        base = [tshark_path, "-w", str(outfile), "-a", f"duration:{duration}", "-a", f"filesize:{PCAP_MAX_FILE_BYTES // 1024}"]
        if iface_args:
            base[1:1] = iface_args
        return base
    return None


def _capture_pcap(interface: str | None, duration: int, count: int) -> dict[str, object]:
    duration = max(1, min(PCAP_MAX_DURATION, duration))
    count = max(1, min(PCAP_MAX_COUNT, count))
    system = platform.system().lower()
    if system == "windows" and not interface:
        # Default to adapter index 1 on Windows if none provided; avoids ETW-only mode.
        interface = "1"
        # Best-effort start of npcap service.
        try:
            start_cmds = [["net", "start", "npcap"], ["net", "start", "npf"]]
            for cmd in start_cmds:
                subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except Exception:
            pass

    tmp_path = Path(tempfile.gettempdir()) / f"capture_{int(time.time())}.pcap"
    cmd = _detect_pcap_command(interface, duration, count, tmp_path)
    if not cmd:
        raise RuntimeError("capture tool not available (tcpdump or tshark required)")
    try:
        completed = subprocess.run(cmd, capture_output=True, timeout=duration + 5)
    except subprocess.TimeoutExpired as exc:
        # Best effort to kill; file may still be usable.
        stderr = exc.stderr.decode("utf-8", errors="ignore") if hasattr(exc, "stderr") and exc.stderr else ""
        raise RuntimeError(f"capture timed out; partial file may be present ({stderr.strip()})") from exc
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"capture failed: {exc}") from exc
    if completed.returncode != 0:
        err = (completed.stderr or b"").decode("utf-8", errors="ignore").strip()
        hint = ""
        if system == "windows" and "NPF" in err.upper():
            hint = " (start the 'npcap' service or reinstall Wireshark/Npcap)"
        raise RuntimeError(f"capture exited with {completed.returncode}: {err or 'no stderr'}{hint}")
    if not tmp_path.exists():
        raise RuntimeError("capture file not created")
    size = tmp_path.stat().st_size
    if size == 0:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError("capture file is empty")
    if size > PCAP_MAX_FILE_BYTES:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError("capture exceeded size limit")
    return {"path": str(tmp_path), "bytes": size, "command": cmd}


def _windows_signed_audio_drivers() -> list[dict[str, str]]:
    if not shutil.which("powershell"):
        return []
    script = r"""
$ErrorActionPreference='SilentlyContinue';
Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -eq 'MEDIA' -or $_.DeviceClass -eq 'AUDIOENDPOINT' } | Select-Object DeviceID, FriendlyName, DriverVersion, DriverDate, DriverProviderName | ConvertTo-Json -Compress
""".strip()
    records = _run_powershell_json(script)
    return records or []


def _audio_info_windows() -> list[dict[str, str | bool | int | None]]:
    devices: list[dict[str, str | bool | int | None]] = []

    # Primary: modern PnP scan with signed driver enrichment so version/date/provider are populated.
    pnp_script = """
$ErrorActionPreference='SilentlyContinue';
# Build lookup from signed drivers
$signed = @{}
Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -eq 'MEDIA' -or $_.DeviceClass -eq 'AUDIOENDPOINT' } | ForEach-Object {
    $signed[$_.DeviceID] = [pscustomobject]@{
        drv_version = $_.DriverVersion
        drv_date    = $_.DriverDate
        provider    = $_.DriverProviderName
    }
}

Get-PnpDevice -Class Media,AudioEndpoint | ForEach-Object {
    $ver = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion').Data
    $date = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverDate').Data
    $signedInfo = $signed[$_.InstanceId]
    [pscustomobject]@{
        name = $_.FriendlyName
        manufacturer = $_.Manufacturer
        status = $_.Status
        pnp_device_id = $_.InstanceId
        driver_version = if ($ver) { $ver } else { $signedInfo.drv_version }
        driver_date = if ($date) { $date } else { $signedInfo.drv_date }
        provider = $signedInfo.provider
    }
} | ConvertTo-Json -Compress -Depth 4
""".strip()
    records = _run_powershell_json(pnp_script)
    if records:
        for rec in records:
            name = (rec.get("name") or rec.get("FriendlyName") or rec.get("pnp_device_id") or "").strip()
            if not name:
                continue
            driver_date, age_days = _normalize_driver_date(rec.get("driver_date"))
            devices.append(
                {
                    "name": name,
                    "manufacturer": (rec.get("manufacturer") or rec.get("provider") or "").strip(),
                    "status": (rec.get("status") or "unknown") or "unknown",
                    "driver_version": (rec.get("driver_version") or rec.get("drv_version") or "unknown") or "unknown",
                    "driver_date": driver_date or (rec.get("drv_date") or ""),
                    "driver_age_days": age_days,
                    "is_current": _is_driver_current(age_days),
                    "provider": (rec.get("provider") or "").strip(),
                    "device_id": rec.get("pnp_device_id") or "",
                }
            )

    # Fallback: CIM/WMI scan for environments without the PnP module (older Windows).
    if not devices:
        cim_script = """
$ErrorActionPreference='SilentlyContinue';
Get-CimInstance Win32_SoundDevice | Select-Object Name,Manufacturer,Status,PNPDeviceID | ConvertTo-Json -Compress
""".strip()
        records = _run_powershell_json(cim_script)
        for rec in records or []:
            name = (rec.get("Name") or rec.get("name") or "").strip()
            if not name:
                continue
            devices.append(
                {
                    "name": name,
                    "manufacturer": (rec.get("Manufacturer") or rec.get("manufacturer") or "").strip(),
                    "status": (rec.get("Status") or rec.get("status") or "unknown") or "unknown",
                    "driver_version": "unknown",
                    "driver_date": "",
                    "driver_age_days": None,
                    "is_current": None,
                    "device_id": rec.get("PNPDeviceID") or "",
                }
            )

    # Last resort: legacy wmic output if nothing else is available.
    if not devices:
        cmd = [
            "wmic",
            "PATH",
            "Win32_SoundDevice",
            "get",
            "Name,Manufacturer,Status,DriverVersion",
            "/format:list",
        ]
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except Exception as exc:  # noqa: BLE001
            return [
                {
                    "name": "Audio scan failed",
                    "status": "error",
                    "manufacturer": "",
                    "driver_version": str(exc),
                    "driver_date": "",
                    "driver_age_days": None,
                    "is_current": False,
                }
            ]
        if completed.returncode != 0:
            return [
                {
                    "name": "Audio scan failed",
                    "status": "error",
                    "manufacturer": "",
                    "driver_version": completed.stderr.strip(),
                    "driver_date": "",
                    "driver_age_days": None,
                    "is_current": False,
                }
            ]
        output = completed.stdout[:MAX_AUDIO_OUTPUT]
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

    # Enrich with signed driver details (device manager equivalent) to fill version/date/provider.
    signed_records = _windows_signed_audio_drivers()
    if signed_records:
        lookup = {}
        for rec in signed_records:
            devid = str(rec.get("DeviceID") or rec.get("deviceid") or "").lower()
            if devid:
                lookup[devid] = rec
        for dev in devices:
            device_id = str(dev.get("device_id") or dev.get("name") or "").lower()
            if not device_id:
                continue
            match = lookup.get(device_id)
            if not match:
                continue
            drv_ver = match.get("DriverVersion") or match.get("driverversion")
            drv_date = match.get("DriverDate") or match.get("driverdate")
            provider = match.get("DriverProviderName") or match.get("driverprovidername")
            if dev.get("driver_version") in {None, "", "unknown"} and drv_ver:
                dev["driver_version"] = drv_ver
            if (not dev.get("driver_date")) and drv_date:
                parsed_date, age_days = _normalize_driver_date(drv_date)
                dev["driver_date"] = parsed_date or drv_date
                dev["driver_age_days"] = age_days if age_days is not None else dev.get("driver_age_days")
                dev["is_current"] = dev.get("is_current") if dev.get("is_current") is not None else _is_driver_current(age_days)
            if not dev.get("provider") and provider:
                dev["provider"] = provider

    for dev in devices:
        dev.setdefault("status", "unknown")
        dev.setdefault("driver_version", "unknown")
        driver_date, age_days = _normalize_driver_date(dev.get("driver_date") if isinstance(dev, dict) else None)
        if isinstance(dev, dict):
            dev["driver_date"] = driver_date or dev.get("driver_date", "")
            dev["driver_age_days"] = age_days if age_days is not None else dev.get("driver_age_days", None)
            if dev.get("is_current") is None:
                dev["is_current"] = _is_driver_current(age_days)
        else:
            dev["is_current"] = None
    return devices or [
        {
            "name": "No audio devices reported",
            "status": "unknown",
            "manufacturer": "",
            "driver_version": "",
            "driver_date": "",
            "driver_age_days": None,
            "is_current": None,
        }
    ]


def _audio_info_linux() -> list[dict[str, str | bool | int | None]]:
    devices: list[dict[str, str | bool | int | None]] = []
    seen: set[str] = set()

    def _add_device(
        name: str, manufacturer: str = "", status: str = "ok", driver_version: str = ""
    ) -> None:
        key = name.strip()
        if not key or key in seen:
            return
        seen.add(key)
        devices.append(
            {
                "name": key[:MAX_AUDIO_OUTPUT],
                "manufacturer": manufacturer,
                "status": status,
                "driver_version": driver_version,
                "driver_date": "",
                "driver_age_days": None,
                "is_current": None,
            }
        )

    try:
        if shutil.which("aplay"):
            completed = subprocess.run(["aplay", "-l"], capture_output=True, text=True, timeout=5)
            if completed.returncode == 0:
                for line in completed.stdout.splitlines():
                    if "card" in line.lower() and ":" in line:
                        _add_device(line.strip())
    except Exception:
        pass

    try:
        if shutil.which("arecord"):
            completed = subprocess.run(["arecord", "-l"], capture_output=True, text=True, timeout=5)
            if completed.returncode == 0:
                for line in completed.stdout.splitlines():
                    if "card" in line.lower() and ":" in line:
                        _add_device(line.strip())
    except Exception:
        pass

    try:
        cards = Path("/proc/asound/cards")
        if cards.exists():
            for line in cards.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    _add_device(line.strip())
    except Exception:
        pass

    try:
        if shutil.which("lspci"):
            completed = subprocess.run(["lspci", "-nnk"], capture_output=True, text=True, timeout=5)
            if completed.returncode == 0:
                for line in completed.stdout.splitlines():
                    lower = line.lower()
                    if "audio device" in lower or "audio controller" in lower or "multimedia audio" in lower:
                        # lspci formats entries as "00:1b.0 Audio device: Vendor Device"
                        parts = line.split(":", 2)
                        description = parts[2].strip() if len(parts) >= 3 else line.strip()
                        _add_device(description)
    except Exception:
        pass

    return devices or [
        {
            "name": "No audio devices found",
            "status": "unknown",
            "manufacturer": "",
            "driver_version": "",
            "driver_date": "",
            "driver_age_days": None,
            "is_current": None,
        }
    ]


def _audio_info_macos() -> list[dict[str, str | bool | int | None]]:
    devices: list[dict[str, str | bool | int | None]] = []
    try:
        completed = subprocess.run(
            ["system_profiler", "-json", "SPAudioDataType"], capture_output=True, text=True, timeout=8
        )
        if completed.returncode == 0 and completed.stdout:
            try:
                data = json.loads(completed.stdout)
            except json.JSONDecodeError:
                data = {}
            for item in data.get("SPAudioDataType", []):
                for dev in item.get("_items", []):
                    name = dev.get("_name") or dev.get("device_name") or "Audio Device"
                    manufacturer = dev.get("manufacturer") or dev.get("manufacturer_name") or ""
                    driver_version = dev.get("driver_version") or dev.get("coreaudio_device_version") or ""
                    devices.append(
                        {
                            "name": str(name),
                            "manufacturer": str(manufacturer),
                            "status": "ok",
                            "driver_version": str(driver_version),
                            "driver_date": "",
                            "driver_age_days": None,
                            "is_current": None,
                        }
                    )
    except Exception:
        pass

    return devices or [
        {
            "name": "Audio check not implemented for macOS",
            "status": "unknown",
            "manufacturer": "",
            "driver_version": "",
            "driver_date": "",
            "driver_age_days": None,
            "is_current": None,
        }
    ]


def _audio_info_portaudio() -> list[dict[str, str | bool | int | None]]:
    """Use PortAudio (sounddevice) to enumerate host devices across platforms."""
    if sd is None:
        return []
    devices: list[dict[str, str | bool | int | None]] = []
    try:
        for dev in sd.query_devices():
            name = str(dev.get("name") or "").strip()
            if not name:
                continue
            hostapi_idx = dev.get("hostapi")
            hostapi = ""
            if hostapi_idx is not None and 0 <= hostapi_idx < len(sd.query_hostapis()):
                hostapi = sd.query_hostapis()[hostapi_idx].get("name") or ""
            devices.append(
                {
                    "name": name[:MAX_AUDIO_OUTPUT],
                    "manufacturer": hostapi,
                    "status": "ok",
                    "driver_version": "portaudio",
                    "driver_date": "",
                    "driver_age_days": None,
                    "is_current": None,
                    "provider": "PortAudio",
                }
            )
    except Exception:
        return []
    return devices


def _juce_audio_scan() -> list[dict[str, str | bool | int | None]]:
    """Optional JUCE-based scan; expects a helper CLI `juce-audio-scan --json` on PATH."""
    if not shutil.which("juce-audio-scan"):
        return []
    try:
        completed = subprocess.run(
            ["juce-audio-scan", "--json"],
            capture_output=True,
            text=True,
            timeout=JUCE_SCAN_TIMEOUT,
        )
    except Exception:
        return []
    if completed.returncode != 0 or not completed.stdout:
        return []
    body = completed.stdout
    try:
        data = json.loads(body)
    except Exception:
        return []
    devices: list[dict[str, str | bool | int | None]] = []
    if isinstance(data, list):
        for rec in data:
            if not isinstance(rec, dict):
                continue
            name = str(rec.get("name") or rec.get("device") or "").strip()
            if not name:
                continue
            manufacturer = str(rec.get("vendor") or rec.get("host") or "").strip()
            devices.append(
                {
                    "name": name[:MAX_AUDIO_OUTPUT],
                    "manufacturer": manufacturer,
                    "status": "ok",
                    "driver_version": str(rec.get("driver") or "juce").strip() or "juce",
                    "driver_date": "",
                    "driver_age_days": None,
                    "is_current": None,
                    "provider": "JUCE",
                }
            )
    return devices


def _sdl_audio_scan() -> list[dict[str, str | bool | int | None]]:
    """Optional SDL2-based scan; expects helper CLI `sdl2-audio-scan --json` on PATH."""
    if not shutil.which("sdl2-audio-scan"):
        return []
    try:
        completed = subprocess.run(
            ["sdl2-audio-scan", "--json"],
            capture_output=True,
            text=True,
            timeout=JUCE_SCAN_TIMEOUT,
        )
    except Exception:
        return []
    if completed.returncode != 0 or not completed.stdout:
        return []
    try:
        data = json.loads(completed.stdout)
    except Exception:
        return []
    devices: list[dict[str, str | bool | int | None]] = []
    if isinstance(data, list):
        for rec in data:
            if not isinstance(rec, dict):
                continue
            name = str(rec.get("name") or "").strip()
            if not name:
                continue
            devices.append(
                {
                    "name": name[:MAX_AUDIO_OUTPUT],
                    "manufacturer": str(rec.get("driver") or rec.get("backend") or "").strip(),
                    "status": "ok",
                    "driver_version": str(rec.get("version") or "sdl2").strip() or "sdl2",
                    "driver_date": "",
                    "driver_age_days": None,
                    "is_current": None,
                    "provider": "SDL2",
                }
            )
    return devices


def _pulseaudio_scan() -> list[dict[str, str | bool | int | None]]:
    """Fallback using PulseAudio (pactl)."""
    if not shutil.which("pactl"):
        return []
    try:
        completed = subprocess.run(
            ["pactl", "list", "short", "sinks"],
            capture_output=True,
            text=True,
            timeout=PULSEAUDIO_SCAN_TIMEOUT,
        )
    except Exception:
        return []
    if completed.returncode != 0 or not completed.stdout:
        return []
    devices: list[dict[str, str | bool | int | None]] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            name = parts[1]
            devices.append(
                {
                    "name": name[:MAX_AUDIO_OUTPUT],
                    "manufacturer": "PulseAudio",
                    "status": "ok",
                    "driver_version": "pulseaudio",
                    "driver_date": "",
                    "driver_age_days": None,
                    "is_current": None,
                    "provider": "PulseAudio",
                }
            )
    return devices


def _pipewire_scan() -> list[dict[str, str | bool | int | None]]:
    """Fallback using PipeWire (pw-dump)."""
    if not shutil.which("pw-dump"):
        return []
    try:
        completed = subprocess.run(
            ["pw-dump"],
            capture_output=True,
            text=True,
            timeout=PIPEWIRE_SCAN_TIMEOUT,
        )
    except Exception:
        return []
    if completed.returncode != 0 or not completed.stdout:
        return []
    try:
        data = json.loads(completed.stdout)
    except Exception:
        return []
    devices: list[dict[str, str | bool | int | None]] = []
    if isinstance(data, list):
        for node in data:
            if not isinstance(node, dict):
                continue
            props = node.get("info", {}).get("props", {}) if isinstance(node.get("info"), dict) else {}
            name = props.get("node.description") or props.get("node.name")
            if not name:
                continue
            devices.append(
                {
                    "name": str(name)[:MAX_AUDIO_OUTPUT],
                    "manufacturer": "PipeWire",
                    "status": "ok",
                    "driver_version": "pipewire",
                    "driver_date": "",
                    "driver_age_days": None,
                    "is_current": None,
                    "provider": "PipeWire",
                }
            )
    return devices


def _merge_audio_devices(primary: list[dict[str, str | bool | int | None]], extra: list[dict[str, str | bool | int | None]]):
    """Combine device lists, avoiding duplicates by name+manufacturer."""
    seen: set[tuple[str, str]] = set()
    merged: list[dict[str, str | bool | int | None]] = []
    for dev in primary + extra:
        name = str(dev.get("name") or "").strip()
        manufacturer = str(dev.get("manufacturer") or "").strip()
        key = (name.lower(), manufacturer.lower())
        if not name or key in seen:
            continue
        seen.add(key)
        merged.append(dev)
    return merged


def _vendor_hint(name: str, manufacturer: str, provider: str | None = None) -> str | None:
    text = f"{name} {manufacturer} {provider or ''}".lower()
    if "realtek" in text:
        return "realtek"
    if "intel" in text:
        return "intel"
    if "amd" in text or "advanced micro devices" in text:
        return "amd"
    if "nvidia" in text:
        return "nvidia"
    if "microsoft" in text or "wasapi" in text:
        return "microsoft"
    if "apple" in text or "coreaudio" in text:
        return "apple"
    if "alsa" in text:
        return "alsa"
    if "creative" in text or "sound blaster" in text or "audigy" in text or "x-fi" in text:
        return "creative"
    if "asus" in text or "xonar" in text or "rog" in text:
        return "asus"
    if "via" in text and "hd" in text:
        return "via"
    if "focusrite" in text:
        return "focusrite"
    if "steinberg" in text or "yamaha" in text:
        return "steinberg"
    if "presonus" in text:
        return "presonus"
    if "behringer" in text or "midas" in text:
        return "behringer"
    if "motu" in text:
        return "motu"
    if "rme" in text:
        return "rme"
    if "universal audio" in text or "uad" in text:
        return "uaudio"
    if "roland" in text or "boss" in text:
        return "roland"
    if "tascam" in text or "teac" in text:
        return "tascam"
    if "m-audio" in text or "maudio" in text:
        return "maudio"
    if "c-media" in text or "cmedia" in text:
        return "cmedia"
    if "cirrus" in text:
        return "cirrus"
    if "analog devices" in text:
        return "analogdevices"
    if "sennheiser" in text or "epos" in text:
        return "sennheiser"
    if "logitech" in text:
        return "logitech"
    if "jbl" in text or "harman" in text:
        return "jbl"
    if "fiio" in text:
        return "fiio"
    if "shure" in text:
        return "shure"
    return None


VENDOR_SOURCES: dict[str, list[dict[str, str]]] = {
    "realtek": [
        {
            "url": "https://www.realtek.com/en/component/zoo/category/pc-audio-codecs-high-definition-audio-codecs-software",
            "pattern": r"Version\\s*[:]?\\s*([0-9]+\\.[0-9.]+)",
            "note": "Realtek HD audio landing page scrape",
        }
    ],
    "intel": [
        {
            "url": "https://www.intel.com/content/www/us/en/download-center/home.html",
            "pattern": r"audio\\s+driver[^0-9]*([0-9]+\\.[0-9.]+)",
            "note": "Intel download center search page probe",
        }
    ],
    "amd": [
        {
            "url": "https://www.amd.com/en/support",
            "pattern": r"audio[^0-9]*driver[^0-9]*([0-9]+\\.[0-9.]+)",
            "note": "AMD support portal scrape",
        }
    ],
    "nvidia": [
        {
            "url": "https://www.nvidia.com/Download/index.aspx",
            "pattern": r"Version\\s*[:]?\\s*([0-9]+\\.[0-9.]+)",
            "note": "NVIDIA download page scrape",
        }
    ],
    "microsoft": [
        {
            "url": "https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/",
            "pattern": r"WASAPI|class driver",
            "note": "Microsoft audio driver docs (version info typically not exposed)",
        }
    ],
    "apple": [
        {
            "url": "https://developer.apple.com/documentation/coreaudio",
            "pattern": r"CoreAudio",
            "note": "CoreAudio docs; drivers ship with macOS",
        }
    ],
    "alsa": [
        {
            "url": "https://www.alsa-project.org/wiki/Download",
            "pattern": r"alsa-driver|ALSA",
            "note": "ALSA project downloads",
        }
    ],
    "creative": [
        {"url": "https://support.creative.com/Drivers/Products.aspx", "pattern": r"Sound Blaster|driver", "note": "Creative driver portal"}
    ],
    "asus": [
        {"url": "https://rog.asus.com/support", "pattern": r"audio|driver", "note": "ASUS ROG/Xonar support"},
        {"url": "https://www.asus.com/support", "pattern": r"audio|driver", "note": "ASUS support"},
    ],
    "via": [
        {"url": "https://www.viatech.com/en/support/drivers/", "pattern": r"audio|hd", "note": "VIA HD audio downloads"}
    ],
    "focusrite": [
        {"url": "https://downloads.focusrite.com/", "pattern": r"Scarlett|Clarett|Driver", "note": "Focusrite downloads"}
    ],
    "steinberg": [
        {"url": "https://o.steinberg.net/en/support/downloads/downloads_computer_based.html", "pattern": r"ASIO|Yamaha", "note": "Steinberg ASIO/Yamaha USB"}
    ],
    "presonus": [
        {"url": "https://www.presonus.com/en/support/downloads/", "pattern": r"Universal Control|AudioBox|Studio", "note": "PreSonus drivers"}
    ],
    "behringer": [
        {"url": "https://www.behringer.com/downloads.html", "pattern": r"U-Phoria|X32|driver", "note": "Behringer USB/X series"}
    ],
    "motu": [
        {"url": "https://motu.com/en-us/download/", "pattern": r"Audio|Driver", "note": "MOTU downloads"}
    ],
    "rme": [
        {"url": "https://www.rme-audio.de/downloads.html", "pattern": r"Driver|Windows|Mac", "note": "RME drivers"}
    ],
    "uaudio": [
        {"url": "https://help.uaudio.com/hc/en-us/sections/206329386-Downloads", "pattern": r"UAD|Apollo|Volt", "note": "Universal Audio drivers"}
    ],
    "roland": [
        {"url": "https://www.roland.com/global/support/", "pattern": r"Driver", "note": "Roland/Boss support"}
    ],
    "tascam": [
        {"url": "https://tascam.com/us/product/category/interfaces/download", "pattern": r"Driver", "note": "TASCAM interfaces"}
    ],
    "maudio": [
        {"url": "https://m-audio.com/support/drivers", "pattern": r"Driver", "note": "M-Audio drivers"}
    ],
    "cmedia": [
        {"url": "https://www.cmedia.com.tw/support/download_center", "pattern": r"USB|Audio", "note": "C-Media USB audio"}
    ],
    "cirrus": [
        {"url": "https://www.cirrus.com/support/", "pattern": r"audio", "note": "Cirrus Logic"},
    ],
    "analogdevices": [
        {"url": "https://www.analog.com/en/design-center/reference-designs/audio-video.html", "pattern": r"audio", "note": "Analog Devices audio"}
    ],
    "sennheiser": [
        {"url": "https://en-us.sennheiser.com/service-support-services-downloads", "pattern": r"USB|Headset|Audio", "note": "Sennheiser/EPOS"}
    ],
    "logitech": [
        {"url": "https://support.logi.com/hc/en-us/articles/360025141574--Downloads", "pattern": r"audio|headset", "note": "Logitech audio/headsets"}
    ],
    "jbl": [
        {"url": "https://support.jbl.com/us/en/support-downloads.html", "pattern": r"audio", "note": "JBL/Harman"}
    ],
    "fiio": [
        {"url": "https://www.fiio.com/resource", "pattern": r"Driver", "note": "FiiO USB DAC drivers"}
    ],
    "shure": [
        {"url": "https://www.shure.com/en-US/support/downloads", "pattern": r"Driver|Motiv", "note": "Shure USB mics/interfaces"}
    ],
}


def _extract_download_link(body: str, vendor: str | None) -> str | None:
    vendor_domain = {
        "realtek": "realtek.com",
        "intel": "intel.com",
        "amd": "amd.com",
        "nvidia": "nvidia.com",
    }.get(vendor or "", "")
    matches = re.findall(r"https?://[^\\s\"'>]+?\\.(?:exe|msi|zip)", body, re.IGNORECASE)
    if not matches:
        return None
    if vendor_domain:
        for link in matches:
            if vendor_domain in link:
                return link
    return matches[0]


def _scrape_latest_driver(vendor: str) -> dict[str, str | None]:
    """Best-effort scrape of official vendor pages for latest driver version."""
    sources = VENDOR_SOURCES.get(vendor, [])
    result: dict[str, str | None] = {
        "vendor": vendor,
        "latest_version": None,
        "source_url": None,
        "download_url": None,
        "note": None,
        "status": "unavailable",
    }
    for source in sources:
        body = _http_get_text(source["url"])
        if not body:
            continue
        match = re.search(source["pattern"], body, re.IGNORECASE)
        if not result["download_url"]:
            result["download_url"] = _extract_download_link(body, vendor)
            if result["download_url"] and not result["source_url"]:
                result["source_url"] = source["url"]
        if match:
            result["latest_version"] = match.group(1)
            result["source_url"] = source["url"]
            result["note"] = source.get("note")
            result["status"] = "ok"
            break
    if result["latest_version"] is None and sources:
        result["source_url"] = result["source_url"] or sources[0]["url"]
        result["note"] = result["note"] or sources[0].get("note")
    return result


def _annotate_with_updates(devices: list[dict[str, str | bool | int | None]]):
    annotated: list[dict[str, str | bool | int | None]] = []
    for dev in devices:
        name = str(dev.get("name") or "")
        manufacturer = str(dev.get("manufacturer") or "")
        provider = str(dev.get("provider") or "")
        vendor = _vendor_hint(name, manufacturer, provider)
        latest_info = _scrape_latest_driver(vendor) if vendor else {"vendor": vendor}
        latest_version = latest_info.get("latest_version")
        installed_version = str(dev.get("driver_version") or "")
        update_available = _compare_versions(installed_version, latest_version)
        enriched = dict(dev)
        enriched["vendor"] = vendor
        enriched["latest_version"] = latest_version
        enriched["update_available"] = update_available
        enriched["latest_source"] = {
            "status": latest_info.get("status"),
            "url": latest_info.get("source_url"),
            "note": latest_info.get("note"),
        }
        enriched["latest_download_url"] = latest_info.get("download_url")
        annotated.append(enriched)
    return annotated


def _audio_info() -> list[dict[str, str | bool | int | None]]:
    system = platform.system().lower()
    if system == "windows":
        devices = _audio_info_windows()
    elif system == "linux":
        devices = _audio_info_linux()
    elif system == "darwin":
        devices = _audio_info_macos()
    else:
        devices = [
            {
                "name": f"Audio check not implemented for {system}",
                "status": "unknown",
                "manufacturer": "",
                "driver_version": "",
                "driver_date": "",
                "driver_age_days": None,
                "is_current": None,
            }
        ]
    # Fallback chain: only proceed to next probe if nothing has been found.
    if not devices:
        devices = _audio_info_portaudio()
    if not devices and system == "linux":
        devices = _pulseaudio_scan()
    if not devices and system == "linux":
        devices = _pipewire_scan()
    if not devices:
        devices = _juce_audio_scan()
    if not devices:
        devices = _sdl_audio_scan()
    return devices


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


DOWNLOAD_SECTIONS = [
    {
        "id": "windows",
        "title": "Windows",
        "entries": [
            {
                "name": "Npcap (capture driver)",
                "description": (
                    "Required for packet capture on Windows. Enable the \"WinPcap Compatible Mode\" "
                    "option during setup."
                ),
                "link": "https://npcap.com/dist/npcap-1.85.exe",
                "steps": [
                    "Download the installer to your Downloads folder.",
                    "Run it as administrator with WinPcap compatibility enabled.",
                    "Reopen FriggIT after the service starts.",
                ],
            },
            {
                "name": "Wireshark / tshark",
                "description": "Installs tshark on Windows, which FriggIT uses when tcpdump is unavailable.",
                "link": "https://www.wireshark.org/download.html",
                "steps": [
                    "Download Wireshark for Windows.",
                    "During setup, keep the \"Install TShark\" option enabled.",
                ],
            },
        ],
    },
    {
        "id": "macos",
        "title": "macOS",
        "entries": [
            {
                "name": "tshark via Wireshark",
                "description": "The macOS Wireshark installer bundles tshark for captures.",
                "link": "https://www.wireshark.org/download.html",
                "steps": [
                    "Download the macOS package (Intel/Apple Silicon).",
                    "Install and grant the capture permissions when prompted.",
                ],
            },
            {
                "name": "tcpdump (optional)",
                "description": "Available via Homebrew (`brew install tcpdump`). Useful as a fallback capture tool.",
                "link": "https://www.tcpdump.org/#latest-release",
                "steps": [
                    "Install Homebrew if needed, then `brew install tcpdump`.",
                    "Verify with `tcpdump --version`.",
                ],
            },
        ],
    },
    {
        "id": "linux",
        "title": "Linux",
        "entries": [
            {
                "name": "tcpdump",
                "description": "Usually provided by your distro (Debian/Ubuntu, Fedora, etc.).",
                "link": "https://www.tcpdump.org/#latest-release",
                "steps": [
                    "Install with your package manager (`sudo apt install tcpdump`, `sudo dnf install tcpdump`, etc.).",
                    "Run `sudo tcpdump --version` to confirm.",
                ],
            },
            {
                "name": "tshark",
                "description": "Included with Wireshark; useful if tcpdump is unavailable.",
                "link": "https://www.wireshark.org/download.html",
                "steps": [
                    "Install the wireshark/tshark packages (`sudo apt install tshark`).",
                    "Add your user to the wireshark group if you want non-root captures.",
                ],
            },
        ],
    },
    {
        "id": "universal",
        "title": "Universal / Optional",
        "entries": [
            {
                "name": "Npcap OEM (silent install)",
                "description": (
                    "For enterprises needing unattended installs. Supports `/S` silent flags and commercial redistribution."
                ),
                "link": "https://npcap.com/oem/",
                "steps": [
                    "Purchase an OEM license.",
                    "Download and deploy with the silent parameters documented by Nmap.",
                ],
            },
        ],
    },
]


@app.route("/downloads")
def downloads():
    return render_template("downloads/index.html", sections=DOWNLOAD_SECTIONS)


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


@app.get("/api/drivers/audio/updates")
def audio_driver_updates():
    try:
        devices = _annotate_with_updates(_audio_info())
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "devices": devices})


@app.post("/api/drivers/audio/install")
def audio_driver_install():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or data.get("download_url") or data.get("source_url") or "").strip()
    vendor = (data.get("vendor") or "").strip() or None
    if not url:
        return jsonify({"ok": False, "error": "missing download_url"}), 400
    try:
        installer_path = _download_driver(url, vendor)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500

    success, message = _install_driver(installer_path)
    status = 200 if success else 500
    return jsonify({"ok": success, "message": message, "path": installer_path}), status


@app.post("/api/pcap")
def pcap_capture():
    data = request.get_json(silent=True) or {}
    interface = (data.get("interface") or "").strip() or None
    duration = int(data.get("duration") or 5)
    count = int(data.get("count") or 200)
    try:
        result = _capture_pcap(interface, duration, count)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, **result})


if __name__ == "__main__":
    try:
        _ensure_pcap_tools()
    except Exception:
        # Best effort; continue even if install fails.
        pass
    try:
        from watchfiles import run_process
    except Exception:
        # watchfiles not installed; run normally
        _run_server()
    else:
        # Automatically restart on file changes for a smoother dev loop.
        run_process(".", target=_run_server)
