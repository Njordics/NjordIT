# FriggIT Tools (Flask PWA)

Flask-backed web app with a browser UI for quick network triage. Includes HTTP/DNS/latency checks, IP config capture, IP scanning, a serial console (Putty-like, single-command), and an audio driver checker. Built as a simple PWA (installable, caches shell offline) for laptops, Chromebooks, or phones.

## Stack
- Flask (API + templating)
- requests (HTTP probes)
- pyserial (USB/COM console)
- Plain JS frontend with service worker and manifest

## Run locally
```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py      # auto-reloads via watchfiles
# open http://localhost:51000
```
For auto-reload during development you can use `watchfiles` (already in requirements):
```bash
watchfiles "flask --app app run"
```

## API
- `GET /api/http?url=` - HEAD probe, returns status and duration.
- `GET /api/dns?domain=` - DNS lookup via system resolver (A/AAAA).
- `GET /api/latency?url=&attempts=3` - multiple GETs, returns samples and average.
- `GET /api/ip` - current client IP (and suggested /24).
- `GET /api/ipconfig` - system IP configuration (ipconfig/ifconfig).
- `GET /api/ip-scan?target=CIDR|start-end&ports=80,443` - ping plus port scan for a range.
- `GET /api/serial/ports` - list available serial/COM ports.
- `POST /api/serial/exec { port, baud, command }` - send one command over serial.
- `GET /api/drivers/audio` - list detected audio devices and driver versions (Windows: WMIC; Linux: aplay/ALSA info).

## Frontend
- Tabs: **Network** (IP Config, IP Scanner, Serial Console) and **Drivers** (Audio Drivers checker). Cards start collapsed; use the arrow or main action to expand.
- `templates/index.html` and `static/js/app.js` handle UI and call APIs.
- `static/manifest.webmanifest` and `static/sw.js` provide PWA install/offline shell caching.

## Notes / next steps
- Audio driver check reports detected devices and versions; "current" is unknown without vendor feeds.
- Add auth or rate limiting if exposed beyond local network.
- Replace system DNS lookup with a dedicated resolver (DoH) if you need consistent results.
- Add more tools (port checks, traceroute via backend) and driver download links.
