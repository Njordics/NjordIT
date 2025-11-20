# NjordIT Tools (Flask PWA)

Flask-backed web app with browser UI for quick HTTP/DNS/latency checks. Built as a simple PWA (installable, caches shell offline) for laptops, Chromebooks, or phones.

## Stack
- Flask (API + templating)
- requests (HTTP probes)
- Plain JS frontend with service worker & manifest

## Run locally
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app run
# open http://localhost:5000
```
For auto-reload during development you can use `watchfiles` (already in requirements):
```bash
watchfiles 'flask --app app run'
```

## API
- `GET /api/http?url=` — HEAD probe, returns status + duration.
- `GET /api/dns?domain=` — DNS lookup via system resolver (A/AAAA).
- `GET /api/latency?url=&attempts=3` — multiple GETs, returns samples and average.

## Frontend
- `templates/index.html` + `static/js/app.js` handle UI and call APIs.
- `static/manifest.webmanifest` and `static/sw.js` provide PWA install/offline shell caching.

## Notes / next steps
- Add auth or rate limiting if exposed beyond local network.
- Replace system DNS lookup with a dedicated resolver (DoH) if you need consistent results.
- Add more tools (port checks, traceroute via backend) and log export. 
