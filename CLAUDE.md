# ScanSentry

An Electron-based on-demand Windows scan tool (Malwarebytes-style, not real-time —
Windows Defender handles real-time). User runs a manual scan, gets a results
screen grouped by category, and picks Quarantine / Delete / Ignore per item.

## Status: backend done, UI not built yet

**Done (do not rewrite unless fixing a bug):**
- `main.js` — Electron main process, IPC handlers for scan/quarantine/settings
- `preload.js` — contextBridge exposing `window.scansentry` API to renderer
- `settings.js` — JSON-backed settings store (VT API key, scan paths, exclusions)
- `quarantine.js` — moves flagged files to a quarantine folder with a
  restore-capable manifest (never permanently deletes on quarantine)
- `scanners/junk.js` — temp/cache file scanner
- `scanners/startup.js` — registry Run keys + Startup folder scanner
- `scanners/hijack.js` — Chrome/Edge/Firefox homepage & search-provider hijack scanner
- `scanners/malware.js` — SHA-256 hash scanner, checks local bad-hash list +
  optional VirusTotal lookup if user supplies an API key

## TODO: build `src/` (the renderer / UI)

This is the main remaining work. Needs:

1. `src/index.html` — app shell: sidebar nav (Scan / Results / Quarantine /
   Settings) + main panel
2. `src/styles.css` — dark, technical palette. Avoid generic AI-design defaults
   (no cream+terracotta, no near-black+neon-green hacker cliche). Suggested
   direction: deep charcoal-navy background, slate panels, cyan accent for
   safe/active, amber for warnings, coral-red for threats/critical. Display
   font for headings, clean sans for body, monospace for file paths/hashes.
2. `src/renderer.js` — wires the UI to `window.scansentry` (see preload.js for
   the full API surface: runScan, onProgress, quarantineItem, deleteItem,
   listQuarantine, restoreQuarantine, deleteQuarantine, getSettings, setSetting)

### Screens needed
- **Scan**: checkboxes for the 4 categories (junk/startup/hijack/malware),
  "Start Scan" button, live progress feed from `onProgress`
- **Results**: grouped by category, each finding has a checkbox, path (mono
  font), severity badge (low/medium/high/critical color-coded), description.
  Sticky action bar appears when items are selected: Quarantine Selected /
  Delete Selected / Ignore Selected (ignore = just uncheck/dismiss, no IPC call)
- **Quarantine**: list of quarantined items from `listQuarantine()`, each with
  Restore / Delete Permanently buttons
- **Settings**: VT API key input, extra scan paths list, exclusions list

## Commands
- `npm install` — install Electron + electron-builder
- `npm start` — run the app
- `npm run dist` — package a Windows installer (electron-builder, NSIS target)

## Notes
- This only runs meaningfully on Windows (registry queries, browser profile
  paths, Windows folder structure). Scanner modules fail gracefully (return
  empty results) on other platforms rather than crashing.
- VirusTotal free tier is rate-limited (~4 req/min) — malware.js already
  throttles for this.
