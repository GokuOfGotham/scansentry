const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const util = require('util');
const execFileP = util.promisify(execFile);

const REG_KEYS = [
  { hive: 'HKCU', key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
  { hive: 'HKCU', key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' },
  { hive: 'HKLM', key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
  { hive: 'HKLM', key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' }
];

// Rough heuristic: entries launching from Temp/AppData-Local-Temp, or with
// no recognizable path (just a bare exe name resolved via PATH), or with
// suspicious flags (-enc, -windowstyle hidden) get flagged higher severity.
function assessSeverity(command) {
  const lower = command.toLowerCase();
  if (lower.includes('\\temp\\') || lower.includes('%temp%')) return 'high';
  if (lower.includes('-enc') || lower.includes('-windowstyle hidden') || lower.includes('powershell')) return 'medium';
  if (lower.includes('\\appdata\\roaming\\')) return 'medium';
  return 'low';
}

async function queryRegistryKey(keyPath) {
  const entries = [];
  try {
    const { stdout } = await execFileP('reg', ['query', keyPath]);
    const lines = stdout.split(/\r?\n/);
    for (const line of lines) {
      // Format: "    ValueName    REG_SZ    C:\path\to\thing.exe -flag"
      const match = line.match(/^\s{4}(\S.*?)\s+(REG_SZ|REG_EXPAND_SZ)\s+(.*)$/);
      if (match) {
        entries.push({ name: match[1], command: match[3].trim() });
      }
    }
  } catch (e) {
    // Key may not exist, or reg.exe unavailable (non-Windows) - skip silently.
  }
  return entries;
}

function startupFolders() {
  const home = os.homedir();
  return [
    path.join(home, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp'),
    'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp'
  ].filter(d => {
    try { return fs.existsSync(d); } catch { return false; }
  });
}

async function scanStartup(onProgress) {
  const findings = [];

  for (const { key } of REG_KEYS) {
    if (onProgress) onProgress(`Checking ${key}`);
    const entries = await queryRegistryKey(key);
    for (const e of entries) {
      findings.push({
        id: 'startup:' + key + ':' + e.name,
        category: 'startup',
        path: key + '\\' + e.name,
        command: e.command,
        size: null,
        severity: assessSeverity(e.command),
        description: `Launches at login: ${e.command}`
      });
    }
  }

  for (const dir of startupFolders()) {
    if (onProgress) onProgress(`Checking ${dir}`);
    try {
      const files = fs.readdirSync(dir);
      for (const f of files) {
        const full = path.join(dir, f);
        findings.push({
          id: 'startup:' + full,
          category: 'startup',
          path: full,
          size: null,
          severity: assessSeverity(full),
          description: 'Shortcut in Startup folder'
        });
      }
    } catch (e) {
      // skip
    }
  }

  return findings;
}

module.exports = { scanStartup };
