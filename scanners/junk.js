const fs = require('fs');
const os = require('os');
const path = require('path');

// Patterns considered safe-to-flag junk. Conservative on purpose: we only
// flag file types that are essentially always regenerable/disposable.
const JUNK_EXTENSIONS = ['.tmp', '.temp', '.log', '.old', '.bak', '.chk', '.dmp', '.gid'];
const JUNK_FILENAMES = ['thumbs.db', 'desktop.ini', '.ds_store'];

function candidateDirs() {
  const home = os.homedir();
  const dirs = [
    os.tmpdir(),
    path.join(home, 'AppData', 'Local', 'Temp'),
    path.join(home, 'AppData', 'Local', 'Microsoft', 'Windows', 'INetCache'),
    path.join(home, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
    path.join(home, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
    path.join(home, 'AppData', 'Local', 'Mozilla', 'Firefox', 'Profiles')
  ];
  return [...new Set(dirs)].filter(d => {
    try { return fs.existsSync(d); } catch { return false; }
  });
}

function isJunk(filePath) {
  const base = path.basename(filePath).toLowerCase();
  if (JUNK_FILENAMES.includes(base)) return true;
  const ext = path.extname(filePath).toLowerCase();
  return JUNK_EXTENSIONS.includes(ext);
}

// Recursively walk a directory collecting junk files. Depth-limited and
// error-tolerant (permission errors on system folders are just skipped).
function walk(dir, results, depth, maxDepth) {
  if (depth > maxDepth) return;
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    try {
      if (entry.isDirectory()) {
        walk(full, results, depth + 1, maxDepth);
      } else if (entry.isFile()) {
        const stat = fs.statSync(full);
        // Any file sitting in a Temp/Cache directory counts as junk regardless
        // of extension, on top of the explicit junk-extension/name check.
        if (isJunk(full) || dir.toLowerCase().includes('temp') || dir.toLowerCase().includes('cache')) {
          results.push({
            path: full,
            size: stat.size,
            mtime: stat.mtimeMs
          });
        }
      }
    } catch (e) {
      // skip unreadable entries
    }
  }
}

async function scanJunk(onProgress) {
  const dirs = candidateDirs();
  const findings = [];

  for (const dir of dirs) {
    if (onProgress) onProgress(`Scanning ${dir}`);
    const results = [];
    walk(dir, results, 0, 6);
    for (const r of results) {
      findings.push({
        id: 'junk:' + r.path,
        category: 'junk',
        path: r.path,
        size: r.size,
        severity: 'low',
        description: 'Temporary/cache file, safe to remove'
      });
    }
  }

  return findings;
}

module.exports = { scanJunk };
