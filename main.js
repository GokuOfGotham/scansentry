const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { fileURLToPath } = require('url');

const SettingsStore = require('./settings');
const QuarantineManager = require('./quarantine');
const { scanJunk } = require('./scanners/junk');
const { scanStartup } = require('./scanners/startup');
const { scanHijack } = require('./scanners/hijack');
const { scanMalware } = require('./scanners/malware');

let mainWindow;
let settings;
let quarantine;
let allowedFileActions = new Set();
let allowedRegistryActions = new Set();

const SCAN_CATEGORIES = new Set(['junk', 'startup', 'hijack', 'malware']);
const RENDERER_SETTING_KEYS = new Set(['vtApiKey', 'scanPaths', 'exclusions']);

function isRegistryPath(p) {
  return /^HK[A-Z_]+\\/i.test(p || '');
}

function normalizeFilePath(filePath) {
  if (typeof filePath !== 'string') throw new Error('Invalid file path.');
  const trimmed = filePath.trim();
  if (!trimmed || !path.isAbsolute(trimmed)) throw new Error('Invalid file path.');
  return path.resolve(trimmed);
}

function fileActionKey(filePath) {
  return normalizeFilePath(filePath).toLowerCase();
}

function registryActionKey(keyPath, valueName) {
  if (typeof keyPath !== 'string' || typeof valueName !== 'string') {
    throw new Error('Invalid registry target.');
  }
  const key = keyPath.trim();
  const value = valueName.trim();
  if (!/^HK(?:CU|LM|CR|U|CC)\\/i.test(key) || !value) {
    throw new Error('Invalid registry target.');
  }
  return `${key.toLowerCase()}\0${value.toLowerCase()}`;
}

function rememberActionableFindings(results) {
  allowedFileActions = new Set();
  allowedRegistryActions = new Set();

  for (const findings of Object.values(results)) {
    if (!Array.isArray(findings)) continue;
    for (const finding of findings) {
      try {
        if (finding.registryKey && finding.registryValue) {
          allowedRegistryActions.add(registryActionKey(finding.registryKey, finding.registryValue));
        } else if (finding.path && !isRegistryPath(finding.path)) {
          allowedFileActions.add(fileActionKey(finding.path));
        }
      } catch (_) {
        // Ignore malformed scanner output instead of granting an action.
      }
    }
  }
}

function assertAllowedFileAction(filePath) {
  const resolved = normalizeFilePath(filePath);
  if (!allowedFileActions.has(resolved.toLowerCase())) {
    throw new Error('This file action is not from the current scan results. Re-run the scan and select the item from Results.');
  }
  return resolved;
}

function assertAllowedRegistryAction(keyPath, valueName) {
  if (!allowedRegistryActions.has(registryActionKey(keyPath, valueName))) {
    throw new Error('This registry action is not from the current scan results. Re-run the scan and select the item from Results.');
  }
}

function validateCategories(categories) {
  if (!Array.isArray(categories)) throw new Error('Invalid scan categories.');
  const unique = [...new Set(categories)];
  if (unique.length === 0 || unique.some(category => !SCAN_CATEGORIES.has(category))) {
    throw new Error('Invalid scan categories.');
  }
  return unique;
}

function validatePathList(value, key) {
  if (!Array.isArray(value) || value.length > 100) throw new Error(`Invalid ${key}.`);
  return value.map(item => {
    const resolved = normalizeFilePath(item);
    if (resolved.startsWith('\\\\.\\') || resolved.startsWith('\\\\?\\')) {
      throw new Error(`Invalid ${key}.`);
    }
    return resolved;
  });
}

function validateSettingValue(key, value) {
  if (!RENDERER_SETTING_KEYS.has(key)) throw new Error('Unknown setting.');
  if (key === 'vtApiKey') {
    if (typeof value !== 'string' || value.length > 512) throw new Error('Invalid API key.');
    return value.trim();
  }
  return validatePathList(value, key);
}

function isTrustedAppUrl(targetUrl) {
  try {
    if (new URL(targetUrl).protocol !== 'file:') return false;
    return path.normalize(fileURLToPath(targetUrl)) === path.join(__dirname, 'src', 'index.html');
  } catch (_) {
    return false;
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 860,
    minHeight: 600,
    backgroundColor: '#FFFFFF',
    icon: path.join(__dirname, 'assets', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      navigateOnDragDrop: false,
      devTools: !app.isPackaged
    }
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, targetUrl) => {
    if (!isTrustedAppUrl(targetUrl)) event.preventDefault();
  });
  mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));
}

app.whenReady().then(() => {
  settings = new SettingsStore(app.getPath('userData'));
  quarantine = new QuarantineManager(app.getPath('userData'));
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

function sendProgress(message) {
  if (mainWindow) mainWindow.webContents.send('scan:progress', message);
}

ipcMain.handle('settings:get', () => settings.all());
ipcMain.handle('settings:set', (event, key, value) => {
  settings.set(key, validateSettingValue(key, value));
  return settings.all();
});

ipcMain.handle('scan:run', async (event, categories) => {
  categories = validateCategories(categories);
  allowedFileActions = new Set();
  allowedRegistryActions = new Set();
  const results = {};

  if (categories.includes('junk')) {
    sendProgress('Starting junk/temp scan...');
    results.junk = await scanJunk(sendProgress);
  }
  if (categories.includes('startup')) {
    sendProgress('Starting startup items scan...');
    results.startup = await scanStartup(sendProgress);
  }
  if (categories.includes('hijack')) {
    sendProgress('Starting browser hijack scan...');
    results.hijack = await scanHijack(sendProgress);
  }
  if (categories.includes('malware')) {
    sendProgress('Starting malware hash scan...');
    results.malware = await scanMalware(sendProgress, {
      vtApiKey: settings.get('vtApiKey'),
      extraPaths: validatePathList(settings.get('scanPaths') || [], 'scanPaths')
    });
  }

  settings.set('lastScan', new Date().toISOString());
  rememberActionableFindings(results);
  sendProgress('Scan complete.');
  return results;
});

ipcMain.handle('item:quarantine', (event, itemPath, meta) => {
  return quarantine.quarantine(assertAllowedFileAction(itemPath), meta);
});

ipcMain.handle('item:delete', (event, itemPath) => {
  const fs = require('fs');
  const target = assertAllowedFileAction(itemPath);
  try {
    fs.unlinkSync(target);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    // Already gone — treat as success
  }
  return { deleted: target };
});

ipcMain.handle('item:delete-batch', (event, paths) => {
  if (!Array.isArray(paths) || paths.length > 5000) throw new Error('Invalid delete request.');
  const targets = paths.map(assertAllowedFileAction);
  const fs = require('fs');
  const deleted = [];
  const skipped = [];  // locked by a running process (EBUSY/EPERM) — not a real error
  const failed = [];
  for (const p of targets) {
    try {
      fs.unlinkSync(p);
      deleted.push(p);
    } catch (e) {
      if (e.code === 'EBUSY' || e.code === 'EPERM') {
        skipped.push(p);
      } else if (e.code === 'ENOENT') {
        deleted.push(p);  // already gone — count as success
      } else {
        failed.push({ path: p, error: e.message });
      }
    }
  }
  return { deleted, skipped, failed };
});

ipcMain.handle('item:quarantine-registry', (event, keyPath, valueName, meta) => {
  assertAllowedRegistryAction(keyPath, valueName);
  return quarantine.quarantineRegistryValue(keyPath, valueName, meta);
});

ipcMain.handle('item:delete-registry', (event, keyPath, valueName) => {
  const { execFileSync } = require('child_process');
  assertAllowedRegistryAction(keyPath, valueName);
  try {
    execFileSync('reg', ['delete', keyPath, '/v', valueName, '/f'], { encoding: 'utf-8' });
    return { deleted: `${keyPath}\\${valueName}` };
  } catch (e) {
    const msg = e.stderr ? e.stderr.toString() : e.message;
    if (msg && msg.includes('Access is denied')) {
      throw new Error('Admin rights required to modify this registry key. Run ScanSentry as administrator.');
    }
    throw new Error('Could not delete registry value: ' + msg);
  }
});

ipcMain.handle('quarantine:list', () => quarantine.list());
ipcMain.handle('quarantine:restore', (event, id) => quarantine.restore(id));
ipcMain.handle('quarantine:delete', (event, id) => quarantine.deletePermanently(id));

ipcMain.handle('shell:showItem', (event, itemPath) => {
  shell.showItemInFolder(assertAllowedFileAction(itemPath));
});
