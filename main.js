const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');

const SettingsStore = require('./settings');
const QuarantineManager = require('./quarantine');
const { scanJunk } = require('./scanners/junk');
const { scanStartup } = require('./scanners/startup');
const { scanHijack } = require('./scanners/hijack');
const { scanMalware } = require('./scanners/malware');

let mainWindow;
let settings;
let quarantine;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 860,
    minHeight: 600,
    backgroundColor: '#FFFFFF',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
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
  settings.set(key, value);
  return settings.all();
});

ipcMain.handle('scan:run', async (event, categories) => {
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
      extraPaths: settings.get('scanPaths') || []
    });
  }

  settings.set('lastScan', new Date().toISOString());
  sendProgress('Scan complete.');
  return results;
});

ipcMain.handle('item:quarantine', (event, itemPath, meta) => {
  return quarantine.quarantine(itemPath, meta);
});

ipcMain.handle('item:delete', (event, itemPath) => {
  const fs = require('fs');
  try {
    fs.unlinkSync(itemPath);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    // Already gone — treat as success
  }
  return { deleted: itemPath };
});

ipcMain.handle('item:delete-batch', (event, paths) => {
  const fs = require('fs');
  const deleted = [];
  const skipped = [];  // locked by a running process (EBUSY/EPERM) — not a real error
  const failed = [];
  for (const p of paths) {
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
  return quarantine.quarantineRegistryValue(keyPath, valueName, meta);
});

ipcMain.handle('item:delete-registry', (event, keyPath, valueName) => {
  const { execFileSync } = require('child_process');
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
  shell.showItemInFolder(itemPath);
});
