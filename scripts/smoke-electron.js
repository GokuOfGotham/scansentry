const path = require('path');
const { app, BrowserWindow, ipcMain } = require('electron');

const rootDir = path.resolve(__dirname, '..');

app.disableHardwareAcceleration();

ipcMain.handle('settings:get', () => ({
  vtApiKey: '',
  scanPaths: [],
  exclusions: [],
  lastScan: null
}));
ipcMain.handle('quarantine:list', () => []);

app.whenReady().then(async () => {
  const window = new BrowserWindow({
    show: false,
    width: 900,
    height: 640,
    webPreferences: {
      preload: path.join(rootDir, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      navigateOnDragDrop: false
    }
  });

  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  await window.loadFile(path.join(rootDir, 'src', 'index.html'));

  const preloadReady = await window.webContents.executeJavaScript(
    'typeof window.scansentry === "object" && typeof window.scansentry.runScan === "function"',
    true
  );

  if (!preloadReady) throw new Error('Preload API was not exposed.');

  console.log('Electron smoke test passed.');
  app.quit();
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
  app.quit();
});
