const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('scansentry', {
  getSettings: () => ipcRenderer.invoke('settings:get'),
  setSetting: (key, value) => ipcRenderer.invoke('settings:set', key, value),

  runScan: (categories) => ipcRenderer.invoke('scan:run', categories),
  onProgress: (callback) => {
    ipcRenderer.removeAllListeners('scan:progress');
    ipcRenderer.on('scan:progress', (event, message) => callback(message));
  },

  quarantineItem: (itemPath, meta) => ipcRenderer.invoke('item:quarantine', itemPath, meta),
  deleteItem: (itemPath) => ipcRenderer.invoke('item:delete', itemPath),
  quarantineRegistryItem: (keyPath, valueName, meta) => ipcRenderer.invoke('item:quarantine-registry', keyPath, valueName, meta),
  deleteRegistryItem: (keyPath, valueName) => ipcRenderer.invoke('item:delete-registry', keyPath, valueName),
  deleteItemBatch: (paths) => ipcRenderer.invoke('item:delete-batch', paths),

  listQuarantine: () => ipcRenderer.invoke('quarantine:list'),
  restoreQuarantine: (id) => ipcRenderer.invoke('quarantine:restore', id),
  deleteQuarantine: (id) => ipcRenderer.invoke('quarantine:delete', id),

  showInFolder: (itemPath) => ipcRenderer.invoke('shell:showItem', itemPath)
});
