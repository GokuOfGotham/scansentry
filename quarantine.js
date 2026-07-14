const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

class QuarantineManager {
  constructor(userDataPath) {
    this.dir = path.join(userDataPath, 'quarantine');
    this.manifestPath = path.join(this.dir, 'manifest.json');
    if (!fs.existsSync(this.dir)) fs.mkdirSync(this.dir, { recursive: true });
    this._loadManifest();
  }

  _loadManifest() {
    try {
      this.manifest = JSON.parse(fs.readFileSync(this.manifestPath, 'utf-8'));
    } catch (e) {
      this.manifest = [];
    }
  }

  _saveManifest() {
    fs.writeFileSync(this.manifestPath, JSON.stringify(this.manifest, null, 2), 'utf-8');
  }

  // Moves a file into quarantine. Renamed with a random id so it cannot be
  // accidentally executed or opened by its original extension/name.
  quarantine(originalPath, meta = {}) {
    const id = crypto.randomBytes(8).toString('hex');
    const storedName = id + '.quarantined';
    const storedPath = path.join(this.dir, storedName);

    try {
      fs.renameSync(originalPath, storedPath);
    } catch (e) {
      if (e.code === 'ENOENT') throw new Error('File no longer exists (already deleted): ' + originalPath);
      throw e;
    }

    const entry = {
      id,
      type: 'file',
      originalPath,
      storedPath,
      category: meta.category || 'unknown',
      severity: meta.severity || 'unknown',
      reason: meta.reason || '',
      quarantinedAt: new Date().toISOString()
    };
    this.manifest.push(entry);
    this._saveManifest();
    return entry;
  }

  // Quarantines a registry value by reading + saving its data into the
  // manifest, then deleting the value. Restore writes it back with reg add.
  quarantineRegistryValue(keyPath, valueName, meta = {}) {
    // Read the value first so we can restore it later
    let valueType = 'REG_SZ';
    let valueData = '';
    try {
      const stdout = execFileSync('reg', ['query', keyPath, '/v', valueName], { encoding: 'utf-8' });
      const m = stdout.match(/\s+(REG_\w+)\s+(.+)/);
      if (m) { valueType = m[1]; valueData = m[2].trim(); }
    } catch (e) {
      const msg = e.stderr ? e.stderr.toString() : e.message;
      if (msg && msg.includes('Access is denied')) {
        throw new Error('Admin rights required to modify this registry key. Run ScanSentry as administrator.');
      }
      throw new Error('Could not read registry value: ' + msg);
    }

    // Delete the registry value
    try {
      execFileSync('reg', ['delete', keyPath, '/v', valueName, '/f'], { encoding: 'utf-8' });
    } catch (e) {
      const msg = e.stderr ? e.stderr.toString() : e.message;
      if (msg && msg.includes('Access is denied')) {
        throw new Error('Admin rights required to modify this registry key. Run ScanSentry as administrator.');
      }
      throw new Error('Could not delete registry value: ' + msg);
    }

    const id = crypto.randomBytes(8).toString('hex');
    const entry = {
      id,
      type: 'registry',
      registryKey: keyPath,
      registryValue: valueName,
      registryType: valueType,
      registryData: valueData,
      originalPath: `${keyPath}\\${valueName}`,
      storedPath: null,
      category: meta.category || 'hijack',
      severity: meta.severity || 'high',
      reason: meta.reason || '',
      quarantinedAt: new Date().toISOString()
    };
    this.manifest.push(entry);
    this._saveManifest();
    return entry;
  }

  restore(id) {
    const idx = this.manifest.findIndex(e => e.id === id);
    if (idx === -1) throw new Error('No quarantine entry with id ' + id);
    const entry = this.manifest[idx];

    if (entry.type === 'registry') {
      try {
        execFileSync('reg', [
          'add', entry.registryKey,
          '/v', entry.registryValue,
          '/t', entry.registryType,
          '/d', entry.registryData,
          '/f'
        ], { encoding: 'utf-8' });
      } catch (e) {
        const msg = e.stderr ? e.stderr.toString() : e.message;
        if (msg && msg.includes('Access is denied')) {
          throw new Error('Admin rights required to restore this registry key. Run ScanSentry as administrator.');
        }
        throw new Error('Could not restore registry value: ' + msg);
      }
      this.manifest.splice(idx, 1);
      this._saveManifest();
      return entry;
    }

    // File restore
    const destDir = path.dirname(entry.originalPath);
    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
    fs.renameSync(entry.storedPath, entry.originalPath);

    this.manifest.splice(idx, 1);
    this._saveManifest();
    return entry;
  }

  deletePermanently(id) {
    const idx = this.manifest.findIndex(e => e.id === id);
    if (idx === -1) throw new Error('No quarantine entry with id ' + id);
    const entry = this.manifest[idx];
    // Registry entries have storedPath: null — nothing to delete from disk
    if (entry.storedPath && fs.existsSync(entry.storedPath)) fs.unlinkSync(entry.storedPath);
    this.manifest.splice(idx, 1);
    this._saveManifest();
    return entry;
  }

  list() {
    return this.manifest;
  }
}

module.exports = QuarantineManager;
