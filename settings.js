const fs = require('fs');
const path = require('path');

class SettingsStore {
  constructor(userDataPath) {
    this.filePath = path.join(userDataPath, 'settings.json');
    this.defaults = {
      vtApiKey: '',
      scanPaths: [],
      exclusions: [],
      lastScan: null
    };
    this._load();
  }

  _load() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf-8');
      this.data = { ...this.defaults, ...JSON.parse(raw) };
    } catch (e) {
      this.data = { ...this.defaults };
    }
  }

  save() {
    fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf-8');
  }

  get(key) {
    return this.data[key];
  }

  set(key, value) {
    this.data[key] = value;
    this.save();
  }

  all() {
    return this.data;
  }
}

module.exports = SettingsStore;
