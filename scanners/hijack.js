const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const util = require('util');
const execFileP = util.promisify(execFile);

// Search/home domains we consider legitimate defaults. Anything else found
// in a "default search provider" or "homepage" field gets flagged for review
// - it doesn't necessarily mean malware, but it's the #1 hijack symptom.
const KNOWN_GOOD_DOMAINS = [
  'google.com', 'bing.com', 'duckduckgo.com', 'yahoo.com',
  'ecosia.org', 'startpage.com', 'brave.com'
];

function domainIsKnownGood(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, '');
    return KNOWN_GOOD_DOMAINS.some(good => host === good || host.endsWith('.' + good));
  } catch (e) {
    return false;
  }
}

function checkChromiumPrefs(browserName, prefsPath) {
  const findings = [];
  if (!fs.existsSync(prefsPath)) return findings;

  let prefs;
  try {
    prefs = JSON.parse(fs.readFileSync(prefsPath, 'utf-8'));
  } catch (e) {
    return findings;
  }

  const homepage = prefs.homepage;
  if (homepage && !domainIsKnownGood(homepage)) {
    findings.push({
      id: `hijack:${browserName}:homepage`,
      category: 'hijack',
      path: prefsPath,
      size: null,
      severity: 'medium',
      description: `${browserName} homepage set to unrecognized site: ${homepage}`,
      field: 'homepage',
      value: homepage
    });
  }

  const searchProvider = prefs.default_search_provider_data &&
    prefs.default_search_provider_data.template_url_data &&
    prefs.default_search_provider_data.template_url_data.url;
  if (searchProvider && !domainIsKnownGood(searchProvider)) {
    findings.push({
      id: `hijack:${browserName}:search`,
      category: 'hijack',
      path: prefsPath,
      size: null,
      severity: 'high',
      description: `${browserName} default search provider set to unrecognized site: ${searchProvider}`,
      field: 'default_search_provider_data',
      value: searchProvider
    });
  }

  const startupUrls = prefs.session && prefs.session.startup_urls;
  if (Array.isArray(startupUrls)) {
    for (const url of startupUrls) {
      if (!domainIsKnownGood(url)) {
        findings.push({
          id: `hijack:${browserName}:startup:${url}`,
          category: 'hijack',
          path: prefsPath,
          size: null,
          severity: 'medium',
          description: `${browserName} opens unrecognized site on launch: ${url}`,
          field: 'session.startup_urls',
          value: url
        });
      }
    }
  }

  return findings;
}

function checkFirefoxPrefs(profilesDir) {
  const findings = [];
  if (!fs.existsSync(profilesDir)) return findings;

  let profiles;
  try {
    profiles = fs.readdirSync(profilesDir, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => path.join(profilesDir, d.name));
  } catch (e) {
    return findings;
  }

  for (const profile of profiles) {
    const prefsFile = path.join(profile, 'prefs.js');
    if (!fs.existsSync(prefsFile)) continue;
    let content;
    try {
      content = fs.readFileSync(prefsFile, 'utf-8');
    } catch (e) {
      continue;
    }

    const homeMatch = content.match(/user_pref\("browser\.startup\.homepage",\s*"([^"]+)"\)/);
    if (homeMatch && !domainIsKnownGood(homeMatch[1])) {
      findings.push({
        id: `hijack:firefox:${profile}:homepage`,
        category: 'hijack',
        path: prefsFile,
        size: null,
        severity: 'medium',
        description: `Firefox homepage set to unrecognized site: ${homeMatch[1]}`,
        field: 'browser.startup.homepage',
        value: homeMatch[1]
      });
    }

    const keywordMatch = content.match(/user_pref\("keyword\.URL",\s*"([^"]+)"\)/);
    if (keywordMatch && !domainIsKnownGood(keywordMatch[1])) {
      findings.push({
        id: `hijack:firefox:${profile}:keyword`,
        category: 'hijack',
        path: prefsFile,
        size: null,
        severity: 'high',
        description: `Firefox address bar search set to unrecognized site: ${keywordMatch[1]}`,
        field: 'keyword.URL',
        value: keywordMatch[1]
      });
    }
  }

  return findings;
}

// ── Registry helpers ──────────────────────────────────────────────────────

// Returns all REG_* values directly under keyPath as [{ name, type, value }]
async function queryRegValues(keyPath) {
  const entries = [];
  try {
    const { stdout } = await execFileP('reg', ['query', keyPath]);
    for (const line of stdout.split(/\r?\n/)) {
      const m = line.match(/^\s{4}(\S.*?)\s+(REG_\w+)\s+(.*)$/);
      if (m) entries.push({ name: m[1].trim(), type: m[2], value: m[3].trim() });
    }
  } catch { /* key doesn't exist or access denied */ }
  return entries;
}

// Reads a single named value; returns the string data or null.
async function queryRegSingleValue(keyPath, valueName) {
  try {
    const { stdout } = await execFileP('reg', ['query', keyPath, '/v', valueName]);
    const m = stdout.match(/\s+REG_\w+\s+(.+)/);
    return m ? m[1].trim() : null;
  } catch { return null; }
}

// ── Policy-forced extension detection ─────────────────────────────────────

// Checks ExtensionInstallForcelist registry keys for a given browser.
// These are the keys malicious software writes to silently force-install
// Chrome/Edge extensions and prevent the user from removing them.
async function checkForcedExtensions(browserName, keyPaths) {
  const findings = [];
  for (const keyPath of keyPaths) {
    const values = await queryRegValues(keyPath);
    for (const { name, value } of values) {
      // Value format: "extensionId;updateUrl" — the part before ; is the extension ID
      const extId = value.split(';')[0].trim();
      const needsAdmin = !keyPath.startsWith('HKCU');
      findings.push({
        id: `hijack:policy:ext:${keyPath}:${name}`,
        category: 'hijack',
        path: `${keyPath} → [${name}]`,
        registryKey: keyPath,
        registryValue: name,
        size: null,
        severity: 'high',
        description: `${browserName} extension force-installed by policy: ${extId}` +
          (needsAdmin ? ' — removal requires admin rights' : ''),
        value: extId
      });
    }
  }
  return findings;
}

// Checks for policy-locked homepage, search provider, and startup URLs.
async function checkPolicySettings(browserName, policyKeyPaths) {
  const findings = [];

  for (const keyPath of policyKeyPaths) {
    const needsAdmin = !keyPath.startsWith('HKCU');
    const adminNote = needsAdmin ? ' — removal requires admin rights' : '';

    const homepage = await queryRegSingleValue(keyPath, 'HomepageLocation');
    if (homepage && !domainIsKnownGood(homepage)) {
      findings.push({
        id: `hijack:policy:home:${keyPath}`,
        category: 'hijack',
        path: `${keyPath} → HomepageLocation`,
        registryKey: keyPath,
        registryValue: 'HomepageLocation',
        size: null,
        severity: 'high',
        description: `${browserName} homepage locked by policy to: ${homepage}${adminNote}`,
        value: homepage
      });
    }

    const searchUrl = await queryRegSingleValue(keyPath, 'DefaultSearchProviderSearchURL');
    if (searchUrl && !domainIsKnownGood(searchUrl)) {
      findings.push({
        id: `hijack:policy:search:${keyPath}`,
        category: 'hijack',
        path: `${keyPath} → DefaultSearchProviderSearchURL`,
        registryKey: keyPath,
        registryValue: 'DefaultSearchProviderSearchURL',
        size: null,
        severity: 'high',
        description: `${browserName} search provider locked by policy to: ${searchUrl}${adminNote}`,
        value: searchUrl
      });
    }

    // RestoreOnStartupURLs lives as numbered values under a subkey
    const startupKey = keyPath + '\\RestoreOnStartupURLs';
    const startupUrls = await queryRegValues(startupKey);
    for (const { name, value } of startupUrls) {
      if (!domainIsKnownGood(value)) {
        findings.push({
          id: `hijack:policy:startup:${startupKey}:${name}`,
          category: 'hijack',
          path: `${startupKey} → [${name}]`,
          registryKey: startupKey,
          registryValue: name,
          size: null,
          severity: 'medium',
          description: `${browserName} startup URL locked by policy to: ${value}${adminNote}`,
          value
        });
      }
    }
  }

  return findings;
}

async function scanHijack(onProgress) {
  const home = os.homedir();
  let findings = [];

  // ── Prefs-file checks (existing) ────────────────────────────────────────
  if (onProgress) onProgress('Checking Chrome preferences');
  findings = findings.concat(checkChromiumPrefs(
    'Chrome',
    path.join(home, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Preferences')
  ));

  if (onProgress) onProgress('Checking Edge preferences');
  findings = findings.concat(checkChromiumPrefs(
    'Edge',
    path.join(home, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Preferences')
  ));

  if (onProgress) onProgress('Checking Firefox preferences');
  findings = findings.concat(checkFirefoxPrefs(
    path.join(home, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
  ));

  // ── Registry policy checks (new) ────────────────────────────────────────
  if (onProgress) onProgress('Checking Chrome policy registry keys');
  findings = findings.concat(await checkForcedExtensions('Chrome', [
    'HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist',
    'HKLM\\SOFTWARE\\WOW6432Node\\Policies\\Google\\Chrome\\ExtensionInstallForcelist',
    'HKCU\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist'
  ]));
  findings = findings.concat(await checkPolicySettings('Chrome', [
    'HKLM\\SOFTWARE\\Policies\\Google\\Chrome',
    'HKLM\\SOFTWARE\\WOW6432Node\\Policies\\Google\\Chrome',
    'HKCU\\SOFTWARE\\Policies\\Google\\Chrome'
  ]));

  if (onProgress) onProgress('Checking Edge policy registry keys');
  findings = findings.concat(await checkForcedExtensions('Edge', [
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist',
    'HKLM\\SOFTWARE\\WOW6432Node\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist',
    'HKCU\\SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist'
  ]));
  findings = findings.concat(await checkPolicySettings('Edge', [
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge',
    'HKLM\\SOFTWARE\\WOW6432Node\\Policies\\Microsoft\\Edge',
    'HKCU\\SOFTWARE\\Policies\\Microsoft\\Edge'
  ]));

  return findings;
}

module.exports = { scanHijack, domainIsKnownGood };
