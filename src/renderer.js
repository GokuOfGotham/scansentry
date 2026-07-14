'use strict';

// ── State ──────────────────────────────────────────────────────────────────
let scanResults = null;      // raw { junk, startup, hijack, malware } from runScan
let allFindings = [];        // flattened, augmented with dismissed flag
let selectedIds = new Set();
let settings = {};
let scanning = false;
let toastTimer = null;

// ── Navigation ─────────────────────────────────────────────────────────────
const screens = document.querySelectorAll('.screen');
const navItems = document.querySelectorAll('.nav-links li');

function showScreen(name) {
  screens.forEach(s => s.classList.toggle('active', s.id === 'screen-' + name));
  navItems.forEach(li => li.classList.toggle('active', li.dataset.screen === name));
  if (name === 'quarantine') renderQuarantine();
  if (name === 'results') renderResults();
  // Hide action bar when leaving results
  if (name !== 'results') hideActionBar();
}

navItems.forEach(li => {
  li.addEventListener('click', () => showScreen(li.dataset.screen));
});

// ── Toast ──────────────────────────────────────────────────────────────────
function showToast(msg, type = '') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'visible' + (type ? ' toast-' + type : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = ''; }, 3500);
}

// ── Helpers ────────────────────────────────────────────────────────────────
function formatSize(bytes) {
  if (!bytes && bytes !== 0) return '';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function formatDate(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleString();
}

function sevClass(sev) {
  return 'sev-' + (sev || 'low');
}

function isRegistryPath(p) {
  return /^HK[A-Z_]+\\/i.test(p || '');
}

// Registry findings that carry registryKey+registryValue are actionable
// via dedicated IPC (not fs ops). Plain registry-path strings (startup items)
// have no registryValue and cannot be file-deleted or quarantined.
function canActOnFinding(f) {
  if (f.registryKey && f.registryValue) return true;
  return f.path && !isRegistryPath(f.path);
}

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Category label display ──────────────────────────────────────────────────
const CATEGORY_LABELS = {
  junk: 'Junk & Temp Files',
  startup: 'Startup Items',
  hijack: 'Browser Hijacks',
  malware: 'Malware Hashes'
};

const CATEGORY_ORDER = ['malware', 'startup', 'hijack', 'junk'];

// ── Scan screen ────────────────────────────────────────────────────────────
const btnStart = document.getElementById('btn-start-scan');
const btnStop = document.getElementById('btn-stop-scan');
const progressLog = document.getElementById('progress-log');
const scanMeta = document.getElementById('scan-meta');

// Category card toggle (clicking the card toggles checkbox)
document.querySelectorAll('.category-card').forEach(card => {
  const cb = card.querySelector('input[type="checkbox"]');
  cb.addEventListener('change', () => {
    card.classList.toggle('selected', cb.checked);
  });
});

function appendLog(msg, cls = '') {
  const line = document.createElement('div');
  line.className = 'log-line' + (cls ? ' ' + cls : '');
  line.textContent = msg;
  progressLog.appendChild(line);
  progressLog.scrollTop = progressLog.scrollHeight;
}

function clearLog() {
  progressLog.innerHTML = '';
}

btnStart.addEventListener('click', async () => {
  const categories = [];
  if (document.getElementById('cb-junk').checked) categories.push('junk');
  if (document.getElementById('cb-startup').checked) categories.push('startup');
  if (document.getElementById('cb-hijack').checked) categories.push('hijack');
  if (document.getElementById('cb-malware').checked) categories.push('malware');

  if (categories.length === 0) {
    showToast('Select at least one category to scan.', 'error');
    return;
  }

  scanning = true;
  btnStart.disabled = true;
  btnStart.innerHTML = '<span class="spinner"></span> Scanning…';
  btnStop.style.display = 'inline-flex';
  progressLog.style.display = 'block';
  clearLog();
  scanMeta.textContent = '';

  // Clear previous results
  scanResults = null;
  allFindings = [];
  selectedIds.clear();
  resetPagination();
  updateResultsBadge();
  hideActionBar();

  window.scansentry.onProgress(msg => {
    appendLog(msg);
  });

  try {
    const results = await window.scansentry.runScan(categories);
    scanResults = results;
    allFindings = buildFindings(results);

    appendLog('Scan complete.', 'done');
    const total = allFindings.length;
    scanMeta.textContent = `Found ${total} item${total !== 1 ? 's' : ''} across ${categories.length} categor${categories.length !== 1 ? 'ies' : 'y'}.`;
    updateResultsBadge();

    if (total > 0) {
      showToast(`Scan complete: ${total} finding${total !== 1 ? 's' : ''}. See Results.`, 'success');
    } else {
      showToast('Scan complete: nothing found.', 'success');
    }
  } catch (err) {
    appendLog('Error: ' + (err && err.message ? err.message : String(err)), 'error');
    showToast('Scan failed. See log for details.', 'error');
  } finally {
    scanning = false;
    btnStart.disabled = false;
    btnStart.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Start Scan';
    btnStop.style.display = 'none';
  }
});

btnStop.addEventListener('click', () => {
  // No IPC for stopping — just note it; the scan will complete naturally.
  appendLog('Stop requested — waiting for current step to finish…', 'error');
});

// ── Build findings list ────────────────────────────────────────────────────
function buildFindings(results) {
  const all = [];
  for (const cat of CATEGORY_ORDER) {
    if (results[cat]) {
      results[cat].forEach(f => all.push({ ...f, dismissed: false }));
    }
  }
  return all;
}

function updateResultsBadge() {
  const active = allFindings.filter(f => !f.dismissed).length;
  const badge = document.getElementById('results-badge');
  badge.textContent = active;
  badge.classList.toggle('hidden', active === 0);
}

// ── Results screen ─────────────────────────────────────────────────────────
const PAGE_SIZE = 100;
const categoryPageSize = {};  // cat → how many rows are currently rendered

// Reset page sizes when a new scan starts (called from scan handler)
function resetPagination() {
  for (const k of Object.keys(categoryPageSize)) delete categoryPageSize[k];
}

function renderResults() {
  const content = document.getElementById('results-content');
  const summary = document.getElementById('results-summary');

  if (!scanResults || allFindings.length === 0) {
    summary.textContent = 'No results yet — run a scan first.';
    content.innerHTML = `
      <div class="results-empty">
        <div class="empty-icon">⬡</div>
        <p>No results yet — run a scan first.</p>
      </div>`;
    return;
  }

  const active = allFindings.filter(f => !f.dismissed);
  summary.textContent = `${active.length} finding${active.length !== 1 ? 's' : ''} (${allFindings.length - active.length} dismissed)`;

  if (active.length === 0) {
    content.innerHTML = `
      <div class="results-empty">
        <div class="empty-icon" style="color:var(--cyan)">✓</div>
        <p>All findings dismissed.</p>
      </div>`;
    return;
  }

  const groups = [];
  for (const cat of CATEGORY_ORDER) {
    const items = active.filter(f => f.category === cat);
    if (items.length > 0) groups.push({ cat, items });
  }

  content.innerHTML = groups.map(({ cat, items }) => {
    const limit = categoryPageSize[cat] || PAGE_SIZE;
    const visible = items.slice(0, limit);
    const hidden = items.length - visible.length;
    const allCatSelected = items.every(f => selectedIds.has(f.id));

    return `
      <div class="category-group" data-cat="${escHtml(cat)}">
        <div class="group-header">
          <span class="group-label">${escHtml(CATEGORY_LABELS[cat] || cat)}</span>
          <span class="group-count">${items.length}</span>
          <button class="select-all-btn" data-cat="${escHtml(cat)}"
                  title="Select all ${items.length} items in this category"
          >${allCatSelected ? 'Deselect all' : 'Select all'}</button>
          <button class="ignore-cat-btn" data-cat="${escHtml(cat)}"
                  title="Dismiss all items in this category without taking action"
          >Ignore all</button>
        </div>
        ${visible.map(f => renderFindingRow(f)).join('')}
        ${hidden > 0 ? `
          <div class="show-more-row">
            <button class="show-more-btn" data-cat="${escHtml(cat)}">
              Show ${Math.min(hidden, PAGE_SIZE)} more
              <span class="show-more-hint">${hidden} of ${items.length} remaining</span>
            </button>
          </div>` : ''}
      </div>`;
  }).join('');

  // Wire checkboxes
  content.querySelectorAll('.finding-cb').forEach(cb => {
    if (selectedIds.has(cb.dataset.id)) {
      cb.checked = true;
      cb.closest('.finding-row').classList.add('selected');
    }
    cb.addEventListener('change', () => {
      const id = cb.dataset.id;
      if (cb.checked) selectedIds.add(id);
      else selectedIds.delete(id);
      cb.closest('.finding-row').classList.toggle('selected', cb.checked);
      updateActionBar();
    });
  });

  // Row click toggles checkbox (unless clicking a button or checkbox directly)
  content.querySelectorAll('.finding-row').forEach(row => {
    row.addEventListener('click', e => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON') return;
      const cb = row.querySelector('.finding-cb');
      cb.checked = !cb.checked;
      cb.dispatchEvent(new Event('change'));
    });
  });

  // Select all / deselect all for a category — operates on ALL items, not just visible
  content.querySelectorAll('.select-all-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const cat = btn.dataset.cat;
      const catItems = allFindings.filter(f => f.category === cat && !f.dismissed);
      const allSelected = catItems.every(f => selectedIds.has(f.id));
      catItems.forEach(f => {
        if (allSelected) selectedIds.delete(f.id);
        else selectedIds.add(f.id);
      });
      // Sync visible checkboxes
      content.querySelectorAll(`.category-group[data-cat="${cat}"] .finding-cb`).forEach(cb => {
        cb.checked = selectedIds.has(cb.dataset.id);
        cb.closest('.finding-row').classList.toggle('selected', cb.checked);
      });
      btn.textContent = allSelected ? 'Select all' : 'Deselect all';
      updateActionBar();
    });
  });

  // Ignore all in category — dismisses without any IPC call
  content.querySelectorAll('.ignore-cat-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const cat = btn.dataset.cat;
      allFindings
        .filter(f => f.category === cat && !f.dismissed)
        .forEach(f => { f.dismissed = true; selectedIds.delete(f.id); });
      updateResultsBadge();
      updateActionBar();
      renderResults();
    });
  });

  // Show more
  content.querySelectorAll('.show-more-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const cat = btn.dataset.cat;
      categoryPageSize[cat] = (categoryPageSize[cat] || PAGE_SIZE) + PAGE_SIZE;
      renderResults();
    });
  });

  // Show-in-folder buttons
  content.querySelectorAll('.show-in-folder').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      window.scansentry.showInFolder(btn.dataset.path);
    });
  });
}

function renderFindingRow(f) {
  const sizeStr = formatSize(f.size);
  const isReg = isRegistryPath(f.path);
  const showFolderBtn = !isReg
    ? `<button class="show-in-folder" data-path="${escHtml(f.path)}" title="Show in Explorer">Show in folder</button>`
    : '';

  const hash = f.hash
    ? `<div class="finding-hash">SHA-256: ${escHtml(f.hash)}</div>`
    : '';

  const meta = [sizeStr, f.command ? f.command : ''].filter(Boolean).join(' · ');

  return `
    <div class="finding-row" data-id="${escHtml(f.id)}">
      <input type="checkbox" class="finding-cb" data-id="${escHtml(f.id)}">
      <div class="finding-body">
        <div class="finding-path">${escHtml(f.path)}</div>
        <div class="finding-desc">${escHtml(f.description)}</div>
        ${meta ? `<div class="finding-meta">${escHtml(meta)}</div>` : ''}
        ${hash}
      </div>
      <div class="finding-actions-col">
        <span class="sev-badge ${sevClass(f.severity)}">${escHtml(f.severity || 'low')}</span>
        ${showFolderBtn}
      </div>
    </div>`;
}

// ── Action bar ─────────────────────────────────────────────────────────────
function updateActionBar() {
  const bar = document.getElementById('action-bar');
  const count = selectedIds.size;
  if (count === 0) {
    bar.classList.remove('visible');
  } else {
    bar.classList.add('visible');
    document.getElementById('action-bar-count').textContent =
      `${count} item${count !== 1 ? 's' : ''} selected`;
  }
}

function hideActionBar() {
  const bar = document.getElementById('action-bar');
  bar.classList.remove('visible');
}

document.getElementById('btn-quarantine-selected').addEventListener('click', async () => {
  const ids = [...selectedIds];
  const targets = allFindings.filter(f => ids.includes(f.id));
  let done = 0, failed = 0, lastErr = '';

  for (const f of targets) {
    if (!canActOnFinding(f)) {
      lastErr = `Cannot quarantine: ${f.path}`;
      failed++;
      continue;
    }
    try {
      const meta = { category: f.category, severity: f.severity, reason: f.description };
      if (f.registryKey && f.registryValue) {
        await window.scansentry.quarantineRegistryItem(f.registryKey, f.registryValue, meta);
      } else {
        await window.scansentry.quarantineItem(f.path, meta);
      }
      dismissFinding(f.id);
      done++;
    } catch (err) {
      failed++;
      lastErr = err && err.message ? err.message : String(err);
      console.error('Quarantine failed for', f.path, err);
    }
  }

  selectedIds.clear();
  hideActionBar();
  updateResultsBadge();
  renderResults();
  await refreshQuarantineBadge();

  if (done > 0) showToast(`Quarantined ${done} item${done !== 1 ? 's' : ''}.`, 'success');
  if (failed > 0) showToast(lastErr || `${failed} item${failed !== 1 ? 's' : ''} could not be quarantined.`, 'error');
});

document.getElementById('btn-delete-selected').addEventListener('click', async () => {
  const ids = [...selectedIds];
  const targets = allFindings.filter(f => ids.includes(f.id));
  let done = 0, failed = 0, lastErr = '';

  // Split into registry items (individual calls) and file items (one batch call)
  const registryTargets = targets.filter(f => f.registryKey && f.registryValue);
  const fileTargets     = targets.filter(f => !f.registryKey && canActOnFinding(f));
  const skipped         = targets.filter(f => !f.registryKey && !canActOnFinding(f));

  skipped.forEach(f => { lastErr = `Cannot delete: ${f.path}`; failed++; });

  // Registry: one-by-one (there are rarely more than a handful)
  for (const f of registryTargets) {
    try {
      await window.scansentry.deleteRegistryItem(f.registryKey, f.registryValue);
      dismissFinding(f.id);
      done++;
    } catch (err) {
      failed++;
      lastErr = err && err.message ? err.message : String(err);
      console.error('Delete failed for', f.path, err);
    }
  }

  // Files: single batch IPC call (handles thousands efficiently)
  let skippedCount = 0;
  if (fileTargets.length > 0) {
    try {
      const result = await window.scansentry.deleteItemBatch(fileTargets.map(f => f.path));
      result.deleted.forEach(p => {
        const f = fileTargets.find(x => x.path === p);
        if (f) { dismissFinding(f.id); done++; }
      });
      // Locked files (browser open) — dismiss them from the list since they'll
      // be gone once the browser closes; don't count as errors.
      (result.skipped || []).forEach(p => {
        const f = fileTargets.find(x => x.path === p);
        if (f) { dismissFinding(f.id); skippedCount++; }
      });
      result.failed.forEach(({ path: p, error }) => {
        failed++;
        lastErr = error || `Failed: ${p}`;
        console.error('Batch delete failed for', p, error);
      });
    } catch (err) {
      failed += fileTargets.length;
      lastErr = err && err.message ? err.message : String(err);
    }
  }

  selectedIds.clear();
  hideActionBar();
  updateResultsBadge();
  renderResults();

  if (done > 0) showToast(`Deleted ${done} item${done !== 1 ? 's' : ''}.`, 'success');
  if (skippedCount > 0) showToast(`${skippedCount} browser cache file${skippedCount !== 1 ? 's' : ''} skipped — close Chrome / Edge / Firefox first, then re-scan.`, '');
  if (failed > 0) showToast(lastErr || `${failed} item${failed !== 1 ? 's' : ''} could not be deleted.`, 'error');
});

document.getElementById('btn-ignore-selected').addEventListener('click', () => {
  [...selectedIds].forEach(id => dismissFinding(id));
  selectedIds.clear();
  hideActionBar();
  updateResultsBadge();
  renderResults();
  showToast('Items dismissed.', '');
});

function dismissFinding(id) {
  const f = allFindings.find(x => x.id === id);
  if (f) f.dismissed = true;
  selectedIds.delete(id);
}

// ── Quarantine screen ──────────────────────────────────────────────────────
async function renderQuarantine() {
  const content = document.getElementById('quarantine-content');
  let items;
  try {
    items = await window.scansentry.listQuarantine();
  } catch (err) {
    content.innerHTML = `<p style="color:var(--red)">Failed to load quarantine list.</p>`;
    return;
  }

  updateQuarantineBadge(items.length);

  if (!items || items.length === 0) {
    content.innerHTML = `<div class="quarantine-empty"><p style="color:var(--text-faint)">Quarantine is empty.</p></div>`;
    return;
  }

  content.innerHTML = items.map(item => `
    <div class="quarantine-item" data-id="${escHtml(item.id)}">
      <div class="qi-body">
        <div class="qi-path">${escHtml(item.originalPath)}</div>
        <div class="qi-meta">
          <span class="sev-badge ${sevClass(item.severity)}">${escHtml(item.severity || 'unknown')}</span>
          &nbsp;${escHtml(item.category || '')}
          ${item.reason ? ` · ${escHtml(item.reason)}` : ''}
          · ${formatDate(item.quarantinedAt)}
        </div>
      </div>
      <div class="qi-actions">
        <button class="btn btn-ghost btn-sm qi-restore" data-id="${escHtml(item.id)}">Restore</button>
        <button class="btn btn-danger btn-sm qi-delete" data-id="${escHtml(item.id)}">Delete Permanently</button>
      </div>
    </div>
  `).join('');

  content.querySelectorAll('.qi-restore').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await window.scansentry.restoreQuarantine(btn.dataset.id);
        showToast('File restored to original location.', 'success');
        renderQuarantine();
      } catch (err) {
        showToast('Restore failed: ' + (err && err.message ? err.message : String(err)), 'error');
      }
    });
  });

  content.querySelectorAll('.qi-delete').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await window.scansentry.deleteQuarantine(btn.dataset.id);
        showToast('File permanently deleted.', 'success');
        renderQuarantine();
      } catch (err) {
        showToast('Delete failed: ' + (err && err.message ? err.message : String(err)), 'error');
      }
    });
  });
}

function updateQuarantineBadge(count) {
  const badge = document.getElementById('quarantine-badge');
  badge.textContent = count;
  badge.classList.toggle('hidden', count === 0);
}

async function refreshQuarantineBadge() {
  try {
    const items = await window.scansentry.listQuarantine();
    updateQuarantineBadge(items.length);
  } catch (_) {}
}

// ── Settings screen ────────────────────────────────────────────────────────
async function loadSettings() {
  try {
    settings = await window.scansentry.getSettings();
  } catch (_) {
    settings = {};
  }

  const vtInput = document.getElementById('input-vt-key');
  vtInput.value = settings.vtApiKey || '';

  renderListEditor('scan-paths-list', settings.scanPaths || []);
  renderListEditor('exclusions-list', settings.exclusions || []);

  // Update last scan info in sidebar
  const lastScan = document.getElementById('last-scan-info');
  lastScan.textContent = settings.lastScan
    ? 'Last scan: ' + formatDate(settings.lastScan)
    : '';
}

function renderListEditor(containerId, items) {
  const el = document.getElementById(containerId);
  if (!items || items.length === 0) {
    el.innerHTML = `<div style="padding:10px 12px;color:var(--text-faint);font-size:11.5px">None configured</div>`;
    return;
  }
  el.innerHTML = items.map((item, i) => `
    <div class="list-item">
      <span>${escHtml(item)}</span>
      <button class="list-item-remove" data-index="${i}" data-list="${escHtml(containerId)}" title="Remove">✕</button>
    </div>
  `).join('');

  el.querySelectorAll('.list-item-remove').forEach(btn => {
    btn.addEventListener('click', async () => {
      const listKey = btn.dataset.list === 'scan-paths-list' ? 'scanPaths' : 'exclusions';
      const arr = [...(settings[listKey] || [])];
      arr.splice(parseInt(btn.dataset.index, 10), 1);
      await window.scansentry.setSetting(listKey, arr);
      settings[listKey] = arr;
      renderListEditor(containerId, arr);
    });
  });
}

// VT key: save on blur
document.getElementById('input-vt-key').addEventListener('blur', async function () {
  try {
    await window.scansentry.setSetting('vtApiKey', this.value.trim());
    settings.vtApiKey = this.value.trim();
  } catch (err) {
    showToast('Failed to save API key.', 'error');
  }
});

// Add scan path
document.getElementById('btn-add-scan-path').addEventListener('click', async () => {
  const input = document.getElementById('scan-path-input');
  const val = input.value.trim();
  if (!val) return;
  const arr = [...(settings.scanPaths || [])];
  if (!arr.includes(val)) {
    arr.push(val);
    await window.scansentry.setSetting('scanPaths', arr);
    settings.scanPaths = arr;
    renderListEditor('scan-paths-list', arr);
  }
  input.value = '';
});

document.getElementById('scan-path-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('btn-add-scan-path').click();
});

// Add exclusion
document.getElementById('btn-add-exclusion').addEventListener('click', async () => {
  const input = document.getElementById('exclusion-input');
  const val = input.value.trim();
  if (!val) return;
  const arr = [...(settings.exclusions || [])];
  if (!arr.includes(val)) {
    arr.push(val);
    await window.scansentry.setSetting('exclusions', arr);
    settings.exclusions = arr;
    renderListEditor('exclusions-list', arr);
  }
  input.value = '';
});

document.getElementById('exclusion-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('btn-add-exclusion').click();
});

// ── Boot ───────────────────────────────────────────────────────────────────
(async () => {
  await loadSettings();
  await refreshQuarantineBadge();
})();
