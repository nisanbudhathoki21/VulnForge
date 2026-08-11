
const state = {
  currentTab: 'findings',
  activeScanId: null,
  activeFinding: null,
  filters: { severity: 'ALL', confirmedOnly: false, search: '' },
  stats: {}, findings: [], scans: [], repeaterHistory: [], activeEventSource: null
};

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initListeners();
  loadAllData();
  setInterval(() => { loadStats(); loadScans(); }, 10000);
});

function initTabs() {
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('data-tab');
      switchTab(target);
    });
  });
}

function switchTab(tabId) {
  state.currentTab = tabId;
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.toggle('active', t.getAttribute('data-tab') === tabId));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('hidden', p.getAttribute('id') !== `tab-${tabId}`));
  if (tabId === 'repeater') loadRepeaterHistory();
}

function initListeners() {
  document.getElementById('filter-severity')?.addEventListener('change', (e) => { state.filters.severity = e.target.value; renderFindings(); });
  document.getElementById('filter-confirmed')?.addEventListener('change', (e) => { state.filters.confirmedOnly = e.target.checked; renderFindings(); });
  document.getElementById('filter-search')?.addEventListener('input', (e) => { state.filters.search = e.target.value.toLowerCase(); renderFindings(); });
  document.getElementById('btn-repeater-send')?.addEventListener('click', handleRepeaterSend);
}

async function loadAllData() {
  await Promise.all([loadStats(), loadScans(), loadFindings()]);
}

async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    state.stats = data;
    document.getElementById('stat-total-scans').innerText = data.total_scans || 0;
    document.getElementById('stat-total-findings').innerText = data.total_findings || 0;
    document.getElementById('stat-confirmed-findings').innerText = data.confirmed_findings || 0;
    document.getElementById('stat-total-requests').innerText = (data.total_requests || 0).toLocaleString();
    document.getElementById('stat-avg-findings').innerText = data.avg_findings_per_scan || '0.0';
    document.getElementById('stat-unique-targets').innerText = data.unique_targets || 0;
    const sb = data.severity_breakdown || {};
    document.getElementById('count-crit').innerText = sb.CRITICAL || 0;
    document.getElementById('count-high').innerText = sb.HIGH || 0;
    document.getElementById('count-med').innerText = sb.MEDIUM || 0;
    document.getElementById('count-low').innerText = sb.LOW || 0;
    document.getElementById('count-info').innerText = sb.INFO || 0;
  } catch (err) {}
}

async function loadScans() {
  try {
    const res = await fetch('/api/scans');
    const data = await res.json();
    state.scans = data;
    renderScansTable(data);
  } catch (err) {}
}

async function loadFindings() {
  try {
    const res = await fetch('/api/findings');
    const data = await res.json();
    state.findings = data;
    renderFindings();
  } catch (err) {}
}

function renderFindings() {
  const container = document.getElementById('findings-container');
  if (!container) return;
  const { severity, confirmedOnly, search } = state.filters;
  const filtered = state.findings.filter(f => {
    if (confirmedOnly && !f.is_confirmed) return false;
    if (severity !== 'ALL' && f.severity.toUpperCase() !== severity) return false;
    if (search) {
      const str = `${f.title} ${f.endpoint} ${f.tested_endpoint} ${f.parameter_name} ${f.vuln_type} ${f.cwe_id}`.toLowerCase();
      if (!str.includes(search)) return false;
    }
    return true;
  });
  document.getElementById('visible-findings-count').innerText = filtered.length;

  if (filtered.length === 0) {
    container.innerHTML = `<div class="text-center py-12 border border-dashed border-slate-800 rounded-lg bg-slate-900/40 text-slate-400">No findings match the current filter criteria.</div>`;
    return;
  }

  container.innerHTML = filtered.map(f => {
    const sevClass = `badge-${f.severity.toLowerCase()}`;
    const confirmedBadge = f.is_confirmed 
      ? `<span class="badge badge-confirmed">✓ 100% CONFIRMED</span>`
      : `<span class="badge badge-info">HIGH CONFIDENCE</span>`;
    const specificEndpoint = f.tested_endpoint || f.endpoint;

    return `
      <div class="border border-slate-800 bg-slate-900/70 hover:bg-slate-900/95 rounded-lg p-5 transition-all mb-4">
        <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div class="flex items-center gap-2">
            <span class="badge ${sevClass}">${f.severity}</span>
            ${confirmedBadge}
            <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">CVSS ${f.cvss_score}</span>
            <span class="text-xs text-slate-400 font-mono">${f.cwe_id || 'CWE-N/A'}</span>
          </div>
          <button onclick="openFindingModal(${f.id})" class="btn btn-primary btn-sm">Inspect Wire Evidence</button>
        </div>
        <h3 class="text-base font-bold text-slate-100 mb-2">${f.title}</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mb-3 bg-slate-950/80 p-2.5 rounded border border-slate-800 text-xs font-mono">
          <div class="truncate"><span class="text-slate-500">Endpoint:</span> <span class="text-cyan-300 font-semibold">${specificEndpoint}</span></div>
          <div class="truncate"><span class="text-slate-500">Parameter:</span> <span class="text-amber-300">${f.parameter_name || 'N/A'}</span></div>
        </div>
        <div class="space-y-1.5 mb-3 text-xs text-slate-300">
          <div><b class="text-slate-400">Summary:</b> ${f.short_description || f.description}</div>
          <div><b class="text-red-400">Impact:</b> ${f.technical_impact || f.impact}</div>
        </div>
        <div class="bg-slate-950 p-2.5 rounded text-xs font-mono text-slate-400 flex items-center justify-between">
          <span class="text-emerald-400 font-bold">${f.request_method} HTTP ${f.response_status || 200}</span>
          <span class="text-sky-300 truncate">${f.verification_proof ? f.verification_proof.substring(0, 90) + '...' : 'Verified wire response'}</span>
        </div>
      </div>
    `;
  }).join('');
}

function renderScansTable(scans) {
  const tbody = document.getElementById('scans-table-body');
  if (!tbody) return;
  if (scans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-500">No scan audits found in database.</td></tr>`;
    return;
  }
  tbody.innerHTML = scans.map(s => `
    <tr class="border-b border-slate-800/60 font-mono text-xs hover:bg-slate-800/30">
      <td class="py-3 px-4 text-cyan-400 font-semibold">${s.id}</td>
      <td class="py-3 px-4 text-slate-200 truncate max-w-xs">${s.target_url}</td>
      <td class="py-3 px-4"><span class="badge ${s.status === 'completed' ? 'badge-confirmed' : 'badge-high'} text-[10px]">${s.status}</span></td>
      <td class="py-3 px-4 text-emerald-400 font-bold">${s.confirmed_count} <span class="text-slate-500 font-normal">/ ${s.findings_count}</span></td>
      <td class="py-3 px-4 text-sky-300 font-bold">${(s.requests_count || 0).toLocaleString()} reqs</td>
      <td class="py-3 px-4 text-slate-400">${s.duration_seconds ? s.duration_seconds.toFixed(2) + 's' : '-'}</td>
      <td class="py-3 px-4 text-right">
        <a href="/api/reports/pdf/${s.id}" target="_blank" class="btn btn-dark btn-sm text-xs py-1 px-2 text-rose-400 border-rose-900/40">PDF</a>
        <a href="/api/reports/markdown/${s.id}" target="_blank" class="btn btn-dark btn-sm text-xs py-1 px-2 text-slate-300">MD</a>
      </td>
    </tr>
  `).join('');
}

async function openFindingModal(findingId) {
  const res = await fetch(`/api/findings/${findingId}`);
  const f = await res.json();
  state.activeFinding = f;
  document.getElementById('finding-modal').classList.remove('hidden');
  document.getElementById('modal-title').innerText = f.title;
  document.getElementById('modal-severity-badge').className = `badge badge-${f.severity.toLowerCase()}`;
  document.getElementById('modal-severity-badge').innerText = f.severity;
  document.getElementById('modal-cvss').innerText = `CVSS v3.1: ${f.cvss_score}`;
  document.getElementById('modal-endpoint').innerText = `${f.request_method} ${f.tested_endpoint || f.endpoint}`;
  document.getElementById('modal-description').innerText = f.description || f.short_description;
  document.getElementById('modal-impact').innerText = f.technical_impact || f.impact;
  document.getElementById('modal-proof').innerText = f.verification_proof || 'Verified wire response.';
  document.getElementById('modal-raw-request').innerText = f.raw_request || '[No Request Captured]';
  document.getElementById('modal-raw-response').innerText = f.raw_response || '[No Response Captured]';
  document.getElementById('modal-remediation').innerText = f.remediation || 'Apply defense-in-depth controls.';
}

function closeFindingModal() {
  document.getElementById('finding-modal').classList.add('hidden');
}

async function handleLaunchScan(e) {
  e.preventDefault();
  const input = document.getElementById('scan-target-url');
  const target = input.value.trim();
  if (!target) return;
  const res = await fetch('/api/scans/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_url: target })
  });
  const data = await res.json();
  switchTab('console');
  startLogStreaming(data.scan_id);
}

function startLogStreaming(scanId) {
  if (state.activeEventSource) state.activeEventSource.close();
  const terminal = document.getElementById('live-terminal-output');
  terminal.innerHTML = `<div class="terminal-line SYSTEM">[VulnForge Console] Connecting to scan ${scanId}...</div>`;
  const es = new EventSource(`/api/logs/stream/${scanId}`);
  state.activeEventSource = es;
  es.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      const div = document.createElement('div');
      div.className = `terminal-line ${data.level || 'INFO'}`;
      div.innerText = data.message;
      terminal.appendChild(div);
      terminal.scrollTop = terminal.scrollHeight;
      if (data.level === 'COMPLETE' || data.level === 'ERROR') loadAllData();
    } catch (e) {}
  };
}

async function handleRepeaterSend() {
  const rawReq = document.getElementById('repeater-raw-request').value;
  const res = await fetch('/api/repeater/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw_request: rawReq })
  });
  const result = await res.json();
  document.getElementById('repeater-status-badge').innerText = `HTTP ${result.status_code}`;
  document.getElementById('repeater-latency').innerText = `${result.duration_ms} ms`;
  document.getElementById('repeater-raw-response').innerText = result.raw_response || '';
  loadRepeaterHistory();
}

async function loadRepeaterHistory() {
  const res = await fetch('/api/repeater/history');
  const items = await res.json();
  const list = document.getElementById('repeater-history-list');
  if (!list) return;
  list.innerHTML = items.map(item => `
    <div onclick="loadRepeaterItem(${item.id})" class="p-2 bg-slate-900 border border-slate-800 rounded mb-1.5 cursor-pointer text-xs font-mono">
      <span class="text-cyan-400 font-bold">${item.method}</span> <span class="text-slate-300 truncate">${item.url}</span>
    </div>
  `).join('');
  state.repeaterHistory = items;
}

function loadRepeaterItem(itemId) {
  const item = state.repeaterHistory.find(i => i.id === itemId);
  if (!item) return;
  document.getElementById('repeater-raw-request').value = item.raw_request;
  document.getElementById('repeater-raw-response').innerText = item.raw_response;
}
