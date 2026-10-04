/**
 * CyberShield — Frontend Logic & SOC Interactions
 * Connects directly to FastAPI backend, renders explainable forensic cards,
 * attack timelines, and evidence breakdowns.
 */

// API Base URL Configuration
// Uses window.CYBERSHIELD_API_BASE or localStorage if set, otherwise defaults to same-origin relative paths (e.g. /api/...)
const API_BASE_URL = (
  (typeof window !== 'undefined' && window.CYBERSHIELD_API_BASE) ||
  (typeof localStorage !== 'undefined' && localStorage.getItem('CYBERSHIELD_API_BASE')) ||
  ''
).replace(/\/+$/, '');

// Global State
let analysisData = {
  summary: null,
  incidents: [],
  events: []
};

// DOM References
const metricTotalEvents = document.getElementById('metricTotalEvents');
const metricSuspiciousEvents = document.getElementById('metricSuspiciousEvents');
const metricActiveIncidents = document.getElementById('metricActiveIncidents');
const metricUniqueEntities = document.getElementById('metricUniqueEntities');
const sidebarIncidentCount = document.getElementById('sidebarIncidentCount');

const incidentsTableBody = document.getElementById('incidentsTableBody');
const suspiciousIpsList = document.getElementById('suspiciousIpsList');
const suspiciousUsersList = document.getElementById('suspiciousUsersList');
const rawLogsTableBody = document.getElementById('rawLogsTableBody');
const rawLogsCountBadge = document.getElementById('rawLogsCountBadge');

const incidentModal = document.getElementById('incidentModal');
const modalTitle = document.getElementById('modalTitle');
const modalBody = document.getElementById('modalBody');

// Navigation Tabs
function switchTab(tabId) {
  const dashNav = document.getElementById('navDashboard');
  const incNav = document.getElementById('navIncidents');
  const logNav = document.getElementById('navLogs');
  
  const dashSection = document.getElementById('viewDashboardSection');
  const logSection = document.getElementById('viewLogsSection');

  dashNav.classList.remove('active');
  incNav.classList.remove('active');
  logNav.classList.remove('active');

  if (tabId === 'dashboard' || tabId === 'incidents') {
    if (tabId === 'dashboard') dashNav.classList.add('active');
    if (tabId === 'incidents') incNav.classList.add('active');
    dashSection.style.display = 'grid';
    logSection.style.display = 'none';
  } else if (tabId === 'logs') {
    logNav.classList.add('active');
    dashSection.style.display = 'none';
    logSection.style.display = 'flex';
  }
}

// Show Toast
function showToast(message, icon = 'ℹ️') {
  const toast = document.getElementById('toastNotification');
  const toastMessage = document.getElementById('toastMessage');
  const toastIcon = document.getElementById('toastIcon');
  
  toastMessage.textContent = message;
  toastIcon.textContent = icon;
  toast.classList.add('show');
  
  setTimeout(() => {
    toast.classList.remove('show');
  }, 3500);
}

// Format Risk Badges
function getRiskBadge(level) {
  const l = (level || 'LOW').toUpperCase();
  if (l === 'CRITICAL') return '<span class="badge badge-critical">CRITICAL</span>';
  if (l === 'HIGH') return '<span class="badge badge-high">HIGH</span>';
  if (l === 'MEDIUM') return '<span class="badge badge-medium">MEDIUM</span>';
  return '<span class="badge badge-low">LOW</span>';
}

function getStatusBadge(status) {
  const s = status || 'New';
  if (s === 'Resolved') return '<span style="color:#51cf66; font-weight:700; display:inline-flex; align-items:center; gap:4px;">● Resolved</span>';
  if (s === 'Investigating') return '<span style="color:#38bdf8; font-weight:700; display:inline-flex; align-items:center; gap:4px;">● Investigating</span>';
  return '<span style="color:#ff6b6b; font-weight:700; display:inline-flex; align-items:center; gap:4px;">● New</span>';
}

// Render Summary Cards
function updateSummaryMetrics(summary) {
  if (!summary) return;
  metricTotalEvents.textContent = summary.total_events || 0;
  metricSuspiciousEvents.textContent = summary.total_suspicious_events || 0;
  metricActiveIncidents.textContent = summary.total_incidents || 0;
  sidebarIncidentCount.textContent = summary.total_incidents || 0;
  metricUniqueEntities.textContent = `${summary.unique_ips || 0} / ${summary.unique_users || 0}`;

  // Render Top Suspicious IPs
  if (summary.suspicious_ips && summary.suspicious_ips.length > 0) {
    suspiciousIpsList.innerHTML = summary.suspicious_ips.slice(0, 5).map(ip => `
      <div class="entity-row">
        <div>
          <div class="entity-name">${escapeHtml(ip.ip)}</div>
          <div style="font-size:0.78rem; color:var(--text-muted); margin-top:2px;">${ip.incident_count} linked incident(s)</div>
        </div>
        <span class="score-pill ${ip.threat_score >= 80 ? 'badge-critical' : 'badge-high'}">Threat: ${ip.threat_score}</span>
      </div>
    `).join('');
  } else {
    suspiciousIpsList.innerHTML = '<div class="empty-state" style="padding:1.5rem 0;">No suspicious IPs identified</div>';
  }

  // Render Top Suspicious Users
  if (summary.suspicious_users && summary.suspicious_users.length > 0) {
    suspiciousUsersList.innerHTML = summary.suspicious_users.slice(0, 5).map(u => `
      <div class="entity-row">
        <div>
          <div class="entity-name">${escapeHtml(u.user)}</div>
          <div style="font-size:0.78rem; color:var(--text-muted); margin-top:2px;">${u.incident_count} linked incident(s)</div>
        </div>
        <span class="score-pill ${u.threat_score >= 80 ? 'badge-critical' : 'badge-high'}">Threat: ${u.threat_score}</span>
      </div>
    `).join('');
  } else {
    suspiciousUsersList.innerHTML = '<div class="empty-state" style="padding:1.5rem 0;">No targeted accounts flagged</div>';
  }
}

// Render Incidents Table
function renderIncidentsTable(incidents) {
  if (!incidents || incidents.length === 0) {
    incidentsTableBody.innerHTML = `
      <tr>
        <td colspan="7">
          <div class="empty-state">
            <div class="empty-state-icon">🛡️</div>
            <p style="font-size:0.95rem;">No suspicious intrusion incidents found.</p>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  incidentsTableBody.innerHTML = incidents.map(inc => `
    <tr onclick="openIncidentDetail('${inc.incident_id}')">
      <td style="font-family:var(--font-mono); font-weight:800; font-size:0.92rem; color:var(--accent-blue);">${inc.incident_id}</td>
      <td>${getRiskBadge(inc.risk_level)} <span style="font-size:0.8rem; color:var(--text-muted); font-family:var(--font-mono); font-weight:700; margin-left:4px;">(${inc.risk_score})</span></td>
      <td>
        <div style="font-family:var(--font-mono); font-weight:700; font-size:0.9rem; color:var(--text-primary);">${escapeHtml(inc.source_ip)}</div>
        <div style="font-size:0.78rem; color:var(--text-secondary); margin-top:2px;">User: <strong>${escapeHtml(inc.user || 'anonymous')}</strong></div>
      </td>
      <td style="font-family:var(--font-mono); font-weight:700; font-size:0.9rem;">${inc.total_events}</td>
      <td style="max-width:240px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-weight:600;" title="${escapeHtml(inc.triggered_rules.join(', '))}">
        ${escapeHtml(inc.triggered_rules[0] || 'Behavioral Anomaly')}
      </td>
      <td>${getStatusBadge(inc.status)}</td>
      <td>
        <button class="btn btn-secondary" style="padding:0.4rem 0.85rem; font-size:0.8rem; font-weight:700;" onclick="event.stopPropagation(); openIncidentDetail('${inc.incident_id}')">
          Forensics →
        </button>
      </td>
    </tr>
  `).join('');
}

// Filter Incidents by Risk Level
function filterIncidents() {
  const filterVal = document.getElementById('filterRisk').value;
  if (!analysisData.incidents) return;
  
  if (filterVal === 'ALL') {
    renderIncidentsTable(analysisData.incidents);
  } else {
    const filtered = analysisData.incidents.filter(i => i.risk_level.toUpperCase() === filterVal);
    renderIncidentsTable(filtered);
  }
}

// Render Ingested Raw Logs
function renderRawLogs(events) {
  if (!events || events.length === 0) {
    rawLogsTableBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:2rem;">No logs loaded.</td></tr>';
    rawLogsCountBadge.textContent = '0 rows';
    return;
  }

  rawLogsCountBadge.textContent = `${events.length} rows`;
  rawLogsTableBody.innerHTML = events.map(e => `
    <tr>
      <td style="font-family:var(--font-mono); font-size:0.82rem;">${escapeHtml(e.timestamp)}</td>
      <td style="font-family:var(--font-mono); font-weight:600;">${escapeHtml(e.source_ip)}</td>
      <td style="font-weight:600;">${escapeHtml(e.username)}</td>
      <td><span style="font-family:var(--font-mono); color:var(--accent-cyan); font-weight:700;">${escapeHtml(e.action)}</span></td>
      <td>
        <span class="badge ${e.status === 'SUCCESS' ? 'badge-low' : (e.status === 'FAILED' ? 'badge-critical' : 'badge-medium')}">
          ${escapeHtml(e.status)}
        </span>
      </td>
      <td style="font-family:var(--font-mono); font-size:0.82rem; color:var(--text-secondary);">${escapeHtml(e.resource)}</td>
      <td style="font-size:0.78rem; color:var(--text-muted);">${escapeHtml(e.user_agent.substring(0, 35))}</td>
    </tr>
  `).join('');
}

// Open Forensics Detail Modal
function openIncidentDetail(incidentId) {
  const inc = analysisData.incidents.find(i => i.incident_id === incidentId);
  if (!inc) return;

  modalTitle.innerHTML = `<span>🔍</span> Forensic Investigation: ${inc.incident_id} — ${escapeHtml(inc.title)}`;

  // Attack sequence HTML
  const sequenceHtml = inc.likely_attack_sequence.map((step, idx) => `
    <div class="sequence-step ${step.includes('Compromise') || step.includes('Breakthrough') ? 'critical-step' : ''}">
      <span class="step-badge">STEP ${idx + 1}</span>
      <div style="flex:1;">${escapeHtml(step)}</div>
    </div>
  `).join('');

  // Evidence list HTML
  const evidenceHtml = inc.evidence.map(item => `
    <li><span>${escapeHtml(item)}</span></li>
  `).join('');

  // Timeline events HTML
  const timelineHtml = inc.related_events.map(ev => `
    <div class="timeline-event ${ev.status === 'FAILED' ? 'event-failed' : 'event-success'}">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem;">
        <span style="color:var(--text-primary); font-family:var(--font-mono); font-weight:700; font-size:0.92rem;">
          ${escapeHtml(ev.action)}
        </span>
        <span style="color:var(--text-muted); font-size:0.8rem; font-family:var(--font-mono);">
          ${escapeHtml(ev.timestamp)}
        </span>
      </div>
      <div style="font-size:0.84rem; color:var(--text-secondary); display:flex; flex-wrap:wrap; gap:0.75rem;">
        <span>Target: <strong style="color:var(--accent-cyan); font-family:var(--font-mono);">${escapeHtml(ev.resource)}</strong></span>
        <span>Outcome: <strong style="font-family:var(--font-mono);">${escapeHtml(ev.status)} (${ev.status_code})</strong></span>
        <span>IP: <strong style="font-family:var(--font-mono);">${escapeHtml(ev.source_ip)}</strong></span>
      </div>
    </div>
  `).join('');

  modalBody.innerHTML = `
    <!-- Top Details Banner -->
    <div class="detail-banner">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem;">
        <div>
          <span style="font-size:0.8rem; text-transform:uppercase; letter-spacing:0.06em; color:var(--status-critical); font-weight:800;">
            ${inc.attack_phase}
          </span>
          <h4>${escapeHtml(inc.title)}</h4>
        </div>
        <div style="text-align:right;">
          ${getRiskBadge(inc.risk_level)}
          <div style="font-family:var(--font-mono); font-size:0.9rem; margin-top:0.35rem; font-weight:800; color:var(--text-primary);">Threat Score: ${inc.risk_score} / 100</div>
        </div>
      </div>
    </div>

    <!-- Incident Metadata Grid -->
    <div class="detail-grid">
      <div>
        <div class="detail-item-label">Intruder Origin IP</div>
        <div class="detail-item-val" style="color:#ff6b6b;">${escapeHtml(inc.source_ip)}</div>
      </div>
      <div>
        <div class="detail-item-label">Target Account</div>
        <div class="detail-item-val" style="color:var(--accent-blue);">${escapeHtml(inc.user)}</div>
      </div>
      <div>
        <div class="detail-item-label">Detection Window</div>
        <div class="detail-item-val">${inc.duration_seconds}s (${inc.total_events} events)</div>
      </div>
      <div>
        <div class="detail-item-label">Incident Status</div>
        <div class="detail-item-val" style="margin-top:0.2rem;">
          <select id="modalStatusSelect" onchange="updateIncidentStatus('${inc.incident_id}', this.value)" style="background:var(--bg-secondary); color:var(--text-primary); border:1px solid var(--border-light); border-radius:var(--radius-sm); padding:0.3rem 0.6rem; font-size:0.84rem; font-weight:700; cursor:pointer;">
            <option value="New" ${inc.status === 'New' ? 'selected' : ''}>● New</option>
            <option value="Investigating" ${inc.status === 'Investigating' ? 'selected' : ''}>● Investigating</option>
            <option value="Resolved" ${inc.status === 'Resolved' ? 'selected' : ''}>● Resolved</option>
          </select>
        </div>
      </div>
    </div>

    <!-- Why Was This Flagged? (Explainability PS requirement) -->
    <div>
      <div class="section-title">
        <span>🎯</span> Explainable Detection Rationale
      </div>
      <div class="rationale-box">
        ${escapeHtml(inc.why_flagged)}
      </div>
    </div>

    <!-- Likely Attack Sequence (High-Value PS requirement) -->
    <div>
      <div class="section-title">
        <span>⚡</span> Likely Attack Sequence (Correlated Chain)
      </div>
      <div class="sequence-container">
        ${sequenceHtml}
      </div>
    </div>

    <!-- Forensic Evidence Items -->
    <div>
      <div class="section-title">
        <span>📋</span> Verified Forensic Evidence
      </div>
      <div class="evidence-box">
        <ul>${evidenceHtml}</ul>
      </div>
    </div>

    <!-- Chronological Event Timeline -->
    <div>
      <div class="section-title">
        <span>⏱️</span> Chronological Event Timeline (${inc.total_events} Correlated Events)
      </div>
      <div class="timeline">
        ${timelineHtml}
      </div>
    </div>
  `;

  incidentModal.classList.add('open');
}

function closeIncidentModal() {
  incidentModal.classList.remove('open');
}

// Update Status in Backend
async function updateIncidentStatus(incidentId, newStatus) {
  try {
    const res = await fetch(`${API_BASE_URL}/api/incidents/${incidentId}/status?status=${newStatus}`, { method: 'PATCH' });
    if (res.ok) {
      showToast(`Incident ${incidentId} status updated to ${newStatus}`, '✅');
      const inc = analysisData.incidents.find(i => i.incident_id === incidentId);
      if (inc) inc.status = newStatus;
      filterIncidents();
    }
  } catch (err) {
    showToast('Failed to update status', '❌');
  }
}

// Load Pre-Configured Sample Data
async function loadSampleLogs() {
  const btn = document.getElementById('btnLoadDemo');
  const originalText = btn.innerHTML;
  btn.innerHTML = '<span>⏳</span> Analyzing logs...';
  btn.disabled = true;

  try {
    const res = await fetch(`${API_BASE_URL}/api/analyze/sample`);
    if (!res.ok) throw new Error('Failed to load sample logs');
    const data = await res.json();
    
    analysisData = data;
    updateSummaryMetrics(data.summary);
    renderIncidentsTable(data.incidents);
    renderRawLogs(data.events);

    showToast(`Successfully analyzed ${data.events.length} security events!`, '🛡️');
  } catch (err) {
    showToast('Error loading sample logs: ' + err.message, '⚠️');
  } finally {
    btn.innerHTML = originalText;
    btn.disabled = false;
  }
}

// Ingest Custom Uploaded Logs
async function handleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('file', file);

  showToast(`Uploading and parsing ${file.name}...`, '⏳');

  try {
    const res = await fetch(`${API_BASE_URL}/api/analyze/upload`, {
      method: 'POST',
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Upload failed');
    }

    const data = await res.json();
    analysisData = data;
    updateSummaryMetrics(data.summary);
    renderIncidentsTable(data.incidents);
    renderRawLogs(data.events);

    showToast(`Analysis complete: ${data.events.length} events processed!`, '✅');
  } catch (err) {
    showToast('Upload error: ' + err.message, '❌');
  } finally {
    event.target.value = '';
  }
}

// Security Escape Utility
function escapeHtml(str) {
  if (typeof str !== 'string') return str || '';
  return str.replace(/[&<>'"]/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}

// Close Modal when clicking outside
window.onclick = function(event) {
  if (event.target === incidentModal) {
    closeIncidentModal();
  }
};

// Initial Auto-load demo data on startup for immediate judge preview
document.addEventListener('DOMContentLoaded', () => {
  loadSampleLogs();
});
