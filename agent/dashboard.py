#!/usr/bin/env python3
"""
Lynx web dashboard — a self-contained HTTP server (stdlib only, no Flask needed).

Endpoints:
    GET  /                    -> HTML dashboard (auto-refreshing)
    GET  /api/status          -> JSON: event/block/version counts + recent alerts
    GET  /api/alerts          -> JSON: recent alerts
    GET  /api/blocks          -> JSON: blocked attackers
    GET  /api/versions        -> JSON: file versions (optional ?path=)
    GET  /api/report          -> JSON/text: generated incident report
    POST /api/restore         -> JSON: restore a file (body: {"path": "...", "version": optional})
    GET  /health              -> 200 ok

Optional auth: if web.auth_token is set, require ?token=<token> or X-Auth-Token header.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lynx EDR</title>
<style>
  :root { --bg:#0f1420; --panel:#1a2233; --fg:#e6ebf5; --muted:#8b96ad; --accent:#4f8cff; --danger:#ff5c6c; --ok:#3ddc97; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,monospace; background:var(--bg); color:var(--fg); }
  header { padding:16px 24px; border-bottom:1px solid #242e44; display:flex; align-items:center; justify-content:space-between; }
  header h1 { margin:0; font-size:18px; letter-spacing:.5px; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; background:var(--ok); margin-right:8px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; padding:20px 24px; }
  .card { background:var(--panel); border:1px solid #242e44; border-radius:10px; padding:16px; }
  .card .num { font-size:28px; font-weight:700; }
  .card .lbl { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.5px; }
  .num.alert { color:var(--danger); } .num.block { color:var(--ok); }
  section { padding:0 24px 24px; }
  h2 { font-size:14px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; border-bottom:1px solid #242e44; padding-bottom:8px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #20293b; }
  th { color:var(--muted); font-weight:600; }
  .sev-high, .sev-critical { color:var(--danger); }
  .sev-medium { color:#ffb454; }
  code { color:var(--accent); }
  .pulse { animation:p 1.5s infinite; }
  @keyframes p { 0%,100%{opacity:1} 50%{opacity:.4} }
  .muted { color:var(--muted); }
  .btn { padding:8px 16px; border:none; border-radius:6px; cursor:pointer; font-size:13px; font-weight:600; }
  .btn-primary { background:var(--accent); color:#fff; }
  .btn-danger { background:var(--danger); color:#fff; }
  .btn-secondary { background:#374151; color:#fff; }
  input, select { padding:8px 12px; border:1px solid #374151; border-radius:6px; background:#1a2233; color:var(--fg); width:100%; }
  label { display:block; margin-bottom:4px; font-size:13px; color:var(--muted); }
  .form-group { margin-bottom:16px; }
  .form-row { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  .command-box { background:#0a0f1a; border:1px solid #242e44; border-radius:6px; padding:16px; font-family:monospace; font-size:12px; color:var(--accent); overflow-x:auto; white-space:pre-wrap; }
  .status-online { color:var(--ok); }
  .status-stale { color:#ffb454; }
  .status-enrolled { color:var(--muted); }
  .status-revoked { color:var(--danger); }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
  .badge-primary { background:#1e3a5f; color:var(--accent); }
  .badge-success { background:#14532d; color:var(--ok); }
  .tabs { display:flex; gap:8px; margin-bottom:16px; border-bottom:1px solid #242e44; padding-bottom:8px; }
  .tab { padding:8px 16px; cursor:pointer; color:var(--muted); border-bottom:2px solid transparent; }
  .tab.active { color:var(--accent); border-bottom-color:var(--accent); }
  .tab-content { display:none; }
  .tab-content.active { display:block; }
</style>
</head>
<body>
<header>
  <h1><span class="dot pulse"></span>Lynx EDR — Dashboard</h1>
  <span class="muted" id="clock"></span>
</header>
<div class="grid">
  <div class="card"><div class="num" id="n-alerts">–</div><div class="lbl">Alerts</div></div>
  <div class="card"><div class="num block" id="n-blocks">–</div><div class="lbl">Blocked attackers</div></div>
  <div class="card"><div class="num" id="n-versions">–</div><div class="lbl">File versions</div></div>
  <div class="card"><div class="num" id="n-custody">–</div><div class="lbl">Artifacts (CoC)</div></div>
</div>
<section>
  <h2>Recent alerts</h2>
  <table><thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Detail</th></tr></thead>
  <tbody id="alerts"><tr><td colspan="4" class="muted">loading…</td></tr></tbody></table>
</section>
<section>
  <h2>Blocked attackers</h2>
  <table><thead><tr><th>Time</th><th>IP</th><th>MAC</th><th>Reason</th><th>Backend</th></tr></thead>
  <tbody id="blocks"><tr><td colspan="5" class="muted">loading…</td></tr></tbody></table>
</section>
<section>
  <h2>File versions</h2>
  <table><thead><tr><th>Time</th><th>Path</th><th>Event</th><th>SHA-256</th></tr></thead>
  <tbody id="versions"><tr><td colspan="4" class="muted">loading…</td></tr></tbody></table>
</section>
<script>
async function j(u){ const r = await fetch(u); return r.json(); }
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g, c=>({'&':'&','<':'<','>':'>'}[c])); }
async function refresh(){
  try {
    const st = await j('/api/status');
    document.getElementById('n-alerts').textContent = st.alerts;
    document.getElementById('n-blocks').textContent = st.blocks;
    document.getElementById('n-versions').textContent = st.versions;
    document.getElementById('n-custody').textContent = st.custody;
    const alerts = st.recent_alerts || [];
    document.getElementById('alerts').innerHTML = alerts.map(a =>
      `<tr><td>${esc(a.ts)}</td><td class="sev-${esc(a.severity)}">${esc(a.severity)}</td><td>${esc(a.source)}</td><td>${esc(a.detail)}</td></tr>`
    ).join('') || '<tr><td colspan="4" class="muted">no alerts</td></tr>';
    const blocks = st.recent_blocks || [];
    document.getElementById('blocks').innerHTML = blocks.map(b =>
      `<tr><td>${esc(b.ts)}</td><td><code>${esc(b.ip)}</code></td><td><code>${esc(b.mac)}</code></td><td>${esc(b.reason)}</td><td>${esc(b.backend)}</td></tr>`
    ).join('') || '<tr><td colspan="5" class="muted">no blocks</td></tr>';
    const vers = st.recent_versions || [];
    document.getElementById('versions').innerHTML = vers.map(v =>
      `<tr><td>${esc(v.ts)}</td><td>${esc(v.orig_path)}</td><td>${esc(v.event)}</td><td><code>${esc(v.sha256.slice(0,16))}…</code></td></tr>`
    ).join('') || '<tr><td colspan="4" class="muted">no versions</td></tr>';
    document.getElementById('clock').textContent = new Date().toLocaleTimeString();
  } catch(e) { console.error(e); }
}
refresh(); setInterval(refresh, 3000);
</script>
</body>
</html>"""

# NEW: Enrollment Page HTML
ENROLL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lynx EDR — Enroll Agent</title>
<style>
  :root { --bg:#0f1420; --panel:#1a2233; --fg:#e6ebf5; --muted:#8b96ad; --accent:#4f8cff; --danger:#ff5c6c; --ok:#3ddc97; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,monospace; background:var(--bg); color:var(--fg); }
  header { padding:16px 24px; border-bottom:1px solid #242e44; display:flex; align-items:center; justify-content:space-between; }
  header h1 { margin:0; font-size:18px; letter-spacing:.5px; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; background:var(--ok); margin-right:8px; }
  .container { max-width: 800px; margin: 0 auto; padding: 24px; }
  .card { background:var(--panel); border:1px solid #242e44; border-radius:10px; padding:24px; margin-bottom:24px; }
  .card h2 { margin-top:0; color:var(--accent); border-bottom:1px solid #242e44; padding-bottom:12px; }
  .form-group { margin-bottom:16px; }
  .form-row { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  label { display:block; margin-bottom:6px; font-size:13px; color:var(--muted); }
  input, select { padding:10px 12px; border:1px solid #374151; border-radius:6px; background:#1a2233; color:var(--fg); width:100%; font-size:14px; }
  .btn { padding:12px 24px; border:none; border-radius:6px; cursor:pointer; font-size:14px; font-weight:600; }
  .btn-primary { background:var(--accent); color:#fff; }
  .btn:disabled { opacity:0.5; cursor:not-allowed; }
  .command-box { background:#0a0f1a; border:1px solid #242e44; border-radius:6px; padding:16px; font-family:monospace; font-size:12px; color:var(--accent); overflow-x:auto; white-space:pre-wrap; margin-top:16px; }
  .success-box { background:#14532d; border:1px solid #166534; border-radius:6px; padding:16px; color:var(--ok); margin-top:16px; }
  .muted { color:var(--muted); }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
  .badge-primary { background:#1e3a5f; color:var(--accent); }
</style>
</head>
<body>
<header>
  <h1><span class="dot" style="background:var(--accent);"></span>Lynx EDR — Enroll Agent</h1>
  <a href="/" class="btn btn-secondary" style="text-decoration:none;">← Back to Dashboard</a>
</header>
<div class="container">
  <div class="card">
    <h2>Enroll New Agent</h2>
    <form id="enroll-form">
      <div class="form-row">
        <div class="form-group">
          <label>Agent Name</label>
          <input type="text" id="agent-name" placeholder="web-server-01" required>
        </div>
        <div class="form-group">
          <label>Agent ID (auto-generated if empty)</label>
          <input type="text" id="agent-id" placeholder="auto-generated">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>Operating System</label>
          <select id="os">
            <option value="linux">Linux</option>
            <option value="windows">Windows</option>
            <option value="macos">macOS</option>
          </select>
        </div>
        <div class="form-group">
          <label>Architecture</label>
          <select id="architecture">
            <option value="x86_64">x86_64</option>
            <option value="arm64">ARM64</option>
            <option value="aarch64">AArch64</option>
            <option value="i386">i386</option>
          </select>
        </div>
      </div>
      <div class="form-group">
        <label>Groups (comma-separated)</label>
        <input type="text" id="groups" value="default" placeholder="production,web-tier">
      </div>
      <div class="form-group">
        <label>Manager URL</label>
        <input type="url" id="manager-url" value="https://187.127.218.67:8443" placeholder="https://manager.example.com:8443">
      </div>
      <button type="submit" class="btn btn-primary" id="submit-btn">Generate Enrollment Command</button>
    </form>
    <div id="result" style="display:none;"></div>
  </div>
  
  <div class="card">
    <h2>Existing Enrollment Tokens</h2>
    <div id="tokens-list" class="muted">Loading...</div>
  </div>
</div>

<script>
async function j(u, opts={}){ const r = await fetch(u, opts); return r.json(); }
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g, c=>({'&':'&','<':'<','>':'>'}[c])); }

document.getElementById('enroll-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('submit-btn');
  btn.disabled = true;
  btn.textContent = 'Generating...';
  
  const body = {
    agent_name: document.getElementById('agent-name').value,
    agent_id: document.getElementById('agent-id').value || undefined,
    os: document.getElementById('os').value,
    architecture: document.getElementById('architecture').value,
    groups: document.getElementById('groups').value.split(',').map(s => s.trim()),
    manager_url: document.getElementById('manager-url').value,
  };
  
  try {
    const result = await j('/api/enroll', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    
    document.getElementById('result').style.display = 'block';
    document.getElementById('result').innerHTML = `
      <div class="success-box">
        <h3>✅ Enrollment Created</h3>
        <div class="form-group">
          <label>Agent ID</label>
          <code>${esc(result.agent_id)}</code>
        </div>
        <div class="form-group">
          <label>Enrollment Token</label>
          <code>${esc(result.enrollment_token)}</code>
        </div>
        <div class="form-group">
          <label>Expires At</label>
          <code>${esc(result.expires_at)}</code>
        </div>
        <div class="form-group">
          <label>Install Command (copy and run on target)</label>
          <div class="command-box">${esc(result.install_command)}</div>
        </div>
      </div>
    `;
  } catch (e) {
    alert('Error: ' + e.message);
  } finally {
    document.getElementById('submit-btn').disabled = false;
    document.getElementById('submit-btn').textContent = 'Generate Enrollment Command';
  }
});

async function loadTokens() {
  try {
    const tokens = await j('/api/enroll/tokens');
    const container = document.getElementById('tokens-list');
    if (tokens.length === 0) {
      container.innerHTML = '<span class="muted">No active enrollment tokens</span>';
      return;
    }
    container.innerHTML = tokens.map(t => `
      <div style="border:1px solid #242e44; border-radius:6px; padding:12px; margin-bottom:8px; background:var(--panel);">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong>${esc(t.agent_name)}</strong> <span class="badge badge-primary">${esc(t.os)}</span>
            <span class="muted" style="margin-left:8px;">${esc(t.agent_id)}</span>
          </div>
          <code>${esc(t.enrollment_token)}</code>
        </div>
        <div class="muted" style="margin-top:4px;">Expires: ${esc(t.expires_at)} | Created: ${esc(t.created_at)}</div>
      </div>
    `).join('');
  } catch (e) {
    document.getElementById('tokens-list').innerHTML = '<span class="muted">Error loading tokens</span>';
  }
}

loadTokens();
</script>
</body>
</html>"""

# NEW: Agents Fleet View HTML
AGENTS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lynx EDR — Agent Fleet</title>
<style>
  :root { --bg:#0f1420; --panel:#1a2233; --fg:#e6ebf5; --muted:#8b96ad; --accent:#4f8cff; --danger:#ff5c6c; --ok:#3ddc97; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,monospace; background:var(--bg); color:var(--fg); }
  header { padding:16px 24px; border-bottom:1px solid #242e44; display:flex; align-items:center; justify-content:space-between; }
  header h1 { margin:0; font-size:18px; letter-spacing:.5px; }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; background:var(--ok); margin-right:8px; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .card { background:var(--panel); border:1px solid #242e44; border-radius:10px; padding:24px; margin-bottom:24px; }
  .card h2 { margin-top:0; color:var(--accent); border-bottom:1px solid #242e44; padding-bottom:12px; }
  .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:16px; margin-bottom:24px; }
  .stat-card { background:var(--panel); border:1px solid #242e44; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:24px; font-weight:700; }
  .stat-card .lbl { color:var(--muted); font-size:12px; text-transform:uppercase; }
  .stat-online { color:var(--ok); }
  .stat-stale { color:#ffb454; }
  .stat-enrolled { color:var(--muted); }
  .stat-revoked { color:var(--danger); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:10px 12px; border-bottom:1px solid #20293b; }
  th { color:var(--muted); font-weight:600; }
  .status-online { color:var(--ok); }
  .status-stale { color:#ffb454; }
  .status-enrolled { color:var(--muted); }
  .status-revoked { color:var(--danger); }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
  .badge-primary { background:#1e3a5f; color:var(--accent); }
  .badge-success { background:#14532d; color:var(--ok); }
  .btn { padding:6px 12px; border:none; border-radius:4px; cursor:pointer; font-size:12px; font-weight:600; }
  .btn-danger { background:var(--danger); color:#fff; }
  .btn-secondary { background:#374151; color:#fff; }
  .muted { color:var(--muted); }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
  .badge-primary { background:#1e3a5f; color:var(--accent); }
  .badge-success { background:#14532d; color:var(--ok); }
  .status-online { color:var(--ok); }
  .status-stale { color:#ffb454; }
  .status-enrolled { color:var(--muted); }
  .status-revoked { color:var(--danger); }
</style>
</head>
<body>
<header>
  <h1><span class="dot" style="background:var(--accent);"></span>Lynx EDR — Agent Fleet</h1>
  <a href="/" class="btn btn-secondary" style="text-decoration:none; padding:8px 16px;">← Back to Dashboard</a>
</header>
<div class="container">
  <div class="card">
    <h2>Agent Fleet Overview</h2>
    <div class="stats-grid" id="stats-grid">
      <div class="stat-card"><div class="num" id="stat-total">–</div><div class="lbl">Total</div></div>
      <div class="stat-card"><div class="num stat-online" id="stat-online">–</div><div class="lbl">Online</div></div>
      <div class="stat-card"><div class="num stat-stale" id="stat-stale">–</div><div class="lbl">Stale</div></div>
      <div class="stat-card"><div class="num stat-enrolled" id="stat-enrolled">–</div><div class="lbl">Enrolled</div></div>
      <div class="stat-card"><div class="num stat-revoked" id="stat-revoked">–</div><div class="lbl">Revoked</div></div>
    </div>
  </div>
  
  <div class="card">
    <h2>Agents</h2>
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>ID</th>
          <th>OS</th>
          <th>Architecture</th>
          <th>Groups</th>
          <th>Status</th>
          <th>Last Seen</th>
          <th>Enrolled</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="agents-body">
        <tr><td colspan="9" class="muted">Loading agents...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<script>
async function j(u, opts={}){ const r = await fetch(u, opts); return r.json(); }
function esc(s){ return (s==null?'':String(s)).replace(/[&<>]/g, c=>({'&':'&','<':'<','>':'>'}[c])); }

async function loadAgents() {
  try {
    const [agents, stats] = await Promise.all([
      j('/api/agents'),
      j('/api/agents/stats')
    ]);
    
    // Update stats
    document.getElementById('stat-total').textContent = stats.total;
    document.getElementById('stat-online').textContent = stats.online;
    document.getElementById('stat-stale').textContent = stats.stale;
    document.getElementById('stat-enrolled').textContent = stats.enrolled;
    document.getElementById('stat-revoked').textContent = stats.revoked;
    
    // Render agents table
    const tbody = document.getElementById('agents-body');
    if (agents.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="muted">No agents enrolled</td></tr>';
      return;
    }
    
    tbody.innerHTML = agents.map(a => `
      <tr>
        <td><strong>${esc(a.agent_name)}</strong></td>
        <td><code>${esc(a.agent_id.slice(0,12))}…</code></td>
        <td><span class="badge badge-primary">${esc(a.os)}</span></td>
        <td>${esc(a.architecture)}</td>
        <td>${esc(a.groups.join(', '))}</td>
        <td><span class="status-${a.status}">● ${esc(a.status)}</span></td>
        <td>${esc(a.last_seen || 'Never')}</td>
        <td>${esc(a.enrolled_at ? a.enrolled_at.slice(0,19) : 'Unknown')}</td>
        <td>
          ${a.status !== 'revoked' ? `<button class="btn btn-danger" onclick="revokeAgent('${esc(a.agent_id)}', '${esc(a.agent_name)}')">Revoke</button>` : '<span class="muted">Revoked</span>'}
        </td>
      </tr>
    `).join('');
  } catch (e) {
    console.error(e);
    document.getElementById('agents-body').innerHTML = '<tr><td colspan="9" class="muted">Error loading agents</td></tr>';
  }
}

async function revokeAgent(agentId, agentName) {
  if (!confirm(`Revoke agent "${agentName}" (${agentId})? This will revoke its certificate and disable it.`)) return;
  
  try {
    await j(`/api/agents/${agentId}/revoke`, { method: 'POST' });
    alert('Agent revoked');
    loadAgents();
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

loadAgents();
setInterval(loadAgents, 30000);
</script>
</body>
</html>"""


class DashboardServer:
    def __init__(self, ledger, backup, reporter, cfg: dict, logger):
        self.ledger = ledger
        self.backup = backup
        self.reporter = reporter
        self.cfg = cfg.get("web", {})
        self.log = logger
        self.auth_token = self.cfg.get("auth_token", "")

    def _authed(self, handler) -> bool:
        if not self.auth_token:
            return True
        qs = parse_qs(urlparse(handler.path).query)
        q_token = qs.get("token", [None])[0]
        h_token = handler.headers.get("X-Auth-Token")
        return q_token == self.auth_token or h_token == self.auth_token

    def make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass  # silence default request logging

            def _send(self, code, body, ctype="application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _json(self, obj, code=200):
                self._send(code, json.dumps(obj, default=str).encode(), "application/json")

            def _html(self, html, code=200):
                self._send(code, html.encode(), "text/html; charset=utf-8")

            def do_GET(self):
                if not server._authed(self):
                    self._json({"error": "unauthorized"}, 401); return
                p = urlparse(self.path).path
                if p == "/" or p == "/index.html":
                    self._send(200, HTML.encode(), "text/html; charset=utf-8")
                elif p == "/health":
                    self._json({"status": "ok"})
                elif p == "/api/status":
                    self._json(server._status())
                elif p == "/api/alerts":
                    self._json(server._alerts())
                elif p == "/api/blocks":
                    self._json(server._blocks())
                elif p == "/api/versions":
                    qs = parse_qs(urlparse(self.path).query)
                    self._json(server._versions(qs.get("path", [None])[0]))
                elif p == "/api/report":
                    md = server.reporter.report()
                    self._send(200, md.encode(), "text/markdown; charset=utf-8")
                # NEW: Enrollment dashboard routes
                elif p == "/enroll":
                    self._html(ENROLL_HTML)
                elif p == "/agents":
                    self._html(AGENTS_HTML)
                elif p == "/api/agents":
                    self._json(server._list_agents())
                elif p.startswith("/api/agents/") and p.count("/") == 3:
                    agent_id = p.split("/")[-1]
                    self._json(server._get_agent(agent_id))
                elif p == "/api/agents/stats":
                    self._json(server._agent_stats())
                else:
                    self._json({"error": "not found"}, 404)

            def do_POST(self):
                if not server._authed(self):
                    self._json({"error": "unauthorized"}, 401); return
                p = urlparse(self.path).path
                if p == "/api/restore":
                    ln = int(self.headers.get("Content-Length", 0))
                    body = json.loads(self.rfile.read(ln) or b"{}")
                    path = body.get("path")
                    version = body.get("version")
                    if not path:
                        self._json({"error": "path required"}, 400); return
                    try:
                        if version:
                            server.backup.restore(path, version)
                        else:
                            server.backup.restore(path)
                        self._json({"status": "restored", "path": path})
                    except Exception as e:
                        self._json({"error": str(e)}, 500)
                # NEW: Enrollment API
                elif p == "/api/enroll":
                    ln = int(self.headers.get("Content-Length", 0))
                    body = json.loads(self.rfile.read(ln) or b"{}")
                    result = server._create_enrollment(body)
                    self._json(result, 201)
                elif p.startswith("/api/agents/") and p.endswith("/revoke"):
                    agent_id = p.split("/")[-2]
                    result = server._revoke_agent(agent_id)
                    self._json(result)
                else:
                    self._json({"error": "not found"}, 404)

        return Handler

    # --- data providers ---
    def _status(self):
        alerts = self.ledger.query(
            "SELECT count(*) c FROM events WHERE event_type='alert'")[0]["c"]
        blocks = self.ledger.query("SELECT count(*) c FROM blocks")[0]["c"]
        versions = self.ledger.query("SELECT count(*) c FROM file_versions")[0]["c"]
        custody = self.ledger.query("SELECT count(*) c FROM chain_custody")[0]["c"]
        recent_alerts = [dict(r) for r in self.ledger.query(
            "SELECT ts, severity, source, detail FROM events "
            "WHERE event_type='alert' ORDER BY id DESC LIMIT 100")]
        recent_blocks = [dict(r) for r in self.ledger.query(
            "SELECT ts, ip, mac, reason, backend FROM blocks ORDER BY id DESC LIMIT 100")]
        recent_versions = [dict(r) for r in self.ledger.query(
            "SELECT ts, orig_path, event, sha256 FROM file_versions "
            "ORDER BY id DESC LIMIT 100")]
        return {
            "alerts": alerts, "blocks": blocks, "versions": versions,
            "custody": custody, "recent_alerts": recent_alerts,
            "recent_blocks": recent_blocks, "recent_versions": recent_versions,
        }

    def _alerts(self):
        return [dict(r) for r in self.ledger.query(
            "SELECT ts, severity, source, detail FROM events "
            "WHERE event_type='alert' ORDER BY id DESC LIMIT 500")]

    def _blocks(self):
        return [dict(r) for r in self.ledger.query(
            "SELECT ts, ip, mac, reason, backend FROM blocks ORDER BY id DESC LIMIT 500")]

    def _versions(self, path=None):
        if path:
            return [dict(r) for r in self.ledger.query(
                "SELECT ts, orig_path, event, sha256 FROM file_versions "
                "WHERE orig_path=? ORDER BY id DESC", (path,))]
        return [dict(r) for r in self.ledger.query(
            "SELECT ts, orig_path, event, sha256 FROM file_versions ORDER BY id DESC LIMIT 500")]

    # NEW: Enrollment API handlers
    def _create_enrollment(self, body: dict):
        """Create new enrollment token."""
        import secrets
        import datetime
        import json
        
        agent_name = body.get("agent_name", "unknown")
        os = body.get("os", "linux")
        architecture = body.get("architecture", "x86_64")
        groups = body.get("groups", ["default"])
        manager_url = body.get("manager_url", "https://187.127.218.67:8443")
        
        enrollment_token = secrets.token_urlsafe(32)
        agent_id = secrets.token_urlsafe(16)
        expires_at = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=24)).isoformat()
        
        # Store token (using the same file as enrollment.py)
        TOKENS_FILE = "/opt/data/edr-agent/manager/enrollment_tokens.json"
        try:
            with open(TOKENS_FILE, "r") as f:
                tokens = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            tokens = {}
        
        token_data = {
            "enrollment_token": enrollment_token,
            "agent_id": agent_id,
            "agent_name": body.get("agent_name", "unknown"),
            "os": body.get("os", "linux"),
            "architecture": body.get("architecture", "x86_64"),
            "groups": groups,
            "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "expires_at": (datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=24)).isoformat(),
        }
        tokens[enrollment_token] = token_data
        with open(TOKENS_FILE, "w") as f:
            json.dump(tokens, f, indent=2)
        
        # Generate install command
        install_command = f"curl -sSL {manager_url}/enroll/{enrollment_token} | bash"
        
        return {
            "enrollment_token": enrollment_token,
            "agent_id": agent_id,
            "install_command": f"curl -sSL {manager_url}/enroll/{enrollment_token} | bash",
            "expires_at": (datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=24)).isoformat(),
        }

    def _revoke_agent(self, agent_id: str):
        """Revoke agent enrollment."""
        # Use agent registry
        try:
            from manager.agent_registry import get_agent_registry
            from manager.ca import get_ca
            registry = get_agent_registry()
            ca = get_ca()
            
            # Revoke certificate
            ca.revoke_agent_cert(agent_id)
            
            # Mark agent as revoked in registry
            registry.revoke_agent(agent_id)
            
            return {"status": "revoked", "agent_id": agent_id}
        except Exception as e:
            return {"error": str(e)}

    # NEW: Agent fleet API handlers
    def _list_agents(self):
        """List all enrolled agents."""
        try:
            from manager.agent_registry import get_agent_registry
            registry = get_agent_registry()
            return registry.list_agents()
        except Exception as e:
            return {"error": str(e)}

    def _get_agent(self, agent_id: str):
        """Get single agent details."""
        try:
            from manager.agent_registry import get_agent_registry
            registry = get_agent_registry()
            agent = registry.get_agent(agent_id)
            if not agent:
                return {"error": "Agent not found"}
            return agent
        except Exception as e:
            return {"error": str(e)}

    def _agent_stats(self):
        """Get agent fleet statistics."""
        try:
            from manager.agent_registry import get_agent_registry
            registry = get_agent_registry()
            stats = registry.get_stats()
            return stats
        except Exception as e:
            return {"error": str(e)}


def start_dashboard(ledger, backup, reporter, cfg, logger) -> ThreadingHTTPServer:
    """Start the dashboard in a background thread; return the httpd instance."""
    web = cfg.get("web", {})
    host = web.get("host", "0.0.0.0")
    port = int(web.get("port", 8080))
    dash = DashboardServer(ledger, backup, reporter, cfg, logger)
    handler = dash.make_handler()
    httpd = ThreadingHTTPServer((host, port), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    logger.info("Web dashboard at http://%s:%d", host, port)
    return httpd