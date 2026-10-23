'use strict';
const $ = id => document.getElementById(id);
let token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
let current = null;
let settingsDirty = false;
let qrURL = null;
history.replaceState(null, '', location.pathname);
const text = (id, value) => { $(id).textContent = value; };
const lines = id => $(id).value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
function notify(message, error = false) { text('notice', message); $('notice').classList.toggle('error', error); $('notice').hidden = false; }
function showAuth() { $('auth-panel').hidden = false; $('workspace').hidden = true; $('reload').hidden = true; }
async function api(path, method = 'GET', data) {
  const response = await fetch('/api/' + path, { method, cache: 'no-store', credentials: 'omit', headers: { Authorization: 'Bearer ' + token, ...(data ? { 'Content-Type': 'application/json' } : {}) }, ...(data ? { body: JSON.stringify(data) } : {}) });
  if (!response.ok) { if (response.status === 401) showAuth(); const error = await response.json(); throw new Error(error.error || 'The operation failed.'); }
  return path.startsWith('files/') ? response.blob() : response.json();
}
async function busy(button, action) {
  button.disabled = true;
  try { await action(); } catch (error) { notify(error.message, true); }
  finally { button.disabled = false; }
}
function input(id, value) { $(id).value = value ?? ''; }
async function refresh() {
  current = await api('snapshot');
  settingsDirty = false;
  const c = current.config;
  $('auth-panel').hidden = true; $('workspace').hidden = false; $('reload').hidden = false;
  input('address', c.server.address); input('port', c.server.port); input('tls-name', c.tls.server_name);
  input('mode', c.client.mode); input('ipv6', c.client.ipv6); input('certificate', c.tls.certificate); input('key', c.tls.key);
  input('listen', c.server.listen); input('server-dns', c.server.dns); input('log-level', c.server.log_level);
  input('mixed-port', c.client.mixed_port); input('dns-port', c.client.dns_listen_port);
  input('dns', (c.client.dns || []).join('\n')); input('bootstrap-dns', (c.client.bootstrap_dns || []).join('\n'));
  input('direct-cidrs', (c.client.direct_cidrs || []).join('\n')); input('ca-file', c.tls.ca_file); input('state-dir', c.state_dir);
  $('udp').checked = c.client.udp;
  text('summary-server', c.server.address ? c.server.address + ':' + c.server.port : 'Not configured');
  text('summary-devices', current.devices.filter(d => !d.revoked).length);
  text('saved-badge', current.configured ? 'Saved locally' : 'Setup needed');
  $('device-form').querySelector('button').disabled = !current.configured;
  const previousClient = $('export-client').value || 'mihomo';
  $('export-client').replaceChildren();
  for (const target of current.clients) { const option = new Option(target.label, target.id); option.disabled = Boolean(c.tls.ca_file) && !target.custom_ca; $('export-client').append(option); }
  $('export-client').value = previousClient;
  updateClient();
  $('devices').replaceChildren(); $('export-device').replaceChildren(new Option('All active devices', ''));
  $('empty-devices').hidden = current.devices.length > 0;
  for (const d of current.devices) {
    const li = document.createElement('li'); const info = document.createElement('div'); info.className = 'device-info';
    const name = document.createElement('div'); name.className = 'device-name'; name.textContent = d.name;
    const status = document.createElement('div'); status.className = 'device-status'; status.textContent = d.revoked ? 'Revoked locally · deployment required' : 'Active in local configuration';
    info.append(name, status); li.append(info);
    if (!d.revoked) {
      $('export-device').append(new Option(d.name, d.name));
      const actions = document.createElement('div'); actions.className = 'device-actions';
      for (const action of ['rotate', 'revoke']) {
        const button = document.createElement('button'); button.type = 'button'; button.textContent = action === 'rotate' ? 'Rotate' : 'Revoke'; if (action === 'revoke') button.className = 'danger';
        button.addEventListener('click', () => {
          const message = action === 'rotate' ? 'Replace the credential for ' + d.name + '? Export a new profile and deploy the updated server configuration.' : 'Revoke ' + d.name + '? This name cannot be reused. Deploy the updated configuration and restart the server to enforce revocation.';
          if (!confirm(message)) return;
          busy(button, async () => { const result = await api('devices', 'POST', {action, name: d.name}); await refresh(); markExportStale(); notify(result.message); });
        });
        actions.append(button);
      }
      li.append(actions);
    }
    $('devices').append(li);
  }
}
function updateClient() {
  const target = current.clients.find(c => c.id === $('export-client').value);
  const customCA = Boolean(current.config.tls.ca_file);
  text('client-note', target.note);
  for (const id of ['export-uri', 'export-qr']) { $(id).disabled = !target.uri || customCA; if (!target.uri || customCA) $(id).checked = false; }
  if (target.required_uri) { $('export-uri').checked = true; $('export-uri').disabled = true; }
  $('client-scope').hidden = target.scope === 'full-profile' && !$('export-uri').checked && !$('export-qr').checked;
  text('client-scope', target.scope === 'full-profile' ? 'The YAML includes routing settings. Optional URLs and QR images carry connection settings only; set routing and DNS in the app when using them.' : 'Connection settings only. Configure routing, DNS, IPv6, and UDP separately in this app; the server form\'s client settings are not included.');
  $('ca-note').hidden = !customCA;
  $('export-form').querySelector('button').disabled = !current.configured || settingsDirty || (customCA && !target.custom_ca);
}
function hideQR() { $('qr-preview').hidden = true; $('qr-image').removeAttribute('src'); if (qrURL) URL.revokeObjectURL(qrURL); qrURL = null; }
$('hide-qr').addEventListener('click', hideQR);
$('export-client').addEventListener('change', () => { updateClient(); markExportStale(); hideQR(); });
for (const id of ['export-uri', 'export-qr']) $(id).addEventListener('change', updateClient);
function markExportStale() { hideQR(); if (!$('export-result').hidden) text('export-status', 'These files are an earlier snapshot. Generate again after changing settings or devices.'); }
$('auth-form').addEventListener('submit', event => { event.preventDefault(); token = $('token').value.trim(); $('token').value = ''; busy(event.submitter, async () => { await refresh(); $('notice').hidden = true; }); });
$('reload').addEventListener('click', event => {
  if (settingsDirty && !confirm('Discard unsaved settings and reload from disk?')) return;
  busy(event.currentTarget, async () => { await refresh(); markExportStale(); notify('Loaded settings from disk.'); });
});
$('settings-form').addEventListener('input', () => {
  settingsDirty = true; text('saved-badge', 'Unsaved changes');
  $('device-form').querySelector('button').disabled = true;
  $('export-form').querySelector('button').disabled = true;
  for (const button of $('devices').querySelectorAll('button')) button.disabled = true;
  notify('Save your settings before managing devices or generating files.');
});
$('settings-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter, async () => {
    const c = structuredClone(current.config);
    c.server.address = $('address').value.trim(); c.server.port = Number($('port').value); c.tls.server_name = $('tls-name').value.trim();
    c.client.mode = $('mode').value; c.client.ipv6 = $('ipv6').value; c.tls.certificate = $('certificate').value.trim(); c.tls.key = $('key').value.trim();
    c.server.listen = $('listen').value.trim(); c.server.dns = $('server-dns').value.trim(); c.server.log_level = $('log-level').value;
    c.client.mixed_port = Number($('mixed-port').value); c.client.dns_listen_port = Number($('dns-port').value);
    c.client.dns = lines('dns'); c.client.bootstrap_dns = lines('bootstrap-dns'); c.client.direct_cidrs = lines('direct-cidrs');
    c.tls.ca_file = $('ca-file').value.trim(); c.client.udp = $('udp').checked;
    const result = await api('config', 'PUT', { config: c, revision: current.config_revision });
    await refresh(); markExportStale(); notify(result.message);
  });
});
$('device-form').addEventListener('submit', event => { event.preventDefault(); busy(event.submitter, async () => { const result = await api('devices', 'POST', { action: 'add', name: $('device-name').value.trim() }); $('device-name').value = ''; await refresh(); markExportStale(); notify(result.message); }); });
$('export-form').addEventListener('submit', event => {
  event.preventDefault();
  busy(event.submitter, async () => {
    const target = current.clients.find(c => c.id === $('export-client').value);
    const result = await api('exports', 'POST', { device: $('export-device').value, client: target.id, uri: $('export-uri').checked, qr: $('export-qr').checked });
    hideQR();
    $('files').replaceChildren(); text('export-path', result.path); text('export-status', 'Snapshot generated from saved settings. Deployment is still pending.');
    for (const file of result.files) {
      const li = document.createElement('li'); const name = document.createElement('span'); name.textContent = file;
      const button = document.createElement('button'); button.type = 'button'; button.textContent = 'Download'; button.setAttribute('aria-label', 'Download ' + file);
      button.addEventListener('click', () => busy(button, async () => {
        const blob = await api('files/' + encodeURIComponent(result.id) + '/' + encodeURIComponent(file));
        const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = file; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 10000);
      }));
      li.append(name);
      const actions = document.createElement('div'); actions.className = 'file-actions';
      if (file.endsWith('.qr.png')) {
        const show = document.createElement('button'); show.type = 'button'; show.textContent = 'Show QR'; show.setAttribute('aria-label', 'Show QR for ' + file);
        show.addEventListener('click', () => busy(show, async () => { const blob = await api('files/' + encodeURIComponent(result.id) + '/' + encodeURIComponent(file)); hideQR(); qrURL = URL.createObjectURL(blob); $('qr-image').src = qrURL; $('qr-preview').hidden = false; }));
        actions.append(show);
      }
      actions.append(button); li.append(actions); $('files').append(li);
    }
    $('export-result').hidden = false; text('export-status', target.label + ' · ' + target.scope + '. Read IMPORT.txt. Deployment is still pending.'); notify(result.message);
  });
});
if (token) refresh().catch(error => { showAuth(); notify(error.message, true); }); else showAuth();
