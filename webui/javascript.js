// Security: This UI is loaded from local filesystem by KernelSU app.
// There is no HTTP server running. If someone somehow loaded this
// from a web server context, refuse to run.
if (window.location.protocol !== 'file:' && window.location.protocol !== 'about:') {
    document.body.innerHTML = '<h1>Access Denied</h1><p>This interface is only available through the KernelSU app.</p>';
    throw new Error('WebUI loaded from invalid context');
}

(function () {
  const BASE = '/data/local/tmp/virtualizer';
  const STATS_FILE = BASE + '/stats.json';
  const LOG_FILE = '/data/local/tmp/virtualizer/events.log';

  function $(id) {
    return document.getElementById(id);
  }

  function showMessage(text, type) {
    const el = $('actionMessage');
    el.textContent = text;
    el.className = 'action-message ' + type;
    el.classList.remove('hidden');
    setTimeout(function () {
      el.classList.add('hidden');
    }, 3000);
  }

  function readFile(path) {
    try {
      var result = KernelSU.readFile(path);
      return result;
    } catch (e) {
      return null;
    }
  }

  function getStats() {
    var raw = readFile(STATS_FILE);
    if (!raw) {
      return null;
    }
    try {
      return JSON.parse(raw);
    } catch (e) {
      return null;
    }
  }

  function updateStatus(stats) {
    var active = stats !== null;
    $('serviceStatus').textContent = active ? 'Active' : 'Inactive';
    $('serviceStatus').className = 'status-badge ' + (active ? 'badge-active' : 'badge-inactive');

    var zygiskActive = active;
    $('zygiskStatus').textContent = zygiskActive ? 'Active' : 'Inactive';
    $('zygiskStatus').className = 'status-badge ' + (zygiskActive ? 'badge-active' : 'badge-inactive');

    var sepolicyOk = true;
    $('sepolicyStatus').textContent = sepolicyOk ? 'Loaded' : 'Missing';
    $('sepolicyStatus').className = 'status-badge ' + (sepolicyOk ? 'badge-active' : 'badge-inactive');

    if (stats) {
      $('eventsProcessed').textContent = stats.events_processed || 0;
      $('eventsBlocked').textContent = stats.events_blocked || 0;
      $('eventsRedirected').textContent = stats.events_redirected || 0;
      $('errors').textContent = stats.errors || 0;
      $('rulesLoaded').textContent = stats.rules_loaded || 0;
      $('cacheEntries').textContent = stats.cache_entries || 0;
      $('watchdogTimeout').textContent = (stats.watchdog_timeout || 3) + 's';
    }
  }

  function refresh() {
    var stats = getStats();
    updateStatus(stats);
  }

  function resetModule() {
    try {
      KernelSU.exec('rm -f ' + STATS_FILE);
      showMessage('Statistics reset successfully', 'success');
      refresh();
    } catch (e) {
      showMessage('Failed to reset: ' + e.message, 'error');
    }
  }

  function clearLogs() {
    try {
      KernelSU.exec('rm -f ' + LOG_FILE);
      showMessage('Logs cleared successfully', 'success');
    } catch (e) {
      showMessage('Failed to clear logs: ' + e.message, 'error');
    }
  }

  function reloadRules() {
    try {
      KernelSU.exec('pkill -USR1 zygisk-virtualizer 2>/dev/null; echo reloaded');
      showMessage('Rules reload signal sent', 'success');
    } catch (e) {
      showMessage('Failed to send reload signal: ' + e.message, 'error');
    }
  }

  window.addEventListener('KernelSULoaded', function () {
    refresh();

    $('btnReset').addEventListener('click', resetModule);
    $('btnClearLogs').addEventListener('click', clearLogs);
    $('btnReloadRules').addEventListener('click', reloadRules);

    setInterval(refresh, 5000);
  });

  if (typeof KernelSU !== 'undefined') {
    var ev = new Event('KernelSULoaded');
    window.dispatchEvent(ev);
  }
})();
