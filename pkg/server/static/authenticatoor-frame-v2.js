// authenticatoor — shared-session frame (v2)
//
// Loaded by /clientFrame inside a hidden iframe on every consuming app.
// This document is same-origin with the auth service, which gives it two
// powers the app pages don't have:
//
//   1. It can call /auth/token with the proxy/provider session cookies
//      attached — a plain same-origin fetch, no CORS, no nested iframes.
//      An opaqueredirect/401 response is the definitive "upstream session
//      gone" signal.
//   2. It shares localStorage with every other app's frame, so one session
//      record (and its refreshes) serves all open apps and tabs. storage
//      events broadcast changes; the Web Locks API (with a localStorage
//      compare-and-set fallback) elects a single refresher.
//
// Trust model: /clientFrame validates the ?origin= query param against the
// return-host allow-list AND pins it via Content-Security-Policy
// frame-ancestors. A page embedded by any other origin never renders, so
// this script may trust its own origin param as the parent origin for
// postMessage in both directions.
//
// Caveat: browsers partition third-party-iframe storage by top-level site
// (eTLD+1). Apps under the same registrable domain as the auth service
// share one session; an app on a foreign domain gets an isolated one
// (still functional — own refresh loop — just not shared).
//
// All request URLs are relative: this file is served same-origin by the
// auth service and needs no templating.

(function () {
  'use strict';

  // Only meaningful when embedded by the outer client.
  if (window.parent === window) return;

  var PARENT_ORIGIN = (function () {
    try {
      var raw = new URLSearchParams(window.location.search).get('origin');
      if (!raw) return '';
      return new URL(raw).origin;
    } catch (e) {
      return '';
    }
  })();
  if (!PARENT_ORIGIN) return;

  var NS = 'ethpandaops.authenticatoor';
  var PROTOCOL_VERSION = 2;

  var KEY_SESSION = 'ethpandaops.authenticatoor.v2.session';
  var KEY_REFRESHING = 'ethpandaops.authenticatoor.v2.refreshing';
  var KEY_LOCK = 'ethpandaops.authenticatoor.v2.lock';
  var LOCK_NAME = 'ethpandaops.authenticatoor.v2.refresh';

  // Refresh when less than this much validity remains.
  var REFRESH_LEAD_SECONDS = 60;
  // Per-frame jitter so concurrent tabs don't stampede the lock at the
  // exact same millisecond. Applied AFTER the lead point — firing a few
  // seconds late is fine, firing early would find a still-fresh session.
  var REFRESH_JITTER_MS = Math.floor(Math.random() * 10000);
  // A refreshing-marker or fallback lock older than this is stale (its
  // owner died mid-refresh) and may be overridden.
  var LOCK_TTL_MS = 30000;
  var RETRY_BACKOFF_MS = [2000, 5000, 15000];
  // Retry cadence while the session is stale-but-valid after exhausting
  // the quick backoff ladder.
  var RETRY_IDLE_MS = 60000;
  var LOGOUT_SERVER_TIMEOUT_MS = 5000;

  function nowSec() { return Math.floor(Date.now() / 1000); }

  function delay(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  // ─── session store (degrades to memory-only if storage throws) ──────────

  var storageBroken = false;
  var memorySession = null;

  function readSession() {
    if (storageBroken) return memorySession;
    var raw = null;
    try {
      raw = localStorage.getItem(KEY_SESSION);
    } catch (e) {
      storageBroken = true;
      return memorySession;
    }
    if (!raw) return null;
    try {
      var s = JSON.parse(raw);
      if (s && typeof s.token === 'string' && typeof s.exp === 'number') return s;
    } catch (e) {}
    // Unparsable garbage — remove it so it can't wedge every frame.
    try { localStorage.removeItem(KEY_SESSION); } catch (e) {}
    return null;
  }

  function writeSession(s) {
    memorySession = s;
    if (storageBroken) return;
    try {
      localStorage.setItem(KEY_SESSION, JSON.stringify(s));
    } catch (e) {
      storageBroken = true;
    }
  }

  function clearSession() {
    memorySession = null;
    try { localStorage.removeItem(KEY_SESSION); } catch (e) {}
  }

  function sessionValid(s) { return !!(s && s.exp > nowSec()); }
  function sessionFresh(s) { return !!(s && s.exp > nowSec() + REFRESH_LEAD_SECONDS); }

  // ─── refreshing marker (drives the "refreshing" status everywhere) ──────

  var localRefreshing = false;

  function setMarker() {
    localRefreshing = true;
    try { localStorage.setItem(KEY_REFRESHING, JSON.stringify({ ts: Date.now() })); } catch (e) {}
  }

  function clearMarker() {
    localRefreshing = false;
    try { localStorage.removeItem(KEY_REFRESHING); } catch (e) {}
  }

  function isRefreshing() {
    if (localRefreshing) return true;
    try {
      var raw = localStorage.getItem(KEY_REFRESHING);
      if (!raw) return false;
      var m = JSON.parse(raw);
      return !!(m && typeof m.ts === 'number' && Date.now() - m.ts < LOCK_TTL_MS);
    } catch (e) {
      return false;
    }
  }

  // ─── status derivation + parent push ────────────────────────────────────

  function tokenInfo() {
    var s = readSession();
    var authed = sessionValid(s);
    var status;
    if (isRefreshing()) {
      status = 'refreshing';
    } else if (authed) {
      status = 'authenticated';
    } else {
      status = 'unauthenticated';
    }
    return {
      status: status,
      authenticated: authed,
      user: authed ? (s.user || '') : '',
      exp: authed ? s.exp : 0,
    };
  }

  var lastPushed = '';

  // pushStatus posts the current state to the parent app. The first call
  // doubles as the ready signal. Deduped by fingerprint unless forced.
  function pushStatus(force) {
    var info = tokenInfo();
    var s = readSession();
    var fingerprint = info.status + '|' + info.user + '|' + info.exp;
    if (!force && fingerprint === lastPushed) return;
    lastPushed = fingerprint;
    try {
      window.parent.postMessage({
        ns: NS,
        v: PROTOCOL_VERSION,
        type: 'status',
        status: info.status,
        tokenInfo: info,
        token: sessionValid(s) ? s.token : null,
      }, PARENT_ORIGIN);
    } catch (e) {}
  }

  // ─── refresh lock (single refresher across all frames) ──────────────────

  var fallbackLockId = String(Math.random()).slice(2) + '.' + Date.now();

  function readLock() {
    try {
      var raw = localStorage.getItem(KEY_LOCK);
      if (!raw) return null;
      var l = JSON.parse(raw);
      if (l && typeof l.id === 'string' && typeof l.ts === 'number') return l;
    } catch (e) {}
    return null;
  }

  // acquireLock runs fn while holding the cross-frame refresh lock.
  // Resolves true if fn ran, false when another frame holds the lock.
  function acquireLock(fn) {
    if (navigator.locks && navigator.locks.request) {
      var ran = false;
      return navigator.locks.request(LOCK_NAME, { ifAvailable: true }, function (lock) {
        if (!lock) return null;
        ran = true;
        return fn();
      }).then(function () { return ran; }, function () { return ran; });
    }

    // Fallback: localStorage compare-and-set with TTL. A lost race here
    // costs one redundant (idempotent) token mint — harmless.
    var existing = readLock();
    if (existing && Date.now() - existing.ts < LOCK_TTL_MS) {
      return Promise.resolve(false);
    }
    try {
      localStorage.setItem(KEY_LOCK, JSON.stringify({ id: fallbackLockId, ts: Date.now() }));
    } catch (e) {
      // Storage broken — nothing to coordinate with; just run.
      return Promise.resolve().then(fn).then(function () { return true; },
        function () { return true; });
    }
    return delay(50).then(function () {
      var cur = readLock();
      if (!cur || cur.id !== fallbackLockId) return false;
      return Promise.resolve().then(fn).catch(function () {}).then(function () {
        try { localStorage.removeItem(KEY_LOCK); } catch (e) {}
        return true;
      });
    });
  }

  // ─── storage-event plumbing ─────────────────────────────────────────────

  var storageWaiters = [];

  function waitForStorageEvent(timeoutMs) {
    return new Promise(function (resolve) {
      var done = false;
      var fire = function () {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve();
      };
      var timer = setTimeout(fire, timeoutMs);
      storageWaiters.push(fire);
    });
  }

  function flushStorageWaiters() {
    var ws = storageWaiters;
    storageWaiters = [];
    for (var i = 0; i < ws.length; i++) ws[i]();
  }

  // ─── refresh machinery ──────────────────────────────────────────────────

  var refreshTimer = null;
  var refreshPromise = null;

  function scheduleRefresh() {
    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }
    var s = readSession();
    if (!s) return;
    var delayMs;
    if (sessionFresh(s)) {
      // Fire just past the lead point, jittered per frame.
      delayMs = Math.max(0, (s.exp - REFRESH_LEAD_SECONDS) * 1000 - Date.now()) +
        REFRESH_JITTER_MS;
    } else if (sessionValid(s)) {
      delayMs = RETRY_IDLE_MS;
    } else {
      // Fully expired and nothing replaced it.
      clearSession();
      pushStatus();
      return;
    }
    refreshTimer = setTimeout(function () {
      refreshTimer = null;
      ensureRefresh();
    }, delayMs);
  }

  // ensureRefresh coalesces concurrent refresh triggers (timer, getToken,
  // visibility) into one in-flight round.
  function ensureRefresh() {
    if (refreshPromise) return refreshPromise;
    refreshPromise = runRefreshRound(0)
      .catch(function () {})
      .then(function () { refreshPromise = null; });
    return refreshPromise;
  }

  // One round: try to become the refresher; when another frame holds the
  // lock, wait for its outcome (storage event) and re-check.
  function runRefreshRound(attempt) {
    if (sessionFresh(readSession())) {
      scheduleRefresh();
      return Promise.resolve();
    }
    return acquireLock(refresh).then(function (ran) {
      if (ran) return undefined;
      return waitForStorageEvent(LOCK_TTL_MS).then(function () {
        var s = readSession();
        if (sessionFresh(s)) return undefined;       // other frame delivered
        if (!isRefreshing() && !sessionValid(s)) return undefined; // it concluded: unauthenticated
        if (attempt >= 2) return undefined;          // give up this round; timer retries
        return runRefreshRound(attempt + 1);
      });
    });
  }

  // refresh runs only while holding the refresh lock.
  function refresh() {
    // Re-check: another frame may have refreshed while we queued.
    if (sessionFresh(readSession())) return Promise.resolve();
    setMarker();
    pushStatus();
    return refreshAttempt(0).then(function () {
      clearMarker();
      pushStatus(true);
      scheduleRefresh();
    });
  }

  function refreshAttempt(attempt) {
    return fetchToken().then(function (outcome) {
      if (outcome === 'ok' || outcome === 'unauthenticated') return undefined;
      if (attempt < RETRY_BACKOFF_MS.length) {
        return delay(RETRY_BACKOFF_MS[attempt]).then(function () {
          return refreshAttempt(attempt + 1);
        });
      }
      // Out of quick retries. If the stored token fully expired the
      // session is gone; otherwise keep it — the scheduler retries at the
      // idle cadence.
      var s = readSession();
      if (s && !sessionValid(s)) clearSession();
      return undefined;
    });
  }

  // fetchToken resolves to 'ok' | 'unauthenticated' | 'error'.
  // redirect:'manual' turns the proxy's login redirect into an
  // opaqueredirect — the definitive "session cookie gone" signal (the
  // frame must never follow a redirect into a login page).
  function fetchToken() {
    return fetch('/auth/token', {
      credentials: 'same-origin',
      redirect: 'manual',
      cache: 'no-store',
    }).then(function (res) {
      if (res.type === 'opaqueredirect' || res.status === 401 || res.status === 403) {
        // The upstream session cookie is gone — or merely invisible to
        // this frame: browsers partition third-party-iframe cookies when
        // the app and the auth service don't share a registrable domain
        // (Firefox's Total Cookie Protection does this for every
        // cross-site embed). A stored token is still cryptographically
        // valid until exp regardless, so only drop the session once it
        // has actually expired — apps stay authenticated on the adopted
        // token and the scheduler keeps retrying at the idle cadence.
        if (!sessionValid(readSession())) {
          clearSession();
        }
        return 'unauthenticated';
      }
      if (!res.ok) return 'error';
      return res.json().then(function (body) {
        if (!body || typeof body.token !== 'string' || typeof body.expr !== 'number') {
          return 'error';
        }
        writeSession({
          token: body.token,
          exp: body.expr,
          user: typeof body.user === 'string' ? body.user : '',
          iat: nowSec(),
        });
        return 'ok';
      }, function () { return 'error'; });
    }, function () { return 'error'; });
  }

  // ─── parent request handling ────────────────────────────────────────────

  function handleGetToken() {
    var s = readSession();
    if (sessionFresh(s)) return Promise.resolve(s.token);
    return ensureRefresh().then(function () {
      var s2 = readSession();
      return sessionValid(s2) ? s2.token : null;
    });
  }

  function handleLogout() {
    clearSession();
    clearMarker();
    try { localStorage.removeItem(KEY_LOCK); } catch (e) {}
    if (refreshTimer) {
      clearTimeout(refreshTimer);
      refreshTimer = null;
    }
    pushStatus(true);
    // Best-effort server-side logout: same-origin POST with the session
    // cookies attached; Set-Cookie in the response is honored against this
    // origin. Other frames converge via the storage event on the removed
    // session key.
    try {
      var opts = { method: 'POST', credentials: 'same-origin', cache: 'no-store' };
      if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) {
        opts.signal = AbortSignal.timeout(LOGOUT_SERVER_TIMEOUT_MS);
      }
      fetch('/auth/logout', opts).catch(function () {});
    } catch (e) {}
    return Promise.resolve(true);
  }

  function handleAdopt(data) {
    if (!data || typeof data.token !== 'string' || typeof data.exp !== 'number' ||
        data.token.split('.').length !== 3 || data.exp <= nowSec()) {
      return Promise.reject(new Error('invalid token'));
    }
    var s = readSession();
    if (!s || s.exp < data.exp) {
      writeSession({
        token: data.token,
        exp: data.exp,
        user: typeof data.user === 'string' ? data.user : '',
        iat: nowSec(),
      });
      pushStatus(true);
      scheduleRefresh();
    }
    // When the stored session is at least as new, keep it — the response
    // tells the parent what actually won.
    return Promise.resolve(tokenInfo());
  }

  function handleRequest(d) {
    switch (d.action) {
      case 'getStatus':
        return Promise.resolve(tokenInfo());
      case 'getToken':
        return handleGetToken();
      case 'logout':
        return handleLogout();
      case 'adoptToken':
        return handleAdopt(d.data);
      default:
        return Promise.reject(new Error('unknown action: ' + d.action));
    }
  }

  window.addEventListener('message', function (event) {
    if (event.origin !== PARENT_ORIGIN) return;
    if (event.source !== window.parent) return;
    var d = event.data;
    if (!d || d.ns !== NS || d.v !== PROTOCOL_VERSION ||
        d.type !== 'request' || typeof d.id !== 'number') {
      return;
    }
    handleRequest(d).then(function (data) {
      respond(d.id, true, data, null);
    }, function (err) {
      respond(d.id, false, null, err && err.message ? err.message : String(err));
    });
  });

  function respond(id, ok, data, error) {
    var msg = { ns: NS, v: PROTOCOL_VERSION, type: 'response', id: id, ok: ok };
    if (ok) {
      msg.data = data;
    } else {
      msg.error = error;
    }
    try { window.parent.postMessage(msg, PARENT_ORIGIN); } catch (e) {}
  }

  // ─── cross-frame sync + lifecycle ───────────────────────────────────────

  window.addEventListener('storage', function (event) {
    // key === null means storage.clear().
    if (event.key !== null && event.key !== KEY_SESSION &&
        event.key !== KEY_REFRESHING) {
      return;
    }
    flushStorageWaiters();
    pushStatus();
    if (event.key === null || event.key === KEY_SESSION) scheduleRefresh();
  });

  // Timers are frozen during sleep and throttled in background tabs;
  // re-evaluate whenever this tab comes back.
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState !== 'visible') return;
    if (!sessionFresh(readSession())) {
      ensureRefresh();
    } else {
      scheduleRefresh();
    }
  });

  // ─── init ───────────────────────────────────────────────────────────────

  // First push doubles as the ready signal for the parent.
  pushStatus(true);
  if (sessionFresh(readSession())) {
    scheduleRefresh();
  } else {
    // No usable shared session — bootstrap one now. If the user holds a
    // proxy session cookie this silently mints the first token (replacing
    // v1's /auth/embed flow); otherwise it concludes unauthenticated.
    ensureRefresh();
  }
})();
