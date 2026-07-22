// authenticatoor — client library (v2, shared session)
//
// Exposes window.ethpandaops.authenticatoor with an event-emitting,
// promise-based API:
//
//   addEventListener('status', cb) / removeEventListener('status', cb)
//     "status" fires whenever the session state changes. cb receives a
//     TokenInfo object:
//       { status: 'unauthenticated'|'authenticated'|'refreshing',
//         authenticated: boolean, user: string, exp: number }
//     A listener added after the state is already known receives the
//     current state once, asynchronously, right after subscribing.
//
//   getStatus(): Promise<TokenInfo>
//     Resolves once the initial state is known. Never rejects.
//
//   getToken(): Promise<string|null>
//     Resolves to a bearer token with comfortable remaining validity, or
//     null when unauthenticated. Triggers a refresh through the shared
//     frame when the cached token is stale.
//
//   login(): Promise<boolean>
//     Resolves true if already authenticated. Otherwise navigates the page
//     through the full /auth/login redirect flow (the returned promise
//     never settles — the page is going away).
//
//   logout(): Promise<void>
//     Logs out everywhere: clears the shared session (all apps and tabs
//     converge to unauthenticated) and pokes the server-side logout.
//
//   authServiceURL(): string
//
// How it works: this script mounts a hidden iframe on the auth-service
// origin (/clientFrame). That frame owns the session — it stores the token
// in auth-origin localStorage (shared by every app's frame via storage
// events), refreshes it before expiry (a single elected refresher across
// all tabs), and pushes status changes to this page over origin-checked
// postMessage. The raw token is kept in memory only on the app origin —
// it is never written to app-origin storage.
//
// Load exactly one client version per page. The auth service URL is
// templated into the file at serve time; load it as
// `<script src="https://auth.<devnet>/client.js?v=2"></script>`.

(function () {
  'use strict';

  // Hard guard: if the global is already populated (script loaded twice,
  // or v1 loaded first), leave it alone.
  var existing = window.ethpandaops && window.ethpandaops.authenticatoor;
  if (existing) return;

  // Templated by the server at request time. Falls back to current origin
  // for local development convenience.
  var AUTH_SERVICE_URL = '__AUTH_SERVICE_URL__';
  if (!AUTH_SERVICE_URL || AUTH_SERVICE_URL.indexOf('__') === 0) {
    AUTH_SERVICE_URL = window.location.origin;
  }
  AUTH_SERVICE_URL = AUTH_SERVICE_URL.replace(/\/+$/, '');

  var AUTH_ORIGIN = (function () {
    try { return new URL(AUTH_SERVICE_URL).origin; } catch (e) { return ''; }
  })();

  var NS = 'ethpandaops.authenticatoor';
  var PROTOCOL_VERSION = 2;

  // The frame load goes through the auth proxy; a cold cache plus a slow
  // proxy round trip can take a while. After this window we degrade to
  // unauthenticated but keep listening — a late frame recovers the
  // connection transparently.
  var FRAME_READY_TIMEOUT_MS = 20000;
  var REQUEST_TIMEOUT_MS = 20000;
  // Minimum remaining validity for a cached token to be served without
  // asking the frame.
  var TOKEN_MIN_VALIDITY_SECONDS = 10;

  // ─── state ──────────────────────────────────────────────────────────────

  var frame = null;
  var frameReady = false;      // true once the frame's first status arrived
  var currentStatus = null;    // null until the first known state
  var currentTokenInfo = null;
  var currentToken = null;     // memory only — never persisted on this origin
  var pendingAdopt = null;     // token captured from the login redirect fragment

  function makeUnauthInfo() {
    return { status: 'unauthenticated', authenticated: false, user: '', exp: 0 };
  }

  // ─── readiness (first known state) ──────────────────────────────────────

  var readyResolvers = [];

  function whenReady() {
    if (currentStatus !== null) return Promise.resolve();
    return new Promise(function (resolve) { readyResolvers.push(resolve); });
  }

  function settleReady() {
    var rs = readyResolvers;
    readyResolvers = [];
    for (var i = 0; i < rs.length; i++) rs[i]();
  }

  // ─── event emitter ──────────────────────────────────────────────────────

  var listeners = {};

  function addListener(type, cb) {
    if (typeof cb !== 'function') return;
    if (!listeners[type]) listeners[type] = [];
    if (listeners[type].indexOf(cb) === -1) listeners[type].push(cb);
    // Late subscriber: replay the current state once, asynchronously.
    if (type === 'status' && currentStatus !== null) {
      setTimeout(function () {
        if (listeners.status && listeners.status.indexOf(cb) !== -1) {
          try { cb(currentTokenInfo || makeUnauthInfo()); } catch (e) {}
        }
      }, 0);
    }
  }

  function removeListener(type, cb) {
    var arr = listeners[type];
    if (!arr) return;
    var i = arr.indexOf(cb);
    if (i !== -1) arr.splice(i, 1);
  }

  function emitStatus() {
    var arr = listeners.status;
    if (!arr || !arr.length) return;
    var info = currentTokenInfo || makeUnauthInfo();
    // Iterate over a copy so listeners can (un)subscribe from inside a
    // callback without skipping anyone.
    var copy = arr.slice();
    for (var i = 0; i < copy.length; i++) {
      try { copy[i](info); } catch (e) {}
    }
  }

  function infoEqual(a, b) {
    if (!a || !b) return a === b;
    return a.status === b.status && a.user === b.user && a.exp === b.exp;
  }

  // applyState updates the tracked session state and emits "status" when it
  // actually changed. Pass token === undefined to keep the cached token.
  function applyState(status, info, token) {
    var changed = currentStatus !== status || !infoEqual(currentTokenInfo, info);
    currentStatus = status;
    currentTokenInfo = info;
    if (token !== undefined) currentToken = token;
    settleReady();
    if (changed) emitStatus();
  }

  // ─── token introspection (fallback when user isn't supplied) ────────────

  function base64UrlDecode(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    try { return atob(s); } catch (e) { return ''; }
  }

  function extractUserFromToken(token) {
    if (!token) return '';
    var parts = token.split('.');
    if (parts.length !== 3) return '';
    var json = base64UrlDecode(parts[1]);
    if (!json) return '';
    try {
      var c = JSON.parse(json);
      return c.email || c.sub || '';
    } catch (e) {
      return '';
    }
  }

  // ─── fragment capture (after /auth/login redirect) ──────────────────────

  function captureFromFragment() {
    if (!window.location.hash || window.location.hash.length < 2) return null;
    var params;
    try {
      params = new URLSearchParams(window.location.hash.slice(1));
    } catch (e) {
      return null;
    }
    var token = params.get('auth_token');
    var exp = parseInt(params.get('exp') || '0', 10);
    if (!token || !exp) return null;

    var user = params.get('user') || extractUserFromToken(token);

    // Strip the auth params from the URL so the user can't accidentally
    // copy/share/bookmark a URL with an embedded token. Preserve any other
    // fragment params if present.
    params.delete('auth_token');
    params.delete('exp');
    params.delete('user');
    var remaining = params.toString();
    var newURL = window.location.pathname + window.location.search +
      (remaining ? '#' + remaining : '');
    try { history.replaceState(null, '', newURL); } catch (e) {}

    return { token: token, exp: exp, user: user };
  }

  // ─── frame message bridge ───────────────────────────────────────────────

  var nextRequestId = 1;
  var pendingRequests = {};

  function request(action, data) {
    return new Promise(function (resolve, reject) {
      if (!frame || !frame.contentWindow || !AUTH_ORIGIN) {
        reject(new Error('authenticatoor: frame not available'));
        return;
      }
      var id = nextRequestId++;
      var timer = setTimeout(function () {
        delete pendingRequests[id];
        reject(new Error('authenticatoor: frame request timeout (' + action + ')'));
      }, REQUEST_TIMEOUT_MS);
      pendingRequests[id] = { resolve: resolve, reject: reject, timer: timer };
      frame.contentWindow.postMessage({
        ns: NS,
        v: PROTOCOL_VERSION,
        type: 'request',
        id: id,
        action: action,
        data: data || null,
      }, AUTH_ORIGIN);
    });
  }

  function onMessage(event) {
    if (!frame || event.source !== frame.contentWindow) return;
    if (event.origin !== AUTH_ORIGIN) return;
    var d = event.data;
    if (!d || d.ns !== NS || d.v !== PROTOCOL_VERSION) return;

    if (d.type === 'status') {
      frameReady = true;
      handleStatusPush(d);
      return;
    }
    if (d.type === 'response') {
      var p = pendingRequests[d.id];
      if (!p) return;
      delete pendingRequests[d.id];
      clearTimeout(p.timer);
      if (d.ok) {
        p.resolve(d.data);
      } else {
        p.reject(new Error(d.error || 'authenticatoor: frame error'));
      }
    }
  }

  function handleStatusPush(d) {
    var info = d.tokenInfo && typeof d.tokenInfo === 'object' ? d.tokenInfo : makeUnauthInfo();

    if (pendingAdopt) {
      // We captured a token from the login redirect and haven't handed it
      // to the frame yet. Hold the provisional authenticated state (don't
      // let a pre-adoption "unauthenticated" push flicker through) and
      // adopt now. The frame's post-adoption pushes carry the final state.
      var adopt = pendingAdopt;
      pendingAdopt = null;
      request('adoptToken', adopt).then(function (adopted) {
        // token === undefined: the frame's own status push (sent before
        // this response) already delivered the winning token.
        applyState(adopted.status, adopted, undefined);
      }).catch(function () {
        // Frame rejected the token — fall back to whatever it reports.
        request('getStatus').then(function (cur) {
          applyState(cur.status, cur, null);
        }).catch(function () {});
      });
      // If the frame already holds a session (another app logged in
      // first), apply it right away; adoption can only upgrade it.
      if (d.status === 'authenticated') {
        applyState(d.status, info, d.token || null);
      }
      return;
    }

    applyState(d.status, info, d.token || null);
  }

  // ─── frame mount ────────────────────────────────────────────────────────

  function mountFrame() {
    frame = document.createElement('iframe');
    frame.style.display = 'none';
    frame.setAttribute('aria-hidden', 'true');
    frame.referrerPolicy = 'no-referrer';
    frame.src = AUTH_SERVICE_URL + '/clientFrame?v=2&origin=' +
      encodeURIComponent(window.location.origin);

    if (document.body) {
      document.body.appendChild(frame);
    } else {
      document.addEventListener('DOMContentLoaded', function () {
        if (!frame.parentNode) document.body.appendChild(frame);
      });
    }

    setTimeout(function () {
      if (currentStatus === null) {
        // No word from the frame — degrade to unauthenticated. The
        // message listener stays attached, so a late frame status
        // recovers the connection.
        applyState('unauthenticated', makeUnauthInfo(), null);
      }
    }, FRAME_READY_TIMEOUT_MS);
  }

  // ─── public API ─────────────────────────────────────────────────────────

  function getStatus() {
    return whenReady().then(function () {
      return currentTokenInfo || makeUnauthInfo();
    });
  }

  function getToken() {
    return whenReady().then(function () {
      var nowSec = Math.floor(Date.now() / 1000);
      if (currentToken && currentTokenInfo &&
          currentTokenInfo.exp > nowSec + TOKEN_MIN_VALIDITY_SECONDS) {
        return currentToken;
      }
      if (!frameReady) {
        // Frame never came up — nothing more we can do silently.
        return currentToken || null;
      }
      return request('getToken').then(function (tok) {
        if (tok) currentToken = tok;
        return tok || null;
      });
    });
  }

  function login() {
    return getStatus().then(function (info) {
      if (info.authenticated) return true;
      // Strip any existing fragment so /auth/login can put auth_token there.
      var returnTo = window.location.origin + window.location.pathname +
        window.location.search;
      window.location.href = AUTH_SERVICE_URL + '/auth/login?return_to=' +
        encodeURIComponent(returnTo);
      // Navigating away — never settles.
      return new Promise(function () {});
    });
  }

  function logout() {
    function clearLocal() {
      pendingAdopt = null;
      applyState('unauthenticated', makeUnauthInfo(), null);
    }
    if (!frameReady) {
      clearLocal();
      return Promise.resolve();
    }
    // The frame clears the shared session (other apps converge via storage
    // events) and best-efforts the server-side logout.
    return request('logout').then(clearLocal, clearLocal);
  }

  function authServiceURL() {
    return AUTH_SERVICE_URL;
  }

  // ─── init ───────────────────────────────────────────────────────────────

  window.addEventListener('message', onMessage);

  var captured = captureFromFragment();
  mountFrame();
  if (captured) {
    // Provisional state: we hold a token straight from /auth/login. The
    // frame adopts it (making it the shared session) as soon as it is
    // ready; its confirming status push supersedes this.
    pendingAdopt = captured;
    applyState('authenticated', {
      status: 'authenticated',
      authenticated: true,
      user: captured.user || '',
      exp: captured.exp,
    }, captured.token);
  }

  // ─── publish ────────────────────────────────────────────────────────────

  if (!window.ethpandaops) window.ethpandaops = {};
  window.ethpandaops.authenticatoor = {
    version:             2,
    addEventListener:    addListener,
    removeEventListener: removeListener,
    getStatus:           getStatus,
    getToken:            getToken,
    login:               login,
    logout:              logout,
    authServiceURL:      authServiceURL,
  };
})();
