// authenticatoor — client library
//
// Exposes window.ethpandaops.authenticatoor with four entry points:
//
//   checkLogin(): Promise<TokenInfo>
//     Run on page load. Tries three sources in order:
//       1. token returned in the URL fragment by /auth/login (resolves
//          immediately, sync)
//       2. fresh token already in sessionStorage (resolves immediately, sync)
//       3. silent iframe (/auth/embed) that posts a token back via
//          postMessage (resolves when the iframe responds, or after a 30s
//          timeout — whichever comes first)
//     Resolves to { authenticated, token, exp, user }; never rejects.
//
//     UX note: do NOT block initial UI rendering on this promise. Render
//     the unauthenticated state immediately and re-render when the promise
//     resolves with authenticated=true. The user can click `login()` at any
//     point during the silent-iframe wait — the page navigates away and
//     the in-flight promise becomes irrelevant.
//
//   login(): void
//     Full-page redirect to /auth/login. The auth service redirects back to
//     the current URL with #auth_token=…&exp=… in the fragment, which the
//     next checkLogin() picks up.
//
//   logout(): void
//     Clears the locally stored token. The CF Access cookie is unaffected
//     (use the upstream provider's logout to clear that).
//
//   getToken(): string | null
//     Returns the cached bearer token for use in API calls. Null if no
//     fresh token is stored. Does not trigger any network activity.
//
// The auth service URL is templated into the file at serve time. This file
// is meant to be loaded as `<script src="https://auth.<devnet>/client.js">`.

(function () {
  'use strict';

  // Hard guard: if the global is already populated (script loaded twice),
  // leave it alone.
  var existing = window.ethpandaops && window.ethpandaops.authenticatoor;
  if (existing) return;

  // Templated by the server at request time. Falls back to current origin
  // for local development convenience.
  var AUTH_SERVICE_URL = '__AUTH_SERVICE_URL__';
  if (!AUTH_SERVICE_URL || AUTH_SERVICE_URL.indexOf('__') === 0) {
    AUTH_SERVICE_URL = window.location.origin;
  }
  // Strip trailing slash for clean concatenation.
  AUTH_SERVICE_URL = AUTH_SERVICE_URL.replace(/\/+$/, '');

  var EXPECTED_ORIGIN = (function () {
    try { return new URL(AUTH_SERVICE_URL).origin; } catch (e) { return ''; }
  })();

  var STORAGE_TOKEN = 'ethpandaops.authenticatoor.token';
  var STORAGE_EXP   = 'ethpandaops.authenticatoor.exp';
  var STORAGE_USER  = 'ethpandaops.authenticatoor.user';

  var REFRESH_THRESHOLD_SECONDS = 60;
  // The iframe load goes through CF Access; if the user has a session
  // cookie it's near-instant, but if CF needs to redirect through their
  // login flow the response can take a while. 30s is a generous upper
  // bound — callers shouldn't block their UI on this promise; render the
  // unauthenticated state immediately and re-render on resolution.
  var IFRAME_TIMEOUT_MS = 30000;

  // ─── storage ────────────────────────────────────────────────────────────

  function readStored() {
    try {
      var token = sessionStorage.getItem(STORAGE_TOKEN);
      var exp = parseInt(sessionStorage.getItem(STORAGE_EXP) || '0', 10);
      var user = sessionStorage.getItem(STORAGE_USER) || '';
      if (!token || !exp) return null;
      return { token: token, exp: exp, user: user };
    } catch (e) {
      return null;
    }
  }

  function writeStored(token, exp, user) {
    try {
      sessionStorage.setItem(STORAGE_TOKEN, token);
      sessionStorage.setItem(STORAGE_EXP, String(exp));
      sessionStorage.setItem(STORAGE_USER, user || '');
    } catch (e) { /* private mode etc */ }
  }

  function clearStored() {
    try {
      sessionStorage.removeItem(STORAGE_TOKEN);
      sessionStorage.removeItem(STORAGE_EXP);
      sessionStorage.removeItem(STORAGE_USER);
    } catch (e) {}
  }

  function isFresh(info) {
    if (!info || !info.exp) return false;
    var nowSec = Math.floor(Date.now() / 1000);
    return info.exp > nowSec + REFRESH_THRESHOLD_SECONDS;
  }

  function makeUnauth() {
    return { authenticated: false, token: '', exp: 0, user: '' };
  }

  function makeAuth(info) {
    return {
      authenticated: true,
      token: info.token,
      exp: info.exp,
      user: info.user || '',
    };
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

    // Prefer the explicit user query param; fall back to the email/sub
    // claim inside the JWT itself.
    var user = params.get('user') || extractUserFromToken(token);
    writeStored(token, exp, user);

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

  // ─── silent iframe → postMessage ────────────────────────────────────────

  function tryIframe(timeoutMs) {
    return new Promise(function (resolve, reject) {
      var iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      iframe.setAttribute('aria-hidden', 'true');
      iframe.referrerPolicy = 'no-referrer';

      var src = AUTH_SERVICE_URL + '/auth/embed?target_origin=' +
        encodeURIComponent(window.location.origin);

      var done = false;
      var timer = null;

      function cleanup() {
        window.removeEventListener('message', onMessage);
        if (timer) clearTimeout(timer);
        if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
      }

      function onMessage(event) {
        if (done) return;
        if (EXPECTED_ORIGIN && event.origin !== EXPECTED_ORIGIN) return;
        var d = event.data;
        if (!d || d.type !== 'authenticatoor.token' || !d.token) return;
        done = true;
        cleanup();
        var user = d.user || extractUserFromToken(d.token);
        writeStored(d.token, d.exp, user);
        resolve({ token: d.token, exp: d.exp, user: user });
      }

      window.addEventListener('message', onMessage);
      timer = setTimeout(function () {
        if (done) return;
        done = true;
        cleanup();
        reject(new Error('authenticatoor: iframe timeout'));
      }, timeoutMs || IFRAME_TIMEOUT_MS);

      iframe.src = src;
      // Defer to ensure the message listener is wired before the iframe loads.
      if (document.body) {
        document.body.appendChild(iframe);
      } else {
        document.addEventListener('DOMContentLoaded', function () {
          if (!done) document.body.appendChild(iframe);
        });
      }
    });
  }

  // ─── public API ─────────────────────────────────────────────────────────

  function checkLogin() {
    // Step 1: fragment after /auth/login redirect.
    captureFromFragment();

    // Step 2: still-fresh stored token.
    var stored = readStored();
    if (isFresh(stored)) {
      return Promise.resolve(makeAuth(stored));
    }

    // Step 3: silent iframe. Times out → unauth (caller can decide to login()).
    return tryIframe(IFRAME_TIMEOUT_MS)
      .then(function (info) { return makeAuth(info); })
      .catch(function () { return makeUnauth(); });
  }

  function login() {
    // Strip any existing fragment so /auth/login can put auth_token there.
    var returnTo = window.location.origin + window.location.pathname +
      window.location.search;
    var url = AUTH_SERVICE_URL + '/auth/login?return_to=' +
      encodeURIComponent(returnTo);
    window.location.href = url;
  }

  function logout() {
    clearStored();
  }

  function getToken() {
    var stored = readStored();
    return isFresh(stored) ? stored.token : null;
  }

  function isLoggedIn() {
    return isFresh(readStored());
  }

  function authServiceURL() {
    return AUTH_SERVICE_URL;
  }

  // ─── publish ────────────────────────────────────────────────────────────

  if (!window.ethpandaops) window.ethpandaops = {};
  window.ethpandaops.authenticatoor = {
    checkLogin:       checkLogin,
    login:            login,
    logout:           logout,
    getToken:         getToken,
    isLoggedIn:       isLoggedIn,
    authServiceURL:   authServiceURL,
  };
})();
