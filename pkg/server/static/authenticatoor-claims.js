// authenticatoor — token claims (shared by the v1 and v2 clients)
//
// This file is not a script of its own. The server inserts it, at serve
// time, into the client libraries where they carry the include marker
// (see clientAsset in handler_client.go), so the evaluator below exists
// once and every client version ships the same text. Everything here is
// local to the including script's function scope; the names carry a
// "claims" prefix to stay clear of the including script's own.
//
// What it provides to a client library:
//
//   claimsTokenState(token)  the decoded claims of a token, or null
//   claimsAPI(current)       the public functions getClaims, hasService,
//                            hasFeature, getTeams, serviceAllowed and
//                            featureAllowed
//
// The token is DECODED, NOT VERIFIED: the payload is base64url-decoded
// and parsed, the signature is not looked at. That is enough to decide
// what a page shows; it is not an access check. The API of each tool
// verifies the token and stays the enforcement.
//
// The evaluator is a port of pkg/auth/services.go (ServiceAllowed,
// FeatureAllowed, parseDirective, queryName) and must answer exactly
// like it; pkg/server/client_claims_test.go runs this text against the Go
// functions. Directive grammar of the "services" claim:
//
//   directive = [+|-]service(:grantSpec)*
//   grantSpec = feature | -feature | all
//   feature   = name | prefix*
//
//   +spamoor                 basic access, no further features
//   +spamoor:basic           the same, spelled out
//   +spamoor:all             basic + every feature ("+spamoor:*" too)
//   +spamoor:f1:f2           basic + f1 + f2
//   +spamoor:all:-plugins    basic + every feature except plugins
//   +spamoor:user*           basic + every feature starting with "user"
//   +all:featA               every service: basic + featA
//   -spamoor                 deny spamoor entirely (features included)
//   -spamoor:f1              remove f1, basic access untouched
//
//   - An empty directive string — a token without the claim — is basic
//     access to every service and nothing more. For a feature it reads
//     like "+all": nothing is said about any feature.
//   - Directives apply left to right, a later one overrides an earlier
//     one; inside one directive the segments apply left to right too.
//   - Basic access defaults to ALLOW when no directive matches the
//     service ("-all,+x" is "only x"). Every positive directive grants
//     it; only a denial of the service takes it away.
//   - A feature is never allowed without basic access to its service.
//   - A malformed directive is skipped as a whole.
//   - Case and ASCII whitespace are ignored throughout.
//
// Names are ASCII. The grammar has no use for anything else, and Go and
// JavaScript do not fold case or trim whitespace alike outside ASCII, so
// this port does not try: a directive list, a service or a feature with
// a character outside ASCII is answered with false, whatever the Go
// evaluator would say. The same goes for an argument of the wrong type.
// The two never disagree in the permissive direction.

var CLAIMS_GRANT_ALL = 'all';
var CLAIMS_FEATURE_BASIC = 'basic';
var CLAIMS_NON_ASCII = /[^\x00-\x7f]/;

// claimsTrim is Go's strings.TrimSpace within ASCII: it strips "\t", "\n",
// "\v", "\f", "\r" and " " from both ends. A loop, not a regular
// expression: the time stays linear whatever the string looks like.
function claimsTrim(s) {
  var start = 0;
  var end = s.length;
  while (start < end && claimsIsSpace(s.charCodeAt(start))) start++;
  while (end > start && claimsIsSpace(s.charCodeAt(end - 1))) end--;
  return s.substring(start, end);
}

function claimsIsSpace(code) {
  return code === 32 || (code >= 9 && code <= 13);
}

// claimsDirectiveList returns the directive list to evaluate: '' for an
// absent claim (undefined or null), null when it cannot be evaluated.
function claimsDirectiveList(directives) {
  if (directives === undefined || directives === null) return '';
  if (typeof directives !== 'string' || CLAIMS_NON_ASCII.test(directives)) return null;
  return directives;
}

function claimsIsName(s) {
  return typeof s === 'string' && !CLAIMS_NON_ASCII.test(s);
}

// claimsServiceAllowed reports whether the named service is permitted by
// a directive list: "may this token be used against the service at all".
// An empty directive list or an empty service allows.
function claimsServiceAllowed(directives, service) {
  directives = claimsDirectiveList(directives);
  if (directives === null || !claimsIsName(service)) return false;
  if (directives === '' || service === '') return true;
  service = claimsTrim(service).toLowerCase();
  if (service === '') return true;

  var allowed = true;
  var parsed = claimsParseDirectives(directives);
  for (var i = 0; i < parsed.length; i++) {
    var d = parsed[i];
    if (!claimsDirectiveMatches(d, service)) continue;
    if (d.allow) {
      allowed = true;
    } else if (!d.targeted) {
      allowed = false;
    }
    // A negative directive with segments excludes features only.
  }
  return allowed;
}

// claimsFeatureAllowed reports whether a feature of a service may be
// used under the directive list. defaultAllow selects the answer for a
// feature the list says nothing about:
//
//   basic access  state      default-deny   default-allow
//   denied        any        no             no
//   allowed       unset      no             yes
//   allowed       granted    yes            yes
//   allowed       excluded   no             no
//
// A token without the claim is the row "allowed, unset". The feature
// "basic", like an empty feature, asks for the service itself. An empty
// service is refused (except by the service gate under the empty
// directive string, which is open whatever is asked), and so is a
// feature that cannot be a feature name: the reserved word "all", or one
// containing ":", ",", "*" or a leading sign.
function claimsFeatureAllowed(directives, service, feature, defaultAllow) {
  directives = claimsDirectiveList(directives);
  if (directives === null || !claimsIsName(service) || !claimsIsName(feature)) return false;
  feature = claimsTrim(feature).toLowerCase();
  var basic = feature === '' || feature === CLAIMS_FEATURE_BASIC;
  if (directives === '' && basic) {
    // The service gate of a token without the claim: always open. Any
    // other feature takes the ordinary walk below, which over no
    // directives ends at base access with the feature unset.
    return true;
  }
  service = claimsTrim(service).toLowerCase();
  if (service === '') return false;
  if (basic) return claimsServiceAllowed(directives, service);
  if (!claimsQueryName(service) || !claimsQueryName(feature) || feature === CLAIMS_GRANT_ALL) {
    return false;
  }

  // state: 0 unset, 1 granted, 2 excluded.
  var base = true;
  var state = 0;
  var parsed = claimsParseDirectives(directives);
  for (var i = 0; i < parsed.length; i++) {
    var d = parsed[i];
    if (!claimsDirectiveMatches(d, service)) continue;
    if (!d.targeted) {
      // A bare directive decides base access. A denial also forgets
      // what was said about the service's features.
      base = d.allow;
      if (!d.allow) state = 0;
      continue;
    }
    if (d.allow) base = true; // a positive directive implies base access
    for (var j = 0; j < d.segments.length; j++) {
      var seg = d.segments[j];
      if (!claimsSegmentCovers(seg, feature)) continue;
      state = seg.remove ? 2 : 1;
    }
  }

  if (!base) return false;
  return state === 1 || (state === 0 && defaultAllow === true);
}

// claimsQueryName reports whether s can be the service or feature of a
// feature query: non-empty and free of the characters that structure a
// directive.
function claimsQueryName(s) {
  return s !== '' && !/[:,*]/.test(s) && s.charAt(0) !== '-' && s.charAt(0) !== '+';
}

function claimsSegmentCovers(seg, feature) {
  if (seg.prefix) return feature.substring(0, seg.name.length) === seg.name;
  if (seg.name === CLAIMS_GRANT_ALL) return true;
  return seg.name === feature;
}

function claimsDirectiveMatches(d, service) {
  return d.service === CLAIMS_GRANT_ALL || d.service === service;
}

// claimsParseDirectives splits a directive list and drops malformed
// entries.
function claimsParseDirectives(directives) {
  var out = [];
  var parts = directives.split(',');
  for (var i = 0; i < parts.length; i++) {
    var d = claimsParseDirective(parts[i]);
    if (d) out.push(d);
  }
  return out;
}

// claimsParseDirective parses one entry; null when it is malformed. The
// result is { allow, service, targeted, segments: [{ name, prefix,
// remove }] }.
function claimsParseDirective(raw) {
  raw = claimsTrim(raw);
  if (raw.length < 2) return null;
  var op = raw.charAt(0);
  if (op !== '+' && op !== '-') return null;
  var fields = raw.substring(1).toLowerCase().split(':');
  var name = claimsTrim(fields[0]);
  if (name === '') return null;

  if (fields.length > 1 && name.indexOf('*') !== -1) {
    // No wildcard in the service position. (A bare "+spam*" stays the
    // literal name of a service that does not exist.)
    return null;
  }

  // Check every segment before any of them takes effect: one malformed
  // segment makes the whole directive malformed, wherever it stands.
  var allow = op === '+';
  var checked = [];
  var i, seg;
  for (i = 1; i < fields.length; i++) {
    seg = claimsTrim(fields[i]);
    var signed = seg.charAt(0) === '-';
    if (signed) seg = claimsTrim(seg.substring(1));
    if (seg === '') return null; // "+svc:", "+svc::f", "+svc:-"
    if (signed && !allow) return null; // "-svc:-x" has no meaning
    var prefix = false;
    var star = seg.indexOf('*');
    if (star !== -1) {
      if (seg === '*') {
        seg = CLAIMS_GRANT_ALL;
      } else if (star === seg.length - 1) {
        seg = seg.substring(0, star);
        prefix = true;
      } else {
        return null; // "us*er", "*admin", "u**"
      }
    }
    if (seg === CLAIMS_FEATURE_BASIC && !prefix && signed) {
      // "+svc:-basic": basic access cannot be excluded from a directive
      // that grants it.
      return null;
    }
    checked.push({ name: seg, signed: signed, prefix: prefix });
  }

  var d = { allow: allow, service: name, targeted: fields.length > 1, segments: [] };
  for (i = 0; i < checked.length; i++) {
    seg = checked[i];
    if (seg.name === CLAIMS_FEATURE_BASIC && !seg.prefix) {
      // "+svc:basic": every positive directive grants it.
      if (allow) continue;
      // "-svc:basic": without basic access nothing is left, so this is
      // the denial of the service.
      return { allow: false, service: name, targeted: false, segments: [] };
    }
    d.segments.push({ name: seg.name, prefix: seg.prefix, remove: seg.signed || !allow });
  }
  return d;
}

// ─── token → claims ───────────────────────────────────────────────────────

// claimsDecodeToken returns the payload object of a JWT, or null when
// the token is not three base64url parts around a JSON object.
function claimsDecodeToken(token) {
  if (typeof token !== 'string') return null;
  var parts = token.split('.');
  if (parts.length !== 3 || !/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
  var b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  var claims;
  try {
    // atob yields one character per byte; put the UTF-8 back together.
    var bin = atob(b64);
    var escaped = '';
    for (var i = 0; i < bin.length; i++) {
      var c = bin.charCodeAt(i);
      escaped += (c < 16 ? '%0' : '%') + c.toString(16);
    }
    claims = JSON.parse(decodeURIComponent(escaped));
  } catch (e) {
    return null;
  }
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) return null;
  return claims;
}

// claimsField returns { ok, value } for one claim. A claim the Go
// verifier would read under another spelling of its name (its JSON
// decoder matches field names without regard to case) is not ok: this
// code would not see what the verifier sees.
function claimsField(claims, name) {
  var has = Object.prototype.hasOwnProperty;
  for (var key in claims) {
    if (!has.call(claims, key) || key === name) continue;
    if (key.toLowerCase() === name || key.toUpperCase() === name.toUpperCase()) {
      return { ok: false, value: undefined };
    }
  }
  return { ok: true, value: has.call(claims, name) ? claims[name] : undefined };
}

var claimsLastToken = null;
var claimsLastState = null;

// claimsTokenState decodes a token into
//
//   { claims: object, services: string|null, teams: string[] }
//
// or null when there is no token or it cannot be decoded. services is
// the raw claim, '' when the token has none, and null when the claim is
// there but is not a string: the Go verifier refuses such a token, so
// the user has no service and no feature. teams is empty unless the
// claim is an array of strings. The last result is kept, so asking again
// for the same token costs nothing.
function claimsTokenState(token) {
  if (!token) return null;
  if (token === claimsLastToken) return claimsLastState;

  var state = null;
  var claims = claimsDecodeToken(token);
  if (claims) {
    var services = claimsField(claims, 'services');
    var teams = claimsField(claims, 'teams');
    state = { claims: claims, services: '', teams: [] };
    if (!services.ok) {
      state.services = null;
    } else if (services.value !== undefined) {
      state.services = typeof services.value === 'string' ? services.value : null;
    }
    if (teams.ok && Array.isArray(teams.value)) {
      var list = [];
      for (var i = 0; i < teams.value.length; i++) {
        if (typeof teams.value[i] !== 'string') {
          list = [];
          break;
        }
        list.push(teams.value[i]);
      }
      state.teams = list;
    }
  }
  claimsLastToken = token;
  claimsLastState = state;
  return state;
}

// claimsAPI builds the public claim functions of a client library.
// current() returns the claimsTokenState of the token the library holds
// right now, or null when the user is not authenticated.
function claimsAPI(current) {
  return {
    getClaims: function () {
      var state = current();
      return state ? state.claims : null;
    },
    hasService: function (service) {
      var state = current();
      return !!state && state.services !== null &&
        claimsServiceAllowed(state.services, service);
    },
    hasFeature: function (service, feature, opts) {
      var state = current();
      return !!state && state.services !== null &&
        claimsFeatureAllowed(state.services, service, feature,
          !!opts && opts.defaultAllow === true);
    },
    getTeams: function () {
      var state = current();
      return state ? state.teams.slice() : [];
    },
    serviceAllowed: claimsServiceAllowed,
    featureAllowed: function (directives, service, feature, defaultAllow) {
      return claimsFeatureAllowed(directives, service, feature, defaultAllow === true);
    },
  };
}
