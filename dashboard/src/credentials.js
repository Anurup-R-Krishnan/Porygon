// Credential storage for the operator console.
//
// The console holds two secrets: the operator token, which authorises
// containment and AI audits, and an optional third-party LLM provider key.
// Both used to live in localStorage, which survives browser restarts
// indefinitely and is readable by every script on the origin -- a token
// entered once for a demo would still be sitting on disk weeks later.
//
// This keeps them in sessionStorage instead, so closing the tab ends their
// life, and gives the operator token a sliding idle expiry so an unattended
// console does not stay authorised. See plans/010-operator-console-hardening.md
// step 4.
//
// Loaded as a plain script by index.html (exposing window.PorygonCredentials)
// and as a CommonJS module by the node:test suite in dashboard/tests/.
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.PorygonCredentials = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var PREFIX = 'porygon.credential.';

  // Where each credential used to be kept, so an existing install can be
  // moved off disk on first load rather than left there.
  var LEGACY_KEYS = {
    operator: 'porygon_operator_token',
    aiKey: 'porygon_ai_api_key',
  };

  // Idle lifetime of the operator token. Each authorised request slides it
  // forward, so an operator actively working is never interrupted.
  var OPERATOR_TOKEN_TTL_MS = 30 * 60 * 1000;

  // Storage access can throw: Safari private mode, a disabled-storage policy,
  // or a sandboxed frame. A credential store that throws would take the whole
  // console down with it, so every access degrades to "nothing stored".
  function safely(fn, fallback) {
    try {
      return fn();
    } catch (error) {
      return fallback;
    }
  }

  function createCredentialStore(options) {
    var session = options && options.session;
    var persistent = options && options.persistent;
    var now = (options && options.now) || function () { return Date.now(); };

    function key(name) {
      return PREFIX + name;
    }

    function read(name) {
      if (!session) return null;
      var raw = safely(function () { return session.getItem(key(name)); }, null);
      if (!raw) return null;
      var entry = safely(function () { return JSON.parse(raw); }, null);
      if (!entry || typeof entry.value !== 'string' || !entry.value) {
        clear(name);
        return null;
      }
      if (typeof entry.expiresAt === 'number' && entry.expiresAt <= now()) {
        clear(name);
        return null;
      }
      return entry;
    }

    function write(name, entry) {
      if (!session) return;
      safely(function () { session.setItem(key(name), JSON.stringify(entry)); });
    }

    function get(name) {
      var entry = read(name);
      return entry ? entry.value : '';
    }

    // ttlMs null or undefined: lives until the tab closes, with no idle limit.
    function set(name, value, ttlMs) {
      var text = typeof value === 'string' ? value.trim() : '';
      if (!text) {
        clear(name);
        return;
      }
      var hasTtl = typeof ttlMs === 'number' && ttlMs > 0;
      write(name, {
        value: text,
        ttlMs: hasTtl ? ttlMs : null,
        expiresAt: hasTtl ? now() + ttlMs : null,
      });
    }

    // Slide an idle-expiring credential forward on use. A no-op for a
    // credential with no TTL or nothing stored.
    function touch(name) {
      var entry = read(name);
      if (!entry || typeof entry.ttlMs !== 'number') return;
      entry.expiresAt = now() + entry.ttlMs;
      write(name, entry);
    }

    function expiresAt(name) {
      var entry = read(name);
      return entry && typeof entry.expiresAt === 'number' ? entry.expiresAt : null;
    }

    function clear(name) {
      if (!session) return;
      safely(function () { session.removeItem(key(name)); });
    }

    // Move a credential out of persistent storage. The persistent copy is
    // always deleted -- that is the point -- but an existing session value
    // wins over it, so a newer token is never replaced by a stale one.
    function migrateLegacy(name, legacyKey, ttlMs) {
      if (!persistent) return false;
      var legacy = safely(function () { return persistent.getItem(legacyKey); }, null);
      if (!legacy) return false;
      safely(function () { persistent.removeItem(legacyKey); });
      if (!get(name)) set(name, legacy, ttlMs);
      return true;
    }

    return {
      get: get,
      set: set,
      touch: touch,
      clear: clear,
      expiresAt: expiresAt,
      migrateLegacy: migrateLegacy,
    };
  }

  return {
    createCredentialStore: createCredentialStore,
    LEGACY_KEYS: LEGACY_KEYS,
    OPERATOR_TOKEN_TTL_MS: OPERATOR_TOKEN_TTL_MS,
  };
});
