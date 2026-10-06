// URL routing for the operator console.
//
// The console wrote the active tab into location.hash on every switch but
// never listened for the hash changing, so the browser's Back button changed
// the URL and left the view where it was. And there was no way to link to a
// particular incident: the Pipeline view always opened on whichever incident
// was newest. Routes are now `#<tab>` or `#pipeline/<incident_id>`, and the
// console applies them on load and on history navigation.
//
// Loaded as a plain script by index.html (window.PorygonRoute) and as CommonJS
// by the node:test suite in dashboard/tests/.
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.PorygonRoute = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var TABS = ['overview', 'pathway', 'telemetry', 'anomalies', 'incidents', 'pipeline', 'vulnerabilities', 'simulator'];
  var DEFAULT_TAB = 'overview';

  // An incident id ends up in a fetch path (/api/v1/incidents/<id>), so a
  // value taken from the URL is held to the shape ids actually have rather
  // than passed through. Anything else is dropped, not encoded.
  var INCIDENT_ID = /^[A-Za-z0-9][A-Za-z0-9-]{7,63}$/;

  function parseRoute(hash) {
    var raw = typeof hash === 'string' ? hash.replace(/^#/, '') : '';
    var parts = raw.split('/');
    var tab = TABS.indexOf(parts[0]) !== -1 ? parts[0] : DEFAULT_TAB;
    var incidentId = tab === 'pipeline' && parts.length === 2 && INCIDENT_ID.test(parts[1])
      ? parts[1]
      : null;
    return { tab: tab, incidentId: incidentId };
  }

  function formatRoute(route) {
    var tab = route && TABS.indexOf(route.tab) !== -1 ? route.tab : DEFAULT_TAB;
    if (tab === 'pipeline' && route.incidentId && INCIDENT_ID.test(route.incidentId)) {
      return '#pipeline/' + route.incidentId;
    }
    return '#' + tab;
  }

  return {
    TABS: TABS,
    DEFAULT_TAB: DEFAULT_TAB,
    parseRoute: parseRoute,
    formatRoute: formatRoute,
  };
});
