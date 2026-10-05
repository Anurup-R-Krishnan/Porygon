// Keyboard and screen-reader support for the operator console.
//
// The console's primary navigation was a row of plain buttons: reachable with
// Tab, but announcing nothing about which view was showing, and with none of
// the arrow-key movement the ARIA tab pattern defines. Its six modals -- among
// them the one that collects the operator token before containment -- had no
// dialog role, no focus trap, and no focus restoration, so Tab walked out of
// an open modal into the page behind it, and closing one dropped focus on
// <body>. See plans/040-console-feature-depth.md.
//
// Loaded as a plain script by index.html (window.PorygonA11y) and as CommonJS
// by the node:test suite in dashboard/tests/.
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.PorygonA11y = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var FOCUSABLE = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled]):not([type="hidden"])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
  ].join(',');

  // Next index when Tab wraps inside a dialog. `current` of -1 means focus is
  // not inside the dialog at all, which sends it to the first (or, with Shift,
  // the last) element.
  function cycleIndex(current, count, backwards) {
    if (count <= 0) return -1;
    if (current < 0) return backwards ? count - 1 : 0;
    return backwards ? (current - 1 + count) % count : (current + 1) % count;
  }

  // ARIA tab pattern: Left/Right move between tabs and wrap, Home/End jump to
  // the ends. Anything else returns null so the key is left alone.
  function tabKeyTarget(key, current, count) {
    if (count <= 0) return null;
    switch (key) {
      case 'ArrowRight': return (current + 1) % count;
      case 'ArrowLeft': return (current - 1 + count) % count;
      case 'Home': return 0;
      case 'End': return count - 1;
      default: return null;
    }
  }

  // Open traps, innermost last. Only the innermost handles Tab, so a token
  // prompt opened over another dialog is not fought over by both.
  var stack = [];

  function createFocusTrap(container, doc) {
    var previous = null;

    function focusables() {
      return Array.prototype.filter.call(container.querySelectorAll(FOCUSABLE), function (el) {
        // Elements hidden by x-show (display:none) have no client rects.
        return el.getClientRects().length > 0;
      });
    }

    function onKeydown(event) {
      if (event.key !== 'Tab' || stack[stack.length - 1] !== trap) return;
      var items = focusables();
      if (!items.length) {
        event.preventDefault();
        if (typeof container.focus === 'function') container.focus();
        return;
      }
      var index = items.indexOf(doc.activeElement);
      // Let the browser move focus between interior elements itself; step in
      // only at the edges, or when focus has somehow left the dialog.
      var atEdge = event.shiftKey ? index === 0 : index === items.length - 1;
      if (index === -1 || atEdge) {
        event.preventDefault();
        items[cycleIndex(index, items.length, event.shiftKey)].focus();
      }
    }

    var trap = {
      activate: function () {
        if (stack.indexOf(trap) !== -1) return;
        previous = doc.activeElement;
        stack.push(trap);
        doc.addEventListener('keydown', onKeydown, true);
        var preferred = container.querySelector('[autofocus]') || focusables()[0];
        if (preferred) {
          preferred.focus();
        } else {
          container.setAttribute('tabindex', '-1');
          container.focus();
        }
      },
      deactivate: function () {
        var at = stack.indexOf(trap);
        if (at === -1) return;
        stack.splice(at, 1);
        doc.removeEventListener('keydown', onKeydown, true);
        // Return focus to whatever opened the dialog, if it still exists.
        if (previous && typeof previous.focus === 'function' && doc.contains(previous)) {
          previous.focus();
        }
        previous = null;
      },
      isActive: function () { return stack.indexOf(trap) !== -1; },
    };
    return trap;
  }

  function _resetForTests() { stack.length = 0; }

  return {
    FOCUSABLE: FOCUSABLE,
    cycleIndex: cycleIndex,
    tabKeyTarget: tabKeyTarget,
    createFocusTrap: createFocusTrap,
    _resetForTests: _resetForTests,
  };
});
