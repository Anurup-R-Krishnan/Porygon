// Scroll reveal: adds `.in` to each `.reveal` element as it enters the
// viewport, using IntersectionObserver rather than a scroll listener.
//
// This was an inline <script> at the end of index.html. The console's
// Content-Security-Policy sets script-src 'self' with no 'unsafe-inline', so
// the browser blocked it and the reveal transitions never ran. Hoisting it to
// its own file keeps the policy strict -- no inline allowance and no script
// hash to keep in sync with the markup. scripts/check_console_supply_chain.py
// asserts index.html contains no inline script so this cannot regress.
(function () {
  'use strict';

  function initReveal() {
    var elements = document.querySelectorAll('.reveal');

    // Without IntersectionObserver the elements would keep their pre-reveal
    // styling forever, so reveal them all rather than hide the console.
    if (typeof IntersectionObserver !== 'function') {
      elements.forEach(function (element) { element.classList.add('in'); });
      return;
    }

    // Honour a reduced-motion preference: reveal immediately instead of
    // animating. The console is an operator tool and must not depend on
    // motion to show its content.
    var reducedMotion = window.matchMedia
      && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reducedMotion) {
      elements.forEach(function (element) { element.classList.add('in'); });
      return;
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });

    elements.forEach(function (element) {
      if (!element.classList.contains('in')) observer.observe(element);
    });
  }

  // app.js re-runs this after its charts render. When this was an inline
  // script initReveal was a global; hoisting it into this closure turned those
  // calls into silent no-ops, so it is exported explicitly. Already-revealed
  // elements are skipped, which makes repeat calls idempotent.
  window.initReveal = initReveal;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initReveal);
  } else {
    // The script is deferred, so DOMContentLoaded may already have fired.
    initReveal();
  }
})();
