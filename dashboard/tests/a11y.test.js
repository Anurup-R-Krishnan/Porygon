// node --test 'dashboard/tests/*.test.js'   (or: make verify-unit)
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { cycleIndex, tabKeyTarget, createFocusTrap, _resetForTests } = require('../src/a11y.js');

// A minimal DOM: enough of document and elements for the trap's contract.
function fakeDocument() {
  const listeners = [];
  const doc = {
    activeElement: null,
    nodes: new Set(),
    addEventListener: (type, fn) => listeners.push({ type, fn }),
    removeEventListener: (type, fn) => {
      const i = listeners.findIndex((l) => l.type === type && l.fn === fn);
      if (i !== -1) listeners.splice(i, 1);
    },
    contains: (node) => doc.nodes.has(node),
    press(key, shiftKey = false) {
      const event = { key, shiftKey, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
      for (const l of [...listeners]) if (l.type === 'keydown') l.fn(event);
      return event;
    },
    listenerCount: () => listeners.length,
  };
  return doc;
}

function element(doc, name, { visible = true } = {}) {
  const el = {
    name,
    attributes: {},
    focus() { doc.activeElement = el; },
    getClientRects: () => (visible ? [{}] : []),
    setAttribute(k, v) { el.attributes[k] = v; },
  };
  doc.nodes.add(el);
  return el;
}

function container(doc, children, { autofocus = null } = {}) {
  const el = element(doc, 'container');
  el.querySelectorAll = () => children;
  el.querySelector = (selector) => (selector === '[autofocus]' ? autofocus : null);
  return el;
}

test.beforeEach(() => _resetForTests());

test('cycleIndex wraps in both directions and recovers escaped focus', () => {
  assert.equal(cycleIndex(0, 3, false), 1);
  assert.equal(cycleIndex(2, 3, false), 0);
  assert.equal(cycleIndex(0, 3, true), 2);
  assert.equal(cycleIndex(-1, 3, false), 0);
  assert.equal(cycleIndex(-1, 3, true), 2);
  assert.equal(cycleIndex(0, 0, false), -1);
});

test('tab keys follow the ARIA tab pattern and ignore everything else', () => {
  assert.equal(tabKeyTarget('ArrowRight', 6, 7), 0, 'wraps forward');
  assert.equal(tabKeyTarget('ArrowLeft', 0, 7), 6, 'wraps backward');
  assert.equal(tabKeyTarget('Home', 4, 7), 0);
  assert.equal(tabKeyTarget('End', 1, 7), 6);
  assert.equal(tabKeyTarget('Enter', 1, 7), null);
  assert.equal(tabKeyTarget('ArrowDown', 1, 7), null);
});

test('opening a dialog focuses its first focusable element', () => {
  const doc = fakeDocument();
  const opener = element(doc, 'opener');
  opener.focus();
  const [a, b] = [element(doc, 'a'), element(doc, 'b')];
  createFocusTrap(container(doc, [a, b]), doc).activate();
  assert.equal(doc.activeElement, a);
});

test('an [autofocus] element wins over document order', () => {
  const doc = fakeDocument();
  const [a, b] = [element(doc, 'a'), element(doc, 'b')];
  createFocusTrap(container(doc, [a, b], { autofocus: b }), doc).activate();
  assert.equal(doc.activeElement, b);
});

test('Tab wraps from last to first and Shift+Tab from first to last', () => {
  const doc = fakeDocument();
  const [a, b, c] = [element(doc, 'a'), element(doc, 'b'), element(doc, 'c')];
  createFocusTrap(container(doc, [a, b, c]), doc).activate();
  c.focus();
  assert.equal(doc.press('Tab').defaultPrevented, true);
  assert.equal(doc.activeElement, a);
  assert.equal(doc.press('Tab', true).defaultPrevented, true);
  assert.equal(doc.activeElement, c);
});

test('interior Tab presses are left to the browser', () => {
  const doc = fakeDocument();
  const [a, b, c] = [element(doc, 'a'), element(doc, 'b'), element(doc, 'c')];
  createFocusTrap(container(doc, [a, b, c]), doc).activate();
  b.focus();
  assert.equal(doc.press('Tab').defaultPrevented, false);
  assert.equal(doc.press('Tab', true).defaultPrevented, false);
});

test('focus that escaped the dialog is pulled back in', () => {
  const doc = fakeDocument();
  const outside = element(doc, 'outside');
  const [a, b] = [element(doc, 'a'), element(doc, 'b')];
  createFocusTrap(container(doc, [a, b]), doc).activate();
  outside.focus();
  doc.press('Tab');
  assert.equal(doc.activeElement, a);
});

test('elements hidden by x-show are skipped', () => {
  const doc = fakeDocument();
  const a = element(doc, 'a');
  const hidden = element(doc, 'hidden', { visible: false });
  const c = element(doc, 'c');
  createFocusTrap(container(doc, [a, hidden, c]), doc).activate();
  c.focus();
  doc.press('Tab');
  assert.equal(doc.activeElement, a, 'wraps past the hidden element');
});

test('a dialog with nothing focusable takes focus itself', () => {
  const doc = fakeDocument();
  const box = container(doc, []);
  createFocusTrap(box, doc).activate();
  assert.equal(doc.activeElement, box);
  assert.equal(box.attributes.tabindex, '-1');
});

test('closing restores focus to the opener and removes the listener', () => {
  const doc = fakeDocument();
  const opener = element(doc, 'opener');
  opener.focus();
  const trap = createFocusTrap(container(doc, [element(doc, 'a')]), doc);
  trap.activate();
  assert.equal(doc.listenerCount(), 1);
  trap.deactivate();
  assert.equal(doc.activeElement, opener);
  assert.equal(doc.listenerCount(), 0);
  assert.equal(trap.isActive(), false);
});

test('focus is not restored to an opener that has left the document', () => {
  const doc = fakeDocument();
  const opener = element(doc, 'opener');
  opener.focus();
  const a = element(doc, 'a');
  const trap = createFocusTrap(container(doc, [a]), doc);
  trap.activate();
  doc.nodes.delete(opener);
  trap.deactivate();
  assert.equal(doc.activeElement, a);
});

test('stacked dialogs: only the innermost traps Tab, and closing it returns focus inside the outer one', () => {
  const doc = fakeDocument();
  const [o1, o2] = [element(doc, 'outer1'), element(doc, 'outer2')];
  const outer = createFocusTrap(container(doc, [o1, o2]), doc);
  outer.activate();
  o2.focus();

  const [i1, i2] = [element(doc, 'inner1'), element(doc, 'inner2')];
  const inner = createFocusTrap(container(doc, [i1, i2]), doc);
  inner.activate();
  i2.focus();
  doc.press('Tab');
  assert.equal(doc.activeElement, i1, 'the inner dialog owns Tab; the outer must not pull focus away');

  inner.deactivate();
  assert.equal(doc.activeElement, o2, 'focus returns to the element in the outer dialog that opened the inner one');
  o2.focus();
  doc.press('Tab');
  assert.equal(doc.activeElement, o1, 'the outer dialog traps again once the inner one closes');
});

test('activate and deactivate are idempotent', () => {
  const doc = fakeDocument();
  const trap = createFocusTrap(container(doc, [element(doc, 'a')]), doc);
  trap.activate();
  trap.activate();
  assert.equal(doc.listenerCount(), 1);
  trap.deactivate();
  trap.deactivate();
  assert.equal(doc.listenerCount(), 0);
});
