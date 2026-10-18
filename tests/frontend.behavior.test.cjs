const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname, '../app/static/app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../app/static/index.html'), 'utf8');
const ids = [...html.matchAll(/id="([^"]+)"/g)].map((match) => match[1]);
const event = (id, decision = 'allow', agent_id = null) => ({ id, decision, agent_id, action: { action_type: 'read_file', target: '/workspace/file' }, timestamp: new Date().toISOString(), risk_score: 4 });
const snapshot = (events = [], rules = [], captures = []) => ({ events, incidents: [], immunity_rules: rules, honeyworld: { captured_actions: captures } });
const response = (value) => ({ ok: true, json: async () => value });
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };

function boot({ initial = snapshot(), intent = { goal: 'Canonical goal', allowed_actions: ['read_file'], allowed_targets: ['/workspace/'], denied_targets: ['/workspace/.env'], allow_network: false } } = {}) {
  const calls = [];
  const queued = new Map();
  const intervals = [];
  let document;
  class Element {
    constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = {}; this.dataset = {}; this.style = { setProperty() {} }; this.attributes = {}; this.className = ''; this.value = ''; this.checked = false; this.hidden = false; this.disabled = false; this._text = ''; this.parentNode = null; this.classList = { add: (name) => { this.className = [...new Set([...this.className.split(/\s+/), name])].join(' ').trim(); }, remove: (name) => { this.className = this.className.split(/\s+/).filter((part) => part !== name).join(' '); }, contains: (name) => this.className.split(/\s+/).includes(name), toggle: (name, enabled) => { if (enabled) this.classList.add(name); else this.classList.remove(name); } }; }
    set textContent(value) { this.replaceChildren(); this._text = String(value ?? ''); }
    get textContent() { return this._text + this.children.map((child) => child.textContent).join(''); }
    append(...children) { for (const child of children) { child.parentNode = this; this.children.push(child); } }
    appendChild(child) { this.append(child); return child; }
    prepend(child) { child.parentNode = this; this.children.unshift(child); }
    replaceChildren(...children) { this.children.forEach((child) => { child.parentNode = null; }); this.children = []; this._text = ''; this.append(...children); }
    addEventListener(type, callback, capture = false) { (this.listeners[type] ||= []).push({ callback, capture }); }
    fire(type, options = {}) { const e = { type, target: this, currentTarget: this, stopped: false, preventDefault() {}, stopImmediatePropagation() { this.stopped = true; }, ...options }; const chain = []; for (let node = this; node; node = node.parentNode) chain.push(node); for (const node of [...chain].reverse()) { for (const handler of node.listeners[type] || []) { if (handler.capture) { handler.callback(e); if (e.stopped) return; } } } for (const node of chain) { for (const handler of node.listeners[type] || []) { if (!handler.capture) { handler.callback(e); if (e.stopped) return; } } } }
    setAttribute(name, value) { this.attributes[name] = value; }
    removeAttribute(name) { delete this.attributes[name]; }
    focus() { document.activeElement = this; }
    closest(selector) { for (let node = this; node; node = node.parentNode) if (selector.startsWith('.') && node.classList.contains(selector.slice(1))) return node; return null; }
    querySelector(selector) { if (selector === '.rule-inventory-head strong') return this.children.find((child) => child.className === 'rule-inventory-head')?.children.find((child) => child.tagName === 'strong'); if (selector === 'button[type="submit"]') return new Element('button'); return null; }
    querySelectorAll() { return []; }
  }
  const elements = Object.fromEntries(ids.map((id) => [id, new Element()]));
  document = { body: new Element('body'), activeElement: null, createElement: (tag) => new Element(tag), createTextNode: (text) => { const node = new Element('#text'); node.textContent = text; return node; }, querySelector: (selector) => selector === '#action-form button[type=submit]' ? new Element('button') : elements[selector.slice(1)], querySelectorAll: (selector) => selector === 'input[name="intent-action"]' || selector === 'input[name="intent-action"]:checked' ? document.actions.filter((input) => !selector.endsWith(':checked') || input.checked) : [], addEventListener() {}, actions: ['read_file', 'write_file', 'run_command', 'http_request', 'github_action'].map((value) => { const input = new Element('input'); input.value = value; return input; }) };
  elements['attack-preset'].value = 'safe-read';
  elements['action-target'].value = '/workspace/README.md';
  const fetch = (url, options = {}) => { calls.push({ url, options }); const entries = queued.get(url); if (entries?.length) { const value = entries.shift(); return value?.promise || Promise.resolve(response(value)); } if (url === '/api/state') return Promise.resolve(response(initial)); if (url === '/api/default-intent') return Promise.resolve(response(intent)); return Promise.resolve(response({})); };
  class EventSource { constructor(url) { this.url = url; this.listeners = {}; EventSource.instance = this; } addEventListener(name, listener) { this.listeners[name] = listener; } emit(name, data) { this.listeners[name]({ data: JSON.stringify(data) }); } close() {} }
  vm.runInNewContext(script, { document, window: { setInterval: (fn, ms) => { intervals.push({ fn, ms }); return intervals.length; }, setTimeout: () => 1, clearTimeout() {}, clearInterval() {} }, fetch, EventSource, navigator: {}, FormData: class {}, console });
  return { elements, document, calls, intervals, source: EventSource.instance, queue(url, value) { (queued.get(url) || queued.set(url, []).get(url)).push(value); }, tick: async () => { intervals[0].fn(); await flush(); } };
}

test('reset clears every panel immediately, closes drawer, refetches, and ignores stale response', async () => {
  const app = boot({ initial: snapshot([event('old', 'quarantine')], [{ id: 'R1', enabled: true }], [{ action_type: 'read_file' }]) });
  await flush();
  app.elements.timeline.children[0].fire('click');
  assert.equal(app.elements['event-drawer'].classList.contains('open'), true);
  const pending = deferred(); app.queue('/api/state', pending);
  app.source.emit('reset', { reason: 'board cleared' });
  assert.equal(app.elements['event-count'].textContent, '0 EVENTS');
  assert.equal(app.elements['rule-count'].textContent, '0 RULES');
  assert.equal(app.elements['capture-count'].textContent, '0');
  assert.equal(app.elements['latest-badge'].textContent, 'WAITING');
  assert.equal(app.elements['quarantine-comparison'].hidden, true);
  assert.equal(app.elements['with-action'].textContent, 'Awaiting decision');
  assert.equal(app.elements['event-drawer'].classList.contains('open'), false);
  app.source.emit('audit_event', event('stale'));
  assert.equal(app.elements['event-count'].textContent, '0 EVENTS');
  pending.resolve(response(snapshot())); await flush();
  assert.equal(app.calls.filter((call) => call.url === '/api/state').length, 2);
  assert.equal(app.calls.some((call) => call.url === '/api/events'), false);
});

test('healthy SSE still reconciles every three seconds; shorter state clears then rereads', async () => {
  const app = boot(); await flush(); app.source.onopen();
  app.source.emit('audit_event', event('one'));
  app.source.emit('audit_event', event('two'));
  assert.equal(app.elements['event-count'].textContent, '2 EVENTS');
  app.queue('/api/state', snapshot([event('canonical')]));
  const reread = deferred(); app.queue('/api/state', reread);
  assert.equal(app.intervals[0].ms, 3000);
  const ticking = app.tick(); await flush();
  assert.equal(app.elements['event-count'].textContent, '0 EVENTS');
  reread.resolve(response(snapshot([event('canonical')]))); await ticking; await flush();
  assert.equal(app.elements['event-count'].textContent, '1 EVENT');
  assert.equal(app.elements.timeline.children.length, 1);
});

test('a pre-reset state request cannot restore stale events after the reset refetch', async () => {
  const app = boot(); await flush();
  const stale = deferred(); app.queue('/api/state', stale);
  app.intervals[0].fn(); await flush();
  app.queue('/api/state', snapshot());
  app.source.emit('reset', {}); await flush();
  stale.resolve(response(snapshot([event('obsolete')]))); await flush();
  assert.equal(app.elements['event-count'].textContent, '0 EVENTS');
  assert.equal(app.elements.timeline.children[0].textContent.includes('No policy decisions yet'), true);
});

test('own demo SSE reset still reconciles and reports completion from its authoritative events', async () => {
  const app = boot({ initial: snapshot([event('previous')]) }); await flush();
  const post = deferred();
  const resetRead = deferred();
  const steps = [event('demo-allow'), event('demo-quarantine', 'quarantine'), event('demo-block', 'block')];
  app.queue('/api/demo', post);
  app.queue('/api/state', resetRead);
  app.elements['run-demo-button'].fire('click'); await flush();
  app.source.emit('reset', {});
  assert.equal(app.elements['event-count'].textContent, '0 EVENTS');
  app.queue('/api/state', snapshot(steps));
  post.resolve(response({ status: 'complete', steps: steps.map((item) => ({ event: item })), state: snapshot(steps) }));
  await flush(); await flush();
  assert.equal(app.elements['event-count'].textContent, '3 EVENTS');
  assert.equal(app.elements['action-status'].textContent, 'Demo complete: allow → quarantine → block.');
  assert.equal(app.elements.toast.textContent, 'Demo sequence complete. Three decisions recorded.');
  resetRead.resolve(response(snapshot())); await flush();
  assert.equal(app.elements['event-count'].textContent, '3 EVENTS');
});

test('rule toggle PATCH and delete DELETE refresh authoritative rules', async () => {
  const app = boot({ initial: snapshot([], [{ id: 'rule-1', enabled: true }]) }); await flush();
  const card = app.elements['rules-list'].children[0];
  const actions = card.children.find((child) => child.className === 'rule-actions');
  const checkbox = actions.children[0].children[0]; checkbox.checked = false;
  app.queue('/api/rules/rule-1', { id: 'rule-1', enabled: false });
  app.queue('/api/state', snapshot([], [{ id: 'rule-1', enabled: false }]));
  checkbox.fire('change'); await flush(); await flush();
  assert.equal(app.calls.at(-2).options.method, 'PATCH');
  assert.equal(JSON.parse(app.calls.at(-2).options.body).enabled, false);
  assert.equal(app.elements['rules-list'].children[0].classList.contains('inactive'), true);
  app.queue('/api/rules/rule-1', {}); app.queue('/api/state', snapshot());
  const current = app.elements['rules-list'].children[0];
  current.children.find((child) => child.className === 'rule-actions').children[1].fire('click'); await flush(); await flush();
  assert.equal(app.calls.at(-2).options.method, 'DELETE');
  assert.equal(app.elements['rule-count'].textContent, '0 RULES');
});

test('canonical default populates boot and button exactly; preset and drawer use top-level identity', async () => {
  const app = boot(); await flush();
  assert.equal(app.elements['denied-paths'].value, '/workspace/.env');
  assert.equal(app.elements['intent-goal'].value, 'Canonical goal');
  assert.equal(app.elements['attack-preset'].children.find((option) => option.value === 'safe-write').textContent.includes('Write outside read-only intent'), true);
  const custom = { goal: 'New canonical', allowed_actions: ['write_file'], allowed_targets: ['/project/'], denied_targets: [], allow_network: true };
  app.queue('/api/default-intent', custom); app.elements['default-intent'].fire('click'); await flush();
  assert.equal(app.elements['denied-paths'].value, '');
  assert.equal(app.elements['intent-goal'].value, 'New canonical');
  assert.equal(app.document.actions[1].checked, true);
  const supplied = event('supplied', 'allow', '<agent-7>'); supplied.action.agent_id = 'legacy';
  app.source.emit('audit_event', supplied);
  app.elements.timeline.children[0].fire('click');
  assert.equal(app.elements['drawer-body'].children[0].textContent.includes('<agent-7>'), true);
  assert.equal(app.elements['drawer-body'].children[0].textContent.includes('legacy'), false);
  app.source.emit('audit_event', event('missing'));
  app.elements.timeline.children[0].fire('click');
  assert.equal(app.elements['drawer-body'].children[0].textContent.includes('Not supplied'), true);
});
