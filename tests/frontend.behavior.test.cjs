const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname, '../app/static/app.js'), 'utf8');
const scenarios = JSON.parse(fs.readFileSync(path.join(__dirname, '../app/static/scenarios.json'), 'utf8'));
const names = 'run-demo-button reset-button theme-toggle connection-label request-rate refresh-button demo-bar demo-step demo-next demo-exit summary-line summary-detail event-count decision-filter action-filter search-filter log-body activity-empty empty-demo-button latest-decision latest-risk latest-reason latest-target latest-action finding-list flow-diagram honey-summary capture-list containment-comparison without-action with-action scenario-list run-all-scenarios batch-summary scenario-results scenario-results-body action-form intent-goal allowed-paths denied-paths allow-network default-intent intent-status intent-goal-error action-type action-target action-target-error action-content action-payload action-payload-error evaluate-button action-status safe-fixture malicious-fixture test-result-summary test-result-reason test-result-findings test-result-output rule-count rules-list rules-empty export-audit export-csv export-rules export-incidents export-status report-select incident-preview download-report event-drawer drawer-title drawer-body drawer-close copy-event-json drawer-close-secondary drawer-backdrop toast page-activity page-test page-rules page-exports'.split(' ');
const baseIntent = { goal: 'Read files', allowed_actions: ['read_file'], allowed_targets: ['/workspace/'], denied_targets: [], allow_network: false };
const snapshot = (events = [], rules = [], incidents = [], captures = []) => ({ events, immunity_rules: rules, incidents, honeyworld_captures: captures, honeyworld: { captured_actions: [] } });
const event = (id, decision = 'allow') => ({ id, decision, timestamp: new Date().toISOString(), action: { action_type: 'read_file', target: '/workspace/README.md' }, risk_score: 0, findings: [] });
const ok = (data) => ({ ok: true, json: async () => data, text: async () => typeof data === 'string' ? data : JSON.stringify(data) });
const fail = (message = 'Failed') => ({ ok: false, status: 500, json: async () => ({ detail: message }) });
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const flush = async () => { for (let i = 0; i < 250; i++) await Promise.resolve(); };

function boot({ initial = snapshot(), intent = baseIntent, intentPending = null, confirm = true, storageError = false } = {}) {
  const calls = [], queues = new Map(), intervals = [], downloads = [];
  let document;
  class Element {
    constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = {}; this.dataset = {}; this.attributes = {}; this.style = {}; this.className = ''; this.value = ''; this.hidden = false; this.disabled = false; this.checked = false; this._text = ''; this.parentNode = null; this.isConnected = true; this.classList = { add: (name) => { this.className = [...new Set([...this.className.split(/\s+/), name])].join(' ').trim(); }, remove: (name) => { this.className = this.className.split(/\s+/).filter((part) => part !== name).join(' '); }, contains: (name) => this.className.split(/\s+/).includes(name), toggle: (name, value) => value ? this.classList.add(name) : this.classList.remove(name) }; }
    set textContent(value) { this.replaceChildren(); this._text = String(value ?? ''); }
    get textContent() { return this._text + this.children.map((child) => child.textContent).join(''); }
    append(...children) { for (let child of children) { if (typeof child === 'string') { const text = new Element('#text'); text.textContent = child; child = text; } child.parentNode = this; this.children.push(child); } }
    appendChild(child) { this.append(child); return child; }
    prepend(child) { child.parentNode = this; this.children.unshift(child); }
    replaceChildren(...children) { this.children.forEach((child) => { child.parentNode = null; }); this.children = []; this._text = ''; this.append(...children); }
    addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); }
    fire(type, extra = {}) { const e = { type, target: this, currentTarget: this, preventDefault() {}, stopPropagation() {}, ...extra }; for (const listener of this.listeners[type] || []) listener(e); }
    setAttribute(name, value) { this.attributes[name] = value; }
    removeAttribute(name) { delete this.attributes[name]; }
    focus() { document.activeElement = this; }
    click() { this.fire('click'); if (this.tagName === 'a') downloads.push(this.download); }
    remove() { this.parentNode && (this.parentNode.children = this.parentNode.children.filter((item) => item !== this)); }
    querySelectorAll(tag) { return this.children.flatMap((child) => [child, ...child.querySelectorAll(tag)]).filter((item) => tag === 'input' ? item.tagName === 'input' : tag.includes('button') ? item.tagName === 'button' : tag.includes('summary') ? ['button', 'a', 'summary'].includes(item.tagName) : false); }
    requestSubmit() { this.fire('submit'); }
  }
  const elements = Object.fromEntries(names.map((name) => [name, new Element()]));
  const links = ['activity', 'test', 'rules', 'exports'].map((page) => { const link = new Element('a'); link.dataset.page = page; return link; });
  const actions = ['read_file', 'write_file', 'run_command', 'http_request', 'github_action'].map((value) => { const input = new Element('input'); input.value = value; return input; });
  document = { body: new Element('body'), documentElement: new Element('html'), activeElement: null, shell: new Element('main'), getElementById: (name) => elements[name], createElement: (tag) => new Element(tag), querySelector: (selector) => selector === '.app-shell' ? document.shell : null, querySelectorAll: (selector) => selector === '[data-page]' ? links : selector === 'input[name="intent-action"]:checked' ? actions.filter((item) => item.checked) : selector === 'input[name="intent-action"]' ? actions : [], addEventListener(type, callback) { (this.listeners[type] ||= []).push(callback); }, listeners: {} };
  elements['action-form'].requestSubmit = () => elements['action-form'].fire('submit');
  elements['event-drawer'].hidden = true; elements['demo-bar'].hidden = true;
  elements['action-type'].value = 'read_file'; elements['action-target'].value = '/workspace/README.md';
  let count = 0;
  const fetch = (url, options = {}) => { calls.push({ url, options }); const queue = queues.get(url); if (queue?.length) { const value = queue.shift(); return value?.promise || Promise.resolve(value?.ok === false ? value : ok(value)); } if (url === '/api/state') return Promise.resolve(ok(initial)); if (url === '/api/default-intent') return intentPending?.promise || Promise.resolve(ok(intent)); if (url === '/static/scenarios.json') return Promise.resolve(ok(scenarios)); if (url === '/api/evaluate') { const action = JSON.parse(options.body).action; const decision = action.target.includes('README') ? 'allow' : action.content?.includes('1gn0re') ? 'block' : action.target.includes('.env') ? 'quarantine' : 'block'; return Promise.resolve(ok({ decision, risk_score: 80, reason: 'Gateway decision', event: { ...event(`e${++count}`, decision), action } })); } return Promise.resolve(ok({})); };
  class EventSource { constructor() { this.listeners = {}; EventSource.instance = this; } addEventListener(name, listener) { this.listeners[name] = listener; } emit(name, value) { this.listeners[name]({ data: JSON.stringify(value) }); } close() {} }
  const window = { setInterval: (fn, ms) => { intervals.push({ fn, ms }); return intervals.length; }, setTimeout: () => 1, clearTimeout() {}, addEventListener() {}, confirm: () => confirm };
  const location = { hash: '' };
  const localStorage = { getItem: () => { if (storageError) throw Error('denied'); return null; }, setItem: () => { if (storageError) throw Error('denied'); } };
  vm.runInNewContext(script, { document, window, location, localStorage, navigator: { clipboard: { writeText: async () => {} } }, URL: { createObjectURL: () => 'blob:test', revokeObjectURL() {} }, Blob, fetch, EventSource, console });
  return { elements, links, document, calls, intervals, downloads, source: EventSource.instance, queue(url, value) { (queues.get(url) || queues.set(url, []).get(url)).push(value); }, tick: async () => { intervals[0].fn(); await flush(); }, fireKey: (extra) => { for (const listener of document.listeners.keydown || []) listener({ preventDefault() {}, ...extra }); } };
}

test('navigation, filtering, keyboard rows and safe event details', async () => {
  const a = boot({ initial: snapshot([event('older'), { ...event('<new>', 'quarantine'), reason: '<img src=x>', agent_id: null }]) }); await flush();
  assert.equal(a.elements['log-body'].children[0].children.length, 6);
  assert.equal(a.elements['log-body'].children[0].children[3].textContent, '/workspace/README.md');
  assert.equal(a.elements['log-body'].children[0].children[3].title, '/workspace/README.md');
  assert.equal(a.elements['log-body'].children[0].children[0].children[0].title.endsWith('ago'), true);
  a.links[1].fire('click'); assert.equal(a.elements['page-test'].hidden, false);
  a.elements['decision-filter'].value = 'allow'; a.elements['decision-filter'].fire('change'); assert.equal(a.elements['log-body'].children.length, 1);
  a.elements['decision-filter'].value = ''; a.elements['decision-filter'].fire('change');
  a.queue('/api/events/%3Cnew%3E', { ...event('<new>', 'quarantine'), reason: '<img src=x>' });
  a.elements['log-body'].children[0].fire('keydown', { key: 'Enter' }); await flush();
  assert.equal(a.calls.some((call) => call.url === '/api/events/%3Cnew%3E'), true);
  assert.equal(a.elements['drawer-body'].children[0].textContent.includes('<img src=x>'), false);
  assert.equal(a.elements['drawer-body'].textContent.includes('quarantined'), true);
  assert.equal(a.elements['drawer-body'].children.some((child) => child.tagName === 'details'), true);
  assert.equal(a.elements['drawer-body'].children.some((child) => child.textContent.includes('Copy')), true);
  assert.equal(a.elements['event-drawer'].attributes['aria-hidden'], 'false');
  assert.equal(a.document.shell.inert, true);
  a.fireKey({ key: 'Escape' }); assert.equal(a.elements['event-drawer'].hidden, true);
  assert.equal(a.elements['event-drawer'].attributes['aria-hidden'], 'true');
  assert.equal(a.document.shell.inert, false);
});

test('SSE reset clears immediately and ignores stale responses; healthy stream still polls at 3s', async () => {
  const a = boot({ initial: snapshot([event('before')], [{ id: 'r1', enabled: true }]) }); await flush();
  const stale = deferred(); a.queue('/api/state', stale); a.intervals[0].fn(); await flush();
  const current = deferred(); a.queue('/api/state', current);
  a.source.emit('reset', {}); assert.equal(a.elements['event-count'].textContent, '0 events'); assert.equal(a.elements['rule-count'].textContent, '0 rules');
  a.source.emit('audit_event', event('late')); assert.equal(a.elements['event-count'].textContent, '0 events');
  current.resolve(ok(snapshot())); await flush(); stale.resolve(ok(snapshot([event('obsolete')]))); await flush();
  assert.equal(a.elements['event-count'].textContent, '0 events'); assert.equal(a.intervals[0].ms, 3000);
  a.source.emit('audit_event', event('fresh')); assert.equal(a.elements['event-count'].textContent, '1 event');
  a.queue('/api/state', snapshot()); a.queue('/api/state', snapshot([event('canonical')])); await a.tick();
  assert.equal(a.elements['event-count'].textContent, '1 event');
});

test('canonical default, editable nested intent, keyboard evaluation and theme storage denial', async () => {
  const a = boot({ storageError: true }); await flush();
  assert.equal(a.elements['intent-goal'].value, 'Read files');
  a.fireKey({ key: 'Enter', ctrlKey: true }); await flush();
  assert.equal(a.calls.filter((call) => call.url === '/api/evaluate').length, 0);
  a.elements['intent-goal'].value = 'Custom'; a.elements['theme-toggle'].fire('click'); assert.equal(a.document.documentElement.dataset.theme, 'dark');
  assert.equal(a.elements['theme-toggle'].attributes['aria-label'], 'Switch to light theme');
  a.links[1].fire('click');
  a.fireKey({ key: 'Enter', ctrlKey: true }); await flush();
  const payload = JSON.parse(a.calls.find((call) => call.url === '/api/evaluate').options.body);
  assert.equal(payload.intent.goal, 'Custom'); assert.equal(payload.action.action_type, 'read_file');
  assert.equal(a.elements['test-result-summary'].textContent.includes('Allowed'), true);
  a.elements['action-target'].value = ''; a.elements['action-target'].fire('input');
  assert.equal(a.elements['evaluate-button'].disabled, true);
  a.elements['default-intent'].fire('click'); await flush(); assert.equal(a.elements['intent-goal'].value, 'Read files');
});

test('boot waits for canonical intent before enabling evaluation', async () => {
  const pending = deferred(); const a = boot({ intentPending: pending }); await flush();
  a.links[1].fire('click');
  assert.equal(a.elements['evaluate-button'].disabled, true);
  a.elements['action-form'].fire('submit'); await flush();
  assert.equal(a.calls.filter((call) => call.url === '/api/evaluate').length, 0);
  pending.resolve(ok(baseIntent)); await flush();
  assert.equal(a.elements['evaluate-button'].disabled, false);
});

test('all fifteen fixtures call the real evaluate API with unique batch fingerprints', async () => {
  const a = boot(); await flush(); a.elements['run-all-scenarios'].fire('click'); await flush();
  assert.equal(a.calls.filter((call) => call.url === '/api/evaluate').length, 15);
  assert.equal(a.elements['scenario-results-body'].children.length, 15);
  assert.equal(a.elements['scenario-results-body'].children[0].children.length, 5);
  assert.equal(a.elements['batch-summary'].textContent.includes('mismatch'), true);
  const first = JSON.parse(a.calls.find((call) => call.url === '/api/evaluate').options.body);
  assert.equal(first.action.content.includes('scenario run'), true);
  a.elements['run-all-scenarios'].fire('click'); await flush();
  const actions = a.calls.filter((call) => call.url === '/api/evaluate').map((call) => JSON.parse(call.options.body).action);
  assert.equal(actions.length, 30); assert.notEqual(actions[0].content, actions[15].content);
  assert.equal(actions[7].target === actions[8].target, false);
});

test('selected fixture shows expected decision before submit and actual result afterward', async () => {
  const a = boot(); await flush();
  const safe = a.elements['scenario-list'].children[0].children[1];
  safe.fire('click');
  assert.equal(a.elements['test-result-summary'].textContent.includes('Expected Allowed · not evaluated yet'), true);
  a.elements['action-form'].fire('submit'); await flush();
  assert.equal(a.elements['test-result-summary'].textContent.includes('Got Allowed'), true);
  assert.equal(a.elements['test-result-summary'].textContent.includes('✓ Match'), true);
  assert.equal(a.elements['test-result-reason'].textContent.includes('Gateway decision'), false);
});

test('fifteen matching API decisions produce the exact completion summary', async () => {
  const a = boot(); await flush();
  scenarios.forEach((fixture, index) => a.queue('/api/evaluate', {
    decision: fixture.expected, risk_score: index, event: event(`fixture-${index}`, fixture.expected),
  }));
  a.elements['run-all-scenarios'].fire('click'); await flush();
  assert.equal(a.elements['batch-summary'].textContent, '15 of 15 matched expected result.');
  assert.equal(a.elements['scenario-results-body'].children.every((row) => row.children[4].textContent === '✓'), true);
});

test('guided demo resets then evaluates exactly four steps without legacy demo endpoint', async () => {
  const a = boot(); await flush(); a.elements['run-demo-button'].fire('click'); await flush();
  assert.equal(a.elements['demo-step'].textContent.includes('Step 1 of 4'), true);
  for (let step = 2; step <= 4; step++) { a.elements['demo-next'].fire('click'); await flush(); assert.equal(a.elements['demo-step'].textContent.includes(`Step ${step} of 4`), true); }
  assert.equal(a.calls.filter((call) => call.url === '/api/evaluate').length, 4);
  assert.equal(a.elements['demo-step'].textContent.includes('Blocked'), true);
  assert.equal(a.calls.some((call) => call.url === '/api/demo'), false);
  const actions = a.calls.filter((call) => call.url === '/api/evaluate').map((call) => JSON.parse(call.options.body).action);
  assert.equal(actions[1].content, actions[2].content); assert.notEqual(actions[2].content, actions[3].content);
  assert.equal(a.elements['page-activity'].hidden, false);
  assert.equal(a.elements['demo-step'].textContent.includes('Gateway decision'), false);
  assert.equal(a.elements['demo-next'].textContent, 'Done');
  assert.equal(a.elements['demo-bar'].hidden, false);
  a.elements['demo-next'].fire('click'); assert.equal(a.elements['demo-bar'].hidden, true);
  a.elements['demo-exit'].fire('click'); assert.equal(a.elements['demo-bar'].hidden, true);
});

test('reset during a pending guided step rejects its stale decision', async () => {
  const a = boot(); await flush();
  a.elements['run-demo-button'].fire('click'); await flush();
  const pending = deferred(); a.queue('/api/evaluate', pending);
  a.elements['demo-next'].fire('click'); await flush();
  a.queue('/api/state', snapshot()); a.elements['reset-button'].fire('click'); await flush();
  pending.resolve(ok({ decision: 'quarantine', event: event('late', 'quarantine') })); await flush();
  assert.equal(a.elements['event-count'].textContent, '0 events');
  assert.equal(a.elements['demo-bar'].hidden, true);
  assert.equal(a.elements['test-result-summary'].textContent, 'No action evaluated.');
});

test('finding-based language and durable capture count never display server flavour', async () => {
  const unsafe = { ...event('unsafe', 'quarantine'), reason: '<raw server flavour>', findings: [{ label: 'secret_to_network', severity: 95, evidence: '<untrusted>' }] };
  const a = boot({ initial: snapshot([unsafe], [], [], [{ action_type: 'read_file', target: '/workspace/.env' }]) }); await flush();
  assert.equal(a.elements['latest-reason'].textContent.includes('Sensitive data was directed'), true);
  assert.equal(a.elements['latest-reason'].textContent.includes('<raw server flavour>'), false);
  assert.equal(a.elements['finding-list'].textContent.includes('Sensitive data was directed'), true);
  assert.equal(a.elements['honey-summary'].textContent.startsWith('1 action captured.'), true);
});

test('rule rollback and confirmed delete refresh authoritative state', async () => {
  const a = boot({ initial: snapshot([], [{ id: 'r1', enabled: true }]) }); await flush();
  const checkbox = a.elements['rules-list'].children[0].children[5].children[0].children[0]; checkbox.checked = false;
  a.queue('/api/rules/r1', fail('Denied')); checkbox.fire('change'); await flush();
  assert.equal(checkbox.checked, true); assert.equal(a.elements.toast.textContent, 'Denied');
  const deleteButton = a.elements['rules-list'].children[0].children[6].children[0];
  a.queue('/api/rules/r1', { status: 'deleted' }); a.queue('/api/state', snapshot()); a.queue('/api/rules', { rules: [] }); deleteButton.fire('click'); await flush();
  assert.equal(a.calls.some((call) => call.url === '/api/rules/r1' && call.options.method === 'DELETE'), true);
  assert.equal(a.elements['rule-count'].textContent, '0 rules');
  const denied = boot({ initial: snapshot([], [{ id: 'r2' }]), confirm: false }); await flush();
  denied.elements['rules-list'].children[0].children[6].children[0].fire('click'); await flush();
  assert.equal(denied.calls.some((call) => call.options.method === 'DELETE'), false);
});

test('successful rule toggle PATCH reconciles the authoritative rule list', async () => {
  const a = boot({ initial: snapshot([], [{ id: 'r3', enabled: true }]) }); await flush();
  const checkbox = a.elements['rules-list'].children[0].children[5].children[0].children[0];
  checkbox.focus();
  checkbox.checked = false; a.queue('/api/rules/r3', { id: 'r3', enabled: false });
  a.queue('/api/state', snapshot([], [{ id: 'r3', enabled: false }]));
  a.queue('/api/rules', { rules: [{ id: 'r3', enabled: false }] });
  checkbox.fire('change'); await flush();
  const patch = a.calls.find((call) => call.url === '/api/rules/r3');
  assert.equal(patch.options.method, 'PATCH');
  assert.equal(JSON.parse(patch.options.body).enabled, false);
  assert.equal(a.calls.some((call) => call.url === '/api/rules'), true);
  assert.equal(a.elements['rules-list'].children[0].children[5].children[0].children[0].checked, false);
  assert.equal(a.document.activeElement.dataset.ruleId, 'r3');
});

test('rules render all seven aligned columns with source, fingerprint copy and matched time', async () => {
  const rule = { id: 'r4', fingerprint: 'deadbeef', source_incident_id: 'incident-1', match_count: 3, last_matched_at: new Date().toISOString(), enabled: true };
  const a = boot({ initial: snapshot([], [rule], [{ id: 'incident-1' }]) }); await flush();
  const row = a.elements['rules-list'].children[0];
  assert.equal(row.children.length, 7);
  assert.equal(row.children[0].textContent.includes('r4'), true);
  assert.equal(row.children[1].textContent.includes('deadbeef'), true);
  assert.equal(row.children[2].children[0].href, '#exports');
  assert.equal(row.children[3].textContent, '3');
  assert.equal(row.children[4].children[0].title.endsWith('ago'), true);
});

test('reset clears Test output and stale drawer while ignoring late response', async () => {
  const a = boot({ initial: snapshot([event('before')]) }); await flush();
  a.links[1].fire('click'); a.elements['action-form'].fire('submit'); await flush();
  assert.equal(a.elements['test-result-summary'].textContent.includes('Allowed'), true);
  const detail = deferred(); a.queue('/api/events/before', detail);
  a.elements['log-body'].children[0].fire('click');
  assert.equal(a.elements['drawer-body'].textContent, 'Loading event details…');
  a.queue('/api/state', snapshot());
  a.source.emit('reset', {}); await flush();
  detail.resolve(ok({ ...event('before'), reason: 'stale' })); await flush();
  assert.equal(a.elements['event-drawer'].hidden, true);
  assert.equal(a.elements['drawer-body'].textContent, '');
  assert.equal(a.elements['test-result-summary'].textContent, 'No action evaluated.');
});

test('manual evaluation cannot overlap and validation details are readable', async () => {
  const a = boot(); await flush(); a.links[1].fire('click');
  const pending = deferred(); a.queue('/api/evaluate', pending);
  a.elements['action-form'].fire('submit'); a.elements['action-form'].fire('submit'); await flush();
  assert.equal(a.calls.filter((call) => call.url === '/api/evaluate').length, 1);
  pending.resolve({ ok: false, status: 422, json: async () => ({ detail: [{ loc: ['body', 'action', 'target'], msg: 'Target is required' }] }) });
  await flush();
  assert.equal(a.elements.toast.textContent, 'action.target: Target is required');
});

test('empty target shows the exact inline validation and keeps Evaluate disabled', async () => {
  const a = boot(); await flush(); a.links[1].fire('click');
  a.elements['action-target'].value = ''; a.elements['action-target'].fire('input');
  assert.equal(a.elements['evaluate-button'].disabled, true);
  a.elements['action-form'].fire('submit'); await flush();
  assert.equal(a.elements['action-target-error'].textContent, 'Enter a target path, command or URL.');
  assert.equal(a.elements['action-target'].attributes['aria-invalid'], 'true');
  assert.equal(a.calls.filter((call) => call.url === '/api/evaluate').length, 0);
});

test('invalid payload shows exact inline validation and does not submit', async () => {
  const a = boot(); await flush(); a.links[1].fire('click');
  a.elements['action-payload'].value = '{invalid';
  a.elements['action-form'].fire('submit'); await flush();
  assert.equal(a.elements['action-payload-error'].textContent, 'Payload must be valid JSON.');
  assert.equal(a.elements['action-payload'].attributes['aria-invalid'], 'true');
  assert.equal(a.calls.filter((call) => call.url === '/api/evaluate').length, 0);
});

test('four exports and incident report preview/download use API bytes', async () => {
  const a = boot({ initial: snapshot([], [], [{ id: 'I-1' }]) }); await flush();
  for (const id of ['export-audit', 'export-csv', 'export-rules', 'export-incidents']) a.elements[id].fire('click'); await flush();
  for (const url of ['/api/export?format=json', '/api/export?format=csv', '/api/rules', '/api/incidents']) assert.equal(a.calls.some((call) => call.url === url), true);
  a.queue('/api/incidents/I-1/report', '# Real report'); a.elements['report-select'].value = 'I-1'; a.elements['report-select'].fire('change'); await flush();
  assert.equal(a.elements['incident-preview'].textContent, '# Real report');
  a.elements['download-report'].fire('click'); assert.equal(a.downloads.some((name) => name === 'bulkhead-incident-I-1.md'), true);
});
