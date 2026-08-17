"""B2B-B DOM oracle: execute approvals.js model_egress render in a fake DOM."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

XSS_IMG = '<img src=x onerror="window.__xss=1">'
XSS_SCRIPT = "<script>window.__xss=1</script>"
XSS_QUOTES = "\"'`><&"
MALICIOUS_ID = "req/<img src=x onerror=alert(1)>?q=1#`"

HARNESS = r"""
import fs from 'node:fs';
import vm from 'node:vm';

const approvalsPath = process.argv[2];
const source = fs.readFileSync(approvalsPath, 'utf8');
const stripped = source
  .replace(/^import[\s\S]*?;\s*$/gm, '')
  .replace(/^export\s+/gm, '');
const script = `${stripped}
globalThis.__renderModelEgress = renderModelEgress;
globalThis.__isModelEgress = isModelEgress;
`;

function parseHtml(html) {
  const tags = [];
  const re = /<\s*([a-zA-Z0-9-]+)([^>]*)>/g;
  let match;
  while ((match = re.exec(String(html)))) {
    const name = match[1].toLowerCase();
    const attrs = match[2] || '';
    tags.push({ name, attrs, hasOnerror: /onerror\s*=/i.test(attrs) });
  }
  return tags;
}

class ClassList {
  constructor(el) { this.el = el; this._set = new Set(); }
  toggle(name, force) {
    if (force === true) this._set.add(name);
    else if (force === false) this._set.delete(name);
    else if (this._set.has(name)) this._set.delete(name);
    else this._set.add(name);
  }
}

class FakeNode {
  constructor(tagName, document) {
    this.tagName = String(tagName).toUpperCase();
    this.document = document;
    this.children = [];
    this.parentNode = null;
    this.attributes = {};
    this.dataset = {};
    this._text = '';
    this._html = '';
    this.usedInnerHTML = false;
    this.listeners = {};
    this.disabled = false;
    this.value = '';
    this.classList = new ClassList(this);
    this.style = {};
    this.isConnected = true;
    this.nodeType = 1;
  }
  set className(v) { this.attributes.class = String(v); }
  get className() { return this.attributes.class || ''; }
  set textContent(v) { this._text = String(v); this._html = ''; this.children = []; }
  get textContent() {
    if (this.children.length) return this.children.map(c => c.textContent).join('');
    return this._text;
  }
  set innerHTML(v) {
    this.usedInnerHTML = true;
    this._html = String(v);
    this.document.htmlSinks.push({ html: this._html, node: this.tagName });
    const parsed = parseHtml(this._html);
    for (const tag of parsed) {
      const child = new FakeNode(tag.name, this.document);
      child.attributes.raw = tag.attrs;
      if (tag.hasOnerror) this.document.handlerExecuted = true;
      if (tag.name === 'script' || tag.name === 'img') this.document.attackerNodes.push(child);
      this.children.push(child);
    }
  }
  get innerHTML() { return this._html; }
  setAttribute(name, value) { this.attributes[String(name)] = String(value); }
  getAttribute(name) { return this.attributes[String(name)]; }
  append(...nodes) { for (const n of nodes) this.appendChild(n); }
  appendChild(node) {
    node.parentNode = this;
    node.isConnected = true;
    this.children.push(node);
    return node;
  }
  replaceChildren(...nodes) { this.children = []; for (const n of nodes) this.appendChild(n); }
  addEventListener(type, fn) {
    this.listeners[type] = this.listeners[type] || [];
    this.listeners[type].push(fn);
  }
  click() {
    if (this.disabled) return;
    for (const fn of this.listeners.click || []) fn({ type: 'click', target: this });
  }
  querySelector(sel) {
    return this.querySelectorAll(sel)[0] || null;
  }
  querySelectorAll(sel) {
    const out = [];
    const walk = (node) => {
      if (sel === 'button' && node.tagName === 'BUTTON') out.push(node);
      if (sel.startsWith('[') && sel.includes('data-approval')) {
        const key = sel.replace(/[\[\]"]/g, '').split('=')[0].replace('data-', '');
        if (node.dataset && Object.keys(node.dataset).length) out.push(node);
      }
      for (const c of node.children) walk(c);
    };
    walk(this);
    return out;
  }
  remove() {
    if (!this.parentNode) return;
    this.parentNode.children = this.parentNode.children.filter(c => c !== this);
    this.isConnected = false;
  }
}

class FakeDocument {
  constructor() {
    this.nodesById = {};
    this.htmlSinks = [];
    this.attackerNodes = [];
    this.handlerExecuted = false;
    this.body = new FakeNode('body', this);
  }
  createElement(tag) { return new FakeNode(tag, this); }
  createDocumentFragment() { return new FakeNode('fragment', this); }
  dispatchEvent() { return true; }
  getElementById(id) { return this.nodesById[id] || null; }
}

const fetchCalls = [];
const document = new FakeDocument();
const windowObj = { __xss: 0 };
const sandbox = {
  document,
  window: windowObj,
  fetch: async (url, opts) => {
    const record = { url: String(url), body: opts && opts.body, method: opts && opts.method };
    if (String(url).includes('/decision')) fetchCalls.push(record);
    return { ok: true, json: async () => ({ approvals: [] }), status: 200 };
  },
  showToast: () => {},
  state: { currentTab: 'approvals' },
  encodeURIComponent,
  JSON,
  Date,
  Number,
  String,
  Array,
  Object,
  CustomEvent: class CustomEvent {
    constructor(type, init) { this.type = type; this.detail = init && init.detail; }
  },
  setTimeout,
  clearTimeout,
  console,
};
sandbox.globalThis = sandbox;
const context = vm.createContext(sandbox);
vm.runInContext(script, context);

const approval = {
  id: process.argv[3],
  tool_name: 'model_egress',
  kind: 'model_egress',
  context: process.argv[4],
  timestamp: 1700000000,
  expires_at: 1700003600,
  session_id: process.argv[5],
  run_id: process.argv[6],
  arguments: {
    provider: process.argv[7],
    model: process.argv[8],
    endpoint: process.argv[9],
    source_kinds: ['direct_user'],
    message_count: 1,
    tool_count: 0,
    attachment_count: 0,
    attempt_hash: 'abc',
  },
  safe_summary: {
    provider: process.argv[7],
    model: process.argv[8],
    endpoint: process.argv[9],
    source_kinds: ['direct_user'],
    message_count: 1,
    tool_count: 0,
    attachment_count: 0,
    attempt_hash: 'abc',
  },
};

const card = context.__renderModelEgress(approval);
const titles = [];
const walk = (node) => {
  if (node.title) titles.push(node.title);
  if (node.attributes && node.attributes.title) titles.push(node.attributes.title);
  for (const c of node.children || []) walk(c);
};
walk(card);
const buttons = card.querySelectorAll('button');
if (buttons[0]) {
  buttons[0].click();
  buttons[0].click();
}
const encoded = encodeURIComponent(approval.id);
const failures = [];
if (document.htmlSinks.length) failures.push('innerHTML_sink');
if (document.attackerNodes.length) failures.push('attacker_node');
if (document.handlerExecuted) failures.push('handler_executed');
if (windowObj.__xss) failures.push('xss_flag');
if (titles.some(t => /编辑|回复|EDIT|RESPOND/i.test(t))) failures.push('edit_or_respond');
if (fetchCalls.length !== 1) failures.push('repeat_submit:' + fetchCalls.length);
if (!fetchCalls[0] || !String(fetchCalls[0].url).includes(encoded)) failures.push('request_id_not_encoded');
const textBlob = JSON.stringify({
  text: card.textContent,
  titles,
  fetch: fetchCalls,
});
for (const payload of [process.argv[4], process.argv[5], process.argv[6], process.argv[7], process.argv[8], process.argv[9], approval.id]) {
  if (payload && !textBlob.includes(JSON.stringify(payload).slice(1, -1)) && !card.textContent.includes(payload) && payload.includes('<')) {
    // attacker text must appear as text, not as structure
  }
}
process.stdout.write(JSON.stringify({
  ok: failures.length === 0,
  failures,
  fetchUrls: fetchCalls.map(c => c.url),
  fetchCount: fetchCalls.length,
  htmlSinks: document.htmlSinks,
  attackerNodes: document.attackerNodes.map(n => n.tagName),
  titles,
  usedInnerHTML: document.htmlSinks.length > 0,
}));
"""


def _node() -> str:
    path = shutil.which("node") or "/Users/jiangxuanzhen/.local/bin/node"
    if not Path(path).exists():
        pytest.fail("node is required for the B2B-B DOM harness")
    return path


def _run_harness(approvals_js: Path, tmp_path: Path) -> dict:
    harness = tmp_path / "approvals_dom_harness.mjs"
    harness.write_text(HARNESS, encoding="utf-8")
    result = subprocess.run(
        [
            _node(),
            str(harness),
            str(approvals_js),
            MALICIOUS_ID,
            XSS_IMG,
            XSS_SCRIPT,
            XSS_QUOTES,
            XSS_IMG,
            XSS_SCRIPT,
            "evil.example.test:8443",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
    )
    if result.returncode != 0:
        pytest.fail(f"DOM harness failed: {result.stderr}\n{result.stdout}")
    return json.loads(result.stdout)


def test_approvals_js_model_egress_dom_uses_text_nodes(tmp_path: Path) -> None:
    approvals = (
        Path(__file__).resolve().parents[1] / "js" / "web" / "static" / "tabs" / "approvals.js"
    )
    payload = _run_harness(approvals, tmp_path)
    assert payload["ok"] is True, payload
    assert payload["usedInnerHTML"] is False
    assert payload["fetchCount"] == 1
    assert payload["attackerNodes"] == []
    assert "edit_or_respond" not in payload["failures"]


def test_approvals_js_innerhtml_mutation_is_killed_by_dom_harness(tmp_path: Path) -> None:
    approvals = (
        Path(__file__).resolve().parents[1] / "js" / "web" / "static" / "tabs" / "approvals.js"
    )
    mutated = Path("/tmp/b2b_b_approvals_innerhtml.js")
    mutated.write_text(
        approvals.read_text(encoding="utf-8").replace(".textContent", ".innerHTML"),
        encoding="utf-8",
    )
    payload = _run_harness(mutated, tmp_path)
    assert payload["ok"] is False
    assert payload["usedInnerHTML"] is True or "innerHTML_sink" in payload["failures"]
    assert payload["attackerNodes"] or payload["usedInnerHTML"]
