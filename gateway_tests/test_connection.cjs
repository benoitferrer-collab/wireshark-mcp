// Boundary checks for the fetch adapter without external browser dependencies.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function setup() {
    const calls = [];
    const storage = new Map([['pcap-api-access:https://api.example.com', 'owner-token']]);
    const context = {
        URL, Headers, Request, console,
        sessionStorage: { getItem: k => storage.get(k), setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k) },
        document: { createElement: () => ({ addEventListener() {} }), querySelector: () => ({ appendChild() {} }) },
        window: { PCAP_CONFIG: { apiBaseUrl: 'https://api.example.com' }, location: { origin: 'https://ui.example.com', href: 'https://ui.example.com/' },
            fetch: async (input, init) => { calls.push({ input: String(input), init }); return { status: 200 }; } },
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../static/js/connection.js'), 'utf8'), context);
    return { context, calls };
}

test('upload goes directly to backend and keeps original body with authentication', async () => {
    const { context, calls } = setup();
    const body = { capture: 'large-file' };
    await context.window.fetch('/api/upload', { method: 'POST', body });
    assert.equal(calls[0].input, 'https://api.example.com/api/upload');
    assert.equal(calls[0].init.body, body);
    assert.equal(calls[0].init.headers.get('Authorization'), 'Bearer owner-token');
});

test('third-party fetch never receives the backend credential', async () => {
    const { context, calls } = setup();
    await context.window.fetch('https://third-party.example/api/history');
    assert.equal(calls[0].input, 'https://third-party.example/api/history');
    assert.equal(calls[0].init.headers, undefined);
});
