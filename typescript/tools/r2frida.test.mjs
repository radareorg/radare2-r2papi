import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { R2Frida } = require('../async/index.js');

// Deliberately no global r2. Replies cross an async boundary like a remote pipe.
function connection(replies) {
  const calls = [];
  const send = async (kind, command) => {
    calls.push([kind, command]);
    await Promise.resolve();
    assert.ok(Object.hasOwn(replies, command), `Unexpected command: ${command}`);
    return replies[command];
  };
  return {
    calls,
    cmd: (c) => send('cmd', c),
    call: (c) => send('call', c),
    callj: (c) => send('callj', c),
  };
}

test('availability uses the supplied connection and caches only success', async () => {
  const replies = { 'o~frida://': '' };
  const pipe = connection(replies);
  const api = new R2Frida(pipe);
  await assert.rejects(api.checkAvailability(), /no frida session/);
  assert.equal(api.isAvailable, false);
  replies['o~frida://'] = 'frida://123';
  await api.checkAvailability();
  await api.checkAvailability();
  assert.equal(pipe.calls.length, 2);
  const other = new R2Frida(connection({ 'o~frida://': '' }));
  await assert.rejects(other.checkAvailability(), /no frida session/);
});

test('enumeration preserves serialized pointers and platform-specific shapes', async () => {
  // Shapes from r2frida's info/classes.ts, info/index.ts and debug/memory.ts.
  const replies = {
    ':ij': { pid: 123, os: 'linux', modulebase: '0x1000000000000001' },
    ':icj': ['Example', 'Foundation.NSObject'],
    ':icj Example': { '- init': '0x1000000000000001' },
    ':icj com.example.Main': ['public void com.example.Main.run()'],
    ':icj.': ['Example'],
    ':iEj': [{ name: 'main', address: '0x1000000000000001', type: 'function' }],
    ':iij': [{ name: 'unresolved', index: 0, targetModuleName: null }],
    ':isj': [{ name: 'local', address: '0x1234', type: 'absolute', isGlobal: false }],
    ':iej': [{ name: 'entry0', address: '0x1234' }],
    ':dmj': [{ base: '0x1234', size: 4096, protection: 'rw-' }],
    ':dmmj': [{ base: '0x5678', size: 8192, protection: 'r-x', file: { path: '/bin/app', offset: 0, size: 8192 } }],
  };
  const api = new R2Frida(connection(replies));
  for (const [method, command] of [
    ['targetDetails', ':ij'], ['enumerateClasses', ':icj'],
    ['enumerateApplicationClasses', ':icj.'], ['enumerateExports', ':iEj'],
    ['enumerateImports', ':iij'], ['enumerateSymbols', ':isj'],
    ['enumerateEntrypoints', ':iej'], ['enumerateMemoryRanges', ':dmj'],
    ['enumerateMemoryMaps', ':dmmj'],
  ]) {
    assert.deepEqual(await api[method](), replies[command], method);
  }
  assert.deepEqual(await api.enumerateMethods('Example'), replies[':icj Example']);
  assert.deepEqual(await api.enumerateMethods('com.example.Main'), replies[':icj com.example.Main']);
  const other = new R2Frida(connection({ ':icj': [] }));
  assert.deepEqual(await other.enumerateClasses(), []);
});

test('eval and class names use the literal channel; invalid arguments are rejected', async () => {
  const expr = 'console.log("a;b~c"); 42';
  const pipe = connection({ [`: ${expr}`]: '42', ':icj Example;dc': [] });
  const api = new R2Frida(pipe);
  assert.equal(await api.eval(expr), '42');
  await api.enumerateMethods('Example;dc');
  assert.deepEqual(pipe.calls, [['call', `: ${expr}`], ['callj', ':icj Example;dc']]);
  for (const name of ['', 'Example Other', 'Example\n:dc', '\tExample']) {
    await assert.rejects(api.enumerateMethods(name), /single class name/);
  }
  assert.equal(pipe.calls.length, 2);
});

test('continue waits for completion and propagates transport errors', async () => {
  let complete;
  const pending = new Promise((resolve) => { complete = resolve; });
  const api = new R2Frida({ call(command) { assert.equal(command, ':dc'); return pending; } });
  let finished = false;
  const result = api.continue().then(() => { finished = true; });
  await Promise.resolve();
  assert.equal(finished, false);
  complete('');
  await result;
  assert.equal(finished, true);
  const error = new Error('Disconnected');
  const broken = new R2Frida({ call: async () => { throw error; } });
  await assert.rejects(broken.continue(), error);
  const invalidJson = new R2Frida({ callj: async () => JSON.parse('invalid') });
  await assert.rejects(invalidJson.enumerateClasses(), SyntaxError);
});
