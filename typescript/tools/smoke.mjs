#!/usr/bin/env node
/**
 * Smoke test: drive the async API against a real r2 instance opened on a small
 * binary (default /bin/ls, override with argv[2]) and assert the typed outputs
 * carry sane data. Exits non-zero on failure.
 *
 * Requires: r2 on PATH, and `npm run abuild` (or `make build`) to have produced
 * async/*.js. Run with: npm run smoke
 */
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { existsSync } from 'fs';
import { execFileSync } from 'child_process';

const require = createRequire(import.meta.url);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const target = process.argv[2] || '/bin/ls';

const MIN_R2 = [6, 2, 0];
let r2version = null;
try {
  const out = execFileSync(process.env.R2_BIN || 'r2', ['-v'], { encoding: 'utf8' });
  const m = out.match(/(\d+)\.(\d+)\.(\d+)/);
  if (m) r2version = [Number(m[1]), Number(m[2]), Number(m[3])];
} catch {
  console.log('SKIP: r2 not found on PATH (set R2_BIN to override)');
  process.exit(0);
}
if (!r2version || r2version[0] < MIN_R2[0] ||
    (r2version[0] === MIN_R2[0] && (r2version[1] < MIN_R2[1] ||
      (r2version[1] === MIN_R2[1] && r2version[2] < MIN_R2[2])))) {
  console.error(`FAIL: radare2 >= ${MIN_R2.join('.')} required, found ${r2version ? r2version.join('.') : 'unknown'}`);
  process.exit(1);
}
console.log(`r2 ${r2version.join('.')} detected (>= ${MIN_R2.join('.')} required)`);

const r2papiPath = join(root, 'async', 'r2papi.js');
if (!existsSync(r2papiPath)) {
  console.error('async/r2papi.js not found — run `npm run abuild` first');
  process.exit(1);
}

const { R2PapiAsync } = require(r2papiPath);
const { R2Shell } = require(join(root, 'async', 'shell.js'));
const r2pipe = require('r2pipe');

// r2pipe@2.8.6's pipe.call/callj are broken (arrow-fn `this` bug); go via cmd.
const adapt = (pipe) => {
  const cmd = (c) =>
    new Promise((resolve, reject) =>
      pipe.cmd(c, (err, out) => (err ? reject(err) : resolve(out)))
    );
  return {
    cmd,
    call: (c) => cmd(`'${c}`),
    callj: (c) => cmd(`'${c}`).then((s) => JSON.parse(s)),
    cmdj: (c) => cmd(c).then((s) => JSON.parse(s)),
    cmdAt: (c, a) => cmd(`${c} @ ${a}`),
    callAt: (c, a) => cmd(`'${c} @ ${a}`),
    log: (m) => console.log('[r2]', m),
    plugin: async () => true,
    unload: async () => true,
  };
};

const r2 = await new Promise((resolve, reject) => {
  const p = r2pipe.pipe(target, (err, r2p) => (err ? reject(err) : resolve(r2p)));
  if (p && typeof p.catch === 'function') p.catch(reject);
});

const api = new R2PapiAsync(adapt(r2));
const sh = new R2Shell(api);
let failures = 0;
const check = (label, cond) => {
  const ok = !!cond;
  console.log((ok ? 'ok  ' : 'FAIL') + '  ' + label);
  if (!ok) failures++;
};

try {
  // priming commands
  await api.cmd('aaa');

  const sections = await api.enumerateSections();
  check('enumerateSections() returns sections', Array.isArray(sections) && sections.length > 0);
  check('section has addr/vsize', sections[0] && typeof sections[0].vaddr === 'number');

  const maps = await api.enumerateMaps();
  check('enumerateMaps() non-empty', maps.length > 0 && typeof maps[0].from === 'number');

  const imports = await api.enumerateImports();
  check('enumerateImports() is an array', Array.isArray(imports));

  const relocs = await api.enumerateRelocations();
  check('enumerateRelocations() is an array', Array.isArray(relocs));

  const info = await api.binInfo();
  check('binInfo().bits is a number', typeof info.bits === 'number' && info.bits > 0);

  const plugins = await api.enumeratePlugins('bin');
  check('enumeratePlugins("bin") unwraps {bin:[...]}', plugins.length > 10 && !!plugins[0].name);

  const modules = await api.enumerateModules();
  check('enumerateModules() non-empty with hex base', modules.length > 0 && /^0x[0-9a-f]+$/i.test(modules[0].base));

  check('shell.fileExists hits', await sh.fileExists('/bin/ls'));
  check('shell.fileExists misses', !(await sh.fileExists('/definitely/not/a/real/path-xyz')));
  check('shell.isDirectory(/tmp)', await sh.isDirectory('/tmp'));
  const rcTrue = await sh.system('true');
  const rcFalse = await sh.system('false');
  check('shell.system(true) === 0', rcTrue === 0);
  check('shell.system(false) === 1', rcFalse === 1);
  const files = await sh.ls();
  check('shell.ls() lists files', Array.isArray(files) && files.length > 0);
  const types = await sh.enumerateFilesystemTypes();
  check('shell.enumerateFilesystemTypes() non-empty', types.length > 0 && !!types[0].name);
} catch (e) {
  console.error('FAIL  unexpected error:', e);
  failures++;
} finally {
  try { r2.quit(); } catch { /* ignore */ }
}

process.exit(failures ? 1 : 0);
