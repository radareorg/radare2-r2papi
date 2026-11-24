# r2papi (TypeScript) — Maintenance & Roadmap

Last updated: 2026-11 after the dependency-upgrade / typed-outputs pass.
Supersedes the previous PLAN.md; its still-relevant items were folded in below.

This document is the working plan for making the TypeScript API maintainable,
idiomatic and honest. It is ordered by leverage. Everything in section 0 is
verified, not aspirational.

---

## 0. What was done in the 2026-11 pass (verified)

**Dependencies**
- typescript ^5.3.3 → ^5.9.3, eslint 8 → 9 (flat config `eslint.config.mjs`, `.eslintrc.json`
  deleted), @typescript-eslint 6 → 8, typedoc 0.25 → 0.28, prettier 3.2 → 3.10.
  `r2pipe` stays at 2.8.6 (already latest). `json2ts` kept (only used by `tools/tsi.sh`).
- Lockfile regenerated. `npm test` now runs `lint + abuild` instead of the old
  `echo "Error: no test specified"` placeholder.
- Only remaining audit findings: 2 moderate in typedoc's transitive `minimatch`
  (dev-only; fixing them means downgrading typedoc — rejected).

**Typed command outputs (new `async/outputs.ts`)**
- Interfaces for the JSON emitted by `iSj iSSj irj iej iij iEj isj obj oj omj L*j mLj mj drj dptj`,
  derived from **live r2 6.2.7 output**, not from memory.
- Wired into `R2PapiAsync`, `ModuleClass`, `ProcessClass`, `ThreadClass` and `R2Shell`.
  The public API no longer returns `Promise<any>` for any of those commands.
- `Lij` returns `{bin: [...]}`, not a bare array — `enumeratePlugins('bin')` now unwraps it
  (this was silently wrong before).
- `enumerateModules` was badly broken (missing `await`, iterated a Promise, leaked
  `cfg.json.num=string` without restoring). Rewritten as a shared `loadModules()`
  that saves/restores `cfg.json.num` and handles non-debug (`obj`+`ilj`) and debug (`dmmj`) layouts.

**Bug fixes**
- `R2PipeAsyncFromSync`: `callj()` delegated to `r2p.cmdj` (wrong channel — bypasses `call`'s
  injection protection); `callAt()` delegated to `r2p.cmdAt`.
- `binInfo()`: `try/catch` never caught anything (missing `await`); now reads `ij` and returns
  `ij.bin` instead of the brittle `ij~{bin}` grep-inside-JSON.
- `searchBytes()` now zero-pads bytes < 0x10 (it produced invalid commands).
- `getBits()`, `countFlags()`, `countFunctions()`, `clearScreen()`, `resizeFile`,
  `insertNullBytes`, `removeBytes`, `seek`, `seekToRelativeOpcode`, `getBlockSize`,
  `setBlockSize`, `analyze*`, `stepOver`, `stepUntil`, `skip`, `id()`, `currentThreadId()`
  were sync signatures wrapping fire-and-forget promises (or `+this.cmd(...)` → `NaN`).
  All are honest `async`/`Promise` now.
- Hex math via `parseInt(x, 10)` on `0x…` strings (`?v`, `b`) now uses a hex-aware parse.
- `ThreadClass` / `ModuleClass` / `ProcessClass` used the global `r2` instead of the injected
  pipe and never awaited — rewritten with constructor injection.
- `R2AI` used the global pipe instead of its own; `setModel()` ignored its argument;
  `getModel()`/`query()` didn't await; constructor args were dropped.
- `R2Shell`: `fileExists`/`isSymlink`/`isDirectory` were `return false` stubs — now real
  (`!test -e|-L|-d`). `ls()` uses host `ls -1A`. `system()` returns the real exit code.
  `mkdir`/`unlink`/`open`/`mount` are honest async and actually run through the host shell.
  `enumerateFilesystemTypes()` returns `mLj` as `FileSystemPlugin[]` (`desc`, not the fictional
  `description`); `enumerateMountpoints()` returns the `mountpoints` key of `mj`.
- Packaging: the published tarball was effectively empty (`files:` didn't match anything, no
  `main`). Now `main`/`types` → `dist/index.js`, `files: [dist, r2papi.r2.js, README.md]`,
  `index.ts` added to the build, and `make pub` stages **separate** `dist` trees for
  `r2papi` (sync) and `r2papi-async` (async) — previously both publishes shipped the same
  sync build. Verified with `npm pack --dry-run` and by `require()`-ing both staged packages.
- `.gitignore`: ignore generated `async/*.js|*.d.ts`, `sync/*.js|*.d.ts`, `r2papi.r2.js`.
- Deleted `p.md` (verbatim duplicate of the old plan's "Priority 5").

**Verified**
- `npm test` (lint + abuild) green; `tsc` strict clean; `make build` green.
- Black-box smoke test against real r2 6.2.7 via node `r2pipe`:
  sections=11, segments=4, relocs=203, imports=90, exports=1, symbols=135,
  entrypoints=1, plugins(bin)=73, maps=5, `modules[0].base=0x100000000`,
  `binInfo().bits=64`, shell `fileExists/isDirectory/isSymlink` all correct on `/bin/ls`.
- Staged `r2papi` and `r2papi-async` packages both `require()` cleanly (main/exports OK).
- r2 bundle (`make one` → `r2papi.r2.js`) loads inside r2 and instantiates `R2Papi`.

**How r2 JS embedding actually works (tribal knowledge)**
- `r2 -i file.js` runs the file through **node**, not r2.
- `r2 -c 'js …'` runs inside r2's embedded qjs, but `-c` is split on `;` — multi-statement
  scripts break with errors like `Invalid 'o' subcommand` (that string is the r2 command
  handler complaining, not JS).
- `R2_PAPI_SCRIPT=path/to/bundle.js r2 -j /bin/ls` preloads the bundle into the qjs shell;
  `-j` is "scriptable qjs shell", not "json output" as `-h` claims.
- `r2.cmd()` returns the command's text output; JSON commands return strings to `JSON.parse`.

---

## 1. Principles (non-negotiable)

1. **One source of truth**: `async/*.ts`. `sync/` is generated. Never hand-edit it.
2. **Typed boundary**: every `*j` command's output conforms to `outputs.ts`. No `Promise<any>`
   in the public API outside the two transport primitives (`cmdj`/`callj`).
3. **Honest async**: any method that talks to r2 is `async`. Fire-and-forget is not allowed;
   use explicit `void` if you really mean it.
4. **No hidden channels**: every r2 interaction goes through the injected `R2PipeAsync`.
   The `R`/`r2` globals exist for frida-compat only and are deprecated.
5. **Typed beats parsed**: parse once at the boundary. No regex-over-JSON, no `ij~{bin}`.
6. **Fail loudly**: throw with command + raw output in the message; never `{} as T` on error.

## 2. Channel contract (use consistently)

| Need | Channel | Notes |
| --- | --- | --- |
| Raw text, no parsing | `cmd` | may emit chrome (`~` filters); treat as lossy |
| Command with `;`/quotes/special chars | `cmd("'" + s)` / `call(s)` | `'` prefix = literal: no r2 command parsing |
| JSON | `cmdj` / `callj` | `JSON.parse` with the command in the error message |
| Hot paths | small explicit `cmdj` queries | never `cmd` + string splitting |

Hard rules
- Never interpolate unsanitized user input into a command. Quote it (see `shQuote` in
  `shell.ts`) or use the `'` prefix; document why.
- Prefer r2-native commands over `!shell` equivalents — `!` output capture is not guaranteed
  across builds (on 6.2.7 it happens to be captured, see §5).
- The npm `r2pipe@2.8.6` ships broken `call`/`callj` (arrow functions using `this` where
  `this` is undefined — they throw at call time). The library therefore never calls
  `pipe.call*` directly; it wraps `pipe.cmd` and parses itself. Keep it that way or patch
  upstream.

## 3. Roadmap

### P0 — correctness net (mostly done; finish it)
- [x] Typed outputs + consumers (this pass).
- [x] Honest-async sweep over the public class surface.
- [ ] Same sweep for `esil.ts`, `opt.ts`, `elang.ts`, `graph.ts`, `pdq.ts`, `r2frida.ts`.
- [ ] Enable `@typescript-eslint/no-floating-promises` + `no-misused-promises`
      (needs `parserOptions.project`) so CI catches this bug class.
- [ ] `cmdj` parse errors include the command and raw output.

### P1 — sync generation that can't silently corrupt
The sed one-liner rewrites `Promise<T>`→`T` with a single-line pattern; multiline generics
break silently. Replace with a small `tools/sync-from-async.mjs` (TS compiler API or explicit
`// SYNC:` annotations). CI check: `make sync && git diff --exit-code sync/`.
Until then: always eyeball `make sync` output.

### P2 — finish the typed boundary
- [ ] `binInfo()`: return typed `ij.bin`, throw on error (drop `as BinFile` fallback `{}`).
- [ ] `enumerateXrefsTo`: return `number[]` (parse the hex) or `NativePointer[]`.
- [ ] `getRegisterStateForEsil`, `ai.ts`, `searchString/Bytes/Disasm`: validate shapes once at
      the boundary instead of letting `any` flow downstream.
- [ ] Ban `Promise<any>` outside the transport layer (eslint rule).
- [ ] Shared helper for "list command that may return `[]` or `null`" (r2 returns both).

### P3 — packaging & distribution
- [x] `main`/`types`/`files` fixed; `index.ts` in the build; staged pack verified for both
      `r2papi` (sync) and `r2papi-async`.
- [ ] `make pub` should run `npm test` first; add a `prepack` guard so a bare `npm pack`
      from the repo root can't ship an empty tarball again.
- [ ] Pick one canonical package (recommend: `r2papi-async`, mark sync deprecated) or drop
      the sync flavor at 1.0. Decide before tagging.
- [ ] Add `LICENSE` (repo claims MIT, file doesn't exist).
- [ ] `CHANGELOG.md`; tag releases; document versioning.

### P4 — runtime model & NativePointer ergonomics
- `NativePointer`
  - batch `readPointers(n)` into one `p8` + local decode (currently n round trips).
  - cache endianness/pointer size per instance (an r2 query per read today).
  - `toString()` is async (frida's is sync) — decide: make it sync from the cached addr, or
    rename to `toStringAsync` and document.
  - `equals()`: fast path when both sides are plain numbers (no r2 round trip).
- Processes/modules/threads (frida parity):
  - [x] `enumerateModules` fixed this pass; locked in by smoke test, needs CI.
  - [ ] `enumerateMallocRanges`/`enumerateSystemRanges` are malloc-name heuristics —
      document as approximate or drop.
- Replace ad-hoc `cfg.json.num` juggling with a `withJsonNumbers()` helper (restores prior value).

### P5 — shell layer honesty
- Split `R2Shell` visually (or by class) into host-fs (`!`-based) vs r2-VFS (`m*` commands).
  Keep API-compatible aliases for one major version.
- `ls()` = host `ls -1A` (works, captured on 6.2.7); `mdq` VFS listing stays separate.
- `system()` returns the real exit code (`!sh -c '…; echo __r2papi_rc=$?'`). Document.

### P6 — verification infrastructure (biggest gap)
- [ ] `node:test` suite with recorded fixtures: run `r2 -q0 /bin/true` with scripted `*j`
      commands, assert `outputs.ts` shapes. Would have caught every bug fixed this pass.
- [ ] `tools/smoke.mjs` driving `/bin/ls` through the async API, asserting
      sections/imports/maps > 0 (guards the whole stack against r2 upgrades).
- [ ] Type-level tests (`tsd` or `expectTypeOf`) on the public surface.
- [ ] CI: lint → tsc → pack dry-run → smoke (r2 installed via setup action or container).
      Repo currently has **no CI at all**.

### P7 — docs
- TypeDoc is wired (`npm run doc`); regenerate on release.
- README: "use from node" walkthrough, "use inside r2" (R2_PAPI_SCRIPT), sync vs async.
- AGENTS.md updated with build/test/smoke commands.

## 4. Open questions for the maintainer
1. Keep the sed-based sync build, or drop the sync flavor before 1.0? (Recommended: drop.)
2. Node floor: 18+? r2 floor: 6.x only, or also support 5.x? (`cfg.json.num` behavior differs.)
3. One package with `exports` subpaths (`r2papi`, `r2papi/r2`) or keep two names?
4. `NativePointer.readPointer()` on 32-bit (`wvp`) — anyone testing that path?
5. Frida API parity: goal or inspiration only? Affects naming forever.

## 5. Execution order
P0 finish → P6 (smoke+CI; protects everything after) → P1 → P2 → P3 → P4 → P5 → P7.
